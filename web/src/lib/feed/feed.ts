// Loading a member's feed and opening its encrypted items in the browser.
//
// `GET /v1/ally/feed` is metadata only. An item's content is a blob (the
// serialized EncryptedItem) that `GET /v1/blobs/{id}` serves only to the
// member and to allies it was sealed to; it is opened here with the
// viewer's X25519 key, with the AAD that binds it to its event or report,
// so the server can't move a body to another item unnoticed.

import { api, seg } from '../api.ts';
import { base64Std, fromUtf8, unb64 } from '../crypto/bytes.ts';
import { eventBodyAad, reportBodyAad } from '../crypto/proto.ts';
import { DecryptError, openItem, type EncryptedItem } from '../crypto/seal.ts';
import type {
	BlurredThumbnail,
	DailyReport,
	EventBody,
	FeedEntry,
	FeedResponse
} from '../types.ts';

export const PAGE = 500;
/** Pages fetched for one view at most (5,000 items). */
export const MAX_PAGES = 10;

export interface Loaded {
	/** Newest first. */
	items: FeedEntry[];
	/** True if the window holds more than MAX_PAGES pages. */
	truncated: boolean;
}

/** Everything received since `sinceMs`, newest first. */
export async function loadFeed(memberId: string, sinceMs: number): Promise<Loaded> {
	const items: FeedEntry[] = [];
	let cursor: string | null = null;
	for (let page = 0; page < MAX_PAGES; page++) {
		const q = new URLSearchParams({ member_id: memberId, limit: String(PAGE) });
		if (cursor) q.set('cursor', cursor);
		else q.set('since_ms', String(sinceMs));
		const r: FeedResponse = await api.get<FeedResponse>(`/v1/ally/feed?${q}`);
		items.push(...r.items);
		if (!r.has_more || !r.next_cursor) return { items: items.reverse(), truncated: false };
		cursor = r.next_cursor;
	}
	return { items: items.reverse(), truncated: true };
}

export type Opened = { kind: 'event'; body: EventBody } | { kind: 'report'; report: DailyReport };

export type OpenFailure = 'not_shared' | 'gone' | 'broken';

const cache = new Map<string, Opened>();

/** A stable key for an entry, for lists and caches. */
export function entryKey(e: FeedEntry): string {
	if (e.type === 'event') return `e:${e.device_id}:${e.seq}`;
	if (e.type === 'report') return `r:${e.report_id}`;
	return `a:${e.alert_id}`;
}

export function hasContent(e: FeedEntry): boolean {
	return e.type === 'report' || (e.type === 'event' && !!e.blob_id);
}

/**
 * Fetch and decrypt an entry's content as `viewerId` with `secret`.
 * Throws an OpenFailure string when it can't be opened.
 */
export async function openEntry(
	e: FeedEntry,
	instanceId: string,
	viewerId: string,
	secret: Uint8Array
): Promise<Opened> {
	const blobId = e.type === 'event' ? e.blob_id : e.type === 'report' ? e.blob_id : null;
	if (!blobId) throw 'gone' satisfies OpenFailure;
	const key = `${viewerId}:${blobId}`;
	const hit = cache.get(key);
	if (hit) return hit;
	let item: EncryptedItem;
	try {
		item = await api.get<EncryptedItem>(`/v1/blobs/${seg(blobId)}`);
	} catch (err) {
		// 404: expired under retention, or not sealed to this viewer.
		if ((err as { status?: number }).status === 404) throw 'gone' satisfies OpenFailure;
		throw err;
	}
	const aad =
		e.type === 'event'
			? eventBodyAad(instanceId, e.device_id, e.seq)
			: e.type === 'report'
				? reportBodyAad(instanceId, e.device_id, e.period_start_ms, e.period_end_ms)
				: new Uint8Array();
	let text: string;
	try {
		text = fromUtf8(openItem(item, aad, viewerId, secret));
	} catch (err) {
		if (err instanceof DecryptError && err.reason === 'no_envelope') {
			throw 'not_shared' satisfies OpenFailure;
		}
		throw 'broken' satisfies OpenFailure;
	}
	let opened: Opened;
	try {
		opened =
			e.type === 'report'
				? { kind: 'report', report: JSON.parse(text) as DailyReport }
				: { kind: 'event', body: JSON.parse(text) as EventBody };
	} catch {
		throw 'broken' satisfies OpenFailure;
	}
	cache.set(key, opened);
	return opened;
}

/** Forget decrypted content (on lock). */
export function clearOpened() {
	cache.clear();
}

/**
 * A `data:` URL for a blurred thumbnail. Only PNGs are accepted (the only
 * image type in the protocol); anything else is not shown.
 */
export function thumbnailUrl(t: BlurredThumbnail): string | null {
	try {
		const png = unb64(t.png);
		const sig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
		if (png.length < 8 || sig.some((b, i) => png[i] !== b)) return null;
		return `data:image/png;base64,${base64Std(png)}`;
	} catch {
		return null;
	}
}

export const FAILURE_TEXT: Record<OpenFailure | 'unreadable', string> = {
	unreadable: "The details were decrypted but aren't in a form this page can show.",
	not_shared: 'Not shared with you: it was sealed before you were an ally, or to other keys.',
	gone: 'The details are no longer stored (they expire under the retention settings).',
	broken: "The details couldn't be decrypted. They may have been damaged or tampered with."
};
