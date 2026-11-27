// Loading a member's feed and opening its encrypted items in the browser.
//
// `GET /v1/ally/feed` is metadata only. An item's content is a blob (the
// serialized EncryptedItem) that `GET /v1/blobs/{id}` serves only to the
// member and to allies it was sealed to; it is opened here with the
// viewer's X25519 key, with the AAD that binds it to its event or report,
// so the server can't move a body to another item unnoticed, and checked
// against the `body_hash` its device signed, so the server can't replace
// it either (`open.ts`). The signatures and each device's hash chain are
// checked in `verify.ts`.

import { api, seg } from '../api.ts';
import { base64Std, unb64 } from '../crypto/bytes.ts';
import type { DeviceEndorsement, Signed } from '../crypto/proto.ts';
import type { EncryptedItem } from '../crypto/seal.ts';
import { openFetched, type OpenFailure, type Opened } from './open.ts';
import type {
	BlurredThumbnail,
	ChainLink,
	ChainResponse,
	FeedEntry,
	FeedResponse,
	Platform
} from '../types.ts';

export type { OpenFailure, Opened };

export const PAGE = 500;
/** Pages fetched for one view at most (5,000 items). */
export const MAX_PAGES = 10;

export interface Loaded {
	/** Newest first. */
	items: FeedEntry[];
	/** True if the window holds more than MAX_PAGES pages. */
	truncated: boolean;
	/** What the instance says each device in `items` is (older instances: none). */
	platforms: Record<string, Platform>;
	/** The member-signed endorsement of each device in `items`. */
	endorsements: Record<string, Signed<DeviceEndorsement>>;
}

/** Everything received since `sinceMs`, newest first. */
export async function loadFeed(memberId: string, sinceMs: number): Promise<Loaded> {
	const items: FeedEntry[] = [];
	const platforms: Record<string, Platform> = {};
	const endorsements: Record<string, Signed<DeviceEndorsement>> = {};
	let cursor: string | null = null;
	for (let page = 0; page < MAX_PAGES; page++) {
		const q = new URLSearchParams({ member_id: memberId, limit: String(PAGE) });
		if (cursor) q.set('cursor', cursor);
		else q.set('since_ms', String(sinceMs));
		const r: FeedResponse = await api.get<FeedResponse>(`/v1/ally/feed?${q}`);
		items.push(...r.items);
		Object.assign(platforms, r.device_platforms);
		Object.assign(endorsements, r.device_endorsements);
		if (!r.has_more || !r.next_cursor)
			return { items: items.reverse(), truncated: false, platforms, endorsements };
		cursor = r.next_cursor;
	}
	return { items: items.reverse(), truncated: true, platforms, endorsements };
}

export const CHAIN_PAGE = 1000;
/** Headers fetched per device at most (20,000). */
export const MAX_CHAIN_PAGES = 20;

/**
 * One device's stored headers from `lo` through `hi` (those the server
 * has). `complete` is false if fetching stopped at the cap first.
 */
export async function loadChain(
	memberId: string,
	deviceId: string,
	lo: number,
	hi: number
): Promise<{ links: ChainLink[]; complete: boolean }> {
	const links: ChainLink[] = [];
	let from = lo;
	for (let page = 0; page < MAX_CHAIN_PAGES; page++) {
		const q = new URLSearchParams({
			member_id: memberId,
			device_id: deviceId,
			from_seq: String(from),
			limit: String(CHAIN_PAGE)
		});
		const r = await api.get<ChainResponse>(`/v1/ally/chain?${q}`);
		links.push(...r.links);
		const last = r.links.at(-1)?.header?.seq;
		if (!r.has_more || typeof last !== 'number' || last >= hi) return { links, complete: true };
		from = last + 1;
	}
	return { links, complete: false };
}

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
 * Throws an OpenFailure string when it can't be opened, or when it isn't
 * the content the entry's signed header commits to (`tampered`).
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
	const opened = openFetched(e, item, instanceId, viewerId, secret);
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
	broken: "The details couldn't be decrypted. They may have been damaged or tampered with.",
	tampered:
		"These details aren't what the computer signed, so the server must have replaced them. They aren't shown."
};
