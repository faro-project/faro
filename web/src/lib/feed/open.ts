// Opening one feed item's fetched ciphertext: check it against the header
// its device signed, decrypt it, and check a report against its header
// (as `faro_core::report::open_report` does). No network, so it can be
// tested without a server; `feed.ts` fetches the blob.

import { fromUtf8 } from '../crypto/bytes.ts';
import { checkBodyCommitment } from '../crypto/event.ts';
import { eventBodyAad, reportBodyAad } from '../crypto/proto.ts';
import { DecryptError, openItem, type EncryptedItem } from '../crypto/seal.ts';
import type { DailyReport, EventBody, FeedEntry } from '../types.ts';
import { reportMatchesHeader } from './verify.ts';

export type Opened = { kind: 'event'; body: EventBody } | { kind: 'report'; report: DailyReport };

export type OpenFailure = 'not_shared' | 'gone' | 'broken' | 'tampered';

/** Throws an OpenFailure string when `item` can't be opened as `e`'s content. */
export function openFetched(
	e: FeedEntry,
	item: EncryptedItem,
	instanceId: string,
	viewerId: string,
	secret: Uint8Array
): Opened {
	if (e.type === 'alert') throw 'gone' satisfies OpenFailure;
	// An entry without a header fails its signature check in `verify.ts`.
	if (e.header && checkBodyCommitment(e.header, item)) throw 'tampered' satisfies OpenFailure;
	const aad =
		e.type === 'event'
			? eventBodyAad(instanceId, e.device_id, e.seq)
			: reportBodyAad(instanceId, e.device_id, e.period_start_ms, e.period_end_ms);
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
	if (e.type === 'report' && e.header && opened.kind === 'report') {
		let same = false;
		try {
			same = reportMatchesHeader(opened.report, e.header);
		} catch {
			same = false;
		}
		if (!same) throw 'tampered' satisfies OpenFailure;
	}
	return opened;
}
