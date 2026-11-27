// Checking the feed in the browser instead of trusting the instance
// (docs/PROTOCOL.md §3.5).
//
// The instance serves every event and report with the header its device
// signed, and the member-signed endorsement of each device. Here, in order:
//
// 1. each device's endorsement against the member's signing key, which the
//    viewer holds themselves (the member) or compared by safety code (an
//    ally), never only because the server said so;
// 2. each item's header signature against its endorsed device key, and the
//    feed's plain fields against the header;
// 3. once its content is fetched, the ciphertext against the header's
//    `body_hash` and `body_len` (and a report's own fields against it);
// 4. each device's hash chain (`GET /v1/ally/chain`) over the range the
//    feed's items and reports cover: every link signed, each `prev_hash`
//    the chain hash of the one before, no `seq` missing, and every stored
//    event that should be in the feed actually listed.
//
// Server alerts are the instance's own words and have nothing to check.

import { unb64Fixed } from '../crypto/bytes.ts';
import {
	chainHash,
	effectiveUrgency,
	EVENT_HEADER_VERSION,
	eventHeaderSigningBytes,
	genesisHash,
	REPORT_HEADER_VERSION,
	reportHeaderSigningBytes,
	verifyHeader,
	type EventHeader,
	type ReportHeader
} from '../crypto/event.ts';
import {
	deviceEndorsementSigningBytes,
	verifySigned,
	type DeviceEndorsement,
	type Signed
} from '../crypto/proto.ts';
import type { ChainLink, DailyReport, FeedEntry } from '../types.ts';

/**
 * Where the member key came from: the viewer's own (`own`), one an ally
 * compared by safety code (`checked`), one the server reports that the
 * ally hasn't compared (`unchecked`), or the one the ally compared although
 * the server now reports another (`changed`).
 */
export type KeyTrust = 'own' | 'checked' | 'unchecked' | 'changed';

export interface MemberKey {
	pk: Uint8Array;
	trust: KeyTrust;
}

/**
 * The key an ally checks against: the one they compared by safety code if
 * they did (even when the server now reports another), else the server's,
 * marked unchecked.
 */
export function allyMemberKey(served: string | null, compared: string | null): MemberKey | null {
	const pick = compared ?? served;
	if (!pick) return null;
	let pk: Uint8Array;
	try {
		pk = unb64Fixed(pick, 32, 'member key');
	} catch {
		return null;
	}
	const trust: KeyTrust = !compared ? 'unchecked' : compared === served ? 'checked' : 'changed';
	return { pk, trust };
}

export type ItemCheck =
	/** Every check passed against a key the viewer holds or compared. */
	| { status: 'verified' }
	/** Every check passed, but against a key nobody compared. */
	| { status: 'unconfirmed' }
	| { status: 'failed'; reason: string }
	/** No member key to check against yet (locked, or no keys). */
	| { status: 'unchecked' }
	/** A server alert: nothing signed to check. */
	| { status: 'server' };

/** Each endorsed device's signing key, or why it can't be used. */
export function deviceKeys(
	key: MemberKey,
	instanceId: string,
	memberId: string,
	endorsements: Record<string, Signed<DeviceEndorsement>>
): Map<string, Uint8Array | string> {
	const out = new Map<string, Uint8Array | string>();
	for (const [id, e] of Object.entries(endorsements)) {
		if (!e || typeof e !== 'object') continue;
		if (!verifySigned(key.pk, e, deviceEndorsementSigningBytes)) {
			out.set(
				id,
				key.trust === 'changed'
					? 'the computer was not approved with the key you compared'
					: 'the computer was not approved with the member’s key'
			);
		} else if (e.instance_id !== instanceId || e.member_id !== memberId || e.device_id !== id) {
			out.set(id, 'the approval is for another computer, person or server');
		} else {
			try {
				out.set(id, unb64Fixed(e.device_sign_pubkey, 32, 'device key'));
			} catch {
				out.set(id, 'the approval names a malformed key');
			}
		}
	}
	return out;
}

/** Why an event's header doesn't back its feed entry, or null. */
function eventMismatch(
	e: Extract<FeedEntry, { type: 'event' }>,
	h: EventHeader,
	instanceId: string
): string | null {
	if (h.v !== EVENT_HEADER_VERSION) return 'an unknown header version';
	if (h.instance_id !== instanceId) return 'it was signed for another server';
	if (h.device_id !== e.device_id || h.seq !== e.seq) return 'the signature is for another event';
	if (h.kind !== e.kind || h.ts_ms !== e.ts_ms) return 'the server changed what it says happened';
	if (effectiveUrgency(h) !== e.urgency) return 'the server changed its urgency';
	return null;
}

function reportMismatch(
	e: Extract<FeedEntry, { type: 'report' }>,
	h: ReportHeader,
	instanceId: string,
	memberId: string
): string | null {
	if (h.v !== REPORT_HEADER_VERSION) return 'an unknown header version';
	if (h.instance_id !== instanceId) return 'it was signed for another server';
	if (h.member_id !== memberId) return 'it is someone else’s report';
	if (
		h.device_id !== e.device_id ||
		h.period_start_ms !== e.period_start_ms ||
		h.period_end_ms !== e.period_end_ms
	) {
		return 'the signature is for another report';
	}
	return null;
}

/** Steps 1 and 2 for one entry. */
export function checkEntry(
	e: FeedEntry,
	key: MemberKey | null,
	keys: Map<string, Uint8Array | string>,
	instanceId: string,
	memberId: string
): ItemCheck {
	if (e.type === 'alert') return { status: 'server' };
	if (!key) return { status: 'unchecked' };
	const fail = (reason: string): ItemCheck => ({ status: 'failed', reason });
	const dev = keys.get(e.device_id);
	if (dev === undefined) return fail('the member never approved this computer');
	if (typeof dev === 'string') return fail(dev);
	if (!e.header || typeof e.sig !== 'string') return fail('it carries no signature');
	let bad: string | null;
	let ok: boolean;
	try {
		if (e.type === 'event') {
			bad = eventMismatch(e, e.header, instanceId);
			ok = !bad && verifyHeader(dev, e.header, e.sig, eventHeaderSigningBytes);
		} else {
			bad = reportMismatch(e, e.header, instanceId, memberId);
			ok = !bad && verifyHeader(dev, e.header, e.sig, reportHeaderSigningBytes);
		}
	} catch {
		return fail('its header is malformed');
	}
	if (bad) return fail(bad);
	if (!ok) return fail('the computer’s signature does not match');
	return { status: key.trust === 'unchecked' ? 'unconfirmed' : 'verified' };
}

/** Step 3 for a report: its decrypted fields against the signed header. */
export function reportMatchesHeader(r: DailyReport, h: ReportHeader): boolean {
	return (
		r.device_id === h.device_id &&
		r.period_start_ms === h.period_start_ms &&
		r.period_end_ms === h.period_end_ms &&
		(r.first_seq ?? null) === (h.first_seq ?? null) &&
		(r.last_seq ?? null) === (h.last_seq ?? null)
	);
}

/** Whether a check passed (the item is what its computer signed). */
export function passed(c: ItemCheck | undefined): boolean {
	return c?.status === 'verified' || c?.status === 'unconfirmed';
}

/**
 * The `seq` range of one device's chain that the passing entries cover:
 * every event's `seq` and every report's signed `first_seq..last_seq`.
 */
export function chainRange(
	entries: FeedEntry[],
	deviceId: string,
	ok: (e: FeedEntry) => boolean
): { lo: number; hi: number } | null {
	let lo = Infinity;
	let hi = -Infinity;
	for (const e of entries) {
		if (e.type === 'alert' || e.device_id !== deviceId || !ok(e)) continue;
		const seqs =
			e.type === 'event' ? [e.seq] : [e.header?.first_seq ?? null, e.header?.last_seq ?? null];
		for (const s of seqs) {
			if (typeof s !== 'number' || !Number.isSafeInteger(s) || s < 0) continue;
			lo = Math.min(lo, s);
			hi = Math.max(hi, s);
		}
	}
	return lo <= hi ? { lo, hi } : null;
}

export interface Gap {
	deviceId: string;
	/** Inclusive. */
	from: number;
	to: number;
	/**
	 * `missing`: the server provided no header for these `seq`s.
	 * `withheld`: it stored the event but left it out of the feed.
	 */
	kind: 'missing' | 'withheld';
	/** For `withheld`: the event's kind. */
	eventKind?: string;
	/** For `missing`: a passing report counts these events. */
	inReport?: boolean;
}

export interface ChainCheck {
	gaps: Gap[];
	/** Why the history the server provided can't be trusted, if it can't. */
	broken: string | null;
	/** Feed events (by `seq`) that aren't the ones in the device's chain. */
	notInChain: Set<number>;
}

/**
 * Step 4 for one device. `links` are what `GET /v1/ally/chain` returned
 * for `range`; `complete` is false if fetching stopped early (then only the
 * part fetched is judged). Every stored event above `none` urgency that was
 * received after `listedAfterMs` must be in `entries`.
 */
export function checkChain(args: {
	instanceId: string;
	deviceId: string;
	devicePk: Uint8Array;
	range: { lo: number; hi: number };
	links: ChainLink[];
	complete: boolean;
	entries: FeedEntry[];
	listedAfterMs: number;
	ok: (e: FeedEntry) => boolean;
}): ChainCheck {
	const { instanceId, deviceId, devicePk, links } = args;
	let broken: string | null = null;
	const good = new Map<number, ChainLink>();
	let prev: ChainLink | null = null;
	let lastSeq = -1;
	for (const l of links) {
		const h = l?.header;
		let valid = false;
		try {
			valid =
				!!h &&
				h.v === EVENT_HEADER_VERSION &&
				h.instance_id === instanceId &&
				h.device_id === deviceId &&
				Number.isSafeInteger(h.seq) &&
				verifyHeader(devicePk, h, l.sig, eventHeaderSigningBytes);
		} catch {
			valid = false;
		}
		if (!valid) {
			broken ??= 'the server’s copy holds an event this computer didn’t sign';
			continue;
		}
		if (h.seq <= lastSeq) {
			broken ??= 'the server’s copy is out of order';
			continue;
		}
		lastSeq = h.seq;
		if (h.seq === 0 && h.prev_hash !== genesisHash(instanceId, deviceId)) {
			broken ??= 'its first event doesn’t start this computer’s history';
		}
		if (prev && prev.header.seq + 1 === h.seq && h.prev_hash !== chainHash(prev.header)) {
			broken ??= `the history was rewritten at event ${h.seq}`;
		}
		if (prev && l.received_at_ms < prev.received_at_ms) {
			broken ??= 'the server’s receive times are out of order';
		}
		good.set(h.seq, l);
		prev = l;
	}

	// Judge only what was fetched.
	const lo = args.range.lo;
	const hi = args.complete ? args.range.hi : Math.min(args.range.hi, lastSeq);
	const mine = args.entries.filter(
		(e): e is Extract<FeedEntry, { type: 'event' | 'report' }> =>
			e.type !== 'alert' && e.device_id === deviceId && args.ok(e)
	);
	const listed = new Map<number, EventHeader>();
	const reported: [number, number][] = [];
	for (const e of mine) {
		if (e.type === 'event' && e.header) listed.set(e.seq, e.header);
		if (e.type === 'report' && e.header?.first_seq != null && e.header.last_seq != null) {
			reported.push([e.header.first_seq, e.header.last_seq]);
		}
	}

	const gaps: Gap[] = [];
	const missing = (from: number, to: number) =>
		gaps.push({
			deviceId,
			from,
			to,
			kind: 'missing',
			inReport: reported.some(([a, b]) => a <= to && from <= b)
		});
	// Over the seqs present, not the whole range: a signed range can be huge.
	let expected = lo;
	for (const s of [...good.keys()].filter((s) => s >= lo && s <= hi).sort((a, b) => a - b)) {
		if (s > expected) missing(expected, s - 1);
		expected = s + 1;
	}
	if (expected <= hi) missing(expected, hi);

	for (const [seq, l] of good) {
		if (seq < lo || seq > hi) continue;
		if (effectiveUrgency(l.header) === 'none' || l.received_at_ms <= args.listedAfterMs) continue;
		if (!listed.has(seq)) {
			gaps.push({ deviceId, from: seq, to: seq, kind: 'withheld', eventKind: l.header.kind });
		}
	}
	gaps.sort((a, b) => a.from - b.from);

	const notInChain = new Set<number>();
	for (const [seq, h] of listed) {
		if (seq > hi) continue;
		const l = good.get(seq);
		if (!l || chainHash(l.header) !== chainHash(h)) notInChain.add(seq);
	}
	return { gaps, broken, notInChain };
}
