// Device-signed event and report headers and the per-device hash chain
// (docs/PROTOCOL.md §3): ports of `faro_proto::event::EventHeader`,
// `faro_proto::report::ReportHeader` and `faro_crypto::chain`.
//
// As everywhere, JSON is transport only: signatures and chain hashes are
// over the canonical bytes, built field by field.

import { hex, unb64, unb64Fixed, type Bytes } from './bytes.ts';
import { Canonical, hash, hashFromString, hashToString } from './canonical.ts';
import { itemBodyHash } from './group.ts';
import { verify } from './keys.ts';
import type { EncryptedItem } from './seal.ts';

export const EVENT_HEADER_VERSION = 1;
export const REPORT_HEADER_VERSION = 1;

export type HeaderUrgency = 'none' | 'normal' | 'urgent';

/** `EventHeader` as JSON. Hashes are `b3:<hex>`. */
export interface EventHeader {
	v: number;
	instance_id: string;
	device_id: string;
	seq: number;
	prev_hash: string;
	ts_ms: number;
	mono_ms: number;
	boot_id: string;
	kind: string;
	urgency: HeaderUrgency;
	body_hash: string;
	body_len: number;
}

/** `ReportHeader` as JSON. */
export interface ReportHeader {
	v: number;
	instance_id: string;
	member_id: string;
	device_id: string;
	period_start_ms: number;
	period_end_ms: number;
	first_seq: number | null;
	last_seq: number | null;
	body_hash: string;
	body_len: number;
}

export function eventHeaderSigningBytes(h: EventHeader): Bytes {
	return new Canonical('faro/event-header/v1')
		.u16(h.v)
		.str(h.instance_id)
		.str(h.device_id)
		.u64(h.seq)
		.fixed(hashFromString(h.prev_hash))
		.i64(h.ts_ms)
		.u64(h.mono_ms)
		.str(h.boot_id)
		.str(h.kind)
		.str(h.urgency)
		.fixed(hashFromString(h.body_hash))
		.u64(h.body_len)
		.finish();
}

export function reportHeaderSigningBytes(h: ReportHeader): Bytes {
	return new Canonical('faro/report-header/v1')
		.u16(h.v)
		.str(h.instance_id)
		.str(h.member_id)
		.str(h.device_id)
		.i64(h.period_start_ms)
		.i64(h.period_end_ms)
		.optU64(h.first_seq)
		.optU64(h.last_seq)
		.fixed(hashFromString(h.body_hash))
		.u64(h.body_len)
		.finish();
}

/** `EventHeader::chain_hash`: what the next event carries as `prev_hash`. */
export function chainHash(h: EventHeader): string {
	return hashToString(hash(eventHeaderSigningBytes(h)));
}

/** `genesis_hash`: the `prev_hash` of a device's first event (`seq` 0). */
export function genesisHash(instanceId: string, deviceId: string): string {
	return hashToString(
		hash(new Canonical('faro/genesis/v1').str(instanceId).str(deviceId).finish())
	);
}

/** Strict Ed25519 over the canonical bytes; false for anything malformed. */
export function verifyHeader<T>(
	devicePk: Uint8Array,
	header: T,
	sig: string,
	signingBytes: (h: T) => Uint8Array
): boolean {
	let key: string;
	let msg: Uint8Array;
	try {
		msg = signingBytes(header);
		key = `${hex(devicePk)}:${sig}:${hex(msg)}`;
	} catch {
		return false;
	}
	// The feed is re-checked on every refresh; a verdict never changes.
	const hit = verdicts.get(key);
	if (hit !== undefined) return hit;
	let ok: boolean;
	try {
		ok = verify(devicePk, msg, unb64Fixed(sig, 64, 'sig'));
	} catch {
		ok = false;
	}
	if (verdicts.size >= MAX_VERDICTS) verdicts.clear();
	verdicts.set(key, ok);
	return ok;
}

const verdicts = new Map<string, boolean>();
const MAX_VERDICTS = 50_000;

const URGENCY_RANK: Record<HeaderUrgency, number> = { none: 0, normal: 1, urgent: 2 };

/** `EventKind::min_urgency` (PROTOCOL.md §3.3). */
export function kindFloor(kind: string): HeaderUrgency {
	if (kind === 'tamper' || kind === 'goodbye') return 'urgent';
	if (kind === 'settings_change' || kind === 'paused' || kind === 'resumed') return 'normal';
	return 'none';
}

/** `max(header.urgency, kind floor)`: the urgency the instance must show. */
export function effectiveUrgency(h: Pick<EventHeader, 'kind' | 'urgency'>): HeaderUrgency {
	const f = kindFloor(h.kind);
	return URGENCY_RANK[h.urgency] >= URGENCY_RANK[f] ? h.urgency : f;
}

/**
 * The header's commitment to the ciphertext the instance served
 * (`SignedEvent::check_shape`, `open_report`): the algorithm, `body_hash`
 * and `body_len`. Returns the reason it fails, or null.
 */
export function checkBodyCommitment(
	h: { body_hash: string; body_len: number },
	item: EncryptedItem
): string | null {
	try {
		if (item.alg !== 'xchacha20poly1305') return 'an unknown encryption';
		if (itemBodyHash(item) !== h.body_hash) return 'content other than the computer signed';
		if (unb64(item.ciphertext).length !== h.body_len) {
			return 'content of another length than the computer signed';
		}
	} catch {
		return 'malformed content';
	}
	return null;
}
