// The member-signed structures (docs/PROTOCOL.md §5) and encryption AADs
// (§4.1): ports of `faro_proto::keys` and the `body_aad` helpers.
//
// JSON is transport only; every signature is over `signingBytes`, built
// field by field. On the wire a signed structure is its fields flattened
// together with `sig` (`Signed<T>`).

import { b64, unb64Fixed, type Bytes } from './bytes.ts';
import { Canonical, hash, hashFromString, hashToString } from './canonical.ts';
import { isWeakX25519, sign, verify } from './keys.ts';

export type Signed<T> = T & { sig: string };

export interface ManifestRef {
	version: number;
	/** `b3:<hex>` */
	hash: string;
}

export interface ManifestAlly {
	ally_id: string;
	/** base64url X25519 key */
	enc_pubkey: string;
}

export interface RecipientManifest {
	instance_id: string;
	member_id: string;
	version: number;
	issued_at_ms: number;
	member_enc_pubkey: string;
	allies: ManifestAlly[];
}

export interface DeviceEndorsement {
	instance_id: string;
	member_id: string;
	device_id: string;
	device_sign_pubkey: string;
	endorsed_at_ms: number;
	min_manifest: ManifestRef;
}

export interface AllyEndorsement {
	instance_id: string;
	member_id: string;
	ally_id: string;
	ally_enc_pubkey: string;
	endorsed_at_ms: number;
}

export interface MemberEncKeyBinding {
	instance_id: string;
	member_id: string;
	member_enc_pubkey: string;
	endorsed_at_ms: number;
}

const key32 = (s: string, what: string) => unb64Fixed(s, 32, what);

export const MAX_MANIFEST_ALLIES = 32;

/** `UserId::is_well_formed` and friends. */
export function isWellFormedId(id: string, prefix: 'usr_' | 'dev_' | 'inst_'): boolean {
	if (!id.startsWith(prefix)) return false;
	const rest = id.slice(prefix.length);
	return rest.length >= 1 && rest.length <= 64 && /^[A-Za-z0-9_-]+$/.test(rest);
}

/** Rust orders `UserId`s as byte strings; ids are ASCII, so code units agree. */
export function compareIds(a: string, b: string): number {
	return a < b ? -1 : a > b ? 1 : 0;
}

/** `RecipientManifest::validate`: the structural checks that need no keys. */
export function validateManifest(m: RecipientManifest): string | null {
	if (!Number.isSafeInteger(m.version) || m.version < 1) return 'version must be at least 1';
	if (m.allies.length > MAX_MANIFEST_ALLIES) return 'too many allies';
	if (!isWellFormedId(m.instance_id, 'inst_')) return 'malformed instance id';
	if (!isWellFormedId(m.member_id, 'usr_')) return 'malformed member id';
	for (let i = 0; i < m.allies.length; i++) {
		const a = m.allies[i];
		if (!isWellFormedId(a.ally_id, 'usr_')) return 'malformed ally id';
		if (a.ally_id === m.member_id) return 'the member is listed as their own ally';
		if (i > 0 && compareIds(m.allies[i - 1].ally_id, a.ally_id) >= 0) {
			return 'allies are not sorted or not unique';
		}
	}
	return null;
}

export function manifestSigningBytes(m: RecipientManifest): Bytes {
	const c = new Canonical('faro/recipient-manifest/v1')
		.str(m.instance_id)
		.str(m.member_id)
		.u64(m.version)
		.i64(m.issued_at_ms)
		.fixed(key32(m.member_enc_pubkey, 'member_enc_pubkey'))
		.u64(m.allies.length);
	for (const a of m.allies) c.str(a.ally_id).fixed(key32(a.enc_pubkey, 'ally enc_pubkey'));
	return c.finish();
}

export function manifestRef(m: RecipientManifest): ManifestRef {
	return { version: m.version, hash: hashToString(hash(manifestSigningBytes(m))) };
}

export function deviceEndorsementSigningBytes(e: DeviceEndorsement): Bytes {
	return new Canonical('faro/device-endorsement/v2')
		.str(e.instance_id)
		.str(e.member_id)
		.str(e.device_id)
		.fixed(key32(e.device_sign_pubkey, 'device_sign_pubkey'))
		.i64(e.endorsed_at_ms)
		.u64(e.min_manifest.version)
		.fixed(hashFromString(e.min_manifest.hash))
		.finish();
}

export function allyEndorsementSigningBytes(e: AllyEndorsement): Bytes {
	return new Canonical('faro/ally-endorsement/v1')
		.str(e.instance_id)
		.str(e.member_id)
		.str(e.ally_id)
		.fixed(key32(e.ally_enc_pubkey, 'ally_enc_pubkey'))
		.i64(e.endorsed_at_ms)
		.finish();
}

export function memberBindingSigningBytes(b: MemberEncKeyBinding): Bytes {
	return new Canonical('faro/member-enc-key/v1')
		.str(b.instance_id)
		.str(b.member_id)
		.fixed(key32(b.member_enc_pubkey, 'member_enc_pubkey'))
		.i64(b.endorsed_at_ms)
		.finish();
}

/**
 * `faro_proto::keys::KeyRewrap`: replace the stored wrapped copies of the
 * member's private keys, signed by the member key. The wrapped values are
 * the exact JSON text that is signed.
 */
export interface KeyRewrap {
	instance_id: string;
	member_id: string;
	sign_pubkey: string;
	issued_at_ms: number;
	wrapped_sign_key: string;
	wrapped_enc_key: string;
	recovery_wrapped: string;
}

export function keyRewrapSigningBytes(r: KeyRewrap): Bytes {
	return new Canonical('faro/key-rewrap/v1')
		.str(r.instance_id)
		.str(r.member_id)
		.fixed(key32(r.sign_pubkey, 'sign_pubkey'))
		.i64(r.issued_at_ms)
		.str(r.wrapped_sign_key)
		.str(r.wrapped_enc_key)
		.str(r.recovery_wrapped)
		.finish();
}

/** Sign `body` with the Ed25519 `seed`, giving the flattened wire form. */
export function signWith<T extends object>(
	seed: Uint8Array,
	body: T,
	signingBytes: (b: T) => Uint8Array
): Signed<T> {
	return { ...body, sig: b64(sign(seed, signingBytes(body))) };
}

/** Split a wire `Signed<T>` and verify it against `pk`. */
export function verifySigned<T extends object>(
	pk: Uint8Array,
	signed: Signed<T>,
	signingBytes: (b: T) => Uint8Array
): boolean {
	const { sig, ...body } = signed;
	try {
		return verify(pk, signingBytes(body as unknown as T), unb64Fixed(sig, 64, 'sig'));
	} catch {
		return false;
	}
}

/**
 * Check a manifest the instance served before building on it: structure,
 * the member's own signature, the expected instance and member, and no
 * small-order keys. Returns the reason it fails, or null.
 */
export function checkManifest(
	m: Signed<RecipientManifest>,
	memberSignPk: Uint8Array,
	instanceId: string,
	memberId: string
): string | null {
	const bad = validateManifest(m);
	if (bad) return bad;
	if (!verifySigned(memberSignPk, m, manifestSigningBytes)) return 'signature does not verify';
	if (m.instance_id !== instanceId || m.member_id !== memberId) {
		return 'it names a different instance or member';
	}
	try {
		const keys = [m.member_enc_pubkey, ...m.allies.map((a) => a.enc_pubkey)];
		if (keys.some((k) => isWeakX25519(key32(k, 'key')))) return 'it lists an unusable key';
	} catch {
		return 'it lists a malformed key';
	}
	return null;
}

/** Strip `sig` and normalize the field set, for building the next version. */
export function manifestBody(m: RecipientManifest): RecipientManifest {
	return {
		instance_id: m.instance_id,
		member_id: m.member_id,
		version: m.version,
		issued_at_ms: m.issued_at_ms,
		member_enc_pubkey: m.member_enc_pubkey,
		allies: m.allies.map((a) => ({ ally_id: a.ally_id, enc_pubkey: a.enc_pubkey }))
	};
}

/** The next version of `prev` with `allies` (sorted here), issued now. */
export function nextManifest(
	prev: RecipientManifest,
	allies: ManifestAlly[],
	now = Date.now()
): RecipientManifest {
	return {
		...manifestBody(prev),
		version: prev.version + 1,
		// Never go backwards, even with a skewed clock.
		issued_at_ms: Math.max(now, prev.issued_at_ms + 1),
		allies: [...allies]
			.map((a) => ({ ally_id: a.ally_id, enc_pubkey: a.enc_pubkey }))
			.sort((a, b) => compareIds(a.ally_id, b.ally_id))
	};
}

// ---- AADs ----------------------------------------------------------------

export function eventBodyAad(instanceId: string, deviceId: string, seq: number): Bytes {
	return new Canonical('faro/event-body/v1').str(instanceId).str(deviceId).u64(seq).finish();
}

export function reportBodyAad(
	instanceId: string,
	deviceId: string,
	periodStartMs: number,
	periodEndMs: number
): Bytes {
	return new Canonical('faro/report-body/v1')
		.str(instanceId)
		.str(deviceId)
		.i64(periodStartMs)
		.i64(periodEndMs)
		.finish();
}
