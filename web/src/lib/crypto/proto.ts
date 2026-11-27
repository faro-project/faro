// The member-signed structures (docs/PROTOCOL.md §5) and encryption AADs
// (§4.1): ports of `faro_proto::keys` and the `body_aad` helpers.
//
// JSON is transport only; every signature is over `signingBytes`, built
// field by field. On the wire a signed structure is its fields flattened
// together with `sig` (`Signed<T>`).

import { blake3 } from '@noble/hashes/blake3.js';
import { b64, unb64Fixed, utf8, type Bytes } from './bytes.ts';
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
	/**
	 * The ally's display name, signed (format 2 only, where every ally has
	 * one, possibly empty). Absent in format 1.
	 */
	name?: string;
}

/** The original format: ally ids and keys, no names. */
export const MANIFEST_FORMAT_V1 = 1;
/** Format 2 adds each ally's display name, inside the signed bytes. */
export const MANIFEST_FORMAT_V2 = 2;
/**
 * Format 3 is format 2 plus `prev_hash`, the hash of the version it was
 * built on, so a device can tell a fork from a successor.
 */
export const MANIFEST_FORMAT_V3 = 3;

/** The 32 zero bytes format 3 signs for "no previous version" (version 1). */
const NO_PREV = new Uint8Array(32);

export interface RecipientManifest {
	/** Absent means format 1 (`MANIFEST_FORMAT_V1`). */
	format?: number;
	instance_id: string;
	member_id: string;
	version: number;
	/**
	 * Format 3: `b3:<hex>` of version `version - 1`, the list this one was
	 * built on. Present above version 1, absent at 1 and in formats 1 and 2.
	 */
	prev_hash?: string;
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

/** `MAX_ALLY_NAME_CHARS`: the instance's own display-name limit. */
export const MAX_ALLY_NAME_CHARS = 64;
/** `MAX_ALLY_NAME_BYTES`: the longest name a manifest may carry, in UTF-8. */
export const MAX_ALLY_NAME_BYTES = 4 * MAX_ALLY_NAME_CHARS;

// The characters `sanitize_ally_name` removes, and those it turns into a
// space. Explicit lists, not Unicode properties, so both implementations
// agree whatever their Unicode version (docs/PROTOCOL.md §5.1).
const NAME_STRIPPED =
	/[\u0000-\u0008\u000e-\u001f\u007f-\u0084\u0086-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff\ufff9-\ufffb]/gu;
const NAME_SPACED = /[\u0009-\u000d\u0085\u2028\u2029]/gu;

/**
 * `faro_proto::keys::sanitize_ally_name`: an ally's display name made safe
 * to sign and to show. Applied to every name before signing a format 2
 * manifest; devices apply the Rust version again before showing it. The two
 * must agree byte for byte (`ally_names` in the shared vectors):
 *
 * 1. remove C0 and C1 controls, DEL and the bidi and invisible format
 *    characters above, and turn tabs and line breaks into spaces;
 * 2. normalize to NFC;
 * 3. collapse runs of U+0020 into one, trimmed from both ends;
 * 4. keep at most 64 code points, then trim a trailing space again.
 */
export function sanitizeAllyName(input: string): string {
	// A lone surrogate can't be encoded as UTF-8; the encoder would write
	// U+FFFD for it, so do that here, where it is visible.
	const cleaned = input
		.toWellFormed()
		.replace(NAME_STRIPPED, '')
		.replace(NAME_SPACED, ' ')
		.normalize('NFC');
	let out = '';
	let chars = 0;
	for (const c of cleaned) {
		if (c === ' ' && (out === '' || out.endsWith(' '))) continue;
		if (chars === MAX_ALLY_NAME_CHARS) break;
		out += c;
		chars++;
	}
	return out.replace(/ +$/, '');
}

/** `RecipientManifest::validate`: the structural checks that need no keys. */
export function validateManifest(m: RecipientManifest): string | null {
	const format = m.format ?? MANIFEST_FORMAT_V1;
	if (
		format !== MANIFEST_FORMAT_V1 &&
		format !== MANIFEST_FORMAT_V2 &&
		format !== MANIFEST_FORMAT_V3
	) {
		return `unknown format ${format}`;
	}
	if (!Number.isSafeInteger(m.version) || m.version < 1) return 'version must be at least 1';
	const links = format === MANIFEST_FORMAT_V3 && m.version > 1;
	if (links && m.prev_hash == null) return 'it does not name the version it follows';
	if (!links && m.prev_hash != null) return 'it carries an unexpected prev_hash';
	if (m.prev_hash != null) {
		try {
			hashFromString(m.prev_hash);
		} catch {
			return 'it carries a malformed prev_hash';
		}
	}
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
		// A name in format 1 isn't covered by the signature.
		if (format === MANIFEST_FORMAT_V1 && a.name != null) return 'it carries unsigned names';
		if (format !== MANIFEST_FORMAT_V1) {
			if (typeof a.name !== 'string') return 'an ally has no name';
			if (utf8(a.name).length > MAX_ALLY_NAME_BYTES) return 'an ally name is too long';
		}
	}
	return null;
}

/**
 * Format 1: tag `faro/recipient-manifest/v1`, each ally its id and key.
 * Format 2: tag `faro/recipient-manifest/v2`, each ally its id, key and name.
 * Format 3: tag `faro/recipient-manifest/v3`, as format 2 with `prev_hash`
 * after `version` (32 zero bytes at version 1).
 */
export function manifestSigningBytes(m: RecipientManifest): Bytes {
	const format = m.format ?? MANIFEST_FORMAT_V1;
	const c = new Canonical(`faro/recipient-manifest/v${format}`)
		.str(m.instance_id)
		.str(m.member_id)
		.u64(m.version);
	if (format === MANIFEST_FORMAT_V3) {
		c.fixed(m.prev_hash == null ? NO_PREV : hashFromString(m.prev_hash));
	}
	c.i64(m.issued_at_ms).fixed(key32(m.member_enc_pubkey, 'member_enc_pubkey')).u64(m.allies.length);
	for (const a of m.allies) {
		c.str(a.ally_id).fixed(key32(a.enc_pubkey, 'ally enc_pubkey'));
		if (format !== MANIFEST_FORMAT_V1) c.str(a.name ?? '');
	}
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

/**
 * `faro_proto::keys::AllyKeyRewrap`: replace the stored wrapped copy of the
 * ally key. An X25519 key can't sign, so the request is proven with a MAC
 * keyed by a challenge the instance sealed to the ally key
 * (`allyKeyRewrapProof`). `wrapped_privkey` is the exact JSON text.
 */
export interface AllyKeyRewrap {
	instance_id: string;
	ally_id: string;
	enc_pubkey: string;
	issued_at_ms: number;
	wrapped_privkey: string;
}

export function allyKeyRewrapProofBytes(r: AllyKeyRewrap): Bytes {
	return new Canonical('faro/ally-key-rewrap/v1')
		.str(r.instance_id)
		.str(r.ally_id)
		.fixed(key32(r.enc_pubkey, 'enc_pubkey'))
		.i64(r.issued_at_ms)
		.str(r.wrapped_privkey)
		.finish();
}

/**
 * The wire form: `r` flattened with `proof`, `BLAKE3-keyed(challenge,
 * proof bytes)` as `b3:<hex>`. Only the MAC leaves the browser, never the
 * challenge, so a hostile instance can't use this to have other sealed boxes
 * (such as item keys) opened for it.
 */
export function proveAllyKeyRewrap(
	r: AllyKeyRewrap,
	challenge: Uint8Array
): AllyKeyRewrap & { proof: string } {
	if (challenge.length !== 32) throw new Error('the challenge must be 32 bytes');
	const mac = blake3(allyKeyRewrapProofBytes(r), { key: challenge });
	return { ...r, proof: hashToString(mac) };
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
	const named = (m.format ?? MANIFEST_FORMAT_V1) !== MANIFEST_FORMAT_V1;
	return {
		...(named ? { format: m.format } : {}),
		instance_id: m.instance_id,
		member_id: m.member_id,
		version: m.version,
		...(m.prev_hash != null ? { prev_hash: m.prev_hash } : {}),
		issued_at_ms: m.issued_at_ms,
		member_enc_pubkey: m.member_enc_pubkey,
		allies: m.allies.map((a) => ({
			ally_id: a.ally_id,
			enc_pubkey: a.enc_pubkey,
			...(named ? { name: a.name ?? '' } : {})
		}))
	};
}

/**
 * The next version of `prev` with `allies` (sorted here), issued now. It is
 * always format 3, linked to `prev` by its hash. Each ally's `name` is the
 * display name to sign (the caller decides which: the name the last list
 * signed, unless the member confirmed a new one), sanitized here; a missing
 * name is signed as empty.
 */
export function nextManifest(
	prev: RecipientManifest,
	allies: ManifestAlly[],
	now = Date.now()
): RecipientManifest {
	const base = manifestBody(prev);
	return {
		format: MANIFEST_FORMAT_V3,
		instance_id: base.instance_id,
		member_id: base.member_id,
		version: prev.version + 1,
		prev_hash: manifestRef(base).hash,
		// Never go backwards, even with a skewed clock.
		issued_at_ms: Math.max(now, prev.issued_at_ms + 1),
		member_enc_pubkey: base.member_enc_pubkey,
		allies: [...allies]
			.map((a) => ({
				ally_id: a.ally_id,
				enc_pubkey: a.enc_pubkey,
				name: sanitizeAllyName(a.name ?? '')
			}))
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
