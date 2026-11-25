// Key generation, signatures, key ids and safety codes: ports of
// `faro_crypto::{sign, keycheck}` and `faro_proto::keys::{key_id,
// safety_code}` (docs/PROTOCOL.md §4.2).

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { compare, equal, hex, randomBytes, type Bytes } from './bytes.ts';
import { Canonical, hash } from './canonical.ts';

// ---- Ed25519 -------------------------------------------------------------

/** A fresh Ed25519 seed (the 32 bytes `SigningKey::to_bytes` returns). */
export function newSigningSeed(): Bytes {
	return randomBytes(32);
}

export function signPublicKey(seed: Uint8Array): Bytes {
	return ed25519.getPublicKey(seed) as Bytes;
}

export function sign(seed: Uint8Array, msg: Uint8Array): Bytes {
	return ed25519.sign(msg, seed) as Bytes;
}

/** Whether `pk` is a valid Ed25519 point that is not of small order. */
export function isUsableSignKey(pk: Uint8Array): boolean {
	if (pk.length !== 32) return false;
	try {
		return !ed25519.Point.fromBytes(pk, false).isSmallOrder();
	} catch {
		return false;
	}
}

/**
 * Strict verification, as `faro_crypto::verify`: canonical encodings only
 * (no ZIP-215 leniency) and no small-order public keys.
 */
export function verify(pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
	if (sig.length !== 64 || !isUsableSignKey(pk)) return false;
	try {
		return ed25519.verify(sig, msg, pk, { zip215: false });
	} catch {
		return false;
	}
}

// ---- X25519 --------------------------------------------------------------

/** A fresh X25519 secret key. */
export function newEncryptionSecret(): Bytes {
	return randomBytes(32);
}

export function encPublicKey(secret: Uint8Array): Bytes {
	return x25519.getPublicKey(secret) as Bytes;
}

/** libsodium's small-order list, compared with the top bit cleared. */
const SMALL_ORDER = [
	'0000000000000000000000000000000000000000000000000000000000000000',
	'0100000000000000000000000000000000000000000000000000000000000000',
	'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
	'5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
	'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
	'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
	'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'
];

/** Whether `k` is a small-order X25519 point (sealing to it is readable by anyone). */
export function isWeakX25519(k: Uint8Array): boolean {
	if (k.length !== 32) return true;
	const m = k.slice();
	m[31] &= 0x7f;
	return SMALL_ORDER.includes(hex(m));
}

// ---- Identifiers ---------------------------------------------------------

/** First 8 bytes of a tagged BLAKE3 of the key, lowercase hex. */
export function keyId(pubkey: Uint8Array): string {
	return hex(hash(new Canonical('faro/key-id/v1').bytes(pubkey).finish()).subarray(0, 8));
}

/**
 * The safety code a member and an ally compare: 12 groups of 5 digits from
 * the member's signing key and the ally's encryption key. Order-independent.
 */
export function safetyCode(a: Uint8Array, b: Uint8Array): string {
	const [lo, hi] = compare(a, b) <= 0 ? [a, b] : [b, a];
	const h = hash(new Canonical('faro/safety-code/v1').bytes(lo).bytes(hi).finish());
	const out = blake3(h, { dkLen: 60 });
	const digits = [...out].map((x) => String(x % 10)).join('');
	return digits.match(/.{5}/g)!.join(' ');
}

/** A key id split for reading aloud: `a1b2 c3d4 e5f6 0718`. */
export function formatKeyId(id: string): string {
	return id.match(/.{1,4}/g)?.join(' ') ?? id;
}

export { equal };
