// Opening what devices encrypt (docs/PROTOCOL.md §4.1), a port of
// `faro_crypto::seal::{open_item, seal_item, seal_to}`.
//
// Devices seal reports and events, and members and allies read them. The
// web app seals only a group's epoch keys (`sealTo`) and group messages
// (reach outs and notes, `sealItem`, PROTOCOL.md §11). A sealed box is
// libsodium's `crypto_box_seal`:
//
//   epk ‖ crypto_box(m, nonce = BLAKE2b-192(epk ‖ pk), pk, esk)
//
// where crypto_box is XSalsa20-Poly1305 under HSalsa20(X25519(esk, pk), 0).

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hsalsa, xsalsa20poly1305 } from '@noble/ciphers/salsa.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { b64, concat, randomBytes, unb64, unb64Fixed, wipe, type Bytes } from './bytes.ts';
import { encPublicKey, isWeakX25519, keyId } from './keys.ts';

/** `faro_proto::EncryptedItem` as JSON. */
export interface EncryptedItem {
	alg: string;
	nonce: string;
	ciphertext: string;
	envelopes: { recipient: string; key_id: string; wrapped_key: string }[];
}

export class DecryptError extends Error {
	readonly reason: 'no_envelope' | 'decrypt' | 'unsupported';

	constructor(reason: DecryptError['reason'], message = 'decryption failed') {
		super(message);
		this.name = 'DecryptError';
		this.reason = reason;
	}
}

const SIGMA = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);

function le32(b: Uint8Array): Uint32Array {
	const out = new Uint32Array(b.length / 4);
	const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
	for (let i = 0; i < out.length; i++) out[i] = dv.getUint32(4 * i, true);
	return out;
}

function fromLe32(w: Uint32Array): Bytes {
	const out = new Uint8Array(w.length * 4);
	const dv = new DataView(out.buffer);
	for (let i = 0; i < w.length; i++) dv.setUint32(4 * i, w[i], true);
	return out;
}

/** libsodium `crypto_box_beforenm`. */
function boxKey(secret: Uint8Array, pub: Uint8Array): Bytes {
	if (isWeakX25519(pub)) throw new DecryptError('decrypt');
	const shared = x25519.getSharedSecret(secret, pub);
	const out = new Uint32Array(8);
	hsalsa(SIGMA, le32(shared), new Uint32Array(4), out);
	wipe(shared);
	return fromLe32(out);
}

/** libsodium `crypto_box_seal_open`. */
export function sealOpen(sealed: Uint8Array, secret: Uint8Array): Bytes {
	if (sealed.length < 32 + 16) throw new DecryptError('decrypt');
	const epk = sealed.subarray(0, 32);
	const pk = encPublicKey(secret);
	const nonce = blake2b(concat(epk, pk), { dkLen: 24 });
	const key = boxKey(secret, epk);
	try {
		return xsalsa20poly1305(key, nonce).decrypt(sealed.subarray(32)) as Bytes;
	} catch {
		throw new DecryptError('decrypt');
	} finally {
		wipe(key);
	}
}

/**
 * libsodium `crypto_box_seal`: what the web app seals is an epoch key to
 * each participant of a group (PROTOCOL.md §10.3). Refuses small-order keys.
 */
export function sealTo(pub: Uint8Array, msg: Uint8Array): Bytes {
	if (pub.length !== 32 || isWeakX25519(pub)) throw new Error('unusable encryption key');
	const esk = randomBytes(32);
	const epk = encPublicKey(esk);
	const nonce = blake2b(concat(epk, pub), { dkLen: 24 });
	const key = boxKey(esk, pub);
	try {
		return concat(epk, xsalsa20poly1305(key, nonce).encrypt(msg));
	} finally {
		wipe(key, esk);
	}
}

/**
 * Decrypt an item as `me` with the X25519 `secret`. Tries the envelope
 * whose key id matches first, then any other envelope addressed to `me`.
 * Wrong keys, a tampered ciphertext and the wrong `aad` all fail alike.
 */
export function openItem(
	item: EncryptedItem,
	aad: Uint8Array,
	me: string,
	secret: Uint8Array
): Bytes {
	if (item.alg !== 'xchacha20poly1305') throw new DecryptError('unsupported', item.alg);
	const mine = keyId(encPublicKey(secret));
	const candidates = item.envelopes
		.filter((e) => e.recipient === me)
		.sort((a, b) => Number(a.key_id !== mine) - Number(b.key_id !== mine));
	if (candidates.length === 0) throw new DecryptError('no_envelope', 'no envelope for you');
	let nonce: Bytes;
	let ciphertext: Bytes;
	try {
		nonce = unb64Fixed(item.nonce, 24, 'nonce');
		ciphertext = unb64(item.ciphertext);
	} catch {
		throw new DecryptError('decrypt');
	}
	for (const env of candidates) {
		let ck: Bytes;
		try {
			ck = sealOpen(unb64(env.wrapped_key), secret);
		} catch {
			continue;
		}
		if (ck.length !== 32) {
			wipe(ck);
			continue;
		}
		try {
			return xchacha20poly1305(ck, nonce, aad).decrypt(ciphertext) as Bytes;
		} catch {
			throw new DecryptError('decrypt');
		} finally {
			wipe(ck);
		}
	}
	throw new DecryptError('decrypt');
}

export interface SealRecipient {
	user_id: string;
	/** X25519 public key. */
	pubkey: Uint8Array;
}

/**
 * `faro_crypto::seal_item`: encrypt once under a random content key with
 * XChaCha20-Poly1305 (`aad` binds it to its context), and seal the key to
 * every recipient.
 */
export function sealItem(
	plaintext: Uint8Array,
	aad: Uint8Array,
	recipients: SealRecipient[]
): EncryptedItem {
	if (recipients.length === 0) throw new Error('no recipients');
	const ck = randomBytes(32);
	const nonce = randomBytes(24);
	try {
		const ciphertext = xchacha20poly1305(ck, nonce, aad).encrypt(plaintext);
		return {
			alg: 'xchacha20poly1305',
			nonce: b64(nonce),
			ciphertext: b64(ciphertext),
			envelopes: recipients.map((r) => ({
				recipient: r.user_id,
				key_id: keyId(r.pubkey),
				wrapped_key: b64(sealTo(r.pubkey, ck))
			}))
		};
	} finally {
		wipe(ck);
	}
}
