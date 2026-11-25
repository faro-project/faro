// Opening what devices encrypt (docs/PROTOCOL.md §4.1), a port of
// `faro_crypto::seal::open_item`.
//
// The web app only ever opens: devices seal, members and allies read. A
// sealed box is libsodium's `crypto_box_seal`:
//
//   epk ‖ crypto_box(m, nonce = BLAKE2b-192(epk ‖ pk), pk, esk)
//
// where crypto_box is XSalsa20-Poly1305 under HSalsa20(X25519(esk, pk), 0).

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hsalsa, xsalsa20poly1305 } from '@noble/ciphers/salsa.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { concat, unb64, unb64Fixed, wipe, type Bytes } from './bytes.ts';
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
