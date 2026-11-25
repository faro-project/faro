// Passphrase and recovery-code wrapping of private keys (docs/PROTOCOL.md
// §4.3), a port of `faro_crypto::passphrase`.
//
// Argon2id v1.3 (p = 1) derives a key from the passphrase; the secret is
// sealed with XChaCha20-Poly1305 under it, with AAD `faro/wrapped-secret/v1`.
// The derivation runs in pure JS (the page's CSP has no
// 'wasm-unsafe-eval'), which takes well under a second at the default
// 64 MiB / 3 passes on current hardware, and yields to the page while it
// runs.

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { argon2idAsync } from '@noble/hashes/argon2.js';
import { b64, randomBytes, unb64, utf8, wipe, type Bytes } from './bytes.ts';

export interface KdfParams {
	m_cost_kib: number;
	t_cost: number;
	p_cost: number;
}

/** `faro_crypto::WrappedSecret` as JSON. Extra fields are allowed and ignored. */
export interface WrappedSecret {
	v: 1;
	kdf: 'argon2id13';
	params: KdfParams;
	salt: string;
	nonce: string;
	ciphertext: string;
}

/** The Rust default: 64 MiB, 3 passes, 1 lane. */
export const DEFAULT_KDF: KdfParams = { m_cost_kib: 64 * 1024, t_cost: 3, p_cost: 1 };

const AAD = utf8('faro/wrapped-secret/v1');

export class UnwrapError extends Error {
	readonly reason: 'wrong_passphrase' | 'unsupported';

	constructor(reason: UnwrapError['reason'], message = 'wrong passphrase or damaged key') {
		super(message);
		this.name = 'UnwrapError';
		this.reason = reason;
	}
}

/**
 * The same bounds as Rust, except memory, capped at 1 GiB here: a browser
 * tab can't spend 4 GiB, and a hostile server must not be able to make it
 * try.
 */
function checkParams(p: KdfParams) {
	const ok =
		p.p_cost === 1 &&
		Number.isInteger(p.m_cost_kib) &&
		Number.isInteger(p.t_cost) &&
		p.m_cost_kib >= 8 &&
		p.m_cost_kib <= 1024 * 1024 &&
		p.t_cost >= 1 &&
		p.t_cost <= 64;
	if (!ok) throw new UnwrapError('unsupported', 'unsupported key-derivation parameters');
}

export type Progress = (fraction: number) => void;

/** A derived wrapping key, reusable for several secrets under one salt. */
export interface WrapKey {
	params: KdfParams;
	salt: Bytes;
	key: Bytes;
}

export async function deriveWrapKey(
	passphrase: string,
	params: KdfParams = DEFAULT_KDF,
	salt: Bytes = randomBytes(16),
	onProgress?: Progress
): Promise<WrapKey> {
	checkParams(params);
	const pw = utf8(passphrase);
	try {
		const key = (await argon2idAsync(pw, salt, {
			t: params.t_cost,
			m: params.m_cost_kib,
			p: params.p_cost,
			dkLen: 32,
			asyncTick: 25,
			onProgress
		})) as Bytes;
		return { params, salt, key };
	} finally {
		wipe(pw);
	}
}

/** Seal `secret` under an already derived key, with a fresh nonce. */
export function wrapWithKey(secret: Uint8Array, k: WrapKey): WrappedSecret {
	const nonce = randomBytes(24);
	const ct = xchacha20poly1305(k.key, nonce, AAD).encrypt(secret);
	return {
		v: 1,
		kdf: 'argon2id13',
		params: { ...k.params },
		salt: b64(k.salt),
		nonce: b64(nonce),
		ciphertext: b64(ct)
	};
}

/** `faro_crypto::wrap_secret`. */
export async function wrapSecret(
	secret: Uint8Array,
	passphrase: string,
	params: KdfParams = DEFAULT_KDF,
	onProgress?: Progress
): Promise<WrappedSecret> {
	const k = await deriveWrapKey(passphrase, params, randomBytes(16), onProgress);
	try {
		return wrapWithKey(secret, k);
	} finally {
		wipe(k.key);
	}
}

function parseWrapped(w: unknown): { params: KdfParams; salt: Bytes; nonce: Bytes; ct: Bytes } {
	const o = w as Partial<WrappedSecret> | null;
	if (!o || typeof o !== 'object' || o.v !== 1 || o.kdf !== 'argon2id13' || !o.params) {
		throw new UnwrapError('unsupported', 'unsupported key format');
	}
	const params = {
		m_cost_kib: Number(o.params.m_cost_kib),
		t_cost: Number(o.params.t_cost),
		p_cost: Number(o.params.p_cost)
	};
	checkParams(params);
	let salt: Bytes, nonce: Bytes, ct: Bytes;
	try {
		salt = unb64(String(o.salt));
		nonce = unb64(String(o.nonce));
		ct = unb64(String(o.ciphertext));
	} catch {
		throw new UnwrapError('wrong_passphrase');
	}
	if (salt.length !== 16 || nonce.length !== 24) throw new UnwrapError('wrong_passphrase');
	return { params, salt, nonce, ct };
}

/** Open `w` with an already derived key (same salt and parameters). */
export function unwrapWithKey(w: unknown, k: WrapKey): Bytes {
	const p = parseWrapped(w);
	try {
		return xchacha20poly1305(k.key, p.nonce, AAD).decrypt(p.ct) as Bytes;
	} catch {
		throw new UnwrapError('wrong_passphrase');
	}
}

/** Whether `k` was derived with `w`'s salt and parameters. */
export function sameDerivation(w: unknown, k: WrapKey): boolean {
	try {
		const p = parseWrapped(w);
		return (
			p.params.m_cost_kib === k.params.m_cost_kib &&
			p.params.t_cost === k.params.t_cost &&
			b64(p.salt) === b64(k.salt)
		);
	} catch {
		return false;
	}
}

/** Derive the key for `w` from `passphrase` (to open `w` and its siblings). */
export async function deriveFor(w: unknown, passphrase: string, onProgress?: Progress) {
	const p = parseWrapped(w);
	return deriveWrapKey(passphrase, p.params, p.salt, onProgress);
}

/** `faro_crypto::unwrap_secret`. Wrong passphrase and damage look the same. */
export async function unwrapSecret(
	w: unknown,
	passphrase: string,
	onProgress?: Progress
): Promise<Bytes> {
	const k = await deriveFor(w, passphrase, onProgress);
	try {
		return unwrapWithKey(w, k);
	} finally {
		wipe(k.key);
	}
}

// ---- Recovery codes ------------------------------------------------------

/** Crockford base32 (no I, L, O, U). */
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/**
 * 160 random bits as 8 groups of 4 Crockford characters, as
 * `faro_crypto::generate_recovery_code`. The formatted string, dashes and
 * all, is the passphrase that wraps the recovery copy.
 */
export function generateRecoveryCode(): string {
	const bytes = randomBytes(20);
	let out = '';
	let acc = 0;
	let bits = 0;
	let n = 0;
	for (const b of bytes) {
		acc = ((acc << 8) | b) & 0xfff;
		bits += 8;
		while (bits >= 5) {
			bits -= 5;
			if (n > 0 && n % 4 === 0) out += '-';
			out += CROCKFORD[(acc >> bits) & 31];
			n++;
		}
	}
	wipe(bytes);
	return out;
}

/**
 * Normalize a typed recovery code to the canonical form: case, spaces and
 * dashes don't matter, and I/L read as 1, O as 0. Null if it can't be one.
 */
export function normalizeRecoveryCode(input: string): string | null {
	const s = input.toUpperCase().replace(/[\s-]/g, '').replace(/[IL]/g, '1').replace(/O/g, '0');
	if (s.length !== 32 || [...s].some((c) => !CROCKFORD.includes(c))) return null;
	return s.match(/.{4}/g)!.join('-');
}
