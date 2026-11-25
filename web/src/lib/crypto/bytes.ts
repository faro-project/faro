// Byte-string helpers: unpadded base64url (the only base64 Faro uses),
// hex, UTF-8 and the browser's CSPRNG.

export type Bytes = Uint8Array<ArrayBuffer>;

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64_INDEX = new Map([...B64URL].map((c, i) => [c, i]));

/** Unpadded base64url, as `faro_proto::encoding::b64_encode`. */
export function b64(bytes: Uint8Array): string {
	let out = '';
	let i = 0;
	for (; i + 2 < bytes.length; i += 3) {
		const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
		out += B64URL[n >> 18] + B64URL[(n >> 12) & 63] + B64URL[(n >> 6) & 63] + B64URL[n & 63];
	}
	const rest = bytes.length - i;
	if (rest === 1) {
		const n = bytes[i] << 16;
		out += B64URL[n >> 18] + B64URL[(n >> 12) & 63];
	} else if (rest === 2) {
		const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
		out += B64URL[n >> 18] + B64URL[(n >> 12) & 63] + B64URL[(n >> 6) & 63];
	}
	return out;
}

/**
 * Decode unpadded base64url. Strict like the Rust decoder: no padding, no
 * other alphabet, no leftover bits.
 */
export function unb64(s: string): Bytes {
	if (s.length % 4 === 1) throw new Error('invalid base64url length');
	const out = new Uint8Array(Math.floor((s.length * 3) / 4));
	let acc = 0;
	let bits = 0;
	let o = 0;
	for (const c of s) {
		const v = B64_INDEX.get(c);
		if (v === undefined) throw new Error('invalid base64url character');
		acc = (acc << 6) | v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out[o++] = (acc >> bits) & 0xff;
		}
	}
	if (acc & ((1 << bits) - 1)) throw new Error('invalid base64url trailing bits');
	return out;
}

/** Decode base64url that must be exactly `len` bytes. */
export function unb64Fixed(s: string, len: number, what = 'value'): Bytes {
	const b = unb64(s);
	if (b.length !== len) throw new Error(`${what} must be ${len} bytes`);
	return b;
}

/** Standard base64 with padding (for `data:` URLs). */
export function base64Std(bytes: Uint8Array): string {
	const s = b64(bytes).replaceAll('-', '+').replaceAll('_', '/');
	return s + '='.repeat((4 - (s.length % 4)) % 4);
}

export function hex(bytes: Uint8Array): string {
	let s = '';
	for (const b of bytes) s += b.toString(16).padStart(2, '0');
	return s;
}

export function unhex(s: string): Bytes {
	if (s.length % 2 || /[^0-9a-f]/i.test(s)) throw new Error('invalid hex');
	const out = new Uint8Array(s.length / 2);
	for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
	return out;
}

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });

export function utf8(s: string): Bytes {
	return enc.encode(s);
}

export function fromUtf8(b: Uint8Array): string {
	return dec.decode(b);
}

export function concat(...parts: Uint8Array[]): Bytes {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let o = 0;
	for (const p of parts) {
		out.set(p, o);
		o += p.length;
	}
	return out;
}

/** Constant-time for equal lengths. */
export function equal(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let d = 0;
	for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
	return d === 0;
}

/** Bytewise comparison, as Rust orders `[u8]`. */
export function compare(a: Uint8Array, b: Uint8Array): number {
	const n = Math.min(a.length, b.length);
	for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
	return a.length - b.length;
}

export function randomBytes(n: number): Bytes {
	const b = new Uint8Array(n);
	crypto.getRandomValues(b);
	return b;
}

/** Overwrite secret bytes once they are no longer needed. */
export function wipe(...bufs: (Uint8Array | null | undefined)[]) {
	for (const b of bufs) b?.fill(0);
}
