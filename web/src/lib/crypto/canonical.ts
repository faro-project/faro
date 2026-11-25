// The canonical byte encoding every signed or hashed structure uses
// (docs/PROTOCOL.md §2), a port of `faro_proto::encoding::Canonical`.

import { blake3 } from '@noble/hashes/blake3.js';
import { concat, hex, unhex, utf8, type Bytes } from './bytes.ts';

const U64_MAX = (1n << 64n) - 1n;
const I64_MIN = -(1n << 63n);
const I64_MAX = (1n << 63n) - 1n;

function int(v: number | bigint): bigint {
	if (typeof v === 'number' && !Number.isSafeInteger(v)) {
		throw new Error('canonical integer is not a safe integer');
	}
	return BigInt(v);
}

export class Canonical {
	private parts: Uint8Array[] = [];

	/** The tag as ASCII, then one NUL byte. */
	constructor(tag: string) {
		if (!/^[\x01-\x7f]+$/.test(tag)) throw new Error('canonical tag must be ASCII without NUL');
		this.parts.push(utf8(tag), new Uint8Array([0]));
	}

	u16(v: number): this {
		if (!Number.isInteger(v) || v < 0 || v > 0xffff) throw new Error('u16 out of range');
		this.parts.push(new Uint8Array([v >> 8, v & 0xff]));
		return this;
	}

	u64(v: number | bigint): this {
		const n = int(v);
		if (n < 0n || n > U64_MAX) throw new Error('u64 out of range');
		const b = new Uint8Array(8);
		new DataView(b.buffer).setBigUint64(0, n);
		this.parts.push(b);
		return this;
	}

	i64(v: number | bigint): this {
		const n = int(v);
		if (n < I64_MIN || n > I64_MAX) throw new Error('i64 out of range');
		const b = new Uint8Array(8);
		new DataView(b.buffer).setBigInt64(0, n);
		this.parts.push(b);
		return this;
	}

	/** `Option<u64>`: 0 for none, n + 1 for some. */
	optU64(v: number | null | undefined): this {
		return this.u64(v == null ? 0n : int(v) + 1n);
	}

	/** u32 big-endian length, then the bytes. */
	bytes(v: Uint8Array): this {
		const len = new Uint8Array(4);
		new DataView(len.buffer).setUint32(0, v.length);
		this.parts.push(len, v);
		return this;
	}

	str(v: string): this {
		return this.bytes(utf8(v));
	}

	/** Raw bytes with no length prefix (hashes, keys). */
	fixed(v: Uint8Array): this {
		this.parts.push(v);
		return this;
	}

	finish(): Bytes {
		return concat(...this.parts);
	}
}

/** BLAKE3-256. */
export function hash(bytes: Uint8Array): Bytes {
	return blake3(bytes) as Bytes;
}

/** A hash as Faro serializes it: `b3:<64 lowercase hex>`. */
export function hashToString(h: Uint8Array): string {
	return `b3:${hex(h)}`;
}

export function hashFromString(s: string): Bytes {
	if (!/^b3:[0-9a-f]{64}$/.test(s)) throw new Error('invalid b3 hash');
	return unhex(s.slice(3));
}
