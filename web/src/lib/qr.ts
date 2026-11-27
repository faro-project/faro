// A small QR code encoder, run in the browser.
//
// An enrollment link holds a one-time code, so the picture is made here and
// never by a remote service. This is a plain implementation of ISO/IEC 18004:
// byte mode, error correction level L, versions 1 to 14 (up to 458 bytes),
// the best of the eight masks by a simplified penalty. Nothing in it touches
// the network.

/** Per version 1 to 14: error correction words per block, and [blocks, data words per block] groups. */
const BLOCKS: [number, [number, number][]][] = [
	[7, [[1, 19]]],
	[10, [[1, 34]]],
	[15, [[1, 55]]],
	[20, [[1, 80]]],
	[26, [[1, 108]]],
	[18, [[2, 68]]],
	[20, [[2, 78]]],
	[24, [[2, 97]]],
	[30, [[2, 116]]],
	[
		18,
		[
			[2, 68],
			[2, 69]
		]
	],
	[20, [[4, 81]]],
	[
		24,
		[
			[2, 92],
			[2, 93]
		]
	],
	[26, [[4, 107]]],
	[
		30,
		[
			[3, 115],
			[1, 116]
		]
	]
];

const ALIGN: number[][] = [
	[],
	[6, 18],
	[6, 22],
	[6, 26],
	[6, 30],
	[6, 34],
	[6, 22, 38],
	[6, 24, 42],
	[6, 26, 46],
	[6, 28, 50],
	[6, 30, 54],
	[6, 32, 58],
	[6, 34, 62],
	[6, 26, 46, 66]
];

/** The most bytes one code can hold. */
export const MAX_BYTES = 458;

function dataWords(version: number): number {
	return BLOCKS[version - 1][1].reduce((n, [count, words]) => n + count * words, 0);
}

// GF(256) with the QR polynomial 0x11D.
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i++) {
	EXP[i] = x;
	LOG[x] = i;
	x <<= 1;
	if (x & 0x100) x ^= 0x11d;
}
for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
const mul = (a: number, b: number) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);

function remainder(data: number[], degree: number): number[] {
	let gen = [1];
	for (let i = 0; i < degree; i++) {
		const next = new Array<number>(gen.length + 1).fill(0);
		for (let j = 0; j < gen.length; j++) {
			next[j] ^= gen[j];
			next[j + 1] ^= mul(gen[j], EXP[i]);
		}
		gen = next;
	}
	const rem = new Array<number>(degree).fill(0);
	for (const b of data) {
		const factor = b ^ (rem.shift() as number);
		rem.push(0);
		for (let i = 0; i < degree; i++) rem[i] ^= mul(gen[i + 1], factor);
	}
	return rem;
}

const MASKS: ((x: number, y: number) => boolean)[] = [
	(x, y) => (x + y) % 2 === 0,
	(_, y) => y % 2 === 0,
	(x) => x % 3 === 0,
	(x, y) => (x + y) % 3 === 0,
	(x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
	(x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
	(x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
	(x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0
];

/** The code as rows of dark (true) and light modules, without a quiet zone. */
export function encodeQr(text: string): boolean[][] {
	const bytes = new TextEncoder().encode(text);
	let version = 1;
	while (version <= 14 && dataWords(version) * 8 < 4 + (version < 10 ? 8 : 16) + bytes.length * 8)
		version++;
	if (version > 14) throw new Error('That link is too long for a QR code.');
	const size = version * 4 + 17;

	// The bit stream: mode, length, bytes, terminator, padding.
	const bits: number[] = [];
	const put = (value: number, n: number) => {
		for (let i = n - 1; i >= 0; i--) bits.push((value >>> i) & 1);
	};
	put(0b0100, 4);
	put(bytes.length, version < 10 ? 8 : 16);
	for (const b of bytes) put(b, 8);
	const capacity = dataWords(version) * 8;
	put(0, Math.min(4, capacity - bits.length));
	while (bits.length % 8) bits.push(0);
	for (let pad = 0xec; bits.length < capacity; pad ^= 0xec ^ 0x11) put(pad, 8);
	const words: number[] = [];
	for (let i = 0; i < bits.length; i += 8) {
		words.push(bits.slice(i, i + 8).reduce((n, b) => (n << 1) | b, 0));
	}

	// Error correction per block, then interleave.
	const [eccLen, groups] = BLOCKS[version - 1];
	const blocks: { data: number[]; ecc: number[] }[] = [];
	let at = 0;
	for (const [count, len] of groups) {
		for (let i = 0; i < count; i++) {
			const data = words.slice(at, at + len);
			at += len;
			blocks.push({ data, ecc: remainder(data, eccLen) });
		}
	}
	const out: number[] = [];
	const longest = Math.max(...blocks.map((b) => b.data.length));
	for (let i = 0; i < longest; i++)
		for (const b of blocks) if (i < b.data.length) out.push(b.data[i]);
	for (let i = 0; i < eccLen; i++) for (const b of blocks) out.push(b.ecc[i]);

	// Fixed patterns.
	const mod = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
	const fixed = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
	const set = (x: number, y: number, dark: boolean) => {
		mod[y][x] = dark;
		fixed[y][x] = true;
	};
	for (let i = 0; i < size; i++) {
		set(6, i, i % 2 === 0);
		set(i, 6, i % 2 === 0);
	}
	for (const [cx, cy] of [
		[3, 3],
		[size - 4, 3],
		[3, size - 4]
	]) {
		for (let dy = -4; dy <= 4; dy++) {
			for (let dx = -4; dx <= 4; dx++) {
				const x = cx + dx;
				const y = cy + dy;
				if (x < 0 || y < 0 || x >= size || y >= size) continue;
				const d = Math.max(Math.abs(dx), Math.abs(dy));
				set(x, y, d !== 2 && d !== 4);
			}
		}
	}
	const pos = ALIGN[version - 1];
	const last = pos.length - 1;
	for (let i = 0; i < pos.length; i++) {
		for (let j = 0; j < pos.length; j++) {
			if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) continue;
			for (let dy = -2; dy <= 2; dy++)
				for (let dx = -2; dx <= 2; dx++)
					set(pos[i] + dx, pos[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
		}
	}
	const drawFormat = (mask: number) => {
		const data = (0b01 << 3) | mask; // error correction level L
		let rem = data;
		for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
		const f = ((data << 10) | rem) ^ 0x5412;
		const bit = (i: number) => ((f >>> i) & 1) === 1;
		for (let i = 0; i <= 5; i++) set(8, i, bit(i));
		set(8, 7, bit(6));
		set(8, 8, bit(7));
		set(7, 8, bit(8));
		for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i));
		for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i));
		for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i));
		set(8, size - 8, true);
	};
	drawFormat(0); // reserves the cells; redrawn with the chosen mask below
	if (version >= 7) {
		let rem = version;
		for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
		const v = (version << 12) | rem;
		for (let i = 0; i < 18; i++) {
			const dark = ((v >>> i) & 1) === 1;
			const a = size - 11 + (i % 3);
			const b = Math.floor(i / 3);
			set(a, b, dark);
			set(b, a, dark);
		}
	}

	// Data, zigzag from the bottom right.
	let n = 0;
	for (let right = size - 1; right >= 1; right -= 2) {
		if (right === 6) right = 5;
		for (let vert = 0; vert < size; vert++) {
			for (let j = 0; j < 2; j++) {
				const x = right - j;
				const y = ((right + 1) & 2) === 0 ? size - 1 - vert : vert;
				if (!fixed[y][x] && n < out.length * 8) {
					mod[y][x] = ((out[n >>> 3] >>> (7 - (n & 7))) & 1) === 1;
					n++;
				}
			}
		}
	}

	// The mask with the lowest penalty.
	const apply = (m: number) => {
		for (let y = 0; y < size; y++)
			for (let x = 0; x < size; x++) if (!fixed[y][x] && MASKS[m](x, y)) mod[y][x] = !mod[y][x];
	};
	const penalty = () => {
		let p = 0;
		for (let y = 0; y < size; y++) {
			for (const get of [(i: number) => mod[y][i], (i: number) => mod[i][y]]) {
				let run = 1;
				for (let i = 1; i < size; i++) {
					if (get(i) === get(i - 1)) {
						run++;
						if (run === 5) p += 3;
						else if (run > 5) p++;
					} else run = 1;
				}
			}
		}
		let dark = 0;
		for (let y = 0; y < size; y++) {
			for (let x = 0; x < size; x++) {
				if (mod[y][x]) dark++;
				if (x + 1 < size && y + 1 < size) {
					const c = mod[y][x];
					if (c === mod[y][x + 1] && c === mod[y + 1][x] && c === mod[y + 1][x + 1]) p += 3;
				}
			}
		}
		const total = size * size;
		return p + Math.floor(Math.abs(dark * 20 - total * 10) / total) * 10;
	};
	let best = 0;
	let bestScore = Infinity;
	for (let m = 0; m < 8; m++) {
		apply(m);
		const score = penalty();
		if (score < bestScore) {
			best = m;
			bestScore = score;
		}
		apply(m); // undo
	}
	apply(best);
	drawFormat(best);
	return mod;
}

/** An SVG path (one unit per module, with a 4 module quiet zone) and its side. */
export function qrPath(modules: boolean[][]): { d: string; side: number } {
	const quiet = 4;
	let d = '';
	modules.forEach((row, y) =>
		row.forEach((dark, x) => {
			if (dark) d += `M${x + quiet} ${y + quiet}h1v1h-1z`;
		})
	);
	return { d, side: modules.length + quiet * 2 };
}
