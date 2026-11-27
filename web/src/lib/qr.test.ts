// The QR encoder: what it makes decodes back to the link. Run with `npm test`.
// jsQR is a development-only decoder; it is not in the app.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import jsQR from 'jsqr';
import { encodeQr, MAX_BYTES, qrPath } from './qr.ts';

/** Renders the modules the way a screen would (with the quiet zone) and decodes them. */
function decode(modules: boolean[][]): string | undefined {
	const scale = 4;
	const quiet = 4;
	const side = (modules.length + quiet * 2) * scale;
	const px = new Uint8ClampedArray(side * side * 4).fill(255);
	modules.forEach((row, y) =>
		row.forEach((dark, x) => {
			if (!dark) return;
			for (let dy = 0; dy < scale; dy++)
				for (let dx = 0; dx < scale; dx++) {
					const i = (((y + quiet) * scale + dy) * side + (x + quiet) * scale + dx) * 4;
					px[i] = px[i + 1] = px[i + 2] = 0;
				}
		})
	);
	return jsQR(px, side, side)?.data;
}

const link = (n: number) =>
	`https://faro.example.org/enroll?c=${'AbCd0123'.repeat(n)}&i=0f3a9c&m=A1B2-C3D4-E5F6`;

test('a typical enrollment link decodes back to itself', () => {
	const l = 'https://faro.example.org/enroll?code=K7QX-4M2P&m=0A1B-2C3D-4E5F-6789';
	assert.equal(decode(encodeQr(l)), l);
});

test('every size from version 1 to 14 round trips, including odd characters', () => {
	const seen = new Set<number>();
	for (let len = 1; len <= MAX_BYTES - 50; len += 3) {
		const text = Array.from({ length: len }, (_, i) => 'a1/?&=-_%é'[i % 10]).join('');
		const modules = encodeQr(text);
		seen.add(modules.length);
		assert.equal(decode(modules), text, `length ${len}`);
	}
	assert.equal(seen.size, 14);
	assert.equal(decode(encodeQr(link(20))), link(20));
});

test('the longest supported text fits and one more byte is refused', () => {
	const max = 'x'.repeat(MAX_BYTES);
	assert.equal(decode(encodeQr(max)), max);
	assert.throws(() => encodeQr(max + 'x'), /too long/);
});

test('the SVG path covers exactly the dark modules', () => {
	const m = encodeQr('faro');
	const { d, side } = qrPath(m);
	assert.equal(side, m.length + 8);
	assert.equal(d.split('M').length - 1, m.flat().filter(Boolean).length);
});

test('encoding uses only local code', () => {
	const real = globalThis.fetch;
	globalThis.fetch = () => {
		throw new Error('network used');
	};
	try {
		encodeQr(link(3));
	} finally {
		globalThis.fetch = real;
	}
	const src = readFileSync(new URL('./qr.ts', import.meta.url), 'utf8');
	assert.doesNotMatch(src, /https?:\/\/|\bfetch\b|XMLHttpRequest|WebSocket|^import /m);
});
