// The enrollment link is built from the member's own key and origin; the
// server's `enroll_url` has no say. Run with `npm test`.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildEnrollLink } from './enroll-link.ts';

const KEY = '0123456789abcdef';

test('builds the link from origin, code and key', () => {
	assert.equal(
		buildEnrollLink('https://faro.example.org', '7Q2K-M9XD', KEY),
		`faro://enroll?i=https%3A%2F%2Ffaro.example.org&c=7Q2K-M9XD&m=${KEY}`
	);
});

test('uses only the origin of the page', () => {
	const l = new URL(
		buildEnrollLink('https://faro.example.org/computers?x=1#frag', '7Q2K-M9XD', KEY)
	);
	assert.equal(l.searchParams.get('i'), 'https://faro.example.org');
	assert.equal(l.hash, '');
	assert.deepEqual(l.searchParams.getAll('m'), [KEY]);
});

test('a malicious code cannot smuggle a fragment or a second m', () => {
	for (const bad of [
		`7Q2K-M9XD#m=ffffffffffffffff`,
		`7Q2K-M9XD&m=ffffffffffffffff`,
		'7Q2K-M9XD#',
		'nope'
	]) {
		assert.throws(() => buildEnrollLink('https://faro.example.org', bad, KEY), bad);
	}
});

test('refuses a malformed key id', () => {
	assert.throws(() => buildEnrollLink('https://faro.example.org', '7Q2K-M9XD', 'abc#'));
});
