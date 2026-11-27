// The enrollment link is assembled in the member's browser; the server's
// `enroll_url` supplies only the instance URL and code. Run with `npm test`.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildEnrollLink } from './enroll-link.ts';

const KEY = '0123456789abcdef';
const ORIGIN = 'https://faro.example.org';
const enc = encodeURIComponent;
const url = (i: string, c = '7Q2K-M9XD') => `faro://enroll?i=${enc(i)}&c=${c}`;

test('builds the link from the server link and the member key', () => {
	assert.equal(
		buildEnrollLink(ORIGIN, url(`${ORIGIN}/`), KEY),
		`faro://enroll?i=https%3A%2F%2Ffaro.example.org%2F&c=7Q2K-M9XD&m=${KEY}`
	);
});

test('keeps a path prefix on the instance URL', () => {
	const l = new URL(buildEnrollLink(ORIGIN, url(`${ORIGIN}/faro`), KEY));
	assert.equal(l.searchParams.get('i'), `${ORIGIN}/faro`);
	assert.deepEqual(l.searchParams.getAll('m'), [KEY]);
});

test('refuses an instance on another origin', () => {
	for (const i of [
		'https://evil.example',
		'http://faro.example.org',
		'https://faro.example.org:8443'
	]) {
		assert.throws(() => buildEnrollLink(ORIGIN, url(i), KEY), i);
	}
});

test('refuses a fragment, an existing m, or a duplicate parameter', () => {
	const ok = url(`${ORIGIN}/`);
	for (const bad of [
		`${ok}#m=ffffffffffffffff`,
		`${ok}#`,
		`${ok}&m=ffffffffffffffff`,
		`${ok}&i=${enc('https://evil.example')}`,
		`${ok}&c=AAAA-BBBB`,
		url(`${ORIGIN}/#x`),
		url(`${ORIGIN}/?x=1`),
		'https://faro.example.org/?i=x&c=7Q2K-M9XD',
		'faro://other?i=x&c=7Q2K-M9XD',
		'garbage',
		url(`${ORIGIN}/`, '7Q2K-M9XD#m=ffffffffffffffff'),
		url(`${ORIGIN}/`, 'nope')
	]) {
		assert.throws(() => buildEnrollLink(ORIGIN, bad, KEY), bad);
	}
});

test('refuses a malformed key id', () => {
	assert.throws(() => buildEnrollLink(ORIGIN, url(`${ORIGIN}/`), 'abc#'));
});
