// The rules for operator content (branding.ts): plain text only, links only
// to mailto: and https:, shown only in page chrome, and never made to look
// like a Faro notice. Run with `npm test`.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { BRANDING_FILES, logoPath, logoWidth, operatorText, supportLink } from './branding.ts';

const SRC = fileURLToPath(new URL('..', import.meta.url));

function sources(dir = SRC): string[] {
	return readdirSync(dir).flatMap((name) => {
		const p = join(dir, name);
		if (statSync(p).isDirectory()) return sources(p);
		return /\.(svelte|ts)$/.test(name) && !name.endsWith('.test.ts') ? [p] : [];
	});
}

const rel = (p: string) => relative(SRC, p).split(sep).join('/');
const read = (r: string) => readFileSync(join(SRC, r), 'utf8');

test('support contacts become mailto: or https: links, nothing else', () => {
	assert.deepEqual(supportLink({ kind: 'email', value: 'help@church.example' }), {
		href: 'mailto:help@church.example',
		text: 'help@church.example'
	});
	assert.equal(
		supportLink({ kind: 'url', value: 'https://church.example/help' })?.href,
		'https://church.example/help'
	);
	const bad: unknown[] = [
		{ kind: 'url', value: 'javascript:alert(1)' },
		{ kind: 'url', value: 'JAVASCRIPT:alert(1)' },
		{ kind: 'url', value: 'data:text/html,<script>alert(1)</script>' },
		{ kind: 'url', value: 'http://church.example' },
		{ kind: 'url', value: 'https://user:pw@church.example' },
		{ kind: 'url', value: '//church.example' },
		{ kind: 'url', value: 'https://church.example/\u202Egnp' },
		{ kind: 'email', value: 'javascript:alert(1)//@x.org' },
		{ kind: 'email', value: 'help@church.example?bcc=x@y.org' },
		{ kind: 'email', value: 'help@church.example\nBcc: x@y.org' },
		{ kind: 'email', value: 'https://church.example' },
		{ kind: 'html', value: 'help@church.example' },
		{ kind: 'url', value: 42 },
		null
	];
	for (const c of bad) {
		assert.equal(supportLink(c as never), null, JSON.stringify(c));
	}
});

test('operator text is one short plain line, shown as typed', () => {
	assert.equal(operatorText('  Welcome <b>all</b> & friends  '), 'Welcome <b>all</b> & friends');
	assert.equal(operatorText('a'.repeat(200)), 'a'.repeat(200));
	for (const bad of [
		'a'.repeat(201),
		'two\nlines',
		'tab\there',
		'esc\u001b[31m',
		'rtl \u202Egnp.exe',
		'zero\u200Bwidth',
		'b\uFEFFom',
		'tag\u{E0041}',
		'',
		'   '
	]) {
		assert.equal(operatorText(bad), null, JSON.stringify(bad));
	}
});

test('logo URLs are built from a logo id only', () => {
	const id = '0123456789abcdef0123456789abcdef';
	assert.equal(logoPath({ id, width: 10, height: 5 }), `/v1/branding/logo/${id}.png`);
	for (const bad of ['../../v1/me', 'https://evil.example/x', id.toUpperCase(), `${id}0`, '']) {
		assert.equal(logoPath({ id: bad, width: 10, height: 5 }), null, bad);
	}
	assert.equal(logoPath(null), null);
	assert.equal(logoWidth({ id, width: 400, height: 100 }, 26), 104);
});

test('no page renders HTML from a string', () => {
	for (const f of sources()) {
		assert.ok(!readFileSync(f, 'utf8').includes('{@html'), `${rel(f)} uses {@html}`);
	}
});

test('operator content appears only in page chrome', () => {
	// Anything that reads or shows branding names one of these.
	const uses =
		/branding\.svelte\.ts|branding\.ts|\/v1\/branding|OperatorNote|SupportContact\.svelte|BrandMark/;
	const allowed = new Set<string>(BRANDING_FILES);
	for (const f of sources()) {
		const r = rel(f);
		if (r === 'lib/types.ts' || r === 'lib/api.ts') continue;
		if (uses.test(readFileSync(f, 'utf8'))) {
			assert.ok(allowed.has(r), `${r} shows operator content; only page chrome may`);
		}
	}
	// And so never in alerts, the feed, reports, safety codes, key
	// fingerprints, tamper warnings or enrollment.
	for (const r of BRANDING_FILES) {
		assert.ok(
			!/^(lib\/(feed|keys|crypto)\/|lib\/ui\/(AllySafetyCode|UnlockKeys|RecoveryCode)|routes\/(activity|allies|computers|supporting|keys|invite|settings)\/)/.test(
				r
			),
			r
		);
	}
});

test('operator text is labelled and never styled as a Faro notice', () => {
	for (const r of ['lib/ui/OperatorNote.svelte', 'lib/ui/SupportContact.svelte']) {
		const s = read(r);
		assert.ok(
			s.includes('OPERATOR_LABEL') || s.includes("this instance's admins"),
			`${r} must say the text is from the instance's admins`
		);
		const markup = s.replace(/<script[\s\S]*?<\/script>/, '');
		for (const look of [
			'role="alert"',
			'role="status"',
			'aria-live',
			'notice',
			'warn',
			'danger',
			'error',
			'--ok',
			'--accent',
			'--brand',
			'<strong',
			'<h1',
			'<h2',
			'⚠',
			'✓',
			'🔒',
			'🔓'
		]) {
			assert.ok(!markup.includes(look), `${r} uses ${look}`);
		}
	}
});

test("the instance's logo sits next to Faro's and never replaces it", () => {
	const s = read('lib/ui/BrandMark.svelte').replace(/<script[\s\S]*?<\/script>/, '');
	const ifEnd = s.indexOf('{/if}');
	const faro = s.indexOf('<Logo');
	assert.ok(ifEnd > 0 && faro > ifEnd, "Faro's logo is shown whether or not there is another");
	assert.ok(s.includes('alt={name}'), "the instance's logo is labelled with the instance's name");
	// Pages that showed Faro's logo now show it through BrandMark.
	for (const r of [
		'routes/+layout.svelte',
		'routes/signin/+page.svelte',
		'routes/setup/+page.svelte'
	]) {
		assert.ok(read(r).includes('<BrandMark'), r);
	}
});
