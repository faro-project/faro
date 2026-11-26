// The web app's third-party notices (third-party.ts): the allowlist comes
// from deny.toml, licence expressions are checked against it, and a bundled
// package without a usable licence fails the build. Run with `npm test`.

import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
	allowedLicences,
	licenceAllowed,
	noticesText,
	packageDir,
	readPackage
} from './third-party.ts';

const deny = readFileSync(join(import.meta.dirname, '../../deny.toml'), 'utf8');
const allowed = allowedLicences(deny);

test("the allowlist is deny.toml's", () => {
	for (const id of ['MIT', 'Apache-2.0', 'Apache-2.0 WITH LLVM-exception', 'MPL-2.0', '0BSD']) {
		assert.ok(allowed.has(id), id);
	}
	for (const id of ['GPL-3.0', 'AGPL-3.0', 'LGPL-2.1', 'CC-BY-NC-4.0']) {
		assert.ok(!allowed.has(id), id);
	}
	assert.throws(() => allowedLicences('[bans]\nallow = ["MIT"]\n'));
});

test('licence expressions must be met with allowed licences only', () => {
	for (const ok of [
		'MIT',
		'(MIT OR Apache-2.0)',
		'MIT OR GPL-3.0',
		'GPL-3.0 OR (MIT AND ISC)',
		'Apache-2.0 WITH LLVM-exception',
		'MIT AND (BSD-3-Clause OR GPL-2.0)'
	]) {
		assert.ok(licenceAllowed(ok, allowed), ok);
	}
	for (const bad of [
		'GPL-3.0',
		'MIT AND GPL-3.0',
		'Apache-2.0 WITH Classpath-exception-2.0',
		'GPL-2.0 WITH LLVM-exception',
		'UNLICENSED',
		'SEE LICENSE IN LICENSE.txt',
		'MIT OR',
		'(MIT',
		'MIT)',
		''
	]) {
		assert.ok(!licenceAllowed(bad, allowed), bad);
	}
});

test('bundled modules map to their package directory', () => {
	assert.equal(
		packageDir('/w/web/node_modules/svelte/src/internal/client/index.js'),
		'/w/web/node_modules/svelte'
	);
	assert.equal(
		packageDir('\0/w/web/node_modules/@noble/hashes/sha2.js?commonjs'),
		'/w/web/node_modules/@noble/hashes'
	);
	assert.equal(
		packageDir('/w/web/node_modules/a/node_modules/@s/b/x.js'),
		'/w/web/node_modules/a/node_modules/@s/b'
	);
	assert.equal(packageDir('/w/web/src/lib/api.ts'), null);
	assert.equal(packageDir('\0virtual:module'), null);
});

test('a bundled package needs an allowed licence and its text', () => {
	const dir = mkdtempSync(join(tmpdir(), 'faro-notices-'));
	try {
		const pkg = (json: object) => writeFileSync(join(dir, 'package.json'), JSON.stringify(json));
		pkg({ name: 'x', version: '1.0.0', license: 'MIT', repository: { url: 'https://x.example' } });
		assert.throws(() => readPackage(dir, allowed), /no licence file/);
		writeFileSync(join(dir, 'LICENSE.md'), 'Copyright (c) X\n\nPermission is hereby granted\n');
		mkdirSync(join(dir, 'license-tools'));
		const p = readPackage(dir, allowed);
		assert.deepEqual(p.texts, [
			{ file: 'LICENSE.md', text: 'Copyright (c) X\n\nPermission is hereby granted' }
		]);
		assert.equal(p.homepage, 'https://x.example');
		const text = noticesText([p]);
		assert.match(text, /^ {2}x 1\.0\.0 \(MIT\)$/m);
		assert.match(text, /Copyright \(c\) X/);

		pkg({ name: 'x', version: '1.0.0', license: 'GPL-3.0-only' });
		assert.throws(() => readPackage(dir, allowed), /isn't allowed/);
		pkg({ name: 'x', version: '1.0.0', licenses: [{ type: 'MIT' }] });
		assert.throws(() => readPackage(dir, allowed), /no SPDX licence/);
	} finally {
		rmSync(dir, { recursive: true });
	}
});
