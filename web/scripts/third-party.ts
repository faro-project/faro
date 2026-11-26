// Third-party notices for the web app (docs/DEVELOPMENT.md "Third-party
// notices"). A Vite plugin lists every npm package whose code ends up in the
// browser bundle, with its licence and licence text, and writes them to
// `third-party-licenses.txt` next to the pages (the `/licenses` page shows
// it). Packages used only to build the app (Vite, TypeScript, Prettier…) are
// not in the bundle and are not listed.
//
// The build fails if a bundled package's licence can't be resolved (no
// `license` field, or no licence file in the package) or isn't on the
// allowlist, which is the `[licenses] allow` list of the repository's
// deny.toml, the one cargo-deny and cargo-about use for the Rust crates.

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Plugin } from 'vite';

/** The notices file, at the root of the build. */
export const NOTICES_FILE = 'third-party-licenses.txt';

/** The deny.toml next to web/ (the container build copies it to `/deny.toml`). */
const DENY_TOML = join(import.meta.dirname, '../../deny.toml');

/** The SPDX identifiers in deny.toml's `[licenses] allow` list. */
export function allowedLicences(denyToml: string): Set<string> {
	const section = denyToml.split(/^\[licenses\]\s*$/m)[1]?.split(/^\[/m)[0];
	const list = section?.match(/^allow\s*=\s*\[([\s\S]*?)^\]/m)?.[1];
	if (list === undefined) throw new Error('deny.toml has no [licenses] allow list');
	const ids = new Set<string>();
	for (const line of list.split('\n')) {
		for (const m of line.replace(/#.*$/, '').matchAll(/"([^"]+)"/g)) ids.add(m[1]);
	}
	if (ids.size === 0) throw new Error('deny.toml allows no licences');
	return ids;
}

/**
 * Whether an SPDX licence expression can be met with allowed licences only:
 * `A OR B` needs one of them, `A AND B` both, and `A WITH E` must be allowed
 * as a whole. Anything that doesn't parse is not allowed.
 */
export function licenceAllowed(expression: string, allowed: ReadonlySet<string>): boolean {
	const tokens = expression.match(/\(|\)|[^\s()]+/g) ?? [];
	let i = 0;
	const peek = () => tokens[i];
	const or = (): boolean => {
		let ok = and();
		while (peek() === 'OR') {
			i++;
			ok = and() || ok;
		}
		return ok;
	};
	const and = (): boolean => {
		let ok = term();
		while (peek() === 'AND') {
			i++;
			ok = term() && ok;
		}
		return ok;
	};
	const term = (): boolean => {
		const t = tokens[i++];
		if (t === '(') {
			const ok = or();
			if (tokens[i++] !== ')') throw new Error('unbalanced parentheses');
			return ok;
		}
		if (t === undefined || ['AND', 'OR', 'WITH', ')'].includes(t)) {
			throw new Error(`unexpected ${t ?? 'end'}`);
		}
		if (peek() === 'WITH') {
			i++;
			const exception = tokens[i++];
			if (exception === undefined || exception === '(' || exception === ')') {
				throw new Error('WITH needs an exception');
			}
			return allowed.has(`${t} WITH ${exception}`);
		}
		return allowed.has(t);
	};
	try {
		const ok = or();
		return i === tokens.length && ok;
	} catch {
		return false;
	}
}

/** The `node_modules/<name>` or `node_modules/@scope/<name>` directory a bundled module comes from. */
export function packageDir(moduleId: string): string | null {
	const id = moduleId.replace(/^\0/, '').split('?')[0].replaceAll('\\', '/');
	const at = id.lastIndexOf('/node_modules/');
	if (at < 0) return null;
	const rest = id.slice(at + '/node_modules/'.length).split('/');
	const name = rest[0].startsWith('@') ? rest.slice(0, 2) : rest.slice(0, 1);
	if (name.length === 0 || name.some((p) => p === '')) return null;
	return id.slice(0, at) + '/node_modules/' + name.join('/');
}

export type BundledPackage = {
	name: string;
	version: string;
	licence: string;
	homepage: string | null;
	texts: { file: string; text: string }[];
};

const LICENCE_FILE = /^(licen[cs]e|copying|notice)([.-].*)?$/i;

/** A bundled package's name, version, licence and licence texts, checked against `allowed`. */
export function readPackage(dir: string, allowed: ReadonlySet<string>): BundledPackage {
	const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
	const name = String(pkg.name ?? dir);
	if (typeof pkg.license !== 'string' || pkg.license.trim() === '') {
		throw new Error(`${name}: no SPDX licence in its package.json`);
	}
	const licence = pkg.license.trim();
	if (!licenceAllowed(licence, allowed)) {
		throw new Error(`${name}: licence "${licence}" isn't allowed by deny.toml`);
	}
	const texts = readdirSync(dir, { withFileTypes: true })
		.filter((e) => e.isFile() && LICENCE_FILE.test(e.name))
		.map((e) => e.name)
		.sort()
		.map((file) => ({ file, text: readFileSync(join(dir, file), 'utf8').trim() }));
	if (texts.length === 0) throw new Error(`${name}: no licence file in ${dir}`);
	const repo = typeof pkg.repository === 'string' ? pkg.repository : pkg.repository?.url;
	const homepage = typeof pkg.homepage === 'string' ? pkg.homepage : (repo ?? null);
	return { name, version: String(pkg.version ?? ''), licence, homepage, texts };
}

/** The notices file for these packages. */
export function noticesText(packages: BundledPackage[]): string {
	const sorted = [...packages].sort((a, b) =>
		a.name === b.name ? a.version.localeCompare(b.version) : a.name.localeCompare(b.name)
	);
	const rule = '-'.repeat(72);
	const out = [
		'Third-party software in the Faro web app',
		'',
		'The web app served by a Faro instance includes the following npm',
		'packages. Each is listed with its licence, followed by the licence text',
		'and notices it ships with.',
		'',
		...sorted.map((p) => `  ${p.name} ${p.version} (${p.licence})`)
	];
	for (const p of sorted) {
		out.push('', rule, `${p.name} ${p.version}`, `Licence: ${p.licence}`);
		if (p.homepage) out.push(p.homepage);
		for (const t of p.texts) out.push('', `${t.file}:`, '', t.text);
	}
	return out.join('\n') + '\n';
}

/** Writes NOTICES_FILE into the browser build: every package its chunks include. */
export function thirdPartyNotices(): Plugin {
	return {
		name: 'faro-third-party-notices',
		apply: 'build',
		generateBundle(_options, bundle) {
			// Only the browser's code is shipped; the server-side build only
			// prerenders the pages.
			if (this.environment.config.consumer !== 'client') return;
			const allowed = allowedLicences(readFileSync(DENY_TOML, 'utf8'));
			const dirs = new Set<string>();
			for (const file of Object.values(bundle)) {
				if (file.type !== 'chunk') continue;
				for (const id of file.moduleIds) {
					const dir = packageDir(id);
					if (dir && existsSync(join(dir, 'package.json'))) dirs.add(dir);
				}
			}
			const packages = new Map<string, BundledPackage>();
			const errors: string[] = [];
			for (const dir of dirs) {
				try {
					const p = readPackage(dir, allowed);
					packages.set(`${p.name}@${p.version}`, p);
				} catch (e) {
					errors.push((e as Error).message);
				}
			}
			if (errors.length) {
				this.error(`third-party notices:\n  ${errors.sort().join('\n  ')}`);
			}
			if (packages.size === 0) this.error('third-party notices: no bundled packages found');
			this.emitFile({
				type: 'asset',
				fileName: NOTICES_FILE,
				source: noticesText([...packages.values()])
			});
		}
	};
}
