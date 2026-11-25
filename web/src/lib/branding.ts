// Instance branding: the rules the web app keeps for operator content.
//
// An instance's operator isn't fully trusted (docs/ARCHITECTURE.md §5.3),
// so what they set is treated as untrusted text:
//
// - It is shown as plain text (Svelte's `{…}`, never raw HTML), so markup
//   in it shows as typed.
// - It appears only in page chrome: the header, the footer and the sign-in
//   and setup pages. Only the files in `BRANDING_FILES` may use it; the
//   test in branding.test.ts checks that, so it can never reach alerts, the
//   feed, reports, safety codes, key fingerprints, tamper warnings or
//   enrollment.
// - It is labelled as the instance's and never styled as a Faro notice.
// - Links are built here, and only as `mailto:` or `https:`, whatever the
//   server sent.
//
// This file has no Svelte runes so `npm test` can import it.

import type { BrandingLogo, SupportContact } from './types.ts';

/** The only source files that may show operator content. */
export const BRANDING_FILES = [
	'lib/branding.ts',
	'lib/branding.svelte.ts',
	'lib/ui/BrandMark.svelte',
	'lib/ui/OperatorNote.svelte',
	'lib/ui/SupportContact.svelte',
	'routes/+layout.svelte',
	'routes/signin/+page.svelte',
	'routes/setup/+page.svelte',
	'routes/admin/branding/+page.svelte'
] as const;

/** The label every piece of operator text carries. */
export const OPERATOR_LABEL = "From this instance's admins";

const LOGO_ID = /^[0-9a-f]{32}$/;

/** The logo's path under the API, or null for anything that isn't a logo id. */
export function logoPath(logo: BrandingLogo | null | undefined): string | null {
	if (!logo || !LOGO_ID.test(logo.id)) return null;
	return `/v1/branding/logo/${logo.id}.png`;
}

/** The logo's width when shown `height` pixels high. */
export function logoWidth(logo: BrandingLogo, height: number): number {
	if (!(logo.width > 0 && logo.height > 0)) return height;
	return Math.max(1, Math.round((height * logo.width) / logo.height));
}

/**
 * A support contact as a link, or null if it is neither a plain email
 * address nor an `https://` URL. The server checks the same; this is the
 * second check, so a bad value can never become a `javascript:` link.
 */
export function supportLink(
	c: SupportContact | null | undefined
): { href: string; text: string } | null {
	if (!c || typeof c.value !== 'string') return null;
	const v = c.value;
	if (v.length > 200 || /[\s<>"'`\\]/.test(v) || hasHiddenChars(v)) return null;
	if (c.kind === 'email') {
		if (!/^[^@:/?#%]+@[^@:/?#%]+\.[^@:/?#%.]+$/.test(v)) return null;
		return { href: `mailto:${v}`, text: v };
	}
	if (c.kind === 'url') {
		let u: URL;
		try {
			u = new URL(v);
		} catch {
			return null;
		}
		if (u.protocol !== 'https:' || !u.hostname || u.username || u.password) return null;
		return { href: u.href, text: v.replace(/^https:\/\//i, '').replace(/\/$/, '') };
	}
	return null;
}

/**
 * Control characters, and characters that are invisible or change the
 * direction of the text around them (the server refuses them too).
 */
export function hasHiddenChars(s: string): boolean {
	return HIDDEN.test(s);
}

const HIDDEN =
	/[\u0000-\u001f\u007f-\u009f\u00ad\u034f\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff9-\ufffb]|\udb40[\udc00-\udc7f]/;

/** Operator text to show, or null if it breaks the rules (one short plain line). */
export function operatorText(s: string | null | undefined, max = 200): string | null {
	if (typeof s !== 'string') return null;
	const t = s.trim();
	if (!t || [...t].length > max || hasHiddenChars(t)) return null;
	return t;
}
