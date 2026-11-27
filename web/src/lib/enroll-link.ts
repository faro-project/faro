// Building the enrollment link the member hands to a new device.
//
// The link carries `m`, the fingerprint of the member's key, which the device
// checks the enrolling instance's member key against. It must come from the
// member's own browser alone: the server must not be able to choose or
// override it. So the final link is assembled here with `searchParams`; the
// server's `enroll_url` only supplies the instance URL (which may have a path
// prefix) and the code, after strict validation.

/** Crockford base32 one-time code, `XXXX-XXXX`. */
const CODE_RE = /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/;
const KEY_ID_RE = /^[0-9a-f]{16}$/;

/**
 * Builds `faro://enroll?i=<instance URL>&c=<code>&m=<member key id>` from the
 * server's `enroll_url` and the member's key fingerprint. The server's link is
 * accepted only if it is a plain `faro://enroll` link with no fragment, no
 * `m`, one `i` and one `c`, and `i` is on this page's own origin. Throws an
 * Error with a message for the member otherwise.
 */
export function buildEnrollLink(
	pageOrigin: string,
	enrollUrl: string,
	memberKeyId: string
): string {
	const bad = () => new Error('The server sent an unexpected enrollment link.');
	if (!KEY_ID_RE.test(memberKeyId)) {
		throw new Error('Your key fingerprint is not in the expected form.');
	}
	if (enrollUrl.includes('#')) throw bad();
	let src: URL;
	try {
		src = new URL(enrollUrl);
	} catch {
		throw bad();
	}
	if (src.protocol !== 'faro:' || src.hostname !== 'enroll') throw bad();
	const is = src.searchParams.getAll('i');
	const cs = src.searchParams.getAll('c');
	if (src.searchParams.has('m') || is.length !== 1 || cs.length !== 1) throw bad();
	if (!CODE_RE.test(cs[0])) throw bad();
	let inst: URL;
	try {
		inst = new URL(is[0]);
	} catch {
		throw bad();
	}
	if (
		(inst.protocol !== 'https:' && inst.protocol !== 'http:') ||
		inst.origin !== pageOrigin ||
		inst.username ||
		inst.password ||
		is[0].includes('#') ||
		is[0].includes('?')
	) {
		throw bad();
	}
	const link = new URL('faro://enroll');
	link.searchParams.set('i', inst.href);
	link.searchParams.set('c', cs[0]);
	link.searchParams.set('m', memberKeyId);
	return link.toString();
}
