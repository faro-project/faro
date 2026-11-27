// Building the enrollment link the member hands to a new device.
//
// The link carries `m`, the fingerprint of the member's key, which the device
// checks the enrolling instance's member key against. It must come from the
// member's own browser alone: the server must not be able to choose or
// override it. So the link is built here from the one-time code and this
// page's own origin, never from a URL the server supplied.

/** Crockford base32 one-time code, `XXXX-XXXX`. */
const CODE_RE = /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/;
const KEY_ID_RE = /^[0-9a-f]{16}$/;

/**
 * `faro://enroll?i=<origin>&c=<code>&m=<member key id>`. Throws an Error with
 * a message for the member if the code or fingerprint is malformed.
 */
export function buildEnrollLink(origin: string, code: string, memberKeyId: string): string {
	if (!CODE_RE.test(code)) {
		throw new Error('The server sent an enrollment code in an unexpected form.');
	}
	if (!KEY_ID_RE.test(memberKeyId)) {
		throw new Error('Your key fingerprint is not in the expected form.');
	}
	const o = new URL(origin);
	if (o.protocol !== 'https:' && o.protocol !== 'http:') {
		throw new Error('Unsupported page origin.');
	}
	const link = new URL('faro://enroll');
	link.searchParams.set('i', o.origin);
	link.searchParams.set('c', code);
	link.searchParams.set('m', memberKeyId);
	return link.toString();
}
