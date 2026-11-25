// An ally's record, in this browser, of which member keys they have
// checked in person with a safety code.
//
// A convenience only (localStorage can be cleared, and is per browser): it
// lets the page warn when the key the server now reports for a member
// differs from the one the ally compared, which would mean the member set up
// new keys, or someone is trying to impersonate them.

const PREFIX = 'faro.verified.';

function storageKey(allyId: string, memberId: string) {
	return `${PREFIX}${allyId}.${memberId}`;
}

export function verifiedKey(allyId: string, memberId: string): string | null {
	try {
		return localStorage.getItem(storageKey(allyId, memberId));
	} catch {
		return null;
	}
}

export function markVerified(allyId: string, memberId: string, memberSignPk: string) {
	try {
		localStorage.setItem(storageKey(allyId, memberId), memberSignPk);
	} catch {
		// Storage unavailable (private window): nothing is remembered.
	}
}

export type Verification = 'verified' | 'changed' | 'unverified';

export function verification(
	allyId: string,
	memberId: string,
	memberSignPk: string | null
): Verification {
	const v = verifiedKey(allyId, memberId);
	if (!v || !memberSignPk) return 'unverified';
	return v === memberSignPk ? 'verified' : 'changed';
}
