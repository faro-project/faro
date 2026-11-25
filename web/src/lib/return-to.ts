// Where to go back to after a sign-in started from a page.
//
// Deleting an account needs a recent sign-in, so the settings page sends a
// sign-in link to the person's own address. The link opens /auth/verify,
// often in a new tab; this remembers to go back to the deletion card from
// there, the same way an invitation being accepted is remembered
// (pending-invite.ts). Only known places are stored, never a URL.

const KEY = 'faro.returnTo';
const MAX_AGE_MS = 30 * 60 * 1000;

export type ReturnTo = 'delete-account';

export function saveReturnTo(to: ReturnTo) {
	try {
		localStorage.setItem(KEY, JSON.stringify({ to, saved_at: Date.now() }));
	} catch {
		// No storage: the person goes back to the page themselves.
	}
}

/** The saved place, if any and recent; it is forgotten once read. */
export function takeReturnTo(): ReturnTo | null {
	try {
		const raw = localStorage.getItem(KEY);
		localStorage.removeItem(KEY);
		if (!raw) return null;
		const v = JSON.parse(raw) as { to?: unknown; saved_at?: unknown };
		if (v.to !== 'delete-account' || typeof v.saved_at !== 'number') return null;
		return Date.now() - v.saved_at > MAX_AGE_MS ? null : v.to;
	} catch {
		return null;
	}
}
