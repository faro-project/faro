// An invitation being accepted across a sign-in.
//
// Accepting an ally invitation needs a session for the invited address, and
// the sign-in link arrives by email, often opening in a new tab. So the
// invitation page keeps the token in localStorage until the invitation is
// accepted, found invalid, or a week old. The token alone is not enough to
// accept: the server also requires a session for the invited address.

const KEY = 'faro.pendingInvite';
const MAX_AGE_MS = 7 * 24 * 3600 * 1000;

export function savePendingInvite(token: string) {
	try {
		localStorage.setItem(KEY, JSON.stringify({ token, saved_at: Date.now() }));
	} catch {
		// No storage: the person opens the invitation link again after signing in.
	}
}

export function pendingInvite(): string | null {
	try {
		const raw = localStorage.getItem(KEY);
		if (!raw) return null;
		const v = JSON.parse(raw) as { token?: unknown; saved_at?: unknown };
		if (typeof v.token !== 'string' || typeof v.saved_at !== 'number') return null;
		if (Date.now() - v.saved_at > MAX_AGE_MS) {
			clearPendingInvite();
			return null;
		}
		return v.token;
	} catch {
		return null;
	}
}

export function clearPendingInvite() {
	try {
		localStorage.removeItem(KEY);
	} catch {
		// Nothing to clear.
	}
}
