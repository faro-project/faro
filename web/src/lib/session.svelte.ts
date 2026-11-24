// Who this browser is signed in as, shared by the header and the pages.
//
// The session itself is an HttpOnly cookie the page cannot read; this only
// mirrors `GET /v1/me`. Pages that sign in or out update it so the header
// follows without a reload.

import { api, ApiError } from './api.ts';
import type { Me, User } from './types.ts';

class Session {
	/** The signed-in user, or null. */
	user = $state<User | null>(null);
	/** False until the first `/v1/me` answer. */
	loaded = $state(false);

	private pending: Promise<User | null> | null = null;

	/** Ask the server who is signed in. Concurrent calls share one request. */
	refresh(): Promise<User | null> {
		this.pending ??= (async () => {
			try {
				this.user = (await api.get<Me>('/v1/me')).user;
			} catch (e) {
				if (!(e instanceof ApiError && e.status === 401)) throw e;
				this.user = null;
			} finally {
				this.loaded = true;
				this.pending = null;
			}
			return this.user;
		})();
		return this.pending;
	}

	/** After a sign-in or account creation answered with the user. */
	signedIn(user: User) {
		this.user = user;
		this.loaded = true;
	}

	/** End the session on the server; the cookie is cleared either way. */
	async signOut() {
		await api.post<void>('/v1/auth/logout');
		this.user = null;
	}
}

export const session = new Session();
