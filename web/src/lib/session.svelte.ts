// Who this browser is signed in as, shared by the header and the pages.
//
// The session itself is an HttpOnly cookie the page cannot read; this only
// mirrors `GET /v1/me`. Pages that sign in or out update it so the header
// follows without a reload.

import { api, ApiError } from './api.ts';
import { keyring } from './keys/keyring.svelte.ts';
import type { Me, User } from './types.ts';

class Session {
	/** The signed-in user, or null. */
	user = $state<User | null>(null);
	/** False until the first `/v1/me` answer. */
	loaded = $state(false);
	/** Whether the user has set up member keys (from `/v1/me`). */
	hasMemberKeys = $state(false);

	private pending: Promise<User | null> | null = null;
	/** Bumped by sign-in and sign-out, so an older answer can't undo them. */
	private generation = 0;

	/** Ask the server who is signed in. Concurrent calls share one request. */
	refresh(): Promise<User | null> {
		this.pending ??= (async () => {
			const gen = this.generation;
			try {
				const me = await api.get<Me>('/v1/me');
				if (gen === this.generation) {
					if (me.user.id !== this.user?.id) keyring.lock();
					this.user = me.user;
					this.hasMemberKeys = me.has_member_keys;
				}
			} catch (e) {
				if (!(e instanceof ApiError && e.status === 401)) throw e;
				if (gen === this.generation) {
					this.user = null;
					keyring.lock();
				}
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
		if (user.id !== this.user?.id) keyring.lock();
		this.generation++;
		this.pending = null;
		this.user = user;
		this.loaded = true;
		// The sign-in answer doesn't say whether member keys exist.
		void this.refresh().catch(() => {});
	}

	/** End the session on the server; the cookie is cleared either way. */
	async signOut() {
		keyring.lock();
		await api.post<void>('/v1/auth/logout');
		this.generation++;
		this.user = null;
		this.hasMemberKeys = false;
	}
}

export const session = new Session();
