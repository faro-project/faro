// Who this browser is signed in as, shared by the header and the pages.
//
// The session itself is an HttpOnly cookie the page cannot read; this only
// mirrors `GET /v1/me`. Pages that sign in or out update it so the header
// follows without a reload.

import { api, ApiError } from './api.ts';
import { keyring } from './keys/keyring.svelte.ts';
import type { DeletionCancelled, Me, PendingDeletion, User } from './types.ts';

class Session {
	/** The signed-in user, or null. */
	user = $state<User | null>(null);
	/** False until the first `/v1/me` answer. */
	loaded = $state(false);
	/** Whether the user has set up member keys (from `/v1/me`). */
	hasMemberKeys = $state(false);
	/** The pending deletion of this account, if any (from `/v1/me`). */
	deletion = $state<PendingDeletion | null>(null);
	/** When this session signed in (from `/v1/me`; 0 until known). */
	startedAt = $state(0);

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
					this.deletion = me.deletion;
					this.startedAt = me.session_started_at_ms;
				}
			} catch (e) {
				if (!(e instanceof ApiError && e.status === 401)) throw e;
				if (gen === this.generation) {
					this.user = null;
					this.deletion = null;
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
		this.deletion = null;
	}

	/** Cancel this account's pending deletion; the same people are told. */
	async cancelDeletion() {
		await api.post<DeletionCancelled>('/v1/me/deletion/cancel', {});
		this.deletion = null;
		await this.refresh();
	}
}

export const session = new Session();
