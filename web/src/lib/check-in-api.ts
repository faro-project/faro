// Requests for check-ins and replies (docs/GROUPS.md §8.6, §16). Shapes and
// the crypto are in `check-in.ts`.

import { api, ApiError, describeError, seg } from './api.ts';
import { checkInErrorMessage, type CreatePost, type PostPage, type PostView } from './check-in.ts';
import type { RosterState } from './crypto/roster.ts';
import { keyring } from './keys/keyring.svelte.ts';
import { reachOutError } from './reach-out-api.ts';
import { currentEpochKey } from './roster-api.ts';

/** A sentence for an error from the check-in routes. */
export function checkInError(e: unknown): string {
	if (e instanceof ApiError) {
		const m = checkInErrorMessage(e.code, e.status);
		if (m) return m;
		return reachOutError(e);
	}
	return describeError(e);
}

export function listPosts(groupId: string, before?: string | null): Promise<PostPage> {
	const q = before ? `?before=${encodeURIComponent(before)}` : '';
	return api.get<PostPage>(`/v1/groups/${seg(groupId)}/posts${q}`);
}

export function createPost(groupId: string, body: CreatePost): Promise<PostView> {
	return api.post<PostView>(`/v1/groups/${seg(groupId)}/posts`, body);
}

/**
 * The key of `epoch` (the current one when omitted) for a group's whole-group
 * posts, opened with whichever of your keys is unlocked and checked against
 * the roster this browser verified. Null if you have no copy or no key is
 * unlocked.
 */
export async function epochKeyFor(
	groupId: string,
	userId: string,
	roster: RosterState,
	epoch?: number
): Promise<{ epoch: number; key: Uint8Array } | null> {
	const secret = (keyring.memberFor(userId) ?? keyring.allyFor(userId))?.encSecret;
	if (!secret) return null;
	return currentEpochKey(groupId, roster, secret, epoch);
}
