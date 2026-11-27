// Requests for reach outs, signed notes and the reach-out settings
// (docs/GROUPS.md §8.3, §10.2). Shapes and the crypto are in `reach-out.ts`.

import { api, ApiError, describeError, seg } from './api.ts';
import type { GroupMessageKind } from './crypto/group.ts';
import { instance } from './instance.svelte.ts';
import type { MemberKeys } from './keys/keyring.svelte.ts';
import { latestManifest } from './keys/member.ts';
import { proposalErrorMessage } from './proposals.ts';
import { loadRoster } from './roster-api.ts';
import {
	checkRecipients,
	reachOutErrorMessage,
	RecipientError,
	type CheckedRecipients,
	type Chosen,
	type Answer,
	type Audience,
	type CreateReachOut,
	type IncomingReachOut,
	type MessageView,
	type MyReachOuts,
	type OutgoingReachOut,
	type ReachOutMode,
	type Recipients,
	type SenderSetting
} from './reach-out.ts';

/** A sentence for an error from these routes. */
export function reachOutError(e: unknown): string {
	if (e instanceof ApiError) {
		const m = reachOutErrorMessage(e.code, e.status) ?? proposalErrorMessage(e.code);
		if (m) return m;
	}
	return describeError(e);
}

/** Who a message would go to, with the key to seal to for each. */
export function loadRecipients(
	kind: GroupMessageKind,
	opts: { audience?: Audience; groupId?: string | null; userIds?: string[] } = {}
): Promise<Recipients> {
	const q = new URLSearchParams({ for: kind });
	if (opts.audience) q.set('audience', opts.audience);
	if (opts.groupId) q.set('group_id', opts.groupId);
	if (opts.userIds?.length) q.set('user_ids', opts.userIds.join(','));
	return api.get<Recipients>(`/v1/me/message-recipients?${q}`);
}

type RecipientsOpts = { audience?: Audience; groupId?: string | null; userIds?: string[] };

function chosenFor(kind: GroupMessageKind, opts: RecipientsOpts): Chosen {
	switch (kind) {
		case 'join_request_note':
			return { audience: 'join_request' };
		case 'proposal_note':
		case 'check_in_reply':
			return { audience: 'people', userIds: opts.userIds ?? [] };
		default: {
			const a = opts.audience ?? 'allies';
			if (a === 'people') return { audience: 'people', userIds: opts.userIds ?? [] };
			if (a === 'group') throw new RecipientError('A whole-group message is sealed to no one.');
			return { audience: a };
		}
	}
}

/**
 * Check `r` (from `loadRecipients(kind, opts)`) against your own verified
 * recipient manifest and, for a message in a group, the group's roster as
 * this browser verifies it now (`checkRecipients`). Throws a
 * `RecipientError` (or the manifest's `ManifestTrustError`) if anything is
 * off: then nothing may be sealed.
 */
export async function checkLoadedRecipients(
	keys: MemberKeys,
	r: Recipients,
	kind: GroupMessageKind,
	opts: RecipientsOpts = {}
): Promise<CheckedRecipients> {
	const chosen = chosenFor(kind, opts);
	const inst = await instance.load();
	if (r.instance_id !== inst.instance_id) {
		throw new RecipientError("The server named another instance's people. Nothing was sent.");
	}
	const manifest = await latestManifest(keys, inst.instance_id);
	const groupId = opts.groupId ?? null;
	const roster =
		groupId && chosen.audience !== 'join_request'
			? (await loadRoster(groupId, keys.userId)).state
			: null;
	return checkRecipients(r, keys.userId, groupId, chosen, {
		allies: manifest?.allies ?? [],
		roster
	});
}

/** `loadRecipients`, then `checkLoadedRecipients`: who a message may be sealed to. */
export async function loadCheckedRecipients(
	keys: MemberKeys,
	kind: GroupMessageKind,
	opts: RecipientsOpts = {}
): Promise<CheckedRecipients> {
	return checkLoadedRecipients(keys, await loadRecipients(kind, opts), kind, opts);
}

export function sendReachOut(body: CreateReachOut): Promise<OutgoingReachOut> {
	return api.post<OutgoingReachOut>('/v1/me/reach-outs', body);
}

export function listReachOuts(): Promise<MyReachOuts> {
	return api.get<MyReachOuts>('/v1/me/reach-outs');
}

export function answerReachOut(id: string, answer: Answer): Promise<IncomingReachOut> {
	return api.post<IncomingReachOut>(`/v1/reach-outs/${seg(id)}/answer`, { answer });
}

export function getMessage(id: string): Promise<MessageView> {
	return api.get<MessageView>(`/v1/group-messages/${seg(id)}`);
}

export function reachOutSettings(): Promise<SenderSetting[]> {
	return api.get<SenderSetting[]>('/v1/me/reach-out-settings');
}

/** "Let their reach outs through quiet hours", on or off. */
export function setQuietBypass(userId: string, on: boolean): Promise<void> {
	const path = `/v1/me/quiet-hours-bypass/${seg(userId)}`;
	return on ? api.put<void>(path, {}) : api.delete<void>(path);
}

export function setReachOutMode(userId: string, mode: ReachOutMode): Promise<void> {
	return api.put<void>(`/v1/me/reach-out-prefs/${seg(userId)}`, { mode });
}
