// Requests for reach outs, signed notes and the reach-out settings
// (docs/GROUPS.md §8.3, §10.2). Shapes and the crypto are in `reach-out.ts`.

import { api, ApiError, describeError, seg } from './api.ts';
import type { GroupMessageKind } from './crypto/group.ts';
import { proposalErrorMessage } from './proposals.ts';
import {
	reachOutErrorMessage,
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
