// The groups pages' error wording and shared loads, on top of the API client.

import { api, ApiError, describeError } from './api.ts';
import { groupErrorMessage, type Links } from './groups.ts';
import { proposalErrorMessage } from './proposals.ts';
import type { MyAllies, SupportedMember } from './types.ts';

/** A sentence for an error from the groups API. */
export function groupError(e: unknown): string {
	if (e instanceof ApiError) {
		const m = proposalErrorMessage(e.code) ?? groupErrorMessage(e.code, e.status);
		if (m) return m;
	}
	return describeError(e);
}

/** Your alliances, as user ids, for the roster's relationship labels. */
export async function loadLinks(roles: { member: boolean; ally: boolean }): Promise<Links> {
	const [mine, supporting] = await Promise.all([
		roles.member
			? api.get<MyAllies>('/v1/me/allies').catch(() => null)
			: Promise.resolve<MyAllies | null>(null),
		roles.ally
			? api.get<SupportedMember[]>('/v1/ally/members').catch(() => null)
			: Promise.resolve<SupportedMember[] | null>(null)
	]);
	return {
		myAllies: (mine?.allies ?? []).map((a) => ({ id: a.ally_id, state: a.state })),
		supporting: (supporting ?? []).map((m) => ({ id: m.member_id, state: m.state }))
	};
}
