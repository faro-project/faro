// Check-ins and replies (docs/GROUPS.md §8.6, PROTOCOL.md §11): the shapes
// the API serves, composing a check-in or a reply, and reading one. Kept
// free of the DOM and Svelte so `npm test` can cover it; the requests are in
// `check-in-api.ts`.
//
// A check-in is written by one person for their allies in the group, the
// facilitators, up to 32 named people or the whole group (sealed with the
// group's epoch key: one envelope, whatever the size). It is signed with the
// author's member key and never notifies anyone. Reading is strict, as for
// reach outs: a post is shown only if its structure, body and signature all
// check out and it is the post, group and kind the server says it is.

import {
	checkInBytes,
	newItemId,
	parseCheckIn,
	sealGroupMessageBody,
	sealGroupMessageToEpoch,
	type CheckInText,
	type SealedGroupMessage
} from './crypto/group.ts';
import { utf8 } from './crypto/bytes.ts';
import type { MemberKeys } from './keys/keyring.svelte.ts';
import type { Verification } from './keys/verified.ts';
import {
	MAX_NAMED,
	MAX_NOTE_CHARS,
	noteLength,
	readSealed,
	sealable,
	type MessageView,
	type ReadKeys,
	type Recipients
} from './reach-out.ts';
import { messageText } from './crypto/group.ts';

export type { CheckInText };
export { MAX_NAMED, MAX_NOTE_CHARS, noteLength };

/** Who a check-in is for. */
export type CheckInAudience = 'allies' | 'facilitators' | 'people' | 'group';

/** `GET /v1/groups/{id}/posts` item: a message with its place in the feed. */
export type PostView = MessageView;

/** `GET /v1/groups/{id}/posts` */
export interface PostPage {
	items: PostView[];
	next_cursor: string | null;
}

/** `POST /v1/groups/{id}/posts` body. */
export interface CreatePost {
	audience?: CheckInAudience;
	user_ids?: string[];
	message: SealedGroupMessage;
}

type Author = Pick<MemberKeys, 'userId' | 'signSeed' | 'encPk'>;

// ---- Composing ---------------------------------------------------------------

/**
 * Seal and sign a check-in to everyone in `recipients` who has a key, and to
 * yourself (allies in the group, the facilitators or named people).
 */
export function composeCheckIn(
	keys: Author,
	recipients: Recipients,
	groupId: string,
	checkIn: CheckInText,
	now = Date.now()
): SealedGroupMessage {
	const to = sealable(recipients).filter((p) => p.user_id !== keys.userId);
	if (to.length === 0) throw new Error('Nobody you chose can read a check-in yet.');
	return sealGroupMessageBody(
		keys.signSeed,
		keys.encPk,
		{
			instance_id: recipients.instance_id,
			group_id: groupId,
			item_id: newItemId(),
			kind: 'check_in',
			author_id: keys.userId,
			issued_at_ms: now,
			recipients: to.map((p) => ({ user_id: p.user_id, enc_pubkey: p.enc_pubkey! }))
		},
		checkInBytes(checkIn)
	);
}

/** Seal and sign a check-in for the whole group with the key of `epoch`. */
export function composeGroupCheckIn(
	keys: Pick<MemberKeys, 'userId' | 'signSeed'>,
	instanceId: string,
	groupId: string,
	epoch: number,
	epochKey: Uint8Array,
	checkIn: CheckInText,
	now = Date.now()
): SealedGroupMessage {
	return sealGroupMessageToEpoch(
		keys.signSeed,
		epochKey,
		{
			instance_id: instanceId,
			group_id: groupId,
			item_id: newItemId(),
			kind: 'check_in',
			author_id: keys.userId,
			issued_at_ms: now,
			recipients: [],
			epoch
		},
		checkInBytes(checkIn)
	);
}

/** A private reply to a check-in: `recipients` is its author alone. */
export function composeReply(
	keys: Author,
	recipients: Recipients,
	groupId: string,
	parentId: string,
	text: string,
	now = Date.now()
): SealedGroupMessage {
	if (!text.trim() || noteLength(text) > MAX_NOTE_CHARS) {
		throw new Error(`A reply is 1 to ${MAX_NOTE_CHARS} characters.`);
	}
	const to = sealable(recipients).filter((p) => p.user_id !== keys.userId);
	if (to.length !== 1) throw new Error("They can't read a reply yet: they have no keys.");
	return sealGroupMessageBody(
		keys.signSeed,
		keys.encPk,
		{
			instance_id: recipients.instance_id,
			group_id: groupId,
			item_id: newItemId(),
			kind: 'check_in_reply',
			author_id: keys.userId,
			issued_at_ms: now,
			recipients: [{ user_id: to[0].user_id, enc_pubkey: to[0].enc_pubkey! }],
			parent_id: parentId
		},
		utf8(JSON.stringify({ text }))
	);
}

// ---- Reading -----------------------------------------------------------------

export interface PostRead {
	status: 'ok' | 'invalid' | 'locked' | 'unreadable';
	/** A check-in's answers. */
	checkIn: CheckInText | null;
	/** A reply's text. */
	text: string | null;
	verified: Verification;
	reason?: string;
}

/**
 * Check a served post and open it as `me`. `groupId` is the group it was
 * asked for in; `instanceId`, when known, must be the one it names. A
 * whole-group post needs `keys.epochKey` (the key of `view.epoch`).
 */
export function readPost(
	view: PostView,
	me: string,
	keys: ReadKeys,
	instanceId: string | null | undefined,
	groupId: string
): PostRead {
	const fail = (
		status: PostRead['status'],
		reason?: string,
		verified: Verification = 'unverified'
	) => ({ status, checkIn: null, text: null, verified, reason }) satisfies PostRead;
	const m = view?.message;
	if (!m) return fail('invalid', 'no message');
	if (m.kind !== 'check_in' && m.kind !== 'check_in_reply') return fail('invalid', 'not a post');
	// The place the server files it under is what was signed.
	if ((view.parent_id ?? null) !== (m.parent_id ?? null)) return fail('invalid', 'wrong parent');
	if ((view.epoch ?? null) !== (m.epoch ?? null)) return fail('invalid', 'wrong epoch');
	const r = readSealed(view, me, keys, instanceId, null, groupId);
	if (r.status !== 'ok') return fail(r.status, r.reason, r.verified);
	if (!r.bytes) return fail('invalid', 'a post has a body', r.verified);
	try {
		return m.kind === 'check_in'
			? { status: 'ok', checkIn: parseCheckIn(r.bytes), text: null, verified: r.verified }
			: { status: 'ok', checkIn: null, text: messageText(r.bytes), verified: r.verified };
	} catch {
		return fail('unreadable', 'malformed body', r.verified);
	}
}

// ---- Wording -----------------------------------------------------------------

export const SCALE_LABELS: Record<number, string> = {
	1: 'Struggling',
	2: 'Hard',
	3: 'Up and down',
	4: 'Good',
	5: 'Going well'
};

export function scaleLabel(n: number): string {
	return SCALE_LABELS[n] ?? String(n);
}

export const WAITING_LINE =
	'Waiting for a facilitator to update the group. Posts to the whole group are paused until then; you can still send to people by name.';

const MESSAGES: Record<string, string> = {
	posting_paused: 'Waiting for a facilitator to update the group. Choose people by name for now.',
	group_key_missing:
		"This group's encryption isn't set up yet. A facilitator's browser does it when they open the group.",
	stale_epoch: "The group's key changed while you were writing. Try again.",
	group_too_large: 'A reach out to the whole group is only for groups of 32 people or fewer.',
	already_replied: 'You already replied to this check-in.',
	cannot_reply_to_self: "You can't reply to your own check-in.",
	no_recipients:
		'There is nobody to send this to yet. Choose other people, or a different audience.',
	too_many_recipients: `A check-in can go to at most ${MAX_NAMED} named people.`,
	invalid_recipients: `Choose 1 to ${MAX_NAMED} people.`,
	member_keys_required:
		'Signing a check-in needs your keys. You can set them up under "Your keys".',
	bad_signature: "The check-in couldn't be signed with your key. Unlock your keys and try again.",
	stale_recipient_key: "Someone's key changed. Try again.",
	clock_skew: "Your computer's clock seems to be off. Check it and try again.",
	invalid_message: "The check-in couldn't be sent as written. Try again.",
	message_exists: 'That was already sent.',
	group_archived: 'This group was closed.'
};

/** A sentence for an error from the check-in routes, or null. */
export function checkInErrorMessage(code: string, status: number): string | null {
	if (status === 429) return "You've posted a lot today. Try again a little later.";
	return MESSAGES[code] ?? null;
}

// ---- The prompt a day before a meeting ----------------------------------------

export const PROMPT_LEAD_MS = 24 * 3600 * 1000;

/**
 * Whether to show "Your group meets tomorrow: write a check-in?": the person
 * turned it on, the next meeting is within a day (and not yet past), and
 * they haven't dismissed or answered it for this meeting.
 */
export function checkInPromptDue(
	nextMeetingAtMs: number | null,
	now: number,
	enabled: boolean,
	lastPromptedFor: number | null
): boolean {
	if (!enabled || nextMeetingAtMs == null) return false;
	if (nextMeetingAtMs <= now || nextMeetingAtMs - now > PROMPT_LEAD_MS) return false;
	return lastPromptedFor !== nextMeetingAtMs;
}

function storage(): Storage | null {
	try {
		return globalThis.localStorage ?? null;
	} catch {
		return null;
	}
}

const promptKey = (userId: string, groupId: string) =>
	`faro.checkin-prompt.v1.${userId}.${groupId}`;

/** The saved choice, per person and group, in this browser only. */
export function loadPromptSetting(
	userId: string,
	groupId: string,
	store: Storage | null = storage()
): { enabled: boolean; dismissedFor: number | null } {
	try {
		const v = JSON.parse(store?.getItem(promptKey(userId, groupId)) ?? 'null') as {
			enabled?: unknown;
			dismissedFor?: unknown;
		} | null;
		return {
			enabled: v?.enabled === true,
			dismissedFor: typeof v?.dismissedFor === 'number' ? v.dismissedFor : null
		};
	} catch {
		return { enabled: false, dismissedFor: null };
	}
}

export function savePromptSetting(
	userId: string,
	groupId: string,
	v: { enabled: boolean; dismissedFor: number | null },
	store: Storage | null = storage()
) {
	try {
		store?.setItem(promptKey(userId, groupId), JSON.stringify(v));
	} catch {
		// Storage is off: the choice isn't remembered.
	}
}
