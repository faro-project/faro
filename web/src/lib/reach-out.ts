// Reach out and signed notes (docs/GROUPS.md §8.3, §10.2): the API's
// shapes, wording, and the two crypto steps the pages need, composing a
// message and reading one. Kept free of the DOM and Svelte so `npm test`
// can cover it; the requests are in `reach-out-api.ts`.
//
// Reading is strict: a message is shown only if its structure, its body and
// the author's signature all check out, and it is the message the server
// says it is. Anything else is refused without showing a word of it. A
// valid signature proves the author's key wrote it; whether that key is
// really the author's is what the safety code tells an ally (`verified`).

import { unb64Fixed } from './crypto/bytes.ts';
import {
	messageText,
	newItemId,
	openGroupMessageBytes,
	openGroupMessageWithEpoch,
	sealGroupMessage,
	sealGroupMessageToEpoch,
	verifyGroupMessage,
	type GroupMessageKind,
	type SealedGroupMessage
} from './crypto/group.ts';
import { verification, type Verification } from './keys/verified.ts';
import type { AllyKey, MemberKeys } from './keys/keyring.svelte.ts';

export const MAX_NOTE_CHARS = 500;
export const MAX_NAMED = 32;

export type Audience = 'allies' | 'facilitators' | 'people' | 'group';
export type Answer = 'call' | 'here';
export type ReachOutMode = 'immediate' | 'digest' | 'off';

/** `GET /v1/me/message-recipients`: one person to seal to. */
export interface RecipientKey {
	user_id: string;
	display_name: string;
	/** null: they have no keys yet, so they can't read a message. */
	enc_pubkey: string | null;
	key_id: string | null;
	source: 'ally_key' | 'member_key' | null;
	/** Your active ally: the key is in your own signed manifest. */
	sender_ally: boolean;
}

export interface Recipients {
	instance_id: string;
	recipients: RecipientKey[];
	/** You have member keys, so you can sign a message. */
	can_sign: boolean;
}

export interface PersonRef {
	user_id: string;
	display_name: string;
}

export interface IncomingReachOut {
	id: string;
	from: PersonRef;
	group_id: string | null;
	group_name: string | null;
	audience: Audience;
	created_at_ms: number;
	/** false: "Sent through the server. Can't be verified." */
	signed: boolean;
	message_id: string | null;
	my_answer: Answer | null;
	my_answered_at_ms: number | null;
	others_answered: { call: number; here: number };
	quiet_hours_bypass: boolean;
}

export interface ReachOutRecipient {
	user_id: string;
	display_name: string;
	answer: Answer | null;
	answered_at_ms: number | null;
}

export interface OutgoingReachOut {
	id: string;
	group_id: string | null;
	group_name: string | null;
	audience: Audience;
	created_at_ms: number;
	signed: boolean;
	message_id: string | null;
	recipients: ReachOutRecipient[];
}

export interface MyReachOuts {
	incoming: IncomingReachOut[];
	outgoing: OutgoingReachOut[];
}

/** `GET /v1/group-messages/{id}`. */
export interface MessageView extends SealedGroupMessage {
	/** Set for a whole-group message (check-ins, group reach outs). */
	epoch?: number | null;
	parent_id?: string | null;
	id: string;
	kind: GroupMessageKind;
	author: { user_id: string; display_name: string; sign_pubkey: string | null };
	created_at_ms: number;
}

/** `GET /v1/me/reach-out-settings`. */
export interface SenderSetting {
	user_id: string;
	display_name: string;
	mode: ReachOutMode;
	quiet_hours_bypass: boolean;
}

/** `POST /v1/me/reach-outs` body. */
export interface CreateReachOut {
	audience: Audience;
	group_id?: string | null;
	user_ids?: string[];
	message?: SealedGroupMessage;
}

// ---- Composing ---------------------------------------------------------------

/** Characters as the server counts them (Unicode scalar values). */
export function noteLength(text: string): number {
	return [...text].length;
}

/** The people in `r` who can read a message (they have a key). */
export function sealable(r: Recipients): RecipientKey[] {
	return r.recipients.filter((p) => p.enc_pubkey);
}

/**
 * Seal and sign a message (or, with `text` null, a signed content-free
 * reach out) to everyone in `recipients` who has a key, and to yourself.
 */
export function composeMessage(
	keys: Pick<MemberKeys, 'userId' | 'signSeed' | 'encPk'>,
	recipients: Recipients,
	kind: GroupMessageKind,
	groupId: string | null,
	text: string | null,
	now = Date.now()
): SealedGroupMessage {
	const to = sealable(recipients).filter((p) => p.user_id !== keys.userId);
	if (to.length === 0) throw new Error('Nobody you chose can read a message yet.');
	return sealGroupMessage(
		keys.signSeed,
		keys.encPk,
		{
			instance_id: recipients.instance_id,
			group_id: groupId,
			item_id: newItemId(),
			kind,
			author_id: keys.userId,
			issued_at_ms: now,
			recipients: to.map((p) => ({ user_id: p.user_id, enc_pubkey: p.enc_pubkey! }))
		},
		text
	);
}

/**
 * Seal and sign a reach out to the whole group with its current epoch key
 * (groups of 32 or fewer). It names nobody: whoever is in the group reads it.
 */
export function composeGroupReachOut(
	keys: Pick<MemberKeys, 'userId' | 'signSeed'>,
	instanceId: string,
	groupId: string,
	epoch: number,
	epochKey: Uint8Array,
	text: string | null,
	now = Date.now()
): SealedGroupMessage {
	if (text !== null && (!text.trim() || noteLength(text) > MAX_NOTE_CHARS)) {
		throw new Error(`A message is 1 to ${MAX_NOTE_CHARS} characters.`);
	}
	return sealGroupMessageToEpoch(
		keys.signSeed,
		epochKey,
		{
			instance_id: instanceId,
			group_id: groupId,
			item_id: newItemId(),
			kind: 'reach_out',
			author_id: keys.userId,
			issued_at_ms: now,
			recipients: [],
			epoch
		},
		text === null ? null : new TextEncoder().encode(JSON.stringify({ text }))
	);
}

// ---- Reading -------------------------------------------------------------------

export interface ReadResult {
	/**
	 * `ok`: checked (and opened, if it has text). `invalid`: it doesn't
	 * check out and isn't shown. `locked`: unlock your keys to read it.
	 * `unreadable`: it checks out but none of your keys opens it.
	 */
	status: 'ok' | 'invalid' | 'locked' | 'unreadable';
	text: string | null;
	/** Whether you compared safety codes with the author's key. */
	verified: Verification;
	/** Why it was refused, for the console. */
	reason?: string;
}

/** What is unlocked: your keys, and for a whole-group message the key of its epoch. */
export interface ReadKeys {
	member?: MemberKeys | null;
	ally?: AllyKey | null;
	/** The group key of the message's epoch (`currentEpochKey`), once opened. */
	epochKey?: Uint8Array | null;
}

export interface ReadBytes {
	status: ReadResult['status'];
	bytes: Uint8Array | null;
	verified: Verification;
	reason?: string;
}

/**
 * Check a served message and open its body as `me`, without parsing it:
 * the shared core of reach outs, notes, check-ins and replies. `instanceId`,
 * when known, must be the one it names; `groupId`, when known, the group.
 * A whole-group message (`epoch` set) is for anyone in the group, and opens
 * with `keys.epochKey`; without it the result is `locked`.
 */
export function readSealed(
	view: MessageView,
	me: string,
	keys: ReadKeys,
	instanceId?: string | null,
	/** Who the page says wrote it (the reach out's sender, the proposer). */
	expectedAuthor?: string | null,
	groupId?: string | null
): ReadBytes {
	const refuse = (reason: string): ReadBytes => ({
		status: 'invalid',
		bytes: null,
		verified: 'unverified',
		reason
	});
	const m = view?.message;
	if (!m || !view.author) return refuse('no message');
	if (!view.author.sign_pubkey) return refuse('the author has no signing key');
	let pk: Uint8Array;
	try {
		pk = unb64Fixed(view.author.sign_pubkey, 32);
	} catch {
		return refuse('malformed signing key');
	}
	const bad = verifyGroupMessage(pk, { message: m, body: view.body ?? null });
	if (bad) return refuse(bad);
	if (m.item_id !== view.id) return refuse('it is not the message asked for');
	if (m.author_id !== view.author.user_id) return refuse('it names another author');
	if (expectedAuthor && m.author_id !== expectedAuthor) return refuse('it is from someone else');
	if (m.kind !== view.kind) return refuse('it is another kind of message');
	if (instanceId && m.instance_id !== instanceId) return refuse('it is for another instance');
	if (groupId && m.group_id !== groupId) return refuse('it is for another group');
	const wholeGroup = m.epoch != null;
	if (!wholeGroup && m.author_id !== me && !m.recipients.some((r) => r.user_id === me)) {
		return refuse('it is not addressed to you');
	}
	const verified = verification(me, m.author_id, view.author.sign_pubkey);
	if (!view.body) return { status: 'ok', bytes: null, verified };
	const sealed = { message: m, body: view.body };
	if (wholeGroup) {
		if (!keys.epochKey) return { status: 'locked', bytes: null, verified };
		try {
			return { status: 'ok', bytes: openGroupMessageWithEpoch(sealed, keys.epochKey), verified };
		} catch {
			return { status: 'unreadable', bytes: null, verified };
		}
	}
	const secrets = [keys.member, keys.ally]
		.filter((k): k is MemberKeys | AllyKey => !!k && k.userId === me)
		.map((k) => k.encSecret);
	if (secrets.length === 0) return { status: 'locked', bytes: null, verified };
	for (const s of secrets) {
		try {
			return { status: 'ok', bytes: openGroupMessageBytes(sealed, me, s), verified };
		} catch {
			// Not this key (a DecryptError): try the next.
		}
	}
	return { status: 'unreadable', bytes: null, verified };
}

/** [`readSealed`] for a body that is a text (reach outs and notes). */
export function readMessage(
	view: MessageView,
	me: string,
	keys: ReadKeys,
	instanceId?: string | null,
	expectedAuthor?: string | null,
	groupId?: string | null
): ReadResult {
	const r = readSealed(view, me, keys, instanceId, expectedAuthor, groupId);
	if (r.status !== 'ok') {
		return { status: r.status, text: null, verified: r.verified, reason: r.reason };
	}
	try {
		return { status: 'ok', text: r.bytes ? messageText(r.bytes) : null, verified: r.verified };
	} catch {
		return { status: 'unreadable', text: null, verified: r.verified };
	}
}

// ---- Wording -------------------------------------------------------------------

export const UNVERIFIED_LINE = "Sent through the server. Can't be verified.";

/** "Jo and 2 others said they'll call." for the people a reach out went to. */
export function othersLine(counts: { call: number; here: number }): string | null {
	const parts: string[] = [];
	if (counts.call) {
		parts.push(
			`${counts.call} ${counts.call === 1 ? 'person said they' : 'people said they'}'ll call`
		);
	}
	if (counts.here) {
		parts.push(`${counts.here} ${counts.here === 1 ? 'person is' : 'people are'} there for them`);
	}
	return parts.length ? `Someone answered: ${parts.join(', and ')}.` : null;
}

export function answerLabel(a: Answer): string {
	return a === 'call' ? "I'll call" : "I'm here";
}

const MESSAGES: Record<string, string> = {
	no_recipients: 'There is nobody to send this to yet. Choose other people.',
	too_many_recipients: `A reach out can go to at most ${MAX_NAMED} people.`,
	invalid_recipients: `Choose 1 to ${MAX_NAMED} people.`,
	cannot_reach_self: "You can't reach out to yourself.",
	member_keys_required: 'Signing a message needs your keys. You can set them up under "Your keys".',
	bad_signature: "The message couldn't be signed with your key. Unlock your keys and try again.",
	stale_recipient_key: "Someone's key changed. Try again.",
	clock_skew: "Your computer's clock seems to be off. Check it and try again.",
	invalid_message: "The message couldn't be sent as written. Try again.",
	message_exists: 'That message was already sent.',
	group_archived: 'This group was closed.',
	group_too_large:
		'A reach out to the whole group is only for groups of 32 people or fewer. Choose your allies, the facilitators or people by name.',
	posting_paused: 'Waiting for a facilitator to update the group. Choose people by name for now.',
	group_key_missing:
		"This group's encryption isn't set up yet. A facilitator's browser does it when they open the group.",
	stale_epoch: "The group's key changed while you were writing. Try again."
};

/** A sentence for a reach-out API error, or null when there is no special wording. */
export function reachOutErrorMessage(code: string, status: number): string | null {
	if (status === 429) return 'You can reach out 3 times an hour. Try again a little later.';
	return MESSAGES[code] ?? null;
}
