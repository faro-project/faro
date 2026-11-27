// Composing and reading check-ins and replies. Run with `npm test`.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { b64, unb64 } from './crypto/bytes.ts';
import { groupMessageSigningBytes } from './crypto/group.ts';
import { encPublicKey, signPublicKey } from './crypto/keys.ts';
import { signWith } from './crypto/proto.ts';
import {
	NOT_IN_ROSTER,
	checkInErrorMessage,
	checkInPromptDue,
	composeCheckIn,
	composeGroupCheckIn,
	composeReply,
	loadPromptSetting,
	readPost,
	savePromptSetting,
	scaleLabel,
	type PostView
} from './check-in.ts';
import type { RosterState } from './crypto/roster.ts';
import {
	checkRecipients,
	composeGroupReachOut,
	readMessage,
	type CheckedRecipients,
	type Recipients
} from './reach-out.ts';

const V = JSON.parse(
	readFileSync(
		join(import.meta.dirname, '../../../crates/faro-crypto/tests/data/web-vectors.json'),
		'utf8'
	)
);
const K = V.keys;
const ids = V.ids;
const GROUP = 'fedcba9876543210fedcba9876543210';

const member = {
	userId: ids.member,
	signSeed: unb64(K.member_sign_seed),
	signPk: unb64(K.member_sign_pubkey),
	encSecret: unb64(K.member_enc_secret),
	encPk: unb64(K.member_enc_pubkey)
};
const allyA = {
	userId: ids.ally_a,
	encSecret: unb64(K.ally_a_secret),
	encPk: unb64(K.ally_a_pubkey)
};
const allyB = {
	userId: ids.ally_b,
	encSecret: unb64(K.ally_b_secret),
	encPk: unb64(K.ally_b_pubkey)
};

const person = (id: string, name: string, pk: string | null) => ({
	user_id: id,
	display_name: name,
	enc_pubkey: pk,
	key_id: null,
	source: pk ? ('ally_key' as const) : null,
	sender_ally: true
});
const served: Recipients = {
	instance_id: ids.instance,
	can_sign: true,
	recipients: [
		person(ids.ally_b, 'Bea', K.ally_b_pubkey),
		person(ids.ally_a, 'Al', K.ally_a_pubkey)
	]
};
/** The group's roster as the readers' browsers verified it. */
const ROSTER: RosterState = {
	instance_id: ids.instance,
	group_id: GROUP,
	next_seq: 1,
	head: 'b3:' + '0'.repeat(64),
	epoch: 3,
	epoch_key_check: 'b3:' + '0'.repeat(64),
	members: {
		[ids.member]: {
			user_id: ids.member,
			role: 'facilitator',
			enc_pubkey: K.member_enc_pubkey,
			sign_pubkey: K.member_sign_pubkey
		},
		[ids.ally_a]: {
			user_id: ids.ally_a,
			role: 'participant',
			enc_pubkey: K.ally_a_pubkey,
			sign_pubkey: null
		},
		[ids.ally_b]: {
			user_id: ids.ally_b,
			role: 'participant',
			enc_pubkey: K.ally_b_pubkey,
			sign_pubkey: null
		}
	},
	epoch_checks: {}
};
/** The author's own allies, from their signed manifest. */
const MY_ALLIES = [
	{ ally_id: ids.ally_a, enc_pubkey: K.ally_a_pubkey },
	{ ally_id: ids.ally_b, enc_pubkey: K.ally_b_pubkey }
];
const recipients = checkRecipients(
	served,
	ids.member,
	GROUP,
	{ audience: 'allies' },
	{ allies: MY_ALLIES, roster: ROSTER }
);
const author = { user_id: ids.member, display_name: 'Sam', sign_pubkey: K.member_sign_pubkey };
const epochKey = new Uint8Array(32).fill(0x42);
const CHECK_IN = { scale: 4 as const, went_well: 'Three good days ✓', ask: 'A call' };

function asView(s: ReturnType<typeof composeCheckIn>): PostView {
	return {
		...s,
		id: s.message.item_id,
		kind: s.message.kind,
		author,
		parent_id: s.message.parent_id ?? null,
		epoch: s.message.epoch ?? null,
		created_at_ms: 1
	};
}

test('a check-in to named people reads for each recipient and the author', () => {
	const v = asView(composeCheckIn(member, recipients, GROUP, CHECK_IN));
	for (const [me, keys] of [
		[ids.ally_a, { ally: allyA }],
		[ids.ally_b, { ally: allyB }],
		[ids.member, { member }]
	] as const) {
		const r = readPost(v, me, keys, ids.instance, GROUP, ROSTER);
		assert.equal(r.status, 'ok', me);
		assert.deepEqual(r.checkIn, CHECK_IN);
	}
	assert.equal(readPost(v, ids.ally_a, {}, ids.instance, GROUP, ROSTER).status, 'locked');
	// Someone it isn't addressed to, another group, another instance, a bad body.
	assert.equal(
		readPost(v, 'usr_stranger', { ally: allyA }, ids.instance, GROUP, ROSTER).status,
		'invalid'
	);
	assert.equal(
		readPost(v, ids.ally_a, { ally: allyA }, ids.instance, '0'.repeat(32), ROSTER).status,
		'invalid'
	);
	assert.equal(
		readPost(v, ids.ally_a, { ally: allyA }, 'inst_other', GROUP, ROSTER).status,
		'invalid'
	);
	const other = asView(composeCheckIn(member, recipients, GROUP, { scale: 1 }));
	assert.equal(
		readPost({ ...v, body: other.body }, ids.ally_a, { ally: allyA }, ids.instance, GROUP, ROSTER)
			.status,
		'invalid'
	);
	// Forged by someone else's key.
	const { sig: _sig, ...header } = v.message;
	const forged = {
		...v,
		message: signWith(new Uint8Array(32).fill(9), header, groupMessageSigningBytes)
	};
	assert.equal(
		readPost(forged, ids.ally_a, { ally: allyA }, ids.instance, GROUP, ROSTER).status,
		'invalid'
	);
	// A check-in can't be passed off as a reach out, or the reverse.
	assert.equal(
		readMessage(v, ids.ally_a, { ally: allyA }, ids.instance, null, GROUP).status,
		'unreadable'
	);
});

test('a whole-group check-in opens with the epoch key of its epoch only', () => {
	const v = asView(composeGroupCheckIn(member, ids.instance, GROUP, 3, epochKey, CHECK_IN));
	assert.deepEqual(v.message.recipients, []);
	// Anyone in the group, with the key.
	for (const me of [ids.ally_a, ids.ally_b, ids.member]) {
		const r = readPost(v, me, { epochKey }, ids.instance, GROUP, ROSTER);
		assert.equal(r.status, 'ok');
		assert.deepEqual(r.checkIn, CHECK_IN);
	}
	assert.equal(readPost(v, ids.ally_a, {}, ids.instance, GROUP, ROSTER).status, 'locked');
	assert.equal(
		readPost(v, ids.ally_a, { epochKey: new Uint8Array(32).fill(1) }, ids.instance, GROUP, ROSTER)
			.status,
		'unreadable'
	);
	// The server files it under another epoch, group, or kind.
	assert.equal(
		readPost({ ...v, epoch: 4 }, ids.ally_a, { epochKey }, ids.instance, GROUP, ROSTER).status,
		'invalid'
	);
	assert.equal(
		readPost({ ...v, epoch: null }, ids.ally_a, { epochKey }, ids.instance, GROUP, ROSTER).status,
		'invalid'
	);
	assert.equal(
		readPost(v, ids.ally_a, { epochKey }, ids.instance, '0'.repeat(32), ROSTER).status,
		'invalid'
	);
	// Re-epoched or moved: the signature or the key wrapping fails.
	const moved = { ...v, epoch: 4, message: { ...v.message, epoch: 4 } };
	assert.equal(
		readPost(moved, ids.ally_a, { epochKey }, ids.instance, GROUP, ROSTER).status,
		'invalid'
	);
});

test('a whole-group reach out reads through readMessage with the epoch key', () => {
	const s = composeGroupReachOut(member, ids.instance, GROUP, 2, epochKey, 'Rough night');
	const v = {
		...s,
		id: s.message.item_id,
		kind: s.message.kind,
		author,
		created_at_ms: 1
	};
	assert.equal(
		readMessage(v, ids.ally_a, { epochKey }, ids.instance, null, GROUP).text,
		'Rough night'
	);
	assert.equal(readMessage(v, ids.ally_a, {}, ids.instance).status, 'locked');
	assert.throws(() => composeGroupReachOut(member, ids.instance, GROUP, 2, epochKey, '  '));
});

test('a reply is bound to its check-in, and private to its author', () => {
	const parent = 'aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb';
	const to: CheckedRecipients = { ...recipients, recipients: [recipients.recipients[1]] };
	const v = asView(composeReply(member, to, GROUP, parent, 'Proud of you'));
	const r = readPost(v, ids.ally_a, { ally: allyA }, ids.instance, GROUP, ROSTER);
	assert.equal(r.status, 'ok');
	assert.equal(r.text, 'Proud of you');
	assert.equal(
		readPost(v, ids.ally_b, { ally: allyB }, ids.instance, GROUP, ROSTER).status,
		'invalid'
	);
	// The server files it under another check-in.
	assert.equal(
		readPost(
			{ ...v, parent_id: 'cccccccccccccccccccccccccccccccc' },
			ids.ally_a,
			{ ally: allyA },
			ids.instance,
			GROUP,
			ROSTER
		).status,
		'invalid'
	);
	assert.equal(
		readPost({ ...v, parent_id: null }, ids.ally_a, { ally: allyA }, ids.instance, GROUP, ROSTER)
			.status,
		'invalid'
	);
	// And the signature covers the parent.
	const moved = { ...v, message: { ...v.message, parent_id: 'cccccccccccccccccccccccccccccccc' } };
	assert.equal(
		readPost(
			{ ...moved, parent_id: 'cccccccccccccccccccccccccccccccc' },
			ids.ally_a,
			{ ally: allyA },
			ids.instance,
			GROUP,
			ROSTER
		).status,
		'invalid'
	);
	assert.throws(
		() => composeReply(member, recipients, GROUP, parent, 'two people'),
		/no keys|reply/i
	);
	assert.throws(() => composeReply(member, to, GROUP, parent, ' '), /characters/);
});

test('composing checks the answers and the people', () => {
	assert.throws(() => composeCheckIn(member, recipients, GROUP, { scale: 7 as 1 }), /scale/);
	assert.throws(() => composeCheckIn(member, recipients, GROUP, { scale: 3, ask: ' ' }));
	assert.throws(
		() =>
			composeCheckIn(
				member,
				{ ...recipients, recipients: [{ ...person('usr_x', 'X', null), trust: null }] },
				GROUP,
				{ scale: 3 }
			),
		/Nobody/
	);
});

test('a hostile recipient list for a check-in or a reply is refused', () => {
	const serverKey = b64(encPublicKey(new Uint8Array(32).fill(7)));
	const t = { allies: MY_ALLIES, roster: ROSTER };
	// "My allies in this group", plus the instance's own key.
	assert.throws(
		() =>
			checkRecipients(
				{ ...served, recipients: [...served.recipients, person('usr_spy', 'Spy', serverKey)] },
				ids.member,
				GROUP,
				{ audience: 'allies' },
				t
			),
		/Spy, who isn't someone you chose/
	);
	// An ally's key swapped, with sender_ally set.
	assert.throws(
		() =>
			checkRecipients(
				{ ...served, recipients: [person(ids.ally_a, 'Al', serverKey)] },
				ids.member,
				GROUP,
				{ audience: 'allies' },
				t
			),
		/ally list/
	);
	// The facilitators: only the roster's.
	assert.throws(
		() =>
			checkRecipients(
				{ ...served, recipients: [person(ids.ally_a, 'Al', K.ally_a_pubkey)] },
				ids.member,
				GROUP,
				{ audience: 'facilitators' },
				t
			),
		/isn't someone you chose/
	);
	// A reply: the check-in's author alone, with their roster key.
	const author = { ...person(ids.ally_a, 'Al', serverKey), sender_ally: false };
	const reply = (r: typeof author) =>
		checkRecipients(
			{ ...served, recipients: [r] },
			ids.member,
			GROUP,
			{ audience: 'people', userIds: [ids.ally_a] },
			{ allies: [], roster: ROSTER }
		);
	assert.throws(() => reply(author), /member list/);
	assert.equal(reply({ ...author, enc_pubkey: K.ally_a_pubkey }).recipients[0].trust, 'roster');
	// And a list checked for another group can't be used here.
	const elsewhere = checkRecipients(
		served,
		ids.member,
		null,
		{ audience: 'allies' },
		{ allies: MY_ALLIES, roster: null }
	);
	assert.throws(() => composeCheckIn(member, elsewhere, GROUP, CHECK_IN), /not checked/);
	assert.throws(() => composeReply(member, elsewhere, GROUP, 'a'.repeat(32), 'hi'), /not checked/);
});

test("a post signed with a key that isn't its author's in the roster is refused", () => {
	const v = asView(composeCheckIn(member, recipients, GROUP, CHECK_IN));
	const evilSeed = new Uint8Array(32).fill(9);
	const { sig: _sig, ...header } = v.message;
	const forged: PostView = {
		...v,
		message: signWith(evilSeed, header, groupMessageSigningBytes),
		author: { ...author, sign_pubkey: b64(signPublicKey(evilSeed)) }
	};
	assert.equal(
		readPost(forged, ids.ally_a, { ally: allyA }, ids.instance, GROUP, null).status,
		'ok'
	);
	assert.equal(
		readPost(forged, ids.ally_a, { ally: allyA }, ids.instance, GROUP, ROSTER).status,
		'invalid'
	);
	const without = { ...ROSTER, members: { [ids.ally_a]: ROSTER.members[ids.ally_a] } };
	assert.equal(
		readPost(v, ids.ally_a, { ally: allyA }, ids.instance, GROUP, without).reason,
		NOT_IN_ROSTER
	);
});

test('the prompt a day before a meeting', () => {
	const H = 3600 * 1000;
	const next = 1_000_000 * H;
	assert.equal(checkInPromptDue(next, next - 23 * H, true, null), true);
	assert.equal(checkInPromptDue(next, next - 25 * H, true, null), false, 'too early');
	assert.equal(checkInPromptDue(next, next + 1, true, null), false, 'already started');
	assert.equal(checkInPromptDue(next, next - H, false, null), false, 'switched off');
	assert.equal(checkInPromptDue(null, 0, true, null), false, 'no meeting');
	assert.equal(checkInPromptDue(next, next - H, true, next), false, 'dismissed for this meeting');
	assert.equal(checkInPromptDue(next + 7 * 24 * H, next + 7 * 24 * H - H, true, next), true);
});

test('the prompt setting is kept per person and group, and survives no storage', () => {
	const map = new Map<string, string>();
	const store = {
		getItem: (k: string) => map.get(k) ?? null,
		setItem: (k: string, v: string) => void map.set(k, v)
	} as Storage;
	assert.deepEqual(loadPromptSetting('u', 'g', store), { enabled: false, dismissedFor: null });
	savePromptSetting('u', 'g', { enabled: true, dismissedFor: 5 }, store);
	assert.deepEqual(loadPromptSetting('u', 'g', store), { enabled: true, dismissedFor: 5 });
	assert.deepEqual(loadPromptSetting('u', 'other', store), { enabled: false, dismissedFor: null });
	map.set('faro.checkin-prompt.v1.u.g', 'not json');
	assert.equal(loadPromptSetting('u', 'g', store).enabled, false);
	const broken = {
		getItem: () => {
			throw new Error('off');
		},
		setItem: () => {
			throw new Error('off');
		}
	} as unknown as Storage;
	assert.equal(loadPromptSetting('u', 'g', broken).enabled, false);
	savePromptSetting('u', 'g', { enabled: true, dismissedFor: null }, broken);
});

test('wording', () => {
	assert.equal(scaleLabel(1), 'Struggling');
	assert.match(checkInErrorMessage('posting_paused', 409) ?? '', /Waiting for a facilitator/);
	assert.match(checkInErrorMessage('x', 429) ?? '', /Try again/);
	assert.equal(checkInErrorMessage('unknown', 400), null);
});
