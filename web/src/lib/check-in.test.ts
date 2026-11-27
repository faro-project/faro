// Composing and reading check-ins and replies. Run with `npm test`.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { unb64 } from './crypto/bytes.ts';
import { groupMessageSigningBytes } from './crypto/group.ts';
import { signWith } from './crypto/proto.ts';
import {
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
import { composeGroupReachOut, readMessage, type Recipients } from './reach-out.ts';

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
const recipients: Recipients = {
	instance_id: ids.instance,
	can_sign: true,
	recipients: [
		person(ids.ally_b, 'Bea', K.ally_b_pubkey),
		person(ids.ally_a, 'Al', K.ally_a_pubkey)
	]
};
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
		const r = readPost(v, me, keys, ids.instance, GROUP);
		assert.equal(r.status, 'ok', me);
		assert.deepEqual(r.checkIn, CHECK_IN);
	}
	assert.equal(readPost(v, ids.ally_a, {}, ids.instance, GROUP).status, 'locked');
	// Someone it isn't addressed to, another group, another instance, a bad body.
	assert.equal(readPost(v, 'usr_stranger', { ally: allyA }, ids.instance, GROUP).status, 'invalid');
	assert.equal(
		readPost(v, ids.ally_a, { ally: allyA }, ids.instance, '0'.repeat(32)).status,
		'invalid'
	);
	assert.equal(readPost(v, ids.ally_a, { ally: allyA }, 'inst_other', GROUP).status, 'invalid');
	const other = asView(composeCheckIn(member, recipients, GROUP, { scale: 1 }));
	assert.equal(
		readPost({ ...v, body: other.body }, ids.ally_a, { ally: allyA }, ids.instance, GROUP).status,
		'invalid'
	);
	// Forged by someone else's key.
	const { sig: _sig, ...header } = v.message;
	const forged = {
		...v,
		message: signWith(new Uint8Array(32).fill(9), header, groupMessageSigningBytes)
	};
	assert.equal(
		readPost(forged, ids.ally_a, { ally: allyA }, ids.instance, GROUP).status,
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
		const r = readPost(v, me, { epochKey }, ids.instance, GROUP);
		assert.equal(r.status, 'ok');
		assert.deepEqual(r.checkIn, CHECK_IN);
	}
	assert.equal(readPost(v, ids.ally_a, {}, ids.instance, GROUP).status, 'locked');
	assert.equal(
		readPost(v, ids.ally_a, { epochKey: new Uint8Array(32).fill(1) }, ids.instance, GROUP).status,
		'unreadable'
	);
	// The server files it under another epoch, group, or kind.
	assert.equal(
		readPost({ ...v, epoch: 4 }, ids.ally_a, { epochKey }, ids.instance, GROUP).status,
		'invalid'
	);
	assert.equal(
		readPost({ ...v, epoch: null }, ids.ally_a, { epochKey }, ids.instance, GROUP).status,
		'invalid'
	);
	assert.equal(
		readPost(v, ids.ally_a, { epochKey }, ids.instance, '0'.repeat(32)).status,
		'invalid'
	);
	// Re-epoched or moved: the signature or the key wrapping fails.
	const moved = { ...v, epoch: 4, message: { ...v.message, epoch: 4 } };
	assert.equal(readPost(moved, ids.ally_a, { epochKey }, ids.instance, GROUP).status, 'invalid');
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
	const to: Recipients = { ...recipients, recipients: [recipients.recipients[1]] };
	const v = asView(composeReply(member, to, GROUP, parent, 'Proud of you'));
	const r = readPost(v, ids.ally_a, { ally: allyA }, ids.instance, GROUP);
	assert.equal(r.status, 'ok');
	assert.equal(r.text, 'Proud of you');
	assert.equal(readPost(v, ids.ally_b, { ally: allyB }, ids.instance, GROUP).status, 'invalid');
	// The server files it under another check-in.
	assert.equal(
		readPost(
			{ ...v, parent_id: 'cccccccccccccccccccccccccccccccc' },
			ids.ally_a,
			{ ally: allyA },
			ids.instance,
			GROUP
		).status,
		'invalid'
	);
	assert.equal(
		readPost({ ...v, parent_id: null }, ids.ally_a, { ally: allyA }, ids.instance, GROUP).status,
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
			GROUP
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
			composeCheckIn(member, { ...recipients, recipients: [person('usr_x', 'X', null)] }, GROUP, {
				scale: 3
			}),
		/Nobody/
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
