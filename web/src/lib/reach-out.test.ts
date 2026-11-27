// Composing and reading reach outs and notes. Run with `npm test`.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { b64, unb64 } from './crypto/bytes.ts';
import { groupMessageSigningBytes } from './crypto/group.ts';
import { encPublicKey, signPublicKey } from './crypto/keys.ts';
import { signWith } from './crypto/proto.ts';
import type { RosterState } from './crypto/roster.ts';
import { join } from 'node:path';

const VECTORS_PATH = join(
	import.meta.dirname,
	'../../../crates/faro-crypto/tests/data/web-vectors.json'
);
import {
	checkRecipients,
	composeMessage,
	noteLength,
	NOT_IN_ROSTER,
	othersLine,
	readMessage,
	reachOutErrorMessage,
	RecipientError,
	unverifiedLine,
	type CheckedRecipients,
	type Chosen,
	type MessageView,
	type RecipientKey,
	type Recipients,
	type Trusted
} from './reach-out.ts';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const V: any = JSON.parse(readFileSync(VECTORS_PATH, 'utf8'));
const K = V.keys;
const ids = V.ids;

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

const served: Recipients = {
	instance_id: ids.instance,
	can_sign: true,
	recipients: [
		{
			user_id: ids.ally_b,
			display_name: 'Bea',
			enc_pubkey: K.ally_b_pubkey,
			key_id: null,
			source: 'ally_key',
			sender_ally: true
		},
		{
			user_id: ids.ally_a,
			display_name: 'Al',
			enc_pubkey: K.ally_a_pubkey,
			key_id: null,
			source: 'ally_key',
			sender_ally: true
		},
		{
			user_id: 'usr_nokey',
			display_name: 'No key',
			enc_pubkey: null,
			key_id: null,
			source: null,
			sender_ally: false
		}
	]
};

/** The sender's allies, from their own signed recipient manifest. */
const MY_ALLIES = [
	{ ally_id: ids.ally_a, enc_pubkey: K.ally_a_pubkey },
	{ ally_id: ids.ally_b, enc_pubkey: K.ally_b_pubkey }
];
const recipients = checkRecipients(
	served,
	ids.member,
	null,
	{ audience: 'people', userIds: [ids.ally_a, ids.ally_b, 'usr_nokey'] },
	{ allies: MY_ALLIES, roster: null }
);

function view(text: string | null, kind: MessageView['kind'] = 'reach_out'): MessageView {
	const s = composeMessage(member, recipients, kind, null, text);
	return {
		...s,
		id: s.message.item_id,
		kind,
		author: { user_id: ids.member, display_name: 'Sam', sign_pubkey: K.member_sign_pubkey },
		created_at_ms: 1
	};
}

test('a composed message reads for each recipient and the author', () => {
	const v = view('Rough night. Can someone call?');
	assert.deepEqual(
		v.message.recipients.map((r) => r.user_id),
		[ids.ally_a, ids.ally_b],
		'sorted, and only people with keys'
	);
	for (const [me, keys] of [
		[ids.ally_a, { ally: allyA }],
		[ids.ally_b, { ally: allyB }],
		[ids.member, { member }]
	] as const) {
		const r = readMessage(v, me, keys, ids.instance);
		assert.equal(r.status, 'ok', me);
		assert.equal(r.text, 'Rough night. Can someone call?');
	}
	assert.equal(readMessage(v, ids.ally_a, {}).status, 'locked');
	// The page expected someone else to have written it.
	assert.equal(readMessage(v, ids.ally_a, { ally: allyA }, ids.instance, ids.member).status, 'ok');
	assert.equal(
		readMessage(v, ids.ally_a, { ally: allyA }, ids.instance, 'usr_someone_else').status,
		'invalid'
	);
	assert.equal(
		readMessage(v, ids.ally_a, { ally: { ...allyA, encSecret: allyB.encSecret } }).status,
		'unreadable'
	);
	const quiet = view(null);
	assert.equal(quiet.body, null);
	assert.deepEqual(readMessage(quiet, ids.ally_a, {}).status, 'ok');
});

test('forged, wrongly signed or swapped messages are refused', () => {
	const v = view('hello');
	// Signed by another key: what an operator holding only public keys could make.
	const { sig: _sig, ...header } = v.message;
	const forged = {
		...v,
		message: signWith(new Uint8Array(32).fill(9), header, groupMessageSigningBytes)
	};
	assert.equal(readMessage(forged, ids.ally_a, { ally: allyA }).status, 'invalid');
	assert.equal(readMessage(forged, ids.ally_a, { ally: allyA }).text, null);
	// The server hands out another key as the author's.
	const otherKey = { ...v, author: { ...v.author, sign_pubkey: K.device_sign_pubkey } };
	assert.equal(readMessage(otherKey, ids.ally_a, { ally: allyA }).status, 'invalid');
	assert.equal(
		readMessage({ ...v, author: { ...v.author, sign_pubkey: null } }, ids.ally_a, {}).status,
		'invalid'
	);
	// A real message served under another id, author, kind or instance.
	assert.equal(
		readMessage({ ...v, id: 'ffffffffffffffffffffffffffffffff' }, ids.ally_a, { ally: allyA })
			.status,
		'invalid'
	);
	assert.equal(
		readMessage({ ...v, author: { ...v.author, user_id: ids.ally_b } }, ids.ally_a, { ally: allyA })
			.status,
		'invalid'
	);
	assert.equal(
		readMessage({ ...v, kind: 'proposal_note' }, ids.ally_a, { ally: allyA }).status,
		'invalid'
	);
	assert.equal(readMessage(v, ids.ally_a, { ally: allyA }, 'inst_other').status, 'invalid');
	// Someone it isn't addressed to.
	assert.equal(readMessage(v, 'usr_stranger', { ally: allyA }).status, 'invalid');
	// An edited text body.
	const other = view('something else');
	assert.equal(
		readMessage({ ...v, body: other.body }, ids.ally_a, { ally: allyA }).status,
		'invalid'
	);
	assert.ok(signPublicKey(member.signSeed));
});

test('composing needs someone with a key', () => {
	assert.throws(
		() =>
			composeMessage(
				member,
				{ ...recipients, recipients: [recipients.recipients[2]] } as CheckedRecipients,
				'reach_out',
				null,
				'hi'
			),
		/Nobody/
	);
	assert.throws(() => view('x'.repeat(501)), /characters/);
	assert.equal(noteLength('é✓'), 2);
});

test('wording', () => {
	assert.equal(othersLine({ call: 0, here: 0 }), null);
	assert.equal(othersLine({ call: 1, here: 0 }), "Someone answered: 1 person said they'll call.");
	assert.match(
		othersLine({ call: 2, here: 1 }) ?? '',
		/2 people said they'll call, and 1 person is there/
	);
	assert.match(reachOutErrorMessage('rate_limited', 429) ?? '', /3 times an hour/);
	assert.equal(reachOutErrorMessage('unknown', 400), null);
});

// ---- A hostile instance's recipient lists -------------------------------------

const GROUP = 'fedcba9876543210fedcba9876543210';
/** A key whose secret the instance holds. */
const SERVER_KEY = b64(encPublicKey(new Uint8Array(32).fill(7)));
const FAC = 'usr_facilitator';
const STRANGER = 'usr_stranger';

const entry = (
	user_id: string,
	display_name: string,
	enc_pubkey: string | null,
	sender_ally = false
): RecipientKey => ({
	user_id,
	display_name,
	enc_pubkey,
	key_id: null,
	source: enc_pubkey ? 'member_key' : null,
	sender_ally
});
const list = (...people: RecipientKey[]): Recipients => ({
	instance_id: ids.instance,
	can_sign: true,
	recipients: people
});

/** The group's roster as the sender's browser verified it. */
const ROSTER: RosterState = {
	instance_id: ids.instance,
	group_id: GROUP,
	next_seq: 4,
	head: 'b3:' + '1'.repeat(64),
	epoch: 2,
	epoch_key_check: 'b3:' + '2'.repeat(64),
	members: {
		[ids.member]: {
			user_id: ids.member,
			role: 'participant',
			enc_pubkey: K.member_enc_pubkey,
			sign_pubkey: K.member_sign_pubkey
		},
		[ids.ally_a]: {
			user_id: ids.ally_a,
			role: 'participant',
			enc_pubkey: K.ally_a_pubkey,
			sign_pubkey: null
		},
		[FAC]: { user_id: FAC, role: 'facilitator', enc_pubkey: K.ally_b_pubkey, sign_pubkey: null }
	},
	epoch_checks: {}
};
const trusted: Trusted = { allies: MY_ALLIES, roster: ROSTER };
const check = (r: Recipients, groupId: string | null, chosen: Chosen, t: Trusted = trusted) =>
	checkRecipients(r, ids.member, groupId, chosen, t);
const allies: Chosen = { audience: 'allies' };
const facilitators: Chosen = { audience: 'facilitators' };

test('your allies: keys come from your own manifest, not from the server', () => {
	const ok = check(
		list(entry(ids.ally_a, 'Al', K.ally_a_pubkey), entry(ids.ally_b, 'Bea', K.ally_b_pubkey)),
		null,
		allies
	);
	assert.deepEqual(
		ok.recipients.map((p) => [p.trust, p.sender_ally]),
		[
			['ally', true],
			['ally', true]
		],
		'sender_ally is worked out here, whatever the server said'
	);
	assert.equal(unverifiedLine(ok), null);
	// The real allies plus one extra entry holding the instance's own key.
	assert.throws(
		() =>
			check(
				list(
					entry(ids.ally_a, 'Al', K.ally_a_pubkey, true),
					entry(STRANGER, 'Helper', SERVER_KEY, true)
				),
				null,
				allies
			),
		(e: unknown) =>
			e instanceof RecipientError && /Helper, who isn't someone you chose/.test(e.message)
	);
	// A real ally with the key swapped, and sender_ally set to look trusted.
	assert.throws(
		() => check(list(entry(ids.ally_a, 'Al', SERVER_KEY, true)), null, allies),
		/isn't the one in your ally list/
	);
	// A malformed key is never "the same".
	assert.throws(
		() => check(list(entry(ids.ally_a, 'Al', 'not a key', true)), null, allies),
		/ally list/
	);
	// Someone listed twice (with two keys).
	assert.throws(
		() =>
			check(
				list(entry(ids.ally_a, 'Al', K.ally_a_pubkey), entry(ids.ally_a, 'Al', SERVER_KEY)),
				null,
				allies
			),
		/twice/
	);
	// No manifest yet: nobody is your ally.
	assert.throws(
		() =>
			check(list(entry(ids.ally_a, 'Al', K.ally_a_pubkey)), null, allies, {
				allies: [],
				roster: null
			}),
		/isn't someone you chose/
	);
	// People without keys are listed (they are told), but nothing is sealed to them.
	const nokey = check(list(entry(ids.ally_a, 'Al', null)), null, allies);
	assert.equal(nokey.recipients[0].trust, null);
});

test('in a group: keys come from the roster this browser verified', () => {
	const ok = check(list(entry(FAC, 'Fran', K.ally_b_pubkey)), GROUP, facilitators);
	assert.equal(ok.recipients[0].trust, 'roster');
	assert.equal(ok.group_id, GROUP);
	// A participant passed off as a facilitator.
	assert.throws(
		() =>
			check(
				list(entry(FAC, 'Fran', K.ally_b_pubkey), entry(ids.ally_a, 'Al', K.ally_a_pubkey)),
				GROUP,
				facilitators
			),
		/Al, who isn't someone you chose/
	);
	// A facilitator's key swapped for the instance's.
	assert.throws(
		() => check(list(entry(FAC, 'Fran', SERVER_KEY)), GROUP, facilitators),
		/isn't the one in this group's member list/
	);
	// Named people: only the ones you named, each with their roster (or ally) key.
	const named = check(
		list(entry(FAC, 'Fran', K.ally_b_pubkey), entry(ids.ally_a, 'Al', K.ally_a_pubkey)),
		GROUP,
		{ audience: 'people', userIds: [FAC, ids.ally_a] }
	);
	assert.deepEqual(
		named.recipients.map((p) => p.trust),
		['roster', 'ally']
	);
	assert.throws(
		() =>
			check(
				list(entry(FAC, 'Fran', K.ally_b_pubkey), entry(STRANGER, 'Extra', SERVER_KEY)),
				GROUP,
				{ audience: 'people', userIds: [FAC] }
			),
		/Extra, who isn't someone you chose/
	);
	// Someone you named who isn't in the verified roster: in a group, no unchecked key.
	assert.throws(
		() =>
			check(list(entry(STRANGER, 'New', SERVER_KEY)), GROUP, {
				audience: 'people',
				userIds: [STRANGER]
			}),
		/isn't in this group's member list yet/
	);
	// "My allies in this group": your allies who are in the roster.
	assert.throws(
		() => check(list(entry(ids.ally_b, 'Bea', K.ally_b_pubkey)), GROUP, allies),
		/isn't someone you chose/
	);
	assert.equal(
		check(list(entry(ids.ally_a, 'Al', K.ally_a_pubkey)), GROUP, allies).recipients[0].trust,
		'ally'
	);
	// No verified roster, one with no entries, another group's, another instance's.
	const one = list(entry(FAC, 'Fran', K.ally_b_pubkey));
	assert.throws(
		() => check(one, GROUP, facilitators, { allies: MY_ALLIES, roster: null }),
		/signed yet/
	);
	assert.throws(
		() =>
			check(one, GROUP, facilitators, { allies: MY_ALLIES, roster: { ...ROSTER, next_seq: 0 } }),
		/signed yet/
	);
	assert.throws(
		() =>
			check(one, GROUP, facilitators, {
				allies: MY_ALLIES,
				roster: { ...ROSTER, group_id: 'other' }
			}),
		/member list/
	);
	assert.throws(
		() => check({ ...one, instance_id: 'inst_other' }, GROUP, facilitators),
		/member list/
	);
});

test('outside a group, a link who is not your ally is accepted, marked not yet verified', () => {
	const r = check(
		list(entry(STRANGER, 'Jo', K.ally_b_pubkey), entry(ids.ally_a, 'Al', K.ally_a_pubkey)),
		null,
		{ audience: 'people', userIds: [STRANGER, ids.ally_a] }
	);
	assert.deepEqual(
		r.recipients.map((p) => p.trust),
		['unverified', 'ally']
	);
	assert.match(unverifiedLine(r) ?? '', /The key of Jo isn't .*not yet verified/);
	// Never for one of your allies: their key must be the one you signed.
	assert.throws(
		() =>
			check(list(entry(ids.ally_a, 'Al', SERVER_KEY)), null, {
				audience: 'people',
				userIds: [ids.ally_a]
			}),
		/ally list/
	);
	// A join request's note: the facilitators of a group you aren't in yet.
	const jr = check(list(entry(FAC, 'Fran', SERVER_KEY)), GROUP, { audience: 'join_request' });
	assert.equal(jr.recipients[0].trust, 'unverified');
	assert.throws(
		() => check(list(entry(ids.ally_a, 'Al', SERVER_KEY)), GROUP, { audience: 'join_request' }),
		/ally list/
	);
});

test('nothing is sealed to an unchecked list, or to one checked for another group', () => {
	assert.throws(
		() => composeMessage(member, served as unknown as CheckedRecipients, 'reach_out', null, 'hi'),
		RecipientError
	);
	assert.throws(() => composeMessage(member, recipients, 'reach_out', GROUP, 'hi'), RecipientError);
	const fac = check(list(entry(FAC, 'Fran', K.ally_b_pubkey)), GROUP, facilitators);
	const s = composeMessage(member, fac, 'reach_out', GROUP, 'hi');
	assert.deepEqual(
		s.message.recipients.map((p) => [p.user_id, p.enc_pubkey]),
		[[FAC, K.ally_b_pubkey]]
	);
});

test("a group message's signing key must be its author's in the verified roster", () => {
	const to = check(list(entry(ids.ally_a, 'Al', K.ally_a_pubkey)), GROUP, {
		audience: 'people',
		userIds: [ids.ally_a]
	});
	const s = composeMessage(member, to, 'proposal_note', GROUP, 'hello');
	const v: MessageView = {
		...s,
		id: s.message.item_id,
		kind: 'proposal_note',
		author: { user_id: ids.member, display_name: 'Sam', sign_pubkey: K.member_sign_pubkey },
		created_at_ms: 1
	};
	const read = (x: MessageView, roster: RosterState | null) =>
		readMessage(x, ids.ally_a, { ally: allyA }, ids.instance, null, GROUP, roster);
	assert.equal(read(v, ROSTER).status, 'ok');
	assert.equal(read(v, ROSTER).text, 'hello');
	// The instance signs a note in Sam's name with its own key, and serves that key as Sam's.
	const evilSeed = new Uint8Array(32).fill(9);
	const { sig: _sig, ...header } = v.message;
	const forged: MessageView = {
		...v,
		message: signWith(evilSeed, header, groupMessageSigningBytes),
		author: { ...v.author, sign_pubkey: b64(signPublicKey(evilSeed)) }
	};
	assert.equal(
		read(forged, null).status,
		'ok',
		'without the roster, only the served key is checked'
	);
	assert.equal(read(forged, ROSTER).status, 'invalid');
	// An author who isn't in the roster at all.
	const gone = { ...ROSTER, members: { [ids.ally_a]: ROSTER.members[ids.ally_a] } };
	assert.equal(read(v, gone).reason, NOT_IN_ROSTER);
	// A roster with no entries yet has nothing to check against.
	assert.equal(read(v, { ...gone, next_seq: 0 }).status, 'ok');
	// Another group's roster is refused.
	assert.equal(read(v, { ...ROSTER, group_id: 'other' }).status, 'invalid');
	// A join request's note is from someone not in the group yet.
	const jr = composeMessage(
		member,
		check(list(entry(ids.ally_a, 'Al', K.ally_a_pubkey)), GROUP, { audience: 'join_request' }),
		'join_request_note',
		GROUP,
		'let me in'
	);
	const jv: MessageView = { ...v, ...jr, id: jr.message.item_id, kind: 'join_request_note' };
	assert.equal(read(jv, gone).status, 'ok');
});
