// Composing and reading reach outs and notes. Run with `npm test`.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { unb64 } from './crypto/bytes.ts';
import { groupMessageSigningBytes } from './crypto/group.ts';
import { signPublicKey } from './crypto/keys.ts';
import { signWith } from './crypto/proto.ts';
import { join } from 'node:path';

const VECTORS_PATH = join(
	import.meta.dirname,
	'../../../crates/faro-crypto/tests/data/web-vectors.json'
);
import {
	composeMessage,
	noteLength,
	othersLine,
	readMessage,
	reachOutErrorMessage,
	type MessageView,
	type Recipients
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

const recipients: Recipients = {
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

function view(text: string | null, kind: MessageView['kind'] = 'reach_out'): MessageView {
	const s = composeMessage(member, recipients, kind, 'fedcba9876543210fedcba9876543210', text);
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
				{ ...recipients, recipients: [recipients.recipients[2]] },
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
