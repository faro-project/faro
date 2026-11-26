// Writes the `from_web` section of crates/faro-crypto/tests/data/web-vectors.json:
// secrets wrapped and structures signed by the web app's crypto code, which
// the Rust test `web_vectors` then opens and verifies. Run `npm run vectors`
// after changing web/src/lib/crypto, then `cargo test -p faro-crypto --test web_vectors`.

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { b64, hex, utf8 } from '../src/lib/crypto/bytes.ts';
import { sign, signPublicKey } from '../src/lib/crypto/keys.ts';
import { deriveWrapKey, wrapSecret, wrapWithKey } from '../src/lib/crypto/passphrase.ts';
import {
	allyEndorsementSigningBytes,
	deviceEndorsementSigningBytes,
	keyRewrapSigningBytes,
	manifestRef,
	manifestSigningBytes,
	memberBindingSigningBytes,
	proveAllyKeyRewrap,
	signWith
} from '../src/lib/crypto/proto.ts';
import {
	emptyRoster,
	groupSafetyCode,
	prepareEntries,
	sealEpochKey,
	signSnapshot,
	type RosterChange
} from '../src/lib/crypto/roster.ts';

const path = join(import.meta.dirname, '../../crates/faro-crypto/tests/data/web-vectors.json');
const v = JSON.parse(readFileSync(path, 'utf8'));
const cheap = { m_cost_kib: 256, t_cost: 2, p_cost: 1 };

// A web-app seed, distinct from the Rust vectors' keys.
const seed = new Uint8Array(32).fill(0x66);
const pk = signPublicKey(seed);
const ids = v.ids;
const memberEnc = v.keys.member_enc_pubkey;

const manifest = signWith(
	seed,
	{
		instance_id: ids.instance,
		member_id: ids.member,
		version: 1,
		issued_at_ms: 1_790_000_000_000,
		member_enc_pubkey: memberEnc,
		allies: [{ ally_id: ids.ally_a, enc_pubkey: v.keys.ally_a_pubkey }]
	},
	manifestSigningBytes
);

// An ally key as the web app uploads it: a WrappedSecret with its recovery
// copy alongside (Rust must ignore the extra field).
const allySecret = new Uint8Array(32).fill(0x12);
const allyWrapped = {
	...(await wrapSecret(allySecret, 'ally passphrase', cheap)),
	recovery: await wrapSecret(allySecret, 'ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345-6789', cheap)
};
// Two secrets under one derivation, as member keys are stored.
const k = await deriveWrapKey('member passphrase', cheap);
const s1 = new Uint8Array(32).fill(0x21);
const s2 = new Uint8Array(32).fill(0x31);

const msg = utf8('signed by the web app');
// What an ally's browser opens from the instance's sealed challenge.
const challenge = new Uint8Array(32).fill(0x44);
v.from_web = {
	comment: 'Written by web/scripts/web-vectors.ts (npm run vectors); checked by the Rust test.',
	sign_pubkey: b64(pk),
	msg_hex: hex(msg),
	sig: b64(sign(seed, msg)),
	wrapped: [
		{ passphrase: 'ally passphrase', plaintext_hex: hex(allySecret), wrapped: allyWrapped },
		{
			passphrase: 'ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345-6789',
			plaintext_hex: hex(allySecret),
			wrapped: allyWrapped.recovery
		},
		{ passphrase: 'member passphrase', plaintext_hex: hex(s1), wrapped: wrapWithKey(s1, k) },
		{ passphrase: 'member passphrase', plaintext_hex: hex(s2), wrapped: wrapWithKey(s2, k) }
	],
	manifest,
	device_endorsement: signWith(
		seed,
		{
			instance_id: ids.instance,
			member_id: ids.member,
			device_id: ids.device,
			device_sign_pubkey: v.keys.device_sign_pubkey,
			endorsed_at_ms: 1_790_000_100_000,
			min_manifest: manifestRef(manifest)
		},
		deviceEndorsementSigningBytes
	),
	ally_endorsement: signWith(
		seed,
		{
			instance_id: ids.instance,
			member_id: ids.member,
			ally_id: ids.ally_a,
			ally_enc_pubkey: v.keys.ally_a_pubkey,
			endorsed_at_ms: 1_790_000_200_000
		},
		allyEndorsementSigningBytes
	),
	member_binding: signWith(
		seed,
		{
			instance_id: ids.instance,
			member_id: ids.member,
			member_enc_pubkey: memberEnc,
			endorsed_at_ms: 1_790_000_000_000
		},
		memberBindingSigningBytes
	),
	key_rewrap: signWith(
		seed,
		{
			instance_id: ids.instance,
			member_id: ids.member,
			sign_pubkey: b64(pk),
			issued_at_ms: 1_790_000_300_000,
			wrapped_sign_key: JSON.stringify(allyWrapped),
			wrapped_enc_key: '{"v":1}',
			recovery_wrapped: '{"sign":{},"enc":{}}'
		},
		keyRewrapSigningBytes
	),
	ally_key_rewrap: {
		challenge_hex: hex(challenge),
		proven: proveAllyKeyRewrap(
			{
				instance_id: ids.instance,
				ally_id: ids.ally_a,
				enc_pubkey: v.keys.ally_a_pubkey,
				issued_at_ms: 1_790_000_400_000,
				wrapped_privkey: JSON.stringify(allyWrapped)
			},
			challenge
		)
	}
};
// A roster log signed by the web app: its creator (the web seed) and ally A
// join, then ally B joins and ally A leaves, then a pure rotation; its
// snapshot; and the last epoch key sealed to ally A.
const webGroup = 'web-group-01';
let roster = emptyRoster(ids.instance, webGroup);
const steps: RosterChange[][] = [
	[
		{
			kind: 'join',
			user_id: ids.ally_a,
			role: 'participant',
			enc_pubkey: v.keys.ally_a_pubkey,
			sign_pubkey: null
		},
		{
			kind: 'join',
			user_id: 'usr_web01',
			role: 'facilitator',
			enc_pubkey: memberEnc,
			sign_pubkey: b64(pk)
		}
	],
	[
		{ kind: 'leave', user_id: ids.ally_a },
		{
			kind: 'join',
			user_id: ids.ally_b,
			role: 'participant',
			enc_pubkey: v.keys.ally_b_pubkey,
			sign_pubkey: null
		}
	],
	[]
];
const rosterEntries = [];
let lastKey: Uint8Array | null = null;
for (const [i, changes] of steps.entries()) {
	const r = prepareEntries(roster, changes, 'usr_web01', seed, {
		now: 1_790_000_700_000 + i,
		rotate: true
	});
	roster = r.state;
	for (const e of r.entries) {
		rosterEntries.push(e.entry);
		lastKey = e.epochKey;
	}
}
// Ally A left, so seal the last key to them by hand: the vector only needs
// a box Rust can open.
const sealedForA = sealEpochKey(lastKey!, [
	{ user_id: ids.ally_a, role: 'participant', enc_pubkey: v.keys.ally_a_pubkey, sign_pubkey: null }
])[0].sealed_key;
v.from_web.roster = {
	group_id: webGroup,
	entries: rosterEntries,
	snapshot: signSnapshot(roster, 'usr_web01', seed, 1_790_000_800_000),
	epoch_key_hex: hex(lastKey!),
	sealed_epoch_key: sealedForA,
	safety_code: groupSafetyCode(ids.instance, webGroup, {
		seq: roster.next_seq - 1,
		hash: roster.head
	})
};

writeFileSync(path, JSON.stringify(v, null, 2) + '\n');
console.log(`wrote from_web to ${path}`);
