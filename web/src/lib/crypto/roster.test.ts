// The roster log port against the Rust vectors, and the client rules
// (GROUPS.md §19, Phase C): fork, rollback, a forged signature, a signer who
// wasn't a facilitator, a withheld entry, rotation on join and leave, and
// the time to rotate the epoch for 1,000 participants.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join as joinPath } from 'node:path';
import { test } from 'node:test';
import { b64, hex, unb64, unhex } from './bytes.ts';
import { encPublicKey, newEncryptionSecret, signPublicKey } from './keys.ts';
import type { Signed } from './proto.ts';
import {
	applyEntry,
	checkHead,
	checkpointOf,
	cloneRoster,
	emptyRoster,
	epochKeyCheck,
	genesisPrevHash,
	groupSafetyCode,
	listsKeys,
	openEpochKey,
	prepareEntries,
	RosterError,
	rosterEntryHash,
	rosterEntrySigningBytes,
	sealEpochKey,
	signSnapshot,
	snapshotSigningBytes,
	sortedMembers,
	stateFromSnapshot,
	validateRosterEntry,
	type RosterChange,
	type RosterEntry,
	type RosterSnapshot,
	type RosterState
} from './roster.ts';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const V: any = JSON.parse(
	readFileSync(
		joinPath(import.meta.dirname, '../../../../crates/faro-crypto/tests/data/web-vectors.json'),
		'utf8'
	)
);
const K = V.keys;
const R = V.roster;

function replay(entries: Signed<RosterEntry>[], from?: RosterState): RosterState {
	const s = from ? cloneRoster(from) : emptyRoster(V.ids.instance, R.group_id);
	for (const e of entries) applyEntry(s, e);
	return s;
}

const rustEntries = (): Signed<RosterEntry>[] =>
	R.entries.map((e: { signed: Signed<RosterEntry> }) => structuredClone(e.signed));

function throwsKind(f: () => unknown, kind: string) {
	assert.throws(f, (e: unknown) => e instanceof RosterError && e.kind === kind, kind);
}

test('roster encodings, hashes and signatures match Rust', () => {
	assert.equal(genesisPrevHash(V.ids.instance, R.group_id), R.genesis_prev_hash);
	for (const e of R.entries) {
		const { sig: _sig, ...body } = e.signed;
		void _sig;
		assert.equal(validateRosterEntry(body), null);
		assert.equal(hex(rosterEntrySigningBytes(body)), e.signing_bytes_hex);
		assert.equal(rosterEntryHash(body), e.hash);
	}
	for (const k of R.epoch_keys) {
		assert.equal(epochKeyCheck(V.ids.instance, R.group_id, k.epoch, unhex(k.key_hex)), k.key_check);
	}
	const s = replay(rustEntries());
	assert.equal(s.next_seq, 3);
	assert.equal(s.epoch, 3);
	assert.deepEqual(Object.keys(s.members).sort(), [V.ids.ally_a, V.ids.member]);
	assert.equal(s.members[V.ids.ally_a].role, 'facilitator');

	const snap = R.snapshot.signed as Signed<RosterSnapshot>;
	const { sig: _s, ...snapBody } = snap;
	void _s;
	assert.equal(hex(snapshotSigningBytes(snapBody)), R.snapshot.signing_bytes_hex);
	assert.deepEqual(stateFromSnapshot(snap).members, s.members);
	assert.equal(stateFromSnapshot(snap).head, s.head);
	// Ed25519 is deterministic: signing again gives Rust's signature.
	const again = signSnapshot(s, V.ids.member, unb64(K.member_sign_seed), snap.at_ms);
	assert.equal(again.sig, snap.sig);
	assert.equal(groupSafetyCode(V.ids.instance, R.group_id, checkpointOf(s)!), R.safety_code);

	// The epoch key Rust sealed opens against the commitment in the roster.
	const key = openEpochKey(
		V.roster_sealed_epoch_key.sealed,
		unb64(K.ally_a_secret),
		V.ids.instance,
		R.group_id,
		3,
		s.epoch_key_check
	);
	assert.equal(hex(key), R.epoch_keys[2].key_hex);
	// Presented as another epoch, or checked against another commitment, it fails.
	throwsKind(
		() =>
			openEpochKey(
				V.roster_sealed_epoch_key.sealed,
				unb64(K.ally_a_secret),
				V.ids.instance,
				R.group_id,
				2,
				s.epoch_key_check
			),
		'bad_signature'
	);
});

test('a fork, a rollback and a withheld entry are refused, and the state is kept', () => {
	const entries = rustEntries();
	const s = replay(entries.slice(0, 2));
	const before = structuredClone(s);

	// Fork: an entry at the next seq that doesn't chain from the checkpoint.
	const forked = { ...entries[2], prev_hash: entries[0].prev_hash };
	throwsKind(() => applyEntry(s, forked), 'fork');
	// Rollback: an entry the client already has.
	throwsKind(() => applyEntry(s, entries[1]), 'rollback');
	// Withheld: the server skips an entry.
	const s1 = replay(entries.slice(0, 1));
	throwsKind(() => applyEntry(s1, entries[2]), 'gap');
	assert.deepEqual(s, before);

	// Heads the server reports.
	const head = checkpointOf(s)!;
	assert.equal(checkHead(s, head), 'same');
	assert.equal(checkHead(s, { seq: head.seq + 1, hash: head.hash }), 'ahead');
	throwsKind(() => checkHead(s, { seq: head.seq - 1, hash: head.hash }), 'rollback');
	throwsKind(() => checkHead(s, { seq: head.seq, hash: entries[0].prev_hash }), 'fork');
});

test('a forged signature and a signer who was not a facilitator are refused', () => {
	const entries = rustEntries();
	const s = replay(entries.slice(0, 1));
	// Any change to a signed entry breaks the signature.
	const tampered = structuredClone(entries[1]);
	tampered.at_ms += 1;
	throwsKind(() => applyEntry(s, tampered), 'bad_signature');
	// A participant (ally A, before entry 1 made them a facilitator) signing
	// is refused before any signature check.
	const byAlly = { ...structuredClone(entries[1]), signer: V.ids.ally_a };
	throwsKind(() => applyEntry(s, byAlly), 'not_facilitator');
	// Ally A became a facilitator in entry 1 but has no signing key.
	const s2 = replay(entries.slice(0, 2));
	const byKeyless = { ...structuredClone(entries[2]), signer: V.ids.ally_a };
	throwsKind(() => applyEntry(s2, byKeyless), 'no_signing_key');
	// The instance adding a reader with a key of its own: someone who isn't
	// in the roster can't sign, and signing as the facilitator with another
	// key fails the signature check.
	const evilSeed = new Uint8Array(32).fill(7);
	const addEvil: RosterChange = {
		kind: 'join',
		user_id: 'usr_evil',
		role: 'participant',
		enc_pubkey: K.ally_b_pubkey,
		sign_pubkey: null
	};
	throwsKind(() => prepareEntries(s, [addEvil], 'usr_evil', evilSeed), 'not_facilitator');
	throwsKind(() => prepareEntries(s, [addEvil], V.ids.member, evilSeed), 'bad_signature');
});

interface Person {
	id: string;
	seed: Uint8Array;
	encSecret: Uint8Array;
	encPk: string;
	signPk: string;
}

function person(id: string, n: number): Person {
	const seed = new Uint8Array(32).fill(n);
	const encSecret = new Uint8Array(32).fill(n + 100);
	return {
		id,
		seed,
		encSecret,
		encPk: b64(encPublicKey(encSecret)),
		signPk: b64(signPublicKey(seed))
	};
}

const join = (p: Person, role: 'facilitator' | 'participant', withSign = false): RosterChange => ({
	kind: 'join',
	user_id: p.id,
	role,
	enc_pubkey: p.encPk,
	sign_pubkey: withSign ? p.signPk : null
});

test('the epoch rotates on join and leave; joiners only get the new epoch', () => {
	const f = person('usr_f', 1);
	const a = person('usr_a', 2);
	const b = person('usr_b', 3);
	const inst = V.ids.instance;
	const g = 'grp1';
	let s = emptyRoster(inst, g);

	let r = prepareEntries(s, [join(f, 'facilitator', true), join(a, 'participant')], f.id, f.seed);
	s = r.state;
	assert.equal(s.epoch, 1);
	const e1 = r.entries[0];
	// Everyone in the roster got the key, and it opens against the commitment.
	assert.deepEqual(
		e1.epochKeys.map((k) => k.user_id),
		[a.id, f.id]
	);
	const aKey1 = openEpochKey(
		e1.epochKeys[0].sealed_key,
		a.encSecret,
		inst,
		g,
		1,
		s.epoch_key_check
	);
	assert.deepEqual(aKey1, e1.epochKey);

	// B joins: a new epoch, sealed to all three; B can't open epoch 1.
	r = prepareEntries(s, [join(b, 'participant')], f.id, f.seed);
	s = r.state;
	assert.equal(s.epoch, 2);
	assert.equal(r.entries[0].epochKeys.length, 3);
	assert.ok(!e1.epochKeys.some((k) => k.user_id === b.id));

	// A leaves: a new epoch that A gets no copy of.
	r = prepareEntries(s, [{ kind: 'leave', user_id: a.id }], f.id, f.seed);
	s = r.state;
	assert.equal(s.epoch, 3);
	assert.deepEqual(
		r.entries[0].epochKeys.map((k) => k.user_id),
		[b.id, f.id]
	);
	assert.ok(!listsKeys(s, a.id, encPublicKey(a.encSecret)));
	assert.ok(listsKeys(s, b.id, encPublicKey(b.encSecret), null));
	assert.ok(listsKeys(s, f.id, encPublicKey(f.encSecret), signPublicKey(f.seed)));

	// A role change alone doesn't rotate.
	r = prepareEntries(s, [{ kind: 'role', user_id: b.id, role: 'facilitator' }], f.id, f.seed);
	assert.equal(r.state.epoch, 3);
	assert.equal(r.entries[0].entry.epoch, null);

	// A sealed key the server swapped for one of its own fails the check.
	const evil = sealEpochKey(new Uint8Array(32).fill(1), [s.members[b.id]])[0].sealed_key;
	throwsKind(() => openEpochKey(evil, b.encSecret, inst, g, 3, s.epoch_key_check), 'bad_signature');

	// Snapshots replay to the same state.
	const snap = signSnapshot(s, f.id, f.seed);
	const fromSnap = stateFromSnapshot(snap);
	assert.deepEqual(sortedMembers(fromSnap), sortedMembers(s));
	assert.equal(fromSnap.head, s.head);
	// A forged snapshot (signed by a key the instance made, naming itself a
	// facilitator) verifies on its own: that's why clients with a checkpoint
	// never jump to a snapshot, and why the group safety code exists.
	const tampered = { ...snap, members: snap.members.slice(1) };
	assert.throws(() => stateFromSnapshot(tampered), RosterError);
});

test('large batches split into entries of at most 256 changes, each rotating', () => {
	// An id that sorts last: the first entry still has to contain its signer.
	const f = person('usr_zzz', 1);
	const people = Array.from({ length: 300 }, (_, i) => {
		const encSecret = newEncryptionSecret();
		return { id: `usr_p${String(i).padStart(4, '0')}`, encPk: b64(encPublicKey(encSecret)) };
	});
	const changes: RosterChange[] = [
		join(f, 'facilitator', true),
		...people.map((p): RosterChange => ({
			kind: 'join',
			user_id: p.id,
			role: 'participant',
			enc_pubkey: p.encPk,
			sign_pubkey: null
		}))
	];
	const r = prepareEntries(emptyRoster(V.ids.instance, 'big'), changes, f.id, f.seed);
	assert.equal(r.entries.length, 2);
	assert.ok(r.entries.every((e) => e.entry.changes.length <= 256 && e.entry.epoch));
	assert.equal(Object.keys(r.state.members).length, 301);
	assert.equal(r.state.epoch, 2);
	// They replay from scratch.
	const again = replay(
		r.entries.map((e) => e.entry),
		emptyRoster(V.ids.instance, 'big')
	);
	assert.equal(again.head, r.state.head);
});

test('epoch rotation for 1,000 participants (timing)', () => {
	const f = person('usr_f', 1);
	const members = Array.from({ length: 999 }, (_, i) => ({
		user_id: `usr_m${String(i).padStart(4, '0')}`,
		role: 'participant' as const,
		enc_pubkey: b64(encPublicKey(newEncryptionSecret())),
		sign_pubkey: null
	}));
	const state: RosterState = {
		...emptyRoster(V.ids.instance, 'scale'),
		next_seq: 1,
		head: genesisPrevHash(V.ids.instance, 'scale'),
		epoch: 1,
		members: Object.fromEntries(
			[
				...members,
				{ user_id: f.id, role: 'facilitator' as const, enc_pubkey: f.encPk, sign_pubkey: f.signPk }
			].map((m) => [m.user_id, m])
		)
	};
	const t0 = performance.now();
	const r = prepareEntries(state, [], f.id, f.seed, { rotate: true });
	const ms = performance.now() - t0;
	assert.equal(r.entries[0].epochKeys.length, 1000);
	console.log(`# rotating the epoch for 1,000 participants took ${ms.toFixed(0)} ms`);
	// GROUPS.md §10.5 expects about a second in a browser; leave room for slow CI.
	assert.ok(ms < 15_000, `${ms} ms`);
});
