// The client's checkpoint rules against a hostile instance (GROUPS.md §19,
// Phase C): a persisted (seq, hash), and a fork, a rollback, a withheld
// entry or a forged entry refused while the last accepted roster is kept.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { b64 } from './crypto/bytes.ts';
import { encPublicKey, signPublicKey } from './crypto/keys.ts';
import type { Signed } from './crypto/proto.ts';
import {
	checkpointOf,
	emptyRoster,
	prepareEntries,
	signSnapshot,
	type RosterChange,
	type RosterEntry,
	type RosterSnapshot,
	type RosterState
} from './crypto/roster.ts';
import {
	memoryStore,
	changeKey,
	splitPending,
	syncRoster,
	type RosterPage,
	type RosterSource
} from './roster-sync.ts';

const INST = 'inst_test';
const G = 'grp1';
const fSeed = new Uint8Array(32).fill(1);
const F = 'usr_f';

function joinOf(id: string, n: number, sign?: Uint8Array): RosterChange {
	return {
		kind: 'join',
		user_id: id,
		role: sign ? 'facilitator' : 'participant',
		enc_pubkey: b64(encPublicKey(new Uint8Array(32).fill(n))),
		sign_pubkey: sign ? b64(signPublicKey(sign)) : null
	};
}

/** A log of `n` entries: the facilitator, then one join per entry. */
function makeLog(n: number, seed = fSeed): { log: Signed<RosterEntry>[]; states: RosterState[] } {
	let s = emptyRoster(INST, G);
	const log: Signed<RosterEntry>[] = [];
	const states: RosterState[] = [];
	for (let i = 0; i < n; i++) {
		const change = i === 0 ? joinOf(F, 50, seed) : joinOf(`usr_p${i}`, 50 + i);
		const r = prepareEntries(s, [change], F, seed, { now: 1000 + i });
		s = r.state;
		log.push(r.entries[0].entry);
		states.push(s);
	}
	return { log, states };
}

/** An instance serving `log` (and `snapshots`), 2 entries per page. */
function source(
	log: Signed<RosterEntry>[],
	snapshots: Signed<RosterSnapshot>[] = [],
	head = log.length ? { seq: log.length - 1, hash: '' } : null
): RosterSource {
	return {
		async page(after): Promise<RosterPage> {
			const from = after === null ? 0 : after + 1;
			const rest = log.filter((e) => e.seq >= from);
			const last = log[log.length - 1];
			return {
				head: head && last ? { seq: head.seq, hash: head.hash || hashOf(last) } : null,
				epoch: 0,
				latest_snapshot_seq: snapshots.length ? snapshots[snapshots.length - 1].seq : null,
				entries: structuredClone(rest.slice(0, 2)),
				more: rest.length > 2
			};
		},
		async snapshot(max) {
			const ok = snapshots.filter((s) => max === null || s.seq <= max);
			return ok.length ? structuredClone(ok[ok.length - 1]) : null;
		}
	};
}

const hashes = new Map<Signed<RosterEntry>, string>();
function hashOf(e: Signed<RosterEntry>): string {
	return hashes.get(e) ?? '';
}

function remember(log: Signed<RosterEntry>[], states: RosterState[]) {
	log.forEach((e, i) => hashes.set(e, states[i].head));
}

test('a first sync accepts the log and persists the checkpoint', async () => {
	const { log, states } = makeLog(5);
	remember(log, states);
	const store = memoryStore();
	const r = await syncRoster(source(log), store, INST, G);
	assert.equal(r.problem, null, r.warning ?? '');
	assert.deepEqual(checkpointOf(r.state), checkpointOf(states[4]));
	assert.deepEqual(store.stored?.head, checkpointOf(states[4]));
	// A second sync with nothing new is quiet.
	const again = await syncRoster(source(log), store, INST, G);
	assert.equal(again.problem, null);
});

test('a rollback is refused and the newer roster kept', async () => {
	const { log, states } = makeLog(5);
	remember(log, states);
	const store = memoryStore();
	await syncRoster(source(log), store, INST, G);
	const r = await syncRoster(source(log.slice(0, 3)), store, INST, G);
	assert.equal(r.problem, 'rollback');
	assert.deepEqual(checkpointOf(r.state), checkpointOf(states[4]));
	assert.deepEqual(store.stored?.head, checkpointOf(states[4]));
	// An instance that pretends the log is empty, too.
	const empty = await syncRoster(source([]), store, INST, G);
	assert.equal(empty.problem, 'rollback');
});

test('a fork is refused, whether at the head or later', async () => {
	const { log, states } = makeLog(4);
	remember(log, states);
	const store = memoryStore();
	await syncRoster(source(log.slice(0, 3)), store, INST, G);
	// Another history from seq 2 on, signed by the same facilitator.
	let s = states[1];
	const alt: Signed<RosterEntry>[] = log.slice(0, 2);
	const altStates = states.slice(0, 2);
	for (let i = 2; i < 4; i++) {
		const r = prepareEntries(s, [joinOf(`usr_q${i}`, 90 + i)], F, fSeed, { now: 5000 + i });
		s = r.state;
		alt.push(r.entries[0].entry);
		altStates.push(s);
	}
	remember(alt, altStates);
	const r = await syncRoster(source(alt), store, INST, G);
	assert.equal(r.problem, 'fork');
	assert.deepEqual(checkpointOf(r.state), checkpointOf(states[2]));
});

test('withheld entries: a gap is refused, a short log is reported incomplete', async () => {
	const { log, states } = makeLog(5);
	remember(log, states);
	const store = memoryStore();
	await syncRoster(source(log.slice(0, 2)), store, INST, G);
	const gap = await syncRoster(source([...log.slice(0, 2), ...log.slice(3)]), store, INST, G);
	assert.equal(gap.problem, 'gap');
	assert.deepEqual(checkpointOf(gap.state), checkpointOf(states[1]));
	// The instance claims seq 4 but serves only up to 3.
	const short = await syncRoster(
		source(log.slice(0, 4), [], { seq: 4, hash: states[4].head }),
		store,
		INST,
		G
	);
	assert.equal(short.problem, 'incomplete');
	assert.deepEqual(checkpointOf(short.state), checkpointOf(states[3]));
});

test('a forged entry is refused, and everything before it kept', async () => {
	const { log, states } = makeLog(4);
	remember(log, states);
	const forged = structuredClone(log);
	// The instance changes an entry the facilitator signed (here its time;
	// any field, such as a join's key, fails the same way).
	forged[3] = { ...forged[3], at_ms: forged[3].at_ms + 1 };
	const store = memoryStore();
	const r = await syncRoster(source(forged), store, INST, G);
	assert.equal(r.problem, 'bad_signature');
	assert.deepEqual(checkpointOf(r.state), checkpointOf(states[2]));
	assert.deepEqual(store.stored?.head, checkpointOf(states[2]));
});

test('with only the head stored, the roster is rebuilt from a snapshot below it', async () => {
	const { log, states } = makeLog(6);
	remember(log, states);
	const snaps = [signSnapshot(states[2], F, fSeed, 7000)];
	const store = memoryStore();
	store.stored = { head: checkpointOf(states[3])! };
	const r = await syncRoster(source(log, snaps), store, INST, G);
	assert.equal(r.problem, null, r.warning ?? '');
	assert.deepEqual(checkpointOf(r.state), checkpointOf(states[5]));
	// With a head that isn't in the instance's log: a fork.
	const store2 = memoryStore();
	store2.stored = { head: { seq: 3, hash: states[2].head } };
	const bad = await syncRoster(source(log, snaps), store2, INST, G);
	assert.equal(bad.problem, 'fork');
});

test('a new browser starts from the latest snapshot', async () => {
	const { log, states } = makeLog(6);
	remember(log, states);
	const snaps = [signSnapshot(states[3], F, fSeed, 7000)];
	const pages: (number | null)[] = [];
	const src = source(log, snaps);
	const spy: RosterSource = {
		page: (a) => {
			pages.push(a);
			return src.page(a);
		},
		snapshot: src.snapshot
	};
	const r = await syncRoster(spy, memoryStore(), INST, G);
	assert.equal(r.problem, null, r.warning ?? '');
	assert.deepEqual(checkpointOf(r.state), checkpointOf(states[5]));
	// It asked for the entries after the snapshot, not the whole log.
	assert.deepEqual(pages, [null, 3]);
	// A snapshot for another group is refused.
	const other = signSnapshot({ ...states[3], group_id: 'grp2' }, F, fSeed, 7000);
	const r2 = await syncRoster(source(log, [other]), memoryStore(), INST, G);
	assert.equal(r2.problem, 'wrong_group');
});

test('pending work: removals are signed automatically, new keys and roles need approval', () => {
	const me = { userId: F, encPk: 'E', signPk: 'S' };
	const r = splitPending(
		[
			{ kind: 'join', user_id: 'usr_a', role: 'participant', enc_pubkey: 'x', sign_pubkey: null },
			{ kind: 'leave', user_id: 'usr_b' },
			{ kind: 'remove', user_id: 'usr_c' },
			{ kind: 'role', user_id: 'usr_d', role: 'facilitator' },
			{ kind: 'keys', user_id: 'usr_e', enc_pubkey: 'y', sign_pubkey: null },
			{ kind: 'join', user_id: F, role: 'facilitator', enc_pubkey: 'E', sign_pubkey: 'S' }
		],
		me
	);
	assert.deepEqual(
		r.auto.map((c) => c.user_id),
		['usr_b', 'usr_c', F]
	);
	// A role change decides who signs the member list: the instance proposing
	// one isn't enough.
	assert.deepEqual(
		r.approve.map((c) => c.user_id),
		['usr_a', 'usr_d', 'usr_e']
	);
	// Nor is it enough for the facilitator's own removal.
	const self = splitPending([{ kind: 'remove', user_id: F }], me);
	assert.deepEqual(self.approve.length, 1);
	// An approval is for that exact change, not for the next one about the same person.
	const join = r.approve[0];
	assert.notEqual(
		changeKey(join),
		changeKey({ ...join, enc_pubkey: 'other' } as typeof join),
		'another key is another change'
	);
	assert.notEqual(
		changeKey({ kind: 'role', user_id: 'usr_d', role: 'facilitator' }),
		changeKey({ kind: 'role', user_id: 'usr_d', role: 'participant' })
	);
	// The instance offering the facilitator's own keys with one of its own.
	const evil = splitPending(
		[{ kind: 'keys', user_id: F, enc_pubkey: 'E', sign_pubkey: 'EVIL' }],
		me
	);
	assert.equal(evil.refused.length, 1);
	assert.equal(evil.auto.length + evil.approve.length, 0);
});
