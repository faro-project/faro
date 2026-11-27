// The recipient list this browser signs or anchors a computer to, against a
// lying instance (#178, #180): a 404 with a fake active ally, an older list
// (one step and two steps), a different list at the same version, a list
// built on another branch, a 404 after this browser signed, and swapped
// ally names. Run with `npm test`.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { b64, type Bytes } from '../crypto/bytes.ts';
import { encPublicKey, signPublicKey } from '../crypto/keys.ts';
import {
	checkManifest,
	MANIFEST_FORMAT_V3,
	manifestRef,
	manifestSigningBytes,
	signWith,
	validateManifest,
	type ManifestAlly,
	type RecipientManifest,
	type Signed
} from '../crypto/proto.ts';
import type { MemberKeys } from './keyring.svelte.ts';
import {
	acceptServed,
	ensureManifestWith,
	ManifestTrustError,
	memoryManifestStore,
	nameChanges,
	namesToSign,
	planNext,
	recordSigned,
	storageManifestStore,
	type ManifestSource
} from './manifest-trust.ts';

const INST = 'inst_test';
const secret = (n: number) => new Uint8Array(32).fill(n) as Bytes;
const keys: MemberKeys = {
	userId: 'usr_member',
	signSeed: secret(1),
	signPk: signPublicKey(secret(1)),
	encSecret: secret(2),
	encPk: encPublicKey(secret(2))
};
const ally = (id: string, n: number, name: string): ManifestAlly => ({
	ally_id: id,
	enc_pubkey: b64(encPublicKey(secret(n))),
	name
});
const PAT = ally('usr_pat', 10, 'Pat');
const SAM = ally('usr_sam', 11, 'Sam');
/** The instance's own key, which it would like devices to encrypt to. */
const EVE = ally('usr_eve', 66, 'Eve');

const sign = (m: RecipientManifest): Signed<RecipientManifest> =>
	signWith(keys.signSeed, m, manifestSigningBytes);

/** A lying instance: serves whatever it is told to, records uploads. */
function liar(served: Signed<RecipientManifest> | null) {
	const s = {
		served,
		uploads: [] as Signed<RecipientManifest>[],
		/** What it claims on `GET /v1/me/allies`; never asked for any more. */
		activeAllies: [EVE],
		async latest() {
			return s.served;
		},
		async put(m: Signed<RecipientManifest>) {
			s.uploads.push(m);
			s.served = m;
			return manifestRef(m);
		}
	};
	return s satisfies ManifestSource;
}

/** The genuine history: Eve was approved at 2 and removed at 3. */
function history() {
	const v1 = sign({
		format: MANIFEST_FORMAT_V3,
		instance_id: INST,
		member_id: keys.userId,
		version: 1,
		issued_at_ms: 1000,
		member_enc_pubkey: b64(keys.encPk),
		allies: []
	});
	const v2 = sign(planNext(v1, { kind: 'add', ally: EVE }, undefined, 2000));
	const v3 = sign(planNext(v2, { kind: 'remove', ids: new Set([EVE.ally_id]) }, undefined, 3000));
	return { v1, v2, v3 };
}

function rejects(fn: () => unknown, problem: string, re: RegExp) {
	assert.throws(fn, (e: unknown) => {
		assert.ok(e instanceof ManifestTrustError, String(e));
		assert.equal(e.problem, problem);
		assert.match(e.message, re);
		return true;
	});
}

test('#178: a 404 and a fake active ally give an empty first list', async () => {
	const src = liar(null);
	const store = memoryManifestStore();
	const m = await ensureManifestWith(src, keys, INST, store);
	assert.equal(src.uploads.length, 1);
	assert.deepEqual(src.uploads[0], m);
	assert.equal(m.version, 1);
	assert.deepEqual(m.allies, [], 'nothing the server listed is signed');
	assert.equal(m.prev_hash, undefined);
	assert.equal(validateManifest(m), null);
	assert.equal(checkManifest(m, keys.signPk, INST, keys.userId), null);
	assert.deepEqual(store.stored, manifestRef(m));
	// The next call builds on it.
	assert.deepEqual(await ensureManifestWith(src, keys, INST, store), m);
	assert.equal(src.uploads.length, 1);
});

test('#180: a 404 once this browser has signed a list is a rollback', async () => {
	const store = memoryManifestStore();
	await ensureManifestWith(liar(null), keys, INST, store);
	// The instance now pretends there is none, to get a fresh version 1
	// (with its key) signed.
	const src = liar(null);
	await assert.rejects(ensureManifestWith(src, keys, INST, store), (e: unknown) => {
		assert.ok(e instanceof ManifestTrustError && e.problem === 'rollback');
		return true;
	});
	assert.equal(src.uploads.length, 0, 'nothing signed');
});

test('#180 one step: an older list is never anchored to or built on', () => {
	const { v2, v3 } = history();
	const store = memoryManifestStore();
	// This browser removed Eve: it signed version 3.
	recordSigned(store, v3);
	// Approving a computer: the instance serves version 2, which lists Eve.
	rejects(() => acceptServed(v2, keys, INST, store), 'rollback', /version 2, older than version 3/);
	assert.deepEqual(store.stored, manifestRef(v3), 'the checkpoint stays');
	// The genuine version 3 is fine.
	assert.deepEqual(acceptServed(v3, keys, INST, store), v3);
});

test('#180 two steps: a different list at the version seen, then its successor', () => {
	const { v2, v3 } = history();
	const store = memoryManifestStore();
	recordSigned(store, v3);
	// A page served version 2 elsewhere signed another version 3 with Eve,
	// then a version 4 on that. This browser refuses both.
	const fork3 = sign(planNext(v2, { kind: 'same' }, undefined, 3500));
	const fork4 = sign(planNext(fork3, { kind: 'same' }, undefined, 4000));
	assert.deepEqual(
		fork4.allies.map((a) => a.ally_id),
		[EVE.ally_id]
	);
	rejects(() => acceptServed(fork3, keys, INST, store), 'fork', /different list/);
	rejects(() => acceptServed(fork4, keys, INST, store), 'fork', /built on another list/);
	assert.deepEqual(store.stored, manifestRef(v3));
	// The genuine successor is accepted and advances the checkpoint; a
	// later version (versions in between unseen) too.
	const v4 = sign(planNext(v3, { kind: 'same' }, undefined, 4000));
	assert.deepEqual(acceptServed(v4, keys, INST, store), v4);
	assert.deepEqual(store.stored, manifestRef(v4));
	const v6 = sign({ ...planNext(v4, { kind: 'same' }, undefined, 5000), version: 6 });
	assert.deepEqual(acceptServed(v6, keys, INST, store), v6);
	assert.equal(store.stored?.version, 6);
});

test('#180: what was seen counts as much as what was signed', () => {
	const { v1, v2, v3 } = history();
	const store = memoryManifestStore();
	assert.deepEqual(acceptServed(v3, keys, INST, store), v3);
	rejects(() => acceptServed(v2, keys, INST, store), 'rollback', /older/);
	rejects(() => acceptServed(v1, keys, INST, store), 'rollback', /older/);
});

test('lists not signed by the member, or for someone else, are refused', () => {
	const { v3 } = history();
	const store = memoryManifestStore();
	const forged = { ...v3, allies: [EVE] };
	rejects(() => acceptServed(forged, keys, INST, store), 'invalid', /signature/);
	rejects(() => acceptServed(v3, keys, 'inst_other', store), 'invalid', /different instance/);
	const otherKey = sign({ ...planNext(v3, { kind: 'same' }), member_enc_pubkey: EVE.enc_pubkey });
	rejects(() => acceptServed(otherKey, keys, INST, store), 'invalid', /different key for you/);
	assert.equal(store.stored, null, 'nothing was seen');
});

test('#180: allies keep their signed names unless the member confirms a change', () => {
	const { v1 } = history();
	const base = sign(planNext(v1, { kind: 'add', ally: PAT }, undefined, 2000));
	const withSam = sign(planNext(base, { kind: 'add', ally: SAM }, undefined, 3000));
	// The instance swaps the two names on `GET /v1/me/allies`.
	const served = new Map([
		[PAT.ally_id, 'Sam'],
		[SAM.ally_id, 'Pat']
	]);
	const kept = planNext(withSam, { kind: 'same' }, namesToSign(withSam, served));
	assert.deepEqual(
		kept.allies.map((a) => [a.ally_id, a.name]),
		[
			[PAT.ally_id, 'Pat'],
			[SAM.ally_id, 'Sam']
		]
	);
	// Both are offered as changes, shown before signing.
	assert.deepEqual(nameChanges(withSam, served), [
		{ ally_id: PAT.ally_id, signed: 'Pat', current: 'Sam' },
		{ ally_id: SAM.ally_id, signed: 'Sam', current: 'Pat' }
	]);
	// A real rename the member ticks is signed, sanitized; the other isn't.
	const renamed = new Map([
		[PAT.ally_id, ' Patricia‮ '],
		[SAM.ally_id, 'Pat']
	]);
	const accepted = new Set([PAT.ally_id]);
	const next = planNext(withSam, { kind: 'same' }, namesToSign(withSam, renamed, accepted));
	assert.deepEqual(
		next.allies.map((a) => a.name),
		['Patricia', 'Sam']
	);
	// The same name, or none at all from the server, is no change.
	assert.deepEqual(nameChanges(withSam, new Map([[PAT.ally_id, ' Pat ']])), []);
	assert.deepEqual(nameChanges(withSam, new Map([[SAM.ally_id, '']])), []);
	// An ally being approved is signed with the name shown when approving.
	const approved = planNext(base, { kind: 'add', ally: SAM }, namesToSign(base, served));
	assert.deepEqual(
		approved.allies.map((a) => a.name),
		['Pat', 'Sam']
	);
});

test('the next list links to the one it was built on', () => {
	const { v2, v3 } = history();
	assert.equal(v3.format, MANIFEST_FORMAT_V3);
	assert.equal(v3.prev_hash, manifestRef(v2).hash);
	assert.equal(validateManifest(v3), null);
	assert.deepEqual(v3.allies, []);
});

test('the checkpoint persists in storage and never moves backwards', () => {
	const data = new Map<string, string>();
	const storage = {
		getItem: (k: string) => data.get(k) ?? null,
		setItem: (k: string, v: string) => void data.set(k, v)
	} as unknown as Storage;
	const { v2, v3 } = history();
	const a = storageManifestStore(storage, INST, keys.userId);
	assert.equal(a.load(), null);
	a.save(manifestRef(v3));
	a.save(manifestRef(v2));
	// Another page load reads it back.
	const b = storageManifestStore(storage, INST, keys.userId);
	assert.deepEqual(b.load(), manifestRef(v3));
	rejects(() => acceptServed(v2, keys, INST, b), 'rollback', /older/);
	// Per instance and member.
	assert.equal(storageManifestStore(storage, INST, 'usr_other').load(), null);
	assert.equal(storageManifestStore(storage, 'inst_other', keys.userId).load(), null);
	// Junk in storage is ignored, and storage that is off doesn't break.
	data.set(`faro.manifest.v1.${INST}.usr_junk`, '{"version":"9","hash":"x"}');
	assert.equal(storageManifestStore(storage, INST, 'usr_junk').load(), null);
	const off = storageManifestStore(null, INST, keys.userId);
	off.save(manifestRef(v3));
	assert.equal(off.load(), null);
});
