// The group roster log (docs/PROTOCOL.md §10, GROUPS.md §10.3): a port of
// `faro_proto::roster` and `faro_crypto::roster`, checked against the same
// shared vectors.
//
// A group's roster is a hash-chained log of facilitator-signed entries. A
// client keeps the last entry it accepted (its checkpoint) and applies only
// entries that extend it: a fork, a rollback, a missing entry, a bad
// signature or a signer who wasn't a facilitator is refused, and the client
// keeps its last accepted roster. Every join, leave, removal and key change
// rotates the group's epoch key in the same entry; the entry commits to the
// new key, which is sealed to each participant separately.
//
// Nothing here calls the API (`lib/groups/roster-sync.ts` does), so
// `npm test` covers it.

import { b64, equal, randomBytes, unb64, unb64Fixed, wipe, type Bytes } from './bytes.ts';
import { Canonical, hash, hashFromString, hashToString } from './canonical.ts';
import { isUsableSignKey, isWeakX25519, sign, verify } from './keys.ts';
import { compareIds, isWellFormedId, type Signed } from './proto.ts';
import { sealOpen, sealTo } from './seal.ts';
import { blake3 } from '@noble/hashes/blake3.js';

export const MAX_ROSTER_CHANGES = 256;
export const MAX_ROSTER_MEMBERS = 100_000;
export const ROSTER_SNAPSHOT_INTERVAL = 256;
/** Clients refuse a larger snapshot download before parsing it. */
export const MAX_ROSTER_SNAPSHOT_BYTES = 8 * 1024 * 1024;
/** And a larger page of entries. */
export const MAX_ROSTER_PAGE_BYTES = 8 * 1024 * 1024;
export const SEALED_EPOCH_KEY_LEN = 80;

export type GroupRole = 'facilitator' | 'participant';

export type RosterChange =
	| {
			kind: 'join';
			user_id: string;
			role: GroupRole;
			enc_pubkey: string;
			sign_pubkey: string | null;
	  }
	| { kind: 'leave'; user_id: string }
	| { kind: 'remove'; user_id: string }
	| { kind: 'role'; user_id: string; role: GroupRole }
	| { kind: 'keys'; user_id: string; enc_pubkey: string; sign_pubkey: string | null };

export interface EpochRotation {
	epoch: number;
	/** `b3:<hex>` commitment to the new key. */
	key_check: string;
}

export interface RosterEntry {
	instance_id: string;
	group_id: string;
	seq: number;
	prev_hash: string;
	at_ms: number;
	signer: string;
	changes: RosterChange[];
	epoch: EpochRotation | null;
}

export interface RosterMember {
	user_id: string;
	role: GroupRole;
	enc_pubkey: string;
	sign_pubkey: string | null;
}

export interface RosterSnapshot {
	instance_id: string;
	group_id: string;
	seq: number;
	head: string;
	at_ms: number;
	signer: string;
	epoch: number;
	epoch_key_check: string;
	members: RosterMember[];
}

export interface RosterHead {
	seq: number;
	hash: string;
}

/** The roster as of one entry. Plain JSON, so it can be persisted. */
export interface RosterState {
	instance_id: string;
	group_id: string;
	/** The seq the next entry must have (0 before the first). */
	next_seq: number;
	/** The last entry's hash, or the genesis hash before the first. */
	head: string;
	epoch: number;
	epoch_key_check: string;
	members: Record<string, RosterMember>;
	/** Commitments of the epochs this client saw rotate, to check older keys. */
	epoch_checks: Record<string, string>;
}

/** How many past epochs' commitments a state remembers. */
const KEEP_EPOCH_CHECKS = 64;

export type RosterErrorKind =
	| 'malformed'
	| 'wrong_group'
	| 'rollback'
	| 'gap'
	| 'fork'
	| 'not_facilitator'
	| 'no_signing_key'
	| 'bad_signature'
	| 'weak_key'
	| 'already_member'
	| 'not_member'
	| 'no_change'
	| 'epoch'
	| 'genesis';

export class RosterError extends Error {
	readonly kind: RosterErrorKind;

	constructor(kind: RosterErrorKind, message: string) {
		super(message);
		this.name = 'RosterError';
		this.kind = kind;
	}
}

const ZERO_HASH = hashToString(new Uint8Array(32));

const fail = (kind: RosterErrorKind, msg: string): never => {
	throw new RosterError(kind, msg);
};

export function isWellFormedGroupId(id: string): boolean {
	return id.length >= 1 && id.length <= 64 && /^[A-Za-z0-9_-]+$/.test(id);
}

const key32 = (s: string, what: string) => unb64Fixed(s, 32, what);
const optKey = (s: string | null): Uint8Array => (s == null ? new Uint8Array(0) : key32(s, 'key'));

function needsRotation(c: RosterChange): boolean {
	return c.kind !== 'role';
}

function encodeChange(c: Canonical, ch: RosterChange): void {
	switch (ch.kind) {
		case 'join':
			c.str('join')
				.str(ch.user_id)
				.str(ch.role)
				.fixed(key32(ch.enc_pubkey, 'enc_pubkey'))
				.bytes(optKey(ch.sign_pubkey));
			break;
		case 'leave':
		case 'remove':
			c.str(ch.kind).str(ch.user_id);
			break;
		case 'role':
			c.str('role').str(ch.user_id).str(ch.role);
			break;
		case 'keys':
			c.str('keys')
				.str(ch.user_id)
				.fixed(key32(ch.enc_pubkey, 'enc_pubkey'))
				.bytes(optKey(ch.sign_pubkey));
			break;
	}
}

function checkIds(instance: string, group: string, signer: string): string | null {
	if (!isWellFormedId(instance, 'inst_')) return 'malformed instance id';
	if (!isWellFormedGroupId(group)) return 'malformed group id';
	if (!isWellFormedId(signer, 'usr_')) return 'malformed signer id';
	return null;
}

/** `RosterEntry::validate`: the structural rules that need no keys. */
export function validateRosterEntry(e: RosterEntry): string | null {
	const bad = checkIds(e.instance_id, e.group_id, e.signer);
	if (bad) return bad;
	if (!Number.isSafeInteger(e.seq) || e.seq < 0) return 'seq out of range';
	if (!Number.isSafeInteger(e.at_ms)) return 'at_ms out of range';
	if (!Array.isArray(e.changes) || e.changes.length > MAX_ROSTER_CHANGES) {
		return `more than ${MAX_ROSTER_CHANGES} changes in one entry`;
	}
	if (e.changes.length === 0 && !e.epoch) return 'an entry changes nothing';
	for (let i = 0; i < e.changes.length; i++) {
		const c = e.changes[i];
		if (!['join', 'leave', 'remove', 'role', 'keys'].includes(c.kind)) return 'unknown change';
		if (!isWellFormedId(c.user_id, 'usr_')) return 'malformed user id';
		if ((c.kind === 'join' || c.kind === 'role') && !isRole(c.role)) return 'unknown role';
		if (i > 0 && compareIds(e.changes[i - 1].user_id, c.user_id) >= 0) {
			return 'changes are not sorted by user, or name someone twice';
		}
	}
	if (e.epoch) {
		if (!Number.isSafeInteger(e.epoch.epoch) || e.epoch.epoch < 1) return 'epoch out of range';
	} else if (e.changes.some(needsRotation)) {
		return 'joins, leaves, removals and key changes must rotate the epoch key';
	}
	return null;
}

function isRole(r: unknown): r is GroupRole {
	return r === 'facilitator' || r === 'participant';
}

export function rosterEntrySigningBytes(e: RosterEntry): Bytes {
	const c = new Canonical('faro/group-roster/v1')
		.str(e.instance_id)
		.str(e.group_id)
		.u64(e.seq)
		.fixed(hashFromString(e.prev_hash))
		.i64(e.at_ms)
		.str(e.signer)
		.u64(e.changes.length);
	for (const ch of e.changes) encodeChange(c, ch);
	if (e.epoch) {
		c.optU64(e.epoch.epoch).fixed(hashFromString(e.epoch.key_check));
	} else {
		c.optU64(null);
	}
	return c.finish();
}

export function rosterEntryHash(e: RosterEntry): string {
	return hashToString(hash(rosterEntrySigningBytes(e)));
}

export function genesisPrevHash(instanceId: string, groupId: string): string {
	return hashToString(
		hash(new Canonical('faro/group-roster-genesis/v1').str(instanceId).str(groupId).finish())
	);
}

export function epochKeyCheck(
	instanceId: string,
	groupId: string,
	epoch: number,
	key: Uint8Array
): string {
	if (key.length !== 32) throw new Error('an epoch key is 32 bytes');
	return hashToString(
		hash(
			new Canonical('faro/group-epoch-key/v1')
				.str(instanceId)
				.str(groupId)
				.u64(epoch)
				.fixed(key)
				.finish()
		)
	);
}

/** The group safety code (GROUPS.md §10.3 item 5): 12 groups of 5 digits. */
export function groupSafetyCode(instanceId: string, groupId: string, head: RosterHead): string {
	const h = hash(
		new Canonical('faro/group-safety-code/v1')
			.str(instanceId)
			.str(groupId)
			.u64(head.seq)
			.fixed(hashFromString(head.hash))
			.finish()
	);
	const out = blake3(h, { dkLen: 60 });
	return [...out]
		.map((x) => String(x % 10))
		.join('')
		.match(/.{5}/g)!
		.join(' ');
}

// ---- Snapshots ------------------------------------------------------------

export function validateSnapshot(s: RosterSnapshot): string | null {
	const bad = checkIds(s.instance_id, s.group_id, s.signer);
	if (bad) return bad;
	if (!Number.isSafeInteger(s.seq) || s.seq < 0) return 'seq out of range';
	if (!Number.isSafeInteger(s.epoch) || s.epoch < 1) return "a snapshot's epoch is at least 1";
	if (!Array.isArray(s.members) || s.members.length > MAX_ROSTER_MEMBERS) return 'too many members';
	for (let i = 0; i < s.members.length; i++) {
		const m = s.members[i];
		if (!isWellFormedId(m.user_id, 'usr_')) return 'malformed user id';
		if (!isRole(m.role)) return 'unknown role';
		if (i > 0 && compareIds(s.members[i - 1].user_id, m.user_id) >= 0) {
			return 'members are not sorted by user, or listed twice';
		}
	}
	return null;
}

export function snapshotSigningBytes(s: RosterSnapshot): Bytes {
	const c = new Canonical('faro/group-roster-snapshot/v1')
		.str(s.instance_id)
		.str(s.group_id)
		.u64(s.seq)
		.fixed(hashFromString(s.head))
		.i64(s.at_ms)
		.str(s.signer)
		.u64(s.epoch)
		.fixed(hashFromString(s.epoch_key_check))
		.u64(s.members.length);
	for (const m of s.members) {
		c.str(m.user_id)
			.str(m.role)
			.fixed(key32(m.enc_pubkey, 'enc_pubkey'))
			.bytes(optKey(m.sign_pubkey));
	}
	return c.finish();
}

function checkKeys(userId: string, enc: string, signPk: string | null): void {
	let ok = false;
	try {
		ok =
			!isWeakX25519(key32(enc, 'enc')) &&
			(signPk == null || isUsableSignKey(key32(signPk, 'sign')));
	} catch {
		ok = false;
	}
	if (!ok) fail('weak_key', `unusable key for ${userId}`);
}

function verifySig(pk: string, bytes: Uint8Array, sig: string): void {
	let ok = false;
	try {
		ok = verify(key32(pk, 'signing key'), bytes, unb64Fixed(sig, 64, 'sig'));
	} catch {
		ok = false;
	}
	if (!ok) fail('bad_signature', 'the signature does not verify');
}

function strip<T extends object>(s: Signed<T>): { body: T; sig: string } {
	const { sig, ...body } = s;
	return { body: body as unknown as T, sig };
}

/** Check a snapshot (structure, keys, signer, signature); return its state. */
export function stateFromSnapshot(signed: Signed<RosterSnapshot>): RosterState {
	const { body: s, sig } = strip(signed);
	const bad = validateSnapshot(s);
	if (bad) fail('malformed', bad);
	const signer = s.members.find((m) => m.user_id === s.signer);
	if (!signer) fail('not_member', `${s.signer} is not in the snapshot`);
	if (signer!.role !== 'facilitator') fail('not_facilitator', `${s.signer} was not a facilitator`);
	if (!signer!.sign_pubkey) fail('no_signing_key', `${s.signer} has no signing key`);
	for (const m of s.members) checkKeys(m.user_id, m.enc_pubkey, m.sign_pubkey);
	let bytes: Bytes;
	try {
		bytes = snapshotSigningBytes(s);
	} catch {
		return fail('malformed', 'malformed snapshot');
	}
	verifySig(signer!.sign_pubkey!, bytes, sig);
	const members: Record<string, RosterMember> = {};
	for (const m of s.members) members[m.user_id] = memberOf(m);
	return {
		instance_id: s.instance_id,
		group_id: s.group_id,
		next_seq: s.seq + 1,
		head: s.head,
		epoch: s.epoch,
		epoch_key_check: s.epoch_key_check,
		members,
		epoch_checks: { [String(s.epoch)]: s.epoch_key_check }
	};
}

function memberOf(m: RosterMember): RosterMember {
	return {
		user_id: m.user_id,
		role: m.role,
		enc_pubkey: m.enc_pubkey,
		sign_pubkey: m.sign_pubkey ?? null
	};
}

/** The snapshot of `state` for `signer` to sign (null before the first entry). */
export function snapshotOf(
	state: RosterState,
	atMs: number,
	signer: string
): RosterSnapshot | null {
	if (state.next_seq === 0) return null;
	return {
		instance_id: state.instance_id,
		group_id: state.group_id,
		seq: state.next_seq - 1,
		head: state.head,
		at_ms: atMs,
		signer,
		epoch: state.epoch,
		epoch_key_check: state.epoch_key_check,
		members: sortedMembers(state)
	};
}

export function sortedMembers(state: RosterState): RosterMember[] {
	return Object.values(state.members).sort((a, b) => compareIds(a.user_id, b.user_id));
}

// ---- State ----------------------------------------------------------------

export function emptyRoster(instanceId: string, groupId: string): RosterState {
	return {
		instance_id: instanceId,
		group_id: groupId,
		next_seq: 0,
		head: genesisPrevHash(instanceId, groupId),
		epoch: 0,
		epoch_key_check: ZERO_HASH,
		members: {},
		epoch_checks: {}
	};
}

export function cloneRoster(s: RosterState): RosterState {
	const members: Record<string, RosterMember> = {};
	for (const [k, m] of Object.entries(s.members)) members[k] = { ...m };
	return { ...s, members, epoch_checks: { ...s.epoch_checks } };
}

export function checkpointOf(s: RosterState): RosterHead | null {
	return s.next_seq === 0 ? null : { seq: s.next_seq - 1, hash: s.head };
}

/**
 * Compare a head the instance reports with the state: an older seq is a
 * rollback, the same seq with another hash a fork (both throw).
 */
export function checkHead(s: RosterState, head: RosterHead): 'same' | 'ahead' {
	const c = checkpointOf(s);
	if (!c) return 'ahead';
	if (head.seq < c.seq)
		fail('rollback', `rollback: the roster is at ${c.seq}, the server says ${head.seq}`);
	if (head.seq === c.seq) {
		if (head.hash !== c.hash)
			fail('fork', `fork at seq ${c.seq}: the roster's history was changed`);
		return 'same';
	}
	return 'ahead';
}

function genesisSignerKey(e: RosterEntry): string {
	if (!e.epoch) fail('genesis', 'the first entry must start epoch 1');
	let key: string | null = null;
	for (const c of e.changes) {
		if (c.kind !== 'join') fail('genesis', 'the first entry may only add people');
		if (c.kind === 'join' && c.user_id === e.signer) {
			if (c.role !== 'facilitator') fail('genesis', 'its signer must join as a facilitator');
			key = c.sign_pubkey;
		}
	}
	if (!key) fail('genesis', 'its signer must join in it with a signing key');
	return key!;
}

/**
 * `RosterState::check`: everything about `e` against `s` that needs no
 * cryptography. Returns the signing key the signature must verify against.
 */
export function checkEntry(s: RosterState, e: RosterEntry): string {
	if (e.instance_id !== s.instance_id || e.group_id !== s.group_id) {
		fail('wrong_group', 'the entry is for another instance or group');
	}
	if (e.seq < s.next_seq) fail('rollback', `rollback: expected seq ${s.next_seq}, got ${e.seq}`);
	if (e.seq > s.next_seq)
		fail('gap', `an entry is missing: expected seq ${s.next_seq}, got ${e.seq}`);
	if (e.prev_hash !== s.head)
		fail('fork', `fork at seq ${e.seq}: the roster's history was changed`);
	if (e.epoch && e.epoch.epoch !== s.epoch + 1) {
		fail('epoch', `the epoch must be ${s.epoch + 1}, not ${e.epoch.epoch}`);
	}
	let key: string;
	if (s.next_seq === 0) {
		key = genesisSignerKey(e);
	} else {
		const m = s.members[e.signer];
		if (!m || m.role !== 'facilitator')
			fail('not_facilitator', `${e.signer} was not a facilitator`);
		if (!m!.sign_pubkey) fail('no_signing_key', `${e.signer} has no signing key in the roster`);
		key = m!.sign_pubkey!;
	}
	for (const c of e.changes) {
		const m = Object.hasOwn(s.members, c.user_id) ? s.members[c.user_id] : undefined;
		if (c.kind === 'join') {
			if (m) fail('already_member', `${c.user_id} is already in the roster`);
			continue;
		}
		if (!m) fail('not_member', `${c.user_id} is not in the roster`);
		if (c.kind === 'role' && m!.role === c.role)
			fail('no_change', `nothing changes for ${c.user_id}`);
		if (
			c.kind === 'keys' &&
			m!.enc_pubkey === c.enc_pubkey &&
			(m!.sign_pubkey ?? null) === (c.sign_pubkey ?? null)
		) {
			fail('no_change', `nothing changes for ${c.user_id}`);
		}
	}
	return key;
}

/** Mutate `s` with an entry that passed every check. */
function applyChecked(s: RosterState, e: RosterEntry, hashOfE: string): void {
	for (const c of e.changes) {
		switch (c.kind) {
			case 'join':
				s.members[c.user_id] = {
					user_id: c.user_id,
					role: c.role,
					enc_pubkey: c.enc_pubkey,
					sign_pubkey: c.sign_pubkey ?? null
				};
				break;
			case 'leave':
			case 'remove':
				delete s.members[c.user_id];
				break;
			case 'role':
				s.members[c.user_id].role = c.role;
				break;
			case 'keys':
				s.members[c.user_id].enc_pubkey = c.enc_pubkey;
				s.members[c.user_id].sign_pubkey = c.sign_pubkey ?? null;
				break;
		}
	}
	if (e.epoch) {
		s.epoch = e.epoch.epoch;
		s.epoch_key_check = e.epoch.key_check;
		s.epoch_checks[String(e.epoch.epoch)] = e.epoch.key_check;
		const old = s.epoch - KEEP_EPOCH_CHECKS;
		if (old > 0) delete s.epoch_checks[String(old)];
	}
	s.next_seq = e.seq + 1;
	s.head = hashOfE;
}

/**
 * Check a signed entry completely against `s` and apply it in place:
 * structure, chain position, signer, changes, keys, signature. On error
 * `s` is unchanged.
 */
export function applyEntry(s: RosterState, signed: Signed<RosterEntry>): void {
	const { body: e, sig } = strip(signed);
	e.epoch = e.epoch ?? null;
	const bad = validateRosterEntry(e);
	if (bad) fail('malformed', bad);
	let bytes: Bytes;
	try {
		bytes = rosterEntrySigningBytes(e);
	} catch {
		return fail('malformed', 'malformed entry');
	}
	const key = checkEntry(s, e);
	for (const c of e.changes) {
		if (c.kind === 'join' || c.kind === 'keys')
			checkKeys(c.user_id, c.enc_pubkey, c.sign_pubkey ?? null);
	}
	verifySig(key, bytes, sig);
	applyChecked(s, e, hashToString(hash(bytes)));
}

// ---- Epoch keys -------------------------------------------------------------

export interface SealedEpochKey {
	user_id: string;
	/** base64url `crypto_box_seal` of the 32-byte key. */
	sealed_key: string;
}

/** Seal `key` to each member's encryption key. */
export function sealEpochKey(key: Uint8Array, members: RosterMember[]): SealedEpochKey[] {
	return members.map((m) => ({
		user_id: m.user_id,
		sealed_key: b64(sealTo(key32(m.enc_pubkey, 'enc_pubkey'), key))
	}));
}

/**
 * Open a sealed epoch key with the X25519 `secret` and check it against the
 * commitment the accepted roster holds for that epoch (`expectedCheck`). A
 * key the server made up fails here.
 */
export function openEpochKey(
	sealedB64: string,
	secret: Uint8Array,
	instanceId: string,
	groupId: string,
	epoch: number,
	expectedCheck: string
): Bytes {
	const key = sealOpen(unb64(sealedB64), secret);
	if (key.length !== 32 || epochKeyCheck(instanceId, groupId, epoch, key) !== expectedCheck) {
		wipe(key);
		throw new RosterError('bad_signature', "the group key doesn't match the signed roster");
	}
	return key;
}

// ---- Signing pending work ----------------------------------------------------

/** One entry to upload, with the epoch key it rotates to (if any). */
export interface PreparedEntry {
	entry: Signed<RosterEntry>;
	epochKeys: SealedEpochKey[];
	/** The new epoch key, for the caller to keep in memory (or wipe). */
	epochKey: Bytes | null;
}

/**
 * Turn `changes` into signed entries that extend `state`, at most
 * MAX_ROSTER_CHANGES each, every one that needs it rotating the epoch (and
 * `rotate` forces a rotation into the last). Each is checked by applying
 * it to a copy of `state`, which is returned as the state after them.
 * `signer`/`seed` are the facilitator's id and Ed25519 seed.
 */
export function prepareEntries(
	state: RosterState,
	changes: RosterChange[],
	signer: string,
	seed: Uint8Array,
	opts: { now?: number; rotate?: boolean } = {}
): { entries: PreparedEntry[]; state: RosterState } {
	const byId = (a: RosterChange, b: RosterChange) => compareIds(a.user_id, b.user_id);
	// Departures go in the first entries, so no new epoch is ever sealed to
	// someone who left (the instance refuses that); joins go last.
	const rank = (c: RosterChange) =>
		c.kind === 'leave' || c.kind === 'remove' ? 0 : c.kind === 'join' ? 2 : 1;
	let ordered = [...changes].sort((a, b) => rank(a) - rank(b) || byId(a, b));
	// The first entry must contain its signer's own join, wherever their id sorts.
	const own = state.next_seq === 0 ? ordered.find((c) => c.user_id === signer) : undefined;
	if (own) ordered = ordered.filter((c) => c !== own);
	const chunks: RosterChange[][] = [];
	for (let i = 0; i < ordered.length;) {
		const room = own && i === 0 ? MAX_ROSTER_CHANGES - 1 : MAX_ROSTER_CHANGES;
		chunks.push(ordered.slice(i, i + room));
		i += room;
	}
	if (own) {
		if (chunks.length === 0) chunks.push([]);
		chunks[0].unshift(own);
	}
	for (const c of chunks) c.sort(byId);
	if (chunks.length === 0 && opts.rotate) chunks.push([]);
	const next = cloneRoster(state);
	const out: PreparedEntry[] = [];
	const now = opts.now ?? Date.now();
	chunks.forEach((chunk, i) => {
		const rotate = chunk.some(needsRotation) || (!!opts.rotate && i === chunks.length - 1);
		let epochKey: Bytes | null = null;
		let epoch: EpochRotation | null = null;
		if (rotate) {
			epochKey = randomBytes(32);
			epoch = {
				epoch: next.epoch + 1,
				key_check: epochKeyCheck(next.instance_id, next.group_id, next.epoch + 1, epochKey)
			};
		}
		const body: RosterEntry = {
			instance_id: next.instance_id,
			group_id: next.group_id,
			seq: next.next_seq,
			prev_hash: next.head,
			at_ms: now,
			signer,
			changes: chunk,
			epoch
		};
		const entry: Signed<RosterEntry> = {
			...body,
			sig: b64(sign(seed, rosterEntrySigningBytes(body)))
		};
		applyEntry(next, entry);
		out.push({
			entry,
			epochKey,
			epochKeys: epochKey ? sealEpochKey(epochKey, sortedMembers(next)) : []
		});
	});
	return { entries: out, state: next };
}

/** Sign the snapshot of `state`. */
export function signSnapshot(
	state: RosterState,
	signer: string,
	seed: Uint8Array,
	now = Date.now()
): Signed<RosterSnapshot> {
	const s = snapshotOf(state, now, signer);
	if (!s) throw new Error('nothing to snapshot yet');
	return { ...s, sig: b64(sign(seed, snapshotSigningBytes(s))) };
}

/** Whether the roster lists `userId` with exactly these keys. */
export function listsKeys(
	state: RosterState,
	userId: string,
	encPk: Uint8Array,
	signPk?: Uint8Array | null
): boolean {
	const m = state.members[userId];
	if (!m) return false;
	try {
		if (!equal(key32(m.enc_pubkey, 'enc'), encPk)) return false;
		if (signPk === undefined) return true;
		if (signPk === null) return m.sign_pubkey == null;
		return m.sign_pubkey != null && equal(key32(m.sign_pubkey, 'sign'), signPk);
	} catch {
		return false;
	}
}
