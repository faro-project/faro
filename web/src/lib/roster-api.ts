// A group's roster log and epoch keys, against the instance's API
// (docs/PROTOCOL.md §10, GROUPS.md §10.3 and §10.5). The rules are in
// `roster-sync.ts` and `crypto/roster.ts`; this file fetches, persists and
// uploads.
//
// What later group features (check-ins sealed with epoch keys, the group
// safety code) build on:
//
// * `loadRoster(groupId, userId)`: the verified roster, with any warning.
// * `currentEpochKey(groupId, state, encSecret)`: the current epoch key,
//   opened and checked against the signed roster.
// * `rosterPending(groupId)`: `posting_paused` says whether whole-group
//   posting must wait ("Waiting for a facilitator to update the group").
// * `groupSafetyCode` in `crypto/roster.ts`, from `checkpointOf(state)`.

import { api, ApiError, seg } from './api.ts';
import { b64, equal, unb64, unb64Fixed, wipe, type Bytes } from './crypto/bytes.ts';
import { newSigningSeed, signPublicKey } from './crypto/keys.ts';
import {
	checkpointOf,
	listsKeys,
	MAX_ROSTER_PAGE_BYTES,
	MAX_ROSTER_SNAPSHOT_BYTES,
	openEpochKey,
	prepareEntries,
	signSnapshot,
	type RosterChange,
	type RosterSnapshot,
	type RosterState
} from './crypto/roster.ts';
import type { Signed } from './crypto/proto.ts';
import { sealOpen, sealTo } from './crypto/seal.ts';
import { instance } from './instance.svelte.ts';
import type { AllyKey } from './keys/keyring.svelte.ts';
import {
	splitPending,
	storageStore,
	syncRoster,
	type OwnKeys,
	type RosterPage,
	type RosterPending,
	type RosterSource,
	type SyncResult
} from './roster-sync.ts';

function storage(): Storage | null {
	try {
		return globalThis.localStorage ?? null;
	} catch {
		return null;
	}
}

export function apiSource(groupId: string): RosterSource {
	const base = `/v1/groups/${seg(groupId)}/roster`;
	return {
		page: (after) =>
			api.getCapped<RosterPage>(
				after === null ? base : `${base}?after_seq=${after}`,
				MAX_ROSTER_PAGE_BYTES
			),
		snapshot: (max) =>
			api
				.getCapped<Signed<RosterSnapshot>>(
					max === null ? `${base}/snapshot` : `${base}/snapshot?max_seq=${max}`,
					MAX_ROSTER_SNAPSHOT_BYTES
				)
				.catch((e) => {
					if (e instanceof ApiError && e.status === 404) return null;
					throw e;
				})
	};
}

/** The roster as this browser has verified it, brought up to date. */
export async function loadRoster(groupId: string, userId: string): Promise<SyncResult> {
	const inst = await instance.load();
	return syncRoster(
		apiSource(groupId),
		storageStore(storage(), userId, groupId),
		inst.instance_id,
		groupId
	);
}

export function rosterPending(groupId: string): Promise<RosterPending> {
	return api.get<RosterPending>(`/v1/groups/${seg(groupId)}/roster/pending`);
}

// ---- Epoch keys -------------------------------------------------------------

interface EpochKeyView {
	epoch: number;
	seq: number;
	key_check: string;
	sealed_key: string;
}

/**
 * The current epoch key (or `epoch`), opened with the X25519 `encSecret`
 * and checked against the commitment this browser verified in the roster.
 * Null if the caller has no copy (not added yet, or joined later).
 */
export async function currentEpochKey(
	groupId: string,
	state: RosterState,
	encSecret: Uint8Array,
	epoch?: number
): Promise<{ epoch: number; key: Bytes } | null> {
	let v: EpochKeyView;
	try {
		const q = epoch === undefined ? '' : `?epoch=${epoch}`;
		v = await api.get<EpochKeyView>(`/v1/groups/${seg(groupId)}/epoch-key${q}`);
	} catch (e) {
		if (e instanceof ApiError && e.status === 404) return null;
		throw e;
	}
	const expected = state.epoch_checks[String(v.epoch)];
	if (!expected) return null; // not an epoch this browser has verified
	const key = openEpochKey(
		v.sealed_key,
		encSecret,
		state.instance_id,
		state.group_id,
		v.epoch,
		expected
	);
	return { epoch: v.epoch, key };
}

// ---- Keys ---------------------------------------------------------------------

export interface GroupSignKeyBlob {
	sign_pubkey: string;
	enc_pubkey: string;
	sealed_seed: string;
}

export function getGroupSignKey(): Promise<GroupSignKeyBlob | null> {
	return api.get<GroupSignKeyBlob>('/v1/me/group-sign-key').catch((e) => {
		if (e instanceof ApiError && e.status === 404) return null;
		throw e;
	});
}

/** Open an ally-only facilitator's group signing key with their unlocked ally key. */
export function openGroupSignKey(blob: GroupSignKeyBlob, ally: AllyKey): Bytes {
	if (!equal(unb64Fixed(blob.enc_pubkey, 32), ally.encPk)) {
		throw new Error('Your group signing key is sealed to another key.');
	}
	const seed = sealOpen(unb64(blob.sealed_seed), ally.encSecret);
	if (seed.length !== 32 || !equal(signPublicKey(seed), unb64Fixed(blob.sign_pubkey, 32))) {
		wipe(seed);
		throw new Error("The group signing key on the server doesn't match its public half.");
	}
	return seed;
}

/**
 * Make a group signing key for an ally-only facilitator (GROUPS.md decision
 * 6): a new Ed25519 seed, sealed to their own encryption key so their
 * passphrase or recovery code opens it with that key. Returns the seed.
 */
export async function createGroupSignKey(ally: AllyKey): Promise<Bytes> {
	const seed = newSigningSeed();
	await api.put('/v1/me/group-sign-key', {
		sign_pubkey: b64(signPublicKey(seed)),
		enc_pubkey: b64(ally.encPk),
		sealed_seed: b64(sealTo(ally.encPk, seed))
	});
	return seed;
}

// ---- Facilitators: signing pending work ---------------------------------------

export interface Signer {
	userId: string;
	seed: Uint8Array;
	encPk: Uint8Array;
}

export interface WorkResult {
	state: RosterState;
	pending: RosterPending;
	/** Entries signed and uploaded. */
	signed: number;
	/** Waiting for the facilitator's approval (joins, others' key changes). */
	needsApproval: RosterChange[];
	/** Changes about this facilitator with keys that aren't theirs. */
	refused: RosterChange[];
}

/**
 * What a facilitator's client does when it opens a group: sign and upload
 * everything pending that it may sign on its own, plus `approved` (changes
 * the facilitator approved, by user id), rotating the epoch as each entry
 * requires, and a snapshot when one is due. Every change is checked against
 * the roster this browser verified (`state`) before it is signed.
 */
export async function signPendingWork(
	groupId: string,
	state: RosterState,
	signer: Signer,
	approved: Set<string> = new Set()
): Promise<WorkResult> {
	const me: OwnKeys = {
		userId: signer.userId,
		encPk: b64(signer.encPk),
		signPk: b64(signPublicKey(signer.seed))
	};
	let signed = 0;
	let pending = await rosterPending(groupId);
	let split = splitPending(pending.changes, me);
	for (let round = 0; round < 6; round++) {
		const head = checkpointOf(state);
		if ((pending.head?.seq ?? -1) !== (head?.seq ?? -1) || pending.head?.hash !== head?.hash) {
			// The instance's head isn't ours: someone else signed. Sync first.
			throw new Error('The group changed while you were updating it. Reload the page.');
		}
		const todo = [...split.auto, ...split.approve.filter((c) => approved.has(c.user_id))];
		// The facilitator needs to be in the roster (and able to sign) first.
		if (todo.length === 0) break;
		const r = prepareEntries(state, todo, signer.userId, signer.seed);
		for (const p of r.entries) {
			await api.post(`/v1/groups/${seg(groupId)}/roster`, {
				entry: p.entry,
				epoch_keys: p.epochKeys
			});
			wipe(p.epochKey);
			signed++;
		}
		state = r.state;
		storageStore(storage(), signer.userId, groupId).save(state);
		pending = await rosterPending(groupId);
		split = splitPending(pending.changes, me);
	}
	if (pending.snapshot_due && checkpointOf(state)) {
		await api.post(
			`/v1/groups/${seg(groupId)}/roster/snapshot`,
			signSnapshot(state, signer.userId, signer.seed)
		);
	}
	return { state, pending, signed, needsApproval: split.approve, refused: split.refused };
}

/** Whether `state` lists the signer as a facilitator with this signing key. */
export function canSign(state: RosterState, signer: Signer): boolean {
	if (state.next_seq === 0) return true; // the first entry is theirs to sign
	const m = state.members[signer.userId];
	return (
		m?.role === 'facilitator' &&
		listsKeys(state, signer.userId, signer.encPk, signPublicKey(signer.seed))
	);
}
