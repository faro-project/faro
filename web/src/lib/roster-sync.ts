// Keeping a group's roster in step with the instance (docs/PROTOCOL.md §10.4,
// GROUPS.md §10.3 item 4), without trusting it.
//
// The client persists a checkpoint, the `(seq, hash)` of the last entry it
// accepted, with the roster as of that entry. Each sync fetches only the
// entries after it and applies each one (`applyEntry`). When something is
// refused (a fork, a rollback, a missing entry, a bad signature, a signer who
// wasn't a facilitator) the client keeps everything it accepted before it,
// stops, and reports a warning: it never steps back or sideways.
//
// The fetches and the storage are passed in (`RosterSource`,
// `CheckpointStore`), so `npm test` can run this against a hostile source.
// `roster-api.ts` binds them to the API and to localStorage.

import { checkHead, checkpointOf, cloneRoster, emptyRoster } from './crypto/roster.ts';
import {
	applyEntry,
	RosterError,
	stateFromSnapshot,
	type RosterChange,
	type RosterEntry,
	type RosterErrorKind,
	type RosterHead,
	type RosterSnapshot,
	type RosterState
} from './crypto/roster.ts';
import type { Signed } from './crypto/proto.ts';

/** `GET /v1/groups/{id}/roster?after_seq=` */
export interface RosterPage {
	head: RosterHead | null;
	epoch: number;
	latest_snapshot_seq: number | null;
	entries: Signed<RosterEntry>[];
	more: boolean;
}

export interface RosterSource {
	/** Entries after `afterSeq` (from the first when null). */
	page(afterSeq: number | null): Promise<RosterPage>;
	/** The latest snapshot at or below `maxSeq` (any when null), or null. */
	snapshot(maxSeq: number | null): Promise<Signed<RosterSnapshot> | null>;
}

/** What is persisted per user and group. */
export interface Stored {
	head: RosterHead;
	/** The roster as of `head`; may be missing if it didn't fit in storage. */
	state?: RosterState;
}

export interface CheckpointStore {
	load(): Stored | null;
	save(state: RosterState): void;
}

export type SyncProblem = RosterErrorKind | 'incomplete' | 'unreachable';

export interface SyncResult {
	/** The last roster this client accepted (empty if it never accepted one). */
	state: RosterState;
	/** Set when something was refused or is missing. */
	problem: SyncProblem | null;
	/** A sentence for the person. */
	warning: string | null;
	/** What the instance says the head is. */
	serverHead: RosterHead | null;
	latestSnapshotSeq: number | null;
}

/** A sentence for each way a roster can fail to check out. */
export function rosterWarning(p: SyncProblem): string {
	const keep = 'Faro keeps using the last member list it checked.';
	switch (p) {
		case 'fork':
			return `The server sent a member list for this group whose history differs from the one this browser checked before. ${keep} Ask a facilitator to compare the group safety code with you.`;
		case 'rollback':
			return `The server sent an older member list for this group than this browser already checked. ${keep}`;
		case 'gap':
		case 'incomplete':
			return `The server left out part of this group's member list. ${keep} Try again later.`;
		case 'bad_signature':
		case 'not_facilitator':
		case 'no_signing_key':
		case 'genesis':
			return `A change to this group's member list wasn't signed by one of its facilitators. ${keep} Tell a facilitator.`;
		case 'unreachable':
			return `This group's member list couldn't be loaded. ${keep}`;
		default:
			return `A change to this group's member list doesn't check out. ${keep} Tell a facilitator.`;
	}
}

function problemOf(e: unknown): SyncProblem {
	return e instanceof RosterError ? e.kind : 'unreachable';
}

function sameIds(s: RosterState, instanceId: string, groupId: string): boolean {
	return s.instance_id === instanceId && s.group_id === groupId;
}

interface Advanced {
	state: RosterState;
	serverHead: RosterHead | null;
	latestSnapshotSeq: number | null;
	error: unknown;
}

/**
 * Apply every entry after `state`'s checkpoint, page by page, in place on a
 * copy. With `checkHeads`, the head the instance reports is first compared
 * with the checkpoint (rollback, fork). With `stopAt`, stops after that seq.
 * Errors are returned with the state as of the last good entry.
 */
async function advance(
	src: RosterSource,
	start: RosterState,
	opts: { checkHeads: boolean; stopAt?: number }
): Promise<Advanced> {
	const state = cloneRoster(start);
	let serverHead: RosterHead | null = null;
	let latestSnapshotSeq: number | null = null;
	try {
		for (let first = true; ; first = false) {
			const after = checkpointOf(state)?.seq ?? null;
			const page = await src.page(after);
			serverHead = page.head;
			latestSnapshotSeq = page.latest_snapshot_seq;
			if (first && opts.checkHeads) {
				if (!page.head) {
					if (state.next_seq > 0) {
						throw new RosterError('rollback', 'the server says the roster is empty');
					}
				} else {
					checkHead(state, page.head);
				}
			}
			for (const e of page.entries) {
				if (opts.stopAt !== undefined && state.next_seq > opts.stopAt) break;
				applyEntry(state, e);
			}
			const reached = opts.stopAt !== undefined && state.next_seq > opts.stopAt;
			if (reached || !page.more || page.entries.length === 0) break;
		}
		return { state, serverHead, latestSnapshotSeq, error: null };
	} catch (error) {
		return { state, serverHead, latestSnapshotSeq, error };
	}
}

function checkSnapshot(s: RosterState, instanceId: string, groupId: string): RosterState {
	if (!sameIds(s, instanceId, groupId)) {
		throw new RosterError('wrong_group', 'the snapshot is for another group');
	}
	return s;
}

/**
 * The roster as of the stored checkpoint, rebuilt when only the head was
 * stored: from the latest snapshot at or below it (or from the first entry),
 * replayed up to the checkpoint, which must then match exactly.
 */
async function rebuild(
	src: RosterSource,
	head: RosterHead,
	instanceId: string,
	groupId: string
): Promise<RosterState> {
	const snap = await src.snapshot(head.seq);
	let base = emptyRoster(instanceId, groupId);
	if (snap && snap.seq <= head.seq) {
		base = checkSnapshot(stateFromSnapshot(snap), instanceId, groupId);
	}
	const r = await advance(src, base, { checkHeads: false, stopAt: head.seq });
	if (r.error) throw r.error;
	const c = checkpointOf(r.state);
	if (!c || c.seq < head.seq) {
		throw new RosterError('rollback', 'the server no longer has the entries this browser checked');
	}
	if (c.hash !== head.hash) {
		throw new RosterError('fork', "the roster's history differs from the one this browser checked");
	}
	return r.state;
}

/**
 * Bring the roster up to date. Never throws: problems come back in the
 * result, with the last roster this client accepted.
 *
 * Without a checkpoint (a first visit, or another browser), the client has
 * nothing to compare with and accepts the latest facilitator-signed
 * snapshot as its starting point, like a device without a manifest anchor
 * (PROTOCOL.md §5.1); the group safety code is how people check it.
 */
export async function syncRoster(
	src: RosterSource,
	store: CheckpointStore,
	instanceId: string,
	groupId: string
): Promise<SyncResult> {
	const saved = store.load();
	let state: RosterState;
	try {
		if (saved?.state && sameIds(saved.state, instanceId, groupId)) {
			const c = checkpointOf(saved.state);
			state =
				c && c.seq === saved.head.seq && c.hash === saved.head.hash
					? saved.state
					: await rebuild(src, saved.head, instanceId, groupId);
		} else if (saved) {
			state = await rebuild(src, saved.head, instanceId, groupId);
		} else {
			const first = await src.page(null);
			state = emptyRoster(instanceId, groupId);
			if (first.latest_snapshot_seq != null) {
				const snap = await src.snapshot(null);
				if (snap) state = checkSnapshot(stateFromSnapshot(snap), instanceId, groupId);
			}
		}
	} catch (e) {
		const p = problemOf(e);
		return {
			state: saved?.state ?? emptyRoster(instanceId, groupId),
			problem: p,
			warning: rosterWarning(p),
			serverHead: null,
			latestSnapshotSeq: null
		};
	}

	const r = await advance(src, state, { checkHeads: true });
	if (checkpointOf(r.state)) store.save(r.state);
	let problem: SyncProblem | null = r.error ? problemOf(r.error) : null;
	const c = checkpointOf(r.state);
	if (!problem && r.serverHead && (!c || c.seq < r.serverHead.seq)) problem = 'incomplete';
	return {
		state: r.state,
		problem,
		warning: problem ? rosterWarning(problem) : null,
		serverHead: r.serverHead,
		latestSnapshotSeq: r.latestSnapshotSeq
	};
}

// ---- Storage --------------------------------------------------------------

/** A CheckpointStore on a Storage (localStorage), one key per user and group. */
export function storageStore(
	storage: Storage | null,
	userId: string,
	groupId: string
): CheckpointStore {
	const key = `faro.roster.v1.${userId}.${groupId}`;
	return {
		load() {
			try {
				const raw = storage?.getItem(key);
				if (!raw) return null;
				const v = JSON.parse(raw) as Stored;
				if (typeof v?.head?.seq !== 'number' || typeof v.head.hash !== 'string') return null;
				return v;
			} catch {
				return null;
			}
		},
		save(state) {
			const head = checkpointOf(state);
			if (!head || !storage) return;
			try {
				storage.setItem(key, JSON.stringify({ head, state } satisfies Stored));
			} catch {
				// Too big for the quota: the head alone still guards against a
				// rollback or a fork; the roster is rebuilt next time.
				try {
					storage.setItem(key, JSON.stringify({ head } satisfies Stored));
				} catch {
					// Storage is off; nothing persists.
				}
			}
		}
	};
}

/** A CheckpointStore in memory (tests). */
export function memoryStore(): CheckpointStore & { stored: Stored | null } {
	const m: CheckpointStore & { stored: Stored | null } = {
		stored: null,
		load: () => (m.stored ? structuredClone(m.stored) : null),
		save(state) {
			const head = checkpointOf(state);
			if (head) m.stored = { head, state: structuredClone(state) };
		}
	};
	return m;
}

// ---- Pending work ---------------------------------------------------------

/** `GET /v1/groups/{id}/roster/pending` */
export interface RosterPending {
	head: RosterHead | null;
	epoch: number;
	changes: RosterChange[];
	waiting_for_keys: string[];
	posting_paused: boolean;
	snapshot_due: boolean;
	latest_snapshot_seq: number | null;
}

/** The keys this facilitator's browser holds, to recognize changes about them. */
export interface OwnKeys {
	userId: string;
	encPk: string;
	signPk: string | null;
}

export interface SplitPending {
	/**
	 * Signed without asking: leaves, removals and role changes, which only
	 * mirror what facilitators and participants already did, and changes to
	 * the facilitator's own keys, which the browser checks against the keys
	 * it holds.
	 */
	auto: RosterChange[];
	/**
	 * Joins and other people's key changes: they give a key access to the
	 * group, and the instance supplied that key, so a facilitator approves
	 * them (names and key ids shown) before they are signed.
	 */
	approve: RosterChange[];
	/** Changes about this facilitator with keys that aren't theirs: never signed. */
	refused: RosterChange[];
}

/** Sort what the instance says is pending into what to sign and what to ask about. */
export function splitPending(changes: RosterChange[], me: OwnKeys): SplitPending {
	const out: SplitPending = { auto: [], approve: [], refused: [] };
	for (const c of changes) {
		if (c.kind === 'leave' || c.kind === 'remove' || c.kind === 'role') {
			out.auto.push(c);
		} else if (c.user_id === me.userId) {
			const mine = c.enc_pubkey === me.encPk && (c.sign_pubkey ?? null) === me.signPk;
			(mine ? out.auto : out.refused).push(c);
		} else {
			out.approve.push(c);
		}
	}
	return out;
}
