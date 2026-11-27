// What this browser checks before it builds on, or anchors a computer to,
// the recipient list the instance serves (PROTOCOL.md §5.1, "The member's
// web app"), without trusting the instance:
//
// * The list must verify against the member's own unlocked key
//   (`checkManifest`) and name their own encryption key.
// * It must not be older than the highest list this browser has signed or
//   seen (the checkpoint, kept in localStorage like a group roster's), nor a
//   different list at that version, nor, when it is the next version, one
//   built on another list (format 3 `prev_hash`). A 404 once this browser
//   has a checkpoint is a rollback too. Otherwise an instance could serve an
//   older list that still names a removed ally, and the page would anchor a
//   new computer to it or sign the next version on top of it.
// * Allies keep the name the last list signed (`namesToSign`); a new name
//   from the instance is signed only once the member confirms it on screen.
//
// Nothing here talks to the API or to storage directly: `member.ts` binds it
// to both, and `npm test` runs it against a lying server
// (`manifest-trust.test.ts`).

import { b64, equal, unb64Fixed } from '../crypto/bytes.ts';
import {
	checkManifest,
	MANIFEST_FORMAT_V3,
	manifestRef,
	manifestSigningBytes,
	nextManifest,
	sanitizeAllyName,
	signWith,
	type ManifestAlly,
	type ManifestRef,
	type RecipientManifest,
	type Signed
} from '../crypto/proto.ts';
import type { MemberKeys } from './keyring.svelte.ts';

export type ManifestTrustProblem = 'invalid' | 'rollback' | 'fork';

export class ManifestTrustError extends Error {
	readonly problem: ManifestTrustProblem;

	constructor(reason: string, problem: ManifestTrustProblem = 'invalid') {
		super(`The recipient list the server returned can't be trusted: ${reason}.`);
		this.name = 'ManifestTrustError';
		this.problem = problem;
	}
}

/** The highest list this browser has signed or seen, per member. */
export interface ManifestCheckpointStore {
	load(): ManifestRef | null;
	/** Never moves backwards: a lower version than the stored one is ignored. */
	save(r: ManifestRef): void;
}

function isRef(v: unknown): v is ManifestRef {
	const r = v as ManifestRef | null;
	return (
		Number.isSafeInteger(r?.version) &&
		(r?.version ?? 0) >= 1 &&
		typeof r?.hash === 'string' &&
		/^b3:[0-9a-f]{64}$/.test(r.hash)
	);
}

/** A checkpoint store on a Storage (localStorage), one key per instance and member. */
export function storageManifestStore(
	storage: Storage | null,
	instanceId: string,
	userId: string
): ManifestCheckpointStore {
	const key = `faro.manifest.v1.${instanceId}.${userId}`;
	const load = (): ManifestRef | null => {
		try {
			const raw = storage?.getItem(key);
			if (!raw) return null;
			const v: unknown = JSON.parse(raw);
			return isRef(v) ? { version: v.version, hash: v.hash } : null;
		} catch {
			return null;
		}
	};
	return {
		load,
		save(r) {
			const have = load();
			if (!storage || (have && have.version >= r.version)) return;
			try {
				storage.setItem(key, JSON.stringify({ version: r.version, hash: r.hash }));
			} catch {
				// Storage is off: nothing persists, and only this page load is
				// protected.
			}
		}
	};
}

/** A checkpoint store in memory (tests). */
export function memoryManifestStore(
	initial: ManifestRef | null = null
): ManifestCheckpointStore & { stored: ManifestRef | null } {
	const s: ManifestCheckpointStore & { stored: ManifestRef | null } = {
		stored: initial,
		load: () => (s.stored ? { ...s.stored } : null),
		save(r) {
			if (!s.stored || s.stored.version < r.version) s.stored = { ...r };
		}
	};
	return s;
}

/** The member's keys this needs: public halves only. */
export interface ManifestOwner {
	userId: string;
	signPk: Uint8Array;
	encPk: Uint8Array;
}

/**
 * Check what the instance served for the member's latest list (null for a
 * 404) against their key and this browser's checkpoint, and advance the
 * checkpoint. Returns the list to build on, or null if the member has none
 * yet. Throws [ManifestTrustError] on anything else.
 */
export function acceptServed(
	served: Signed<RecipientManifest> | null,
	owner: ManifestOwner,
	instanceId: string,
	store: ManifestCheckpointStore
): Signed<RecipientManifest> | null {
	const have = store.load();
	if (!served) {
		if (have) {
			throw new ManifestTrustError(
				`it says you have none, but this browser has already seen version ${have.version}`,
				'rollback'
			);
		}
		return null;
	}
	const bad = checkManifest(served, owner.signPk, instanceId, owner.userId);
	if (bad) throw new ManifestTrustError(bad);
	if (!equal(unb64Fixed(served.member_enc_pubkey, 32), owner.encPk)) {
		throw new ManifestTrustError('it lists a different key for you');
	}
	const got = manifestRef(served);
	if (have) {
		if (got.version < have.version) {
			throw new ManifestTrustError(
				`it is version ${got.version}, older than version ${have.version}, which this browser has already seen`,
				'rollback'
			);
		}
		if (got.version === have.version && got.hash !== have.hash) {
			throw new ManifestTrustError(
				`it is a different list from the version ${have.version} this browser has already seen`,
				'fork'
			);
		}
		if (
			got.version === have.version + 1 &&
			served.prev_hash != null &&
			served.prev_hash !== have.hash
		) {
			throw new ManifestTrustError(
				`it was built on another list than the version ${have.version} this browser has already seen`,
				'fork'
			);
		}
	}
	store.save(got);
	return served;
}

/** After an upload the instance accepted: this browser signed `m`. */
export function recordSigned(store: ManifestCheckpointStore, m: RecipientManifest): void {
	store.save(manifestRef(m));
}

/** Where the member's latest list comes from and goes to (the API, or a test stub). */
export interface ManifestSource {
	/** `GET /v1/members/{id}/recipient-manifest`; null for a 404. */
	latest(): Promise<Signed<RecipientManifest> | null>;
	/** `PUT /v1/me/recipient-manifest` */
	put(m: Signed<RecipientManifest>): Promise<unknown>;
}

/**
 * The first list (version 1): only the member's own key. Allies are added
 * by approving them, which signs the next version, so nothing the instance
 * says about active allies is ever signed here (#178).
 */
export function firstManifest(
	keys: MemberKeys,
	instanceId: string,
	now = Date.now()
): Signed<RecipientManifest> {
	return signWith(
		keys.signSeed,
		{
			format: MANIFEST_FORMAT_V3,
			instance_id: instanceId,
			member_id: keys.userId,
			version: 1,
			issued_at_ms: now,
			member_enc_pubkey: b64(keys.encPk),
			allies: []
		},
		manifestSigningBytes
	);
}

/**
 * The checked latest list, after signing and uploading the first one if
 * the member has none (and this browser has never seen one: then a 404 is
 * a rollback, [acceptServed]).
 */
export async function ensureManifestWith(
	src: ManifestSource,
	keys: MemberKeys,
	instanceId: string,
	store: ManifestCheckpointStore
): Promise<Signed<RecipientManifest>> {
	const latest = acceptServed(await src.latest(), keys, instanceId, store);
	if (latest) return latest;
	const m = firstManifest(keys, instanceId);
	await src.put(m);
	recordSigned(store, m);
	return m;
}

// ---- What the next list says ----------------------------------------------

/** An ally whose name on the instance isn't the one the last list signed. */
export interface NameChange {
	ally_id: string;
	/** The name in the list being built on (sanitized; may be empty). */
	signed: string;
	/** The name the instance shows now (sanitized). */
	current: string;
}

/**
 * The allies of `base` whose current display name (`current`, as the page
 * shows it) differs from the one `base` signed. A name the instance no
 * longer has, or an empty one, is no change.
 */
export function nameChanges(
	base: RecipientManifest,
	current: ReadonlyMap<string, string>
): NameChange[] {
	const out: NameChange[] = [];
	for (const a of base.allies) {
		const now = current.get(a.ally_id);
		if (now === undefined) continue;
		const cur = sanitizeAllyName(now);
		const signed = sanitizeAllyName(a.name ?? '');
		if (cur !== '' && cur !== signed) out.push({ ally_id: a.ally_id, signed, current: cur });
	}
	return out;
}

/**
 * The name to sign for each ally of `base`: the one `base` signed, unless
 * the member confirmed the new one (`accepted`, by ally id).
 */
export function namesToSign(
	base: RecipientManifest,
	current: ReadonlyMap<string, string>,
	accepted: ReadonlySet<string> = new Set()
): Map<string, string> {
	return new Map(
		base.allies.map((a) => {
			const now = current.get(a.ally_id);
			return [a.ally_id, accepted.has(a.ally_id) && now !== undefined ? now : (a.name ?? '')];
		})
	);
}

/** How the next list differs from the one it is built on. */
export type ManifestChange =
	| { kind: 'add'; ally: ManifestAlly }
	| { kind: 'remove'; ids: ReadonlySet<string> }
	| { kind: 'same' };

/**
 * The next version after `base` with `change`, each remaining ally named
 * as `names` says (default: the name `base` signed). This is both what the
 * page shows before signing and what it signs.
 */
export function planNext(
	base: RecipientManifest,
	change: ManifestChange,
	names: ReadonlyMap<string, string> = new Map(),
	now?: number
): RecipientManifest {
	const removed = change.kind === 'remove' ? change.ids : new Set<string>();
	const allies: ManifestAlly[] = base.allies
		.filter((a) => !removed.has(a.ally_id))
		.map((a) => ({
			ally_id: a.ally_id,
			enc_pubkey: a.enc_pubkey,
			name: names.get(a.ally_id) ?? a.name ?? ''
		}));
	if (change.kind === 'add') allies.push(change.ally);
	return nextManifest(base, allies, now);
}
