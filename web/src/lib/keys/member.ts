// Member keys (ARCHITECTURE.md §5.2, PROTOCOL.md §4.3 and §5): created and
// unlocked in the browser; the instance stores only public keys and
// passphrase-wrapped secrets it cannot open.
//
// Storage format (opaque to the server, documented in PROTOCOL.md §4.3):
//
// * `wrapped_sign_key` and `wrapped_enc_key`: the Ed25519 seed and the
//   X25519 secret, each a `WrappedSecret` under the passphrase. Both use
//   one Argon2id derivation (same salt and parameters, separate random
//   nonces), so unlocking costs one derivation.
// * `recovery_wrapped`: `{sign, enc}`, the same two secrets wrapped under
//   the recovery code, likewise sharing one derivation.

import { api, ApiError, seg } from '../api.ts';
import { b64, equal, unb64Fixed, wipe } from '../crypto/bytes.ts';
import {
	encPublicKey,
	newEncryptionSecret,
	newSigningSeed,
	signPublicKey
} from '../crypto/keys.ts';
import {
	deriveFor,
	deriveWrapKey,
	generateRecoveryCode,
	sameDerivation,
	unwrapWithKey,
	UnwrapError,
	wrapWithKey,
	type Progress
} from '../crypto/passphrase.ts';
import {
	checkManifest,
	keyRewrapSigningBytes,
	manifestRef,
	manifestSigningBytes,
	memberBindingSigningBytes,
	nextManifest,
	signWith,
	verifySigned,
	type ManifestAlly,
	type RecipientManifest,
	type Signed
} from '../crypto/proto.ts';
import type { MemberKeysBlob, PutMemberKeys, RecoveryWrapped, User } from '../types.ts';
import type { MemberKeys } from './keyring.svelte.ts';
import { rewrapMemberWrapped, type RewrapChoice } from './wrapping.ts';

export const MIN_PASSPHRASE = 10;

/** A short reason a passphrase is not acceptable, or null. */
export function passphraseProblem(p: string): string | null {
	if ([...p].length < MIN_PASSPHRASE) return `Use at least ${MIN_PASSPHRASE} characters.`;
	if (/^(.)\1+$/u.test(p)) return 'Use more than one repeated character.';
	return null;
}

export interface CreatedKeys {
	keys: MemberKeys;
	recoveryCode: string;
}

/**
 * Generate member keys, wrap them, and store them on the instance
 * (`PUT /v1/me/keys`). Two Argon2id runs: passphrase and recovery code.
 */
export async function createMemberKeys(
	user: User,
	instanceId: string,
	passphrase: string,
	onProgress?: Progress
): Promise<CreatedKeys> {
	const signSeed = newSigningSeed();
	const encSecret = newEncryptionSecret();
	const signPk = signPublicKey(signSeed);
	const encPk = encPublicKey(encSecret);
	const recoveryCode = generateRecoveryCode();

	const half = (from: number) => (f: number) => onProgress?.(from + f / 2);
	const pw = await deriveWrapKey(passphrase, undefined, undefined, half(0));
	const rc = await deriveWrapKey(recoveryCode, undefined, undefined, half(0.5));
	let body: PutMemberKeys;
	try {
		const recovery: RecoveryWrapped = {
			sign: wrapWithKey(signSeed, rc),
			enc: wrapWithKey(encSecret, rc)
		};
		body = {
			sign_pubkey: b64(signPk),
			enc_binding: signWith(
				signSeed,
				{
					instance_id: instanceId,
					member_id: user.id,
					member_enc_pubkey: b64(encPk),
					endorsed_at_ms: Date.now()
				},
				memberBindingSigningBytes
			),
			wrapped_sign_key: wrapWithKey(signSeed, pw),
			wrapped_enc_key: wrapWithKey(encSecret, pw),
			recovery_wrapped: recovery
		};
	} finally {
		wipe(pw.key, rc.key);
	}
	await api.put('/v1/me/keys', body);
	return { keys: { userId: user.id, signSeed, signPk, encSecret, encPk }, recoveryCode };
}

export function getMemberKeys(): Promise<MemberKeysBlob | null> {
	return api.get<MemberKeysBlob>('/v1/me/keys').catch((e) => {
		if (e instanceof ApiError && e.status === 404) return null;
		throw e;
	});
}

/**
 * Open the member keys with the passphrase, or with the recovery code when
 * `recovery` is set (the code must already be normalized). Checks that the
 * secrets match the stored public keys and that the encryption key binding
 * is signed by the signing key, so a tampered blob can't slip in other keys.
 */
export async function unlockMemberKeys(
	blob: MemberKeysBlob,
	userId: string,
	secret: string,
	recovery: boolean,
	onProgress?: Progress
): Promise<MemberKeys> {
	let wSign: unknown, wEnc: unknown;
	if (recovery) {
		const r = blob.recovery_wrapped as Partial<RecoveryWrapped> | null;
		if (!r?.sign || !r?.enc) {
			throw new UnwrapError('unsupported', 'These keys have no recovery copy in this format.');
		}
		wSign = r.sign;
		wEnc = r.enc;
	} else {
		wSign = blob.wrapped_sign_key;
		wEnc = blob.wrapped_enc_key;
	}
	const k = await deriveFor(wSign, secret, onProgress);
	let signSeed: Uint8Array | null = null;
	let encSecret: Uint8Array | null = null;
	try {
		signSeed = unwrapWithKey(wSign, k);
		if (sameDerivation(wEnc, k)) {
			encSecret = unwrapWithKey(wEnc, k);
		} else {
			const k2 = await deriveFor(wEnc, secret);
			try {
				encSecret = unwrapWithKey(wEnc, k2);
			} finally {
				wipe(k2.key);
			}
		}
	} catch (e) {
		wipe(signSeed, encSecret);
		throw e;
	} finally {
		wipe(k.key);
	}
	const signPk = signPublicKey(signSeed);
	const encPk = encPublicKey(encSecret);
	const binding = blob.enc_binding;
	const ok =
		signSeed.length === 32 &&
		encSecret.length === 32 &&
		equal(signPk, unb64Fixed(blob.sign_pubkey, 32)) &&
		equal(encPk, unb64Fixed(binding.member_enc_pubkey, 32)) &&
		binding.member_id === userId &&
		verifySigned(signPk, binding, memberBindingSigningBytes);
	if (!ok) {
		wipe(signSeed, encSecret);
		throw new UnwrapError(
			'unsupported',
			'The keys stored on the server do not match their public halves.'
		);
	}
	return {
		userId,
		signSeed: signSeed as MemberKeys['signSeed'],
		signPk,
		encSecret: encSecret as MemberKeys['encSecret'],
		encPk
	};
}

// ---- Recipient manifests --------------------------------------------------

export class ManifestTrustError extends Error {
	constructor(reason: string) {
		super(`The recipient list the server returned can't be trusted: ${reason}.`);
		this.name = 'ManifestTrustError';
	}
}

/**
 * The member's latest recipient manifest, verified against their own
 * signing key. Null if they have none yet.
 */
export async function latestManifest(
	keys: MemberKeys,
	instanceId: string
): Promise<Signed<RecipientManifest> | null> {
	let m: Signed<RecipientManifest>;
	try {
		m = await api.get<Signed<RecipientManifest>>(
			`/v1/members/${seg(keys.userId)}/recipient-manifest`
		);
	} catch (e) {
		if (e instanceof ApiError && e.status === 404) return null;
		throw e;
	}
	const bad = checkManifest(m, keys.signPk, instanceId, keys.userId);
	if (bad) throw new ManifestTrustError(bad);
	if (!equal(unb64Fixed(m.member_enc_pubkey, 32), keys.encPk)) {
		throw new ManifestTrustError('it lists a different key for you');
	}
	return m;
}

/** Sign a manifest body with the member key. */
export function signManifest(keys: MemberKeys, m: RecipientManifest): Signed<RecipientManifest> {
	return signWith(keys.signSeed, m, manifestSigningBytes);
}

/**
 * The first manifest (version 1). Lists `allies` (normally none: allies are
 * added by approving them, which signs the next version).
 */
export function firstManifest(
	keys: MemberKeys,
	instanceId: string,
	allies: ManifestAlly[] = []
): Signed<RecipientManifest> {
	const base: RecipientManifest = {
		instance_id: instanceId,
		member_id: keys.userId,
		version: 0,
		issued_at_ms: 0,
		member_enc_pubkey: b64(keys.encPk),
		allies: []
	};
	return signManifest(keys, nextManifest(base, allies));
}

/** Sign and upload the first manifest if there is none. Returns the latest. */
export async function ensureManifest(
	keys: MemberKeys,
	instanceId: string,
	activeAllies: () => Promise<ManifestAlly[]>
): Promise<Signed<RecipientManifest>> {
	const latest = await latestManifest(keys, instanceId);
	if (latest) return latest;
	const m = firstManifest(keys, instanceId, await activeAllies());
	await api.put('/v1/me/recipient-manifest', m);
	return m;
}

// ---- Changing the passphrase ----------------------------------------------

/**
 * Re-wrap the unlocked member keys under a new passphrase and/or a new
 * recovery code, signed with the member key so the server accepts the
 * replacement (`PUT /v1/me/keys/wrapped`, PROTOCOL.md §4.3). The keys
 * themselves don't change, and each new copy is checked before it is sent
 * (`wrapping.ts`). Returns the new recovery code, if one was made.
 */
export async function rewrapMemberKeys(
	keys: MemberKeys,
	instanceId: string,
	choice: RewrapChoice,
	onProgress?: Progress
): Promise<string | null> {
	const current = await getMemberKeys();
	if (!current) throw new Error('Your keys are not set up.');
	if (
		!equal(unb64Fixed(current.sign_pubkey, 32), keys.signPk) ||
		!equal(unb64Fixed(current.enc_binding.member_enc_pubkey, 32), keys.encPk)
	) {
		throw new UnwrapError('unsupported', 'The keys on the server are not the ones you unlocked.');
	}
	const { recoveryCode, ...wrapped } = await rewrapMemberWrapped(keys, current, choice, onProgress);
	const body = signWith(
		keys.signSeed,
		{
			instance_id: instanceId,
			member_id: keys.userId,
			sign_pubkey: b64(keys.signPk),
			issued_at_ms: Date.now(),
			...wrapped
		},
		keyRewrapSigningBytes
	);
	await api.put('/v1/me/keys/wrapped', body);
	return recoveryCode;
}

export { manifestRef, nextManifest };
