// The ally's encryption key (ARCHITECTURE.md §5.2 step 1): one X25519 key
// per ally account, created in the browser when they accept their first
// invitation, and reused for every member they support.
//
// Stored as `wrapped_privkey`: a `WrappedSecret` under the passphrase, with
// a `recovery` field holding the same secret wrapped under the recovery
// code (PROTOCOL.md §4.3). Rust readers parse it as a plain WrappedSecret.

import { api, ApiError } from '../api.ts';
import { b64, equal, unb64, unb64Fixed, wipe, type Bytes } from '../crypto/bytes.ts';
import { encPublicKey, newEncryptionSecret } from '../crypto/keys.ts';
import {
	deriveWrapKey,
	generateRecoveryCode,
	unwrapSecret,
	UnwrapError,
	wrapWithKey,
	type Progress
} from '../crypto/passphrase.ts';
import { proveAllyKeyRewrap } from '../crypto/proto.ts';
import { DecryptError, sealOpen } from '../crypto/seal.ts';
import type { AllyKeyBlob, AllyKeyChallenge, AllyWrappedKey } from '../types.ts';
import type { AllyKey } from './keyring.svelte.ts';
import { rewrapAllyWrapped, type RewrapChoice } from './wrapping.ts';

export function getAllyKey(): Promise<AllyKeyBlob | null> {
	return api.get<AllyKeyBlob>('/v1/me/ally-key').catch((e) => {
		if (e instanceof ApiError && e.status === 404) return null;
		throw e;
	});
}

export interface NewAllyKey {
	key: AllyKey;
	wrapped: AllyWrappedKey;
	recoveryCode: string;
}

/** Generate and wrap a new ally key (not uploaded: accepting does that). */
export async function newAllyKey(
	userId: string,
	passphrase: string,
	onProgress?: Progress
): Promise<NewAllyKey> {
	const encSecret = newEncryptionSecret();
	const encPk = encPublicKey(encSecret);
	const recoveryCode = generateRecoveryCode();
	const pw = await deriveWrapKey(passphrase, undefined, undefined, (f) => onProgress?.(f / 2));
	const rc = await deriveWrapKey(recoveryCode, undefined, undefined, (f) =>
		onProgress?.(0.5 + f / 2)
	);
	try {
		const wrapped: AllyWrappedKey = {
			...wrapWithKey(encSecret, pw),
			recovery: wrapWithKey(encSecret, rc)
		};
		return { key: { userId, encSecret, encPk }, wrapped, recoveryCode };
	} finally {
		wipe(pw.key, rc.key);
	}
}

/** Open the ally key with the passphrase or (normalized) recovery code. */
export async function unlockAllyKey(
	blob: AllyKeyBlob,
	userId: string,
	secret: string,
	recovery: boolean,
	onProgress?: Progress
): Promise<AllyKey> {
	const w = blob.wrapped_privkey as AllyWrappedKey | null;
	const target = recovery ? w?.recovery : w;
	if (!target) {
		throw new UnwrapError('unsupported', 'This key has no recovery copy.');
	}
	const encSecret = await unwrapSecret(target, secret, onProgress);
	const encPk = encPublicKey(encSecret);
	if (encSecret.length !== 32 || !equal(encPk, unb64Fixed(blob.enc_pubkey, 32))) {
		wipe(encSecret);
		throw new UnwrapError(
			'unsupported',
			'The key stored on the server does not match its public half.'
		);
	}
	return { userId, encSecret, encPk };
}

/**
 * Re-wrap the unlocked ally key under a new passphrase and/or a new
 * recovery code (`PUT /v1/me/ally-key/wrapped`, PROTOCOL.md §4.3). The key
 * itself doesn't change, so members see no new safety code. An X25519 key
 * can't sign, so the request is proven with a challenge the instance seals
 * to the key: it is opened here and only a MAC keyed with it is sent back.
 * Returns the new recovery code, if one was made.
 */
export async function rewrapAllyKey(
	key: AllyKey,
	instanceId: string,
	choice: RewrapChoice,
	onProgress?: Progress
): Promise<string | null> {
	const current = await getAllyKey();
	if (!current || !equal(unb64Fixed(current.enc_pubkey, 32), key.encPk)) {
		throw new UnwrapError('unsupported', 'The key on the server is not the one you unlocked.');
	}
	const { wrapped, recoveryCode } = await rewrapAllyWrapped(
		key.encSecret,
		key.encPk,
		current.wrapped_privkey,
		choice,
		onProgress
	);
	const c = await api.post<AllyKeyChallenge>('/v1/me/ally-key/challenge');
	if (!equal(unb64Fixed(c.enc_pubkey, 32), key.encPk)) {
		throw new UnwrapError('unsupported', 'The server asked about a different key.');
	}
	let challenge: Bytes | null = null;
	try {
		challenge = sealOpen(unb64(c.sealed_challenge), key.encSecret);
		const body = proveAllyKeyRewrap(
			{
				instance_id: instanceId,
				ally_id: key.userId,
				enc_pubkey: b64(key.encPk),
				issued_at_ms: c.issued_at_ms,
				wrapped_privkey: wrapped
			},
			challenge
		);
		await api.put('/v1/me/ally-key/wrapped', body);
	} catch (e) {
		if (e instanceof DecryptError) {
			throw new UnwrapError('unsupported', "The server's challenge isn't for your key.");
		}
		throw e;
	} finally {
		wipe(challenge);
	}
	return recoveryCode;
}

export { b64 };
