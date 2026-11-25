// The ally's encryption key (ARCHITECTURE.md §5.2 step 1): one X25519 key
// per ally account, created in the browser when they accept their first
// invitation, and reused for every member they support.
//
// Stored as `wrapped_privkey`: a `WrappedSecret` under the passphrase, with
// a `recovery` field holding the same secret wrapped under the recovery
// code (PROTOCOL.md §4.3). Rust readers parse it as a plain WrappedSecret.

import { api, ApiError } from '../api.ts';
import { b64, equal, unb64Fixed, wipe } from '../crypto/bytes.ts';
import { encPublicKey, newEncryptionSecret } from '../crypto/keys.ts';
import {
	deriveWrapKey,
	generateRecoveryCode,
	unwrapSecret,
	UnwrapError,
	wrapWithKey,
	type Progress
} from '../crypto/passphrase.ts';
import type { AllyKeyBlob, AllyWrappedKey } from '../types.ts';
import type { AllyKey } from './keyring.svelte.ts';

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

export { b64 };
