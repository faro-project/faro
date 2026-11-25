// New wrapped copies of keys that are already unlocked (PROTOCOL.md §4.3):
// a new passphrase, a new recovery code, or both. The keys themselves never
// change.
//
// The instance can't tell a good wrapped copy from a broken one, and a
// broken one would lock the person out of their keys. So every new copy is
// opened again here, from the exact JSON text that will be uploaded, and
// what comes out must have the stored public key. Only then is it sent.
//
// No API calls here (`member.ts` and `ally.ts` make them), so `npm test`
// can run it.

import { equal, wipe, type Bytes } from '../crypto/bytes.ts';
import { encPublicKey, signPublicKey } from '../crypto/keys.ts';
import {
	DEFAULT_KDF,
	deriveWrapKey,
	generateRecoveryCode,
	sameDerivation,
	unwrapWithKey,
	UnwrapError,
	wrapWithKey,
	type KdfParams,
	type Progress,
	type WrapKey,
	type WrappedSecret
} from '../crypto/passphrase.ts';
import type { AllyWrappedKey, RecoveryWrapped } from '../types.ts';

/** What to replace. At least one must be set. */
export interface RewrapChoice {
	/** The new passphrase, or null to keep the current passphrase copy. */
	passphrase: string | null;
	/** Make a new recovery code (the old one stops working). */
	newRecovery: boolean;
}

const CHECK_FAILED =
	"The new copy of your key didn't open to the same key, so nothing was changed. Reload the page and try again.";

/**
 * Open `text` (the JSON that will be uploaded) with `k` and check that the
 * secret inside has the public key `pk`. Throws if not.
 */
export function checkWrapped(
	text: string,
	k: WrapKey,
	publicOf: (secret: Bytes) => Bytes,
	pk: Uint8Array
): void {
	let secret: Bytes | null = null;
	let ok = false;
	try {
		const w: unknown = JSON.parse(text);
		if (sameDerivation(w, k)) {
			secret = unwrapWithKey(w, k);
			ok = secret.length === 32 && equal(publicOf(secret), pk);
		}
	} catch {
		ok = false;
	} finally {
		wipe(secret);
	}
	if (!ok) throw new UnwrapError('unsupported', CHECK_FAILED);
}

/** Run the Argon2id derivations a choice needs, reporting overall progress. */
async function derive(
	choice: RewrapChoice,
	params: KdfParams,
	onProgress?: Progress
): Promise<{ pw: WrapKey | null; rc: WrapKey | null; recoveryCode: string | null }> {
	if (!choice.passphrase && !choice.newRecovery) throw new Error('Nothing to change.');
	const steps = (choice.passphrase ? 1 : 0) + (choice.newRecovery ? 1 : 0);
	let done = 0;
	const step = () => {
		const from = done++ / steps;
		return (f: number) => onProgress?.(from + f / steps);
	};
	const pw = choice.passphrase
		? await deriveWrapKey(choice.passphrase, params, undefined, step())
		: null;
	const recoveryCode = choice.newRecovery ? generateRecoveryCode() : null;
	try {
		const rc = recoveryCode ? await deriveWrapKey(recoveryCode, params, undefined, step()) : null;
		return { pw, rc, recoveryCode };
	} catch (e) {
		wipe(pw?.key);
		throw e;
	}
}

/** Wrap `secret` under `k` and check the result; returns its JSON text. */
function wrapChecked(
	secret: Bytes,
	k: WrapKey,
	publicOf: (secret: Bytes) => Bytes,
	pk: Uint8Array
): string {
	const text = JSON.stringify(wrapWithKey(secret, k));
	checkWrapped(text, k, publicOf, pk);
	return text;
}

export interface AllyRewrapped {
	/** The new `wrapped_privkey`, as the JSON text to upload. */
	wrapped: string;
	recoveryCode: string | null;
}

/**
 * New `wrapped_privkey` for the unlocked ally key (`encSecret`, whose public
 * key is `encPk`). Whatever `choice` doesn't replace is kept from `current`,
 * the stored value.
 */
export async function rewrapAllyWrapped(
	encSecret: Bytes,
	encPk: Uint8Array,
	current: unknown,
	choice: RewrapChoice,
	onProgress?: Progress,
	params: KdfParams = DEFAULT_KDF
): Promise<AllyRewrapped> {
	const cur = (current && typeof current === 'object' ? current : {}) as Partial<AllyWrappedKey>;
	const { pw, rc, recoveryCode } = await derive(choice, params, onProgress);
	try {
		let pass: Record<string, unknown>;
		if (pw) {
			pass = JSON.parse(wrapChecked(encSecret, pw, encPublicKey, encPk));
		} else {
			pass = { ...cur };
			delete pass.recovery;
		}
		const recovery: unknown = rc
			? JSON.parse(wrapChecked(encSecret, rc, encPublicKey, encPk))
			: cur.recovery;
		const wrapped = JSON.stringify(recovery ? { ...pass, recovery } : pass);
		// The passphrase copy is the outer object, so check it in place too.
		if (pw) checkWrapped(wrapped, pw, encPublicKey, encPk);
		return { wrapped, recoveryCode };
	} finally {
		wipe(pw?.key, rc?.key);
	}
}

export interface MemberSecrets {
	signSeed: Bytes;
	signPk: Uint8Array;
	encSecret: Bytes;
	encPk: Uint8Array;
}

export interface MemberRewrapped {
	/** The JSON text of each new value, as signed in a `KeyRewrap`. */
	wrapped_sign_key: string;
	wrapped_enc_key: string;
	recovery_wrapped: string;
	recoveryCode: string | null;
}

/**
 * New wrapped copies of the unlocked member keys. Whatever `choice` doesn't
 * replace is kept from `current`, the stored values.
 */
export async function rewrapMemberWrapped(
	keys: MemberSecrets,
	current: { wrapped_sign_key: unknown; wrapped_enc_key: unknown; recovery_wrapped: unknown },
	choice: RewrapChoice,
	onProgress?: Progress,
	params: KdfParams = DEFAULT_KDF
): Promise<MemberRewrapped> {
	const { pw, rc, recoveryCode } = await derive(choice, params, onProgress);
	try {
		const sign = (k: WrapKey) => wrapChecked(keys.signSeed, k, signPublicKey, keys.signPk);
		const enc = (k: WrapKey) => wrapChecked(keys.encSecret, k, encPublicKey, keys.encPk);
		let recovery_wrapped = JSON.stringify(current.recovery_wrapped);
		if (rc) {
			const r: RecoveryWrapped = {
				sign: JSON.parse(sign(rc)) as WrappedSecret,
				enc: JSON.parse(enc(rc)) as WrappedSecret
			};
			recovery_wrapped = JSON.stringify(r);
		}
		return {
			wrapped_sign_key: pw ? sign(pw) : JSON.stringify(current.wrapped_sign_key),
			wrapped_enc_key: pw ? enc(pw) : JSON.stringify(current.wrapped_enc_key),
			recovery_wrapped,
			recoveryCode
		};
	} finally {
		wipe(pw?.key, rc?.key);
	}
}
