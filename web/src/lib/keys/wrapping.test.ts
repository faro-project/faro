// Re-wrapping unlocked keys (wrapping.ts): the new copies open with the new
// passphrase or recovery code to the same keys, whatever isn't replaced is
// kept exactly, and a copy that doesn't hold the right key is refused.
// Run with `npm test`.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { equal, type Bytes } from '../crypto/bytes.ts';
import { encPublicKey, signPublicKey } from '../crypto/keys.ts';
import {
	deriveWrapKey,
	unwrapSecret,
	UnwrapError,
	wrapSecret,
	wrapWithKey,
	type KdfParams
} from '../crypto/passphrase.ts';
import { checkWrapped, rewrapAllyWrapped, rewrapMemberWrapped } from './wrapping.ts';

/** Cheap enough for a test, still a real Argon2id run. */
const cheap: KdfParams = { m_cost_kib: 256, t_cost: 1, p_cost: 1 };

const secret = (b: number) => new Uint8Array(32).fill(b) as Bytes;
const encSecret = secret(0x12);
const encPk = encPublicKey(encSecret);

async function storedAllyKey() {
	return {
		...(await wrapSecret(encSecret, 'old passphrase', cheap)),
		recovery: await wrapSecret(encSecret, 'OLD0-CODE', cheap)
	};
}

async function opens(w: unknown, pass: string, expected: Uint8Array): Promise<boolean> {
	try {
		return equal(await unwrapSecret(w, pass), expected);
	} catch {
		return false;
	}
}

test('an ally key gets a new passphrase and keeps its recovery code', async () => {
	const current = await storedAllyKey();
	const r = await rewrapAllyWrapped(
		encSecret,
		encPk,
		current,
		{ passphrase: 'new passphrase', newRecovery: false },
		undefined,
		cheap
	);
	assert.equal(r.recoveryCode, null);
	const w = JSON.parse(r.wrapped);
	assert.ok(await opens(w, 'new passphrase', encSecret));
	assert.ok(!(await opens(w, 'old passphrase', encSecret)));
	assert.deepEqual(w.recovery, current.recovery);
	assert.ok(await opens(w.recovery, 'OLD0-CODE', encSecret));
});

test('an ally key gets a new recovery code and keeps its passphrase', async () => {
	const current = await storedAllyKey();
	let last = 0;
	const r = await rewrapAllyWrapped(
		encSecret,
		encPk,
		current,
		{ passphrase: null, newRecovery: true },
		(f) => (last = f),
		cheap
	);
	assert.ok(r.recoveryCode);
	assert.ok(last > 0.9 && last <= 1);
	const w = JSON.parse(r.wrapped);
	const { recovery: _old, ...pass } = current;
	void _old;
	const { recovery, ...kept } = w;
	assert.deepEqual(kept, pass);
	assert.ok(await opens(w, 'old passphrase', encSecret));
	assert.ok(await opens(recovery, r.recoveryCode, encSecret));
	assert.ok(!(await opens(recovery, 'OLD0-CODE', encSecret)));
});

test('an ally key gets both at once, and needs one of them', async () => {
	const current = await storedAllyKey();
	const r = await rewrapAllyWrapped(
		encSecret,
		encPk,
		current,
		{ passphrase: 'new passphrase', newRecovery: true },
		undefined,
		cheap
	);
	const w = JSON.parse(r.wrapped);
	assert.ok(await opens(w, 'new passphrase', encSecret));
	assert.ok(await opens(w.recovery, r.recoveryCode!, encSecret));
	await assert.rejects(
		rewrapAllyWrapped(encSecret, encPk, current, { passphrase: null, newRecovery: false }),
		/Nothing to change/
	);
});

test('a copy that holds a different key is refused before upload', async () => {
	// The secret in memory doesn't match the stored public key (a corrupted
	// keyring, say): the new copy would lock the ally out, so nothing is made.
	const other = await storedAllyKey();
	await assert.rejects(
		rewrapAllyWrapped(
			secret(0x13),
			encPk,
			other,
			{ passphrase: 'new passphrase', newRecovery: false },
			undefined,
			cheap
		),
		(e: unknown) => e instanceof UnwrapError && e.reason === 'unsupported'
	);
	const k = await deriveWrapKey('p', cheap);
	const good = JSON.stringify(wrapWithKey(encSecret, k));
	checkWrapped(good, k, encPublicKey, encPk);
	const wrongKey = JSON.stringify(wrapWithKey(secret(0x14), k));
	assert.throws(() => checkWrapped(wrongKey, k, encPublicKey, encPk), UnwrapError);
	const k2 = await deriveWrapKey('p', cheap);
	assert.throws(() => checkWrapped(good, k2, encPublicKey, encPk), UnwrapError, 'other salt');
	const broken = JSON.parse(good);
	broken.ciphertext = broken.ciphertext.slice(0, -4) + 'AAAA';
	assert.throws(() => checkWrapped(JSON.stringify(broken), k, encPublicKey, encPk), UnwrapError);
	assert.throws(() => checkWrapped('not json', k, encPublicKey, encPk), UnwrapError);
});

test('member keys round-trip through a re-wrap', async () => {
	const keys = {
		signSeed: secret(0x21),
		signPk: signPublicKey(secret(0x21)),
		encSecret: secret(0x31),
		encPk: encPublicKey(secret(0x31))
	};
	const k = await deriveWrapKey('old passphrase', cheap);
	const rk = await deriveWrapKey('OLD0-CODE', cheap);
	const current = {
		wrapped_sign_key: wrapWithKey(keys.signSeed, k),
		wrapped_enc_key: wrapWithKey(keys.encSecret, k),
		recovery_wrapped: {
			sign: wrapWithKey(keys.signSeed, rk),
			enc: wrapWithKey(keys.encSecret, rk)
		}
	};
	const pass = await rewrapMemberWrapped(
		keys,
		current,
		{ passphrase: 'new passphrase', newRecovery: false },
		undefined,
		cheap
	);
	assert.ok(await opens(JSON.parse(pass.wrapped_sign_key), 'new passphrase', keys.signSeed));
	assert.ok(await opens(JSON.parse(pass.wrapped_enc_key), 'new passphrase', keys.encSecret));
	assert.deepEqual(JSON.parse(pass.recovery_wrapped), current.recovery_wrapped);

	const code = await rewrapMemberWrapped(
		keys,
		current,
		{ passphrase: null, newRecovery: true },
		undefined,
		cheap
	);
	assert.deepEqual(JSON.parse(code.wrapped_sign_key), current.wrapped_sign_key);
	assert.deepEqual(JSON.parse(code.wrapped_enc_key), current.wrapped_enc_key);
	const r = JSON.parse(code.recovery_wrapped);
	assert.ok(await opens(r.sign, code.recoveryCode!, keys.signSeed));
	assert.ok(await opens(r.enc, code.recoveryCode!, keys.encSecret));
	await assert.rejects(
		rewrapMemberWrapped(
			{ ...keys, encSecret: secret(0x32) },
			current,
			{ passphrase: 'new passphrase', newRecovery: false },
			undefined,
			cheap
		),
		UnwrapError
	);
});
