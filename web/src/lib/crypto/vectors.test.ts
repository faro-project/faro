// Checks this port against values the Rust crates produced
// (crates/faro-crypto/tests/data/web-vectors.json; that crate's
// `web_vectors` test checks the same file, and the `from_web` part that
// `npm run vectors` writes from this code). Run with `npm test`.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fromUtf8, hex, unb64, unhex, utf8 } from './bytes.ts';
import { Canonical, hashToString } from './canonical.ts';
import { encPublicKey, isWeakX25519, keyId, safetyCode, signPublicKey, verify } from './keys.ts';
import {
	generateRecoveryCode,
	normalizeRecoveryCode,
	unwrapSecret,
	wrapSecret
} from './passphrase.ts';
import {
	allyEndorsementSigningBytes,
	allyKeyRewrapProofBytes,
	checkManifest,
	deviceEndorsementSigningBytes,
	eventBodyAad,
	keyRewrapSigningBytes,
	MANIFEST_FORMAT_V1,
	MANIFEST_FORMAT_V2,
	MANIFEST_FORMAT_V3,
	manifestRef,
	manifestSigningBytes,
	memberBindingSigningBytes,
	nextManifest,
	proveAllyKeyRewrap,
	MAX_ALLY_NAME_BYTES,
	reportBodyAad,
	sanitizeAllyName,
	signWith,
	validateManifest,
	verifySigned,
	type RecipientManifest,
	type Signed
} from './proto.ts';
import { DecryptError, openItem, sealItem, sealOpen, sealTo, type EncryptedItem } from './seal.ts';
import {
	checkInBytes,
	groupMessageBodyAad,
	groupMessageEpochAad,
	groupMessageSigningBytes,
	openGroupMessage,
	openGroupMessageWithEpoch,
	parseCheckIn,
	sealGroupMessage,
	sealGroupMessageToEpoch,
	validateGroupMessage,
	verifyGroupMessage,
	type GroupMessage,
	type SealedGroupMessage
} from './group.ts';

export const VECTORS_PATH = join(
	import.meta.dirname,
	'../../../../crates/faro-crypto/tests/data/web-vectors.json'
);

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const V: any = JSON.parse(readFileSync(VECTORS_PATH, 'utf8'));
const K = V.keys;

test('canonical encoding', () => {
	const layout = new Canonical('t')
		.u16(1)
		.str('ab')
		.u64(2)
		.i64(-1)
		.fixed(new Uint8Array([0xaa, 0xbb]))
		.finish();
	assert.equal(hex(layout), V.canonical.layout_hex);
	assert.equal(
		hex(eventBodyAad(V.ids.instance, V.event_item.device_id, V.event_item.seq)),
		V.canonical.event_body_aad_hex
	);
	assert.equal(
		hex(
			reportBodyAad(
				V.ids.instance,
				V.report_item.device_id,
				V.report_item.period_start_ms,
				V.report_item.period_end_ms
			)
		),
		V.canonical.report_body_aad_hex
	);
	assert.throws(() => new Canonical('t').u64(-1));
	assert.throws(() => new Canonical('t').u64(2 ** 53));
});

test('key derivation from secrets', () => {
	assert.equal(
		hashToString(signPublicKey(unb64(K.member_sign_seed))).length,
		67 // sanity: hashToString works on any 32 bytes
	);
	assert.deepEqual(signPublicKey(unb64(K.member_sign_seed)), unb64(K.member_sign_pubkey));
	assert.deepEqual(encPublicKey(unb64(K.member_enc_secret)), unb64(K.member_enc_pubkey));
	assert.deepEqual(encPublicKey(unb64(K.ally_a_secret)), unb64(K.ally_a_pubkey));
	assert.deepEqual(encPublicKey(unb64(K.ally_b_secret)), unb64(K.ally_b_pubkey));
});

test('key ids and safety codes', () => {
	for (const k of V.key_id) assert.equal(keyId(unb64(k.pubkey)), k.key_id);
	const { a, b, code } = V.safety_code;
	assert.equal(safetyCode(unb64(a), unb64(b)), code);
	assert.equal(safetyCode(unb64(b), unb64(a)), code);
});

test('ed25519 signatures', () => {
	const pk = unb64(K.member_sign_pubkey);
	const msg = unhex(V.ed25519.msg_hex);
	assert.ok(verify(pk, msg, unb64(V.ed25519.sig)));
	const bad = msg.slice();
	bad[0] ^= 1;
	assert.ok(!verify(pk, bad, unb64(V.ed25519.sig)));
	// The identity point is a small-order key and never verifies.
	const identity = new Uint8Array(32);
	identity[0] = 1;
	assert.ok(!verify(identity, msg, new Uint8Array(64)));
});

test('small-order x25519 keys', () => {
	assert.ok(isWeakX25519(new Uint8Array(32)));
	const hi = new Uint8Array(32);
	hi[0] = 1;
	hi[31] = 0x80;
	assert.ok(isWeakX25519(hi));
	assert.ok(!isWeakX25519(unb64(K.ally_a_pubkey)));
});

test('sealed boxes from Rust open', () => {
	const out = sealOpen(unb64(V.sealed_box.sealed), unb64(V.sealed_box.recipient_secret));
	assert.equal(hex(out), V.sealed_box.plaintext_hex);
	assert.throws(() => sealOpen(unb64(V.sealed_box.sealed), unb64(K.ally_b_secret)), DecryptError);
});

test('encrypted items from Rust open for each recipient', () => {
	const ev = V.event_item;
	const item = ev.item as EncryptedItem;
	const aad = eventBodyAad(V.ids.instance, ev.device_id, ev.seq);
	assert.equal(
		fromUtf8(openItem(item, aad, V.ids.member, unb64(K.member_enc_secret))),
		ev.plaintext
	);
	assert.equal(fromUtf8(openItem(item, aad, V.ids.ally_a, unb64(K.ally_a_secret))), ev.plaintext);
	// Wrong AAD (a body moved to another event), wrong key, no envelope.
	const other = eventBodyAad(V.ids.instance, ev.device_id, ev.seq + 1);
	assert.throws(() => openItem(item, other, V.ids.ally_a, unb64(K.ally_a_secret)), DecryptError);
	assert.throws(() => openItem(item, aad, V.ids.ally_a, unb64(K.ally_b_secret)), DecryptError);
	assert.throws(
		() => openItem(item, aad, V.ids.ally_b, unb64(K.ally_b_secret)),
		(e: unknown) => e instanceof DecryptError && e.reason === 'no_envelope'
	);

	const r = V.report_item;
	const raad = reportBodyAad(V.ids.instance, r.device_id, r.period_start_ms, r.period_end_ms);
	assert.equal(
		fromUtf8(openItem(r.item as EncryptedItem, raad, V.ids.ally_b, unb64(K.ally_b_secret))),
		r.plaintext
	);
});

test('wrapped secrets from Rust unwrap', async () => {
	for (const w of V.wrapped) {
		assert.equal(hex(await unwrapSecret(w.wrapped, w.passphrase)), w.plaintext_hex);
		await assert.rejects(unwrapSecret(w.wrapped, w.passphrase + 'x'));
	}
	const tooBig = { ...V.wrapped[0].wrapped, params: { m_cost_kib: 4 << 20, t_cost: 1, p_cost: 1 } };
	await assert.rejects(unwrapSecret(tooBig, 'x'), /unsupported/);
	const lanes = { ...V.wrapped[0].wrapped, params: { m_cost_kib: 64, t_cost: 1, p_cost: 4 } };
	await assert.rejects(unwrapSecret(lanes, 'x'), /unsupported/);
});

test('wrap and unwrap round trip', async () => {
	const secret = new Uint8Array(32).fill(5);
	const w = await wrapSecret(secret, 'pw', { m_cost_kib: 64, t_cost: 1, p_cost: 1 });
	assert.deepEqual(await unwrapSecret(w, 'pw'), secret);
	await assert.rejects(unwrapSecret(w, 'PW'));
});

test('manifests, endorsements and bindings match Rust', () => {
	const pk = unb64(K.member_sign_pubkey);
	const seed = unb64(K.member_sign_seed);
	const m = V.manifest.signed as Signed<RecipientManifest>;
	assert.equal(validateManifest(m), null);
	assert.equal(hex(manifestSigningBytes(m)), V.manifest.signing_bytes_hex);
	assert.deepEqual(manifestRef(m), { version: m.version, hash: V.manifest.hash });
	assert.ok(verifySigned(pk, m, manifestSigningBytes));
	assert.equal(checkManifest(m, pk, V.ids.instance, V.ids.member), null);
	assert.match(checkManifest(m, pk, V.ids.instance, 'usr_other') ?? '', /different/);
	// Ed25519 is deterministic, so signing again gives Rust's signature.
	const { sig, ...body } = m;
	assert.equal(signWith(seed, body, manifestSigningBytes).sig, sig);

	for (const [name, bytes] of [
		['device_endorsement', deviceEndorsementSigningBytes],
		['ally_endorsement', allyEndorsementSigningBytes],
		['member_binding', memberBindingSigningBytes],
		['key_rewrap', keyRewrapSigningBytes]
	] as const) {
		const s = V[name].signed;
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		assert.equal(hex((bytes as (b: any) => Uint8Array)(s)), V[name].signing_bytes_hex, name);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		assert.ok(verifySigned(pk, s, bytes as (b: any) => Uint8Array), name);
	}
	assert.equal(V.device_endorsement.signed.min_manifest.hash, V.manifest.hash);
});

test('ally key re-wrap proofs match Rust', () => {
	const { proof, ...body } = V.ally_key_rewrap.proven;
	const challenge = unhex(V.ally_key_rewrap.challenge_hex);
	assert.equal(hex(allyKeyRewrapProofBytes(body)), V.ally_key_rewrap.proof_bytes_hex);
	assert.equal(proveAllyKeyRewrap(body, challenge).proof, proof);
	// Every field, and the challenge, is covered.
	const other = new Uint8Array(challenge).fill(0x56);
	assert.notEqual(proveAllyKeyRewrap(body, other).proof, proof);
	for (const change of [
		{ instance_id: 'inst_other' },
		{ ally_id: 'usr_other' },
		{ enc_pubkey: K.ally_b_pubkey },
		{ issued_at_ms: body.issued_at_ms + 1 },
		{ wrapped_privkey: body.wrapped_privkey + ' ' }
	]) {
		assert.notEqual(proveAllyKeyRewrap({ ...body, ...change }, challenge).proof, proof);
	}
	assert.throws(() => proveAllyKeyRewrap(body, challenge.subarray(1)), /32 bytes/);
	// The 32-byte challenge comes as a sealed box to the ally key, like the
	// Rust-sealed box here.
	const opened = sealOpen(unb64(V.sealed_box.sealed), unb64(V.sealed_box.recipient_secret));
	assert.equal(opened.length, 32);
});

test('manifest validation and the next version', () => {
	const m = V.manifest.signed as Signed<RecipientManifest>;
	const unsorted = { ...m, allies: [...m.allies].reverse() };
	assert.match(validateManifest(unsorted) ?? '', /sorted/);
	assert.match(validateManifest({ ...m, version: 0 }) ?? '', /version/);
	assert.match(
		validateManifest({ ...m, allies: [{ ally_id: m.member_id, enc_pubkey: K.ally_a_pubkey }] }) ??
			'',
		/own ally/
	);
	const next = nextManifest(m, [...m.allies].reverse(), 0);
	assert.equal(next.version, m.version + 1);
	assert.equal(next.issued_at_ms, m.issued_at_ms + 1);
	assert.equal(validateManifest(next), null);
	assert.ok(!('sig' in next));
	// Every re-sign is format 3, linked to the version it follows, unnamed
	// allies signed with an empty name.
	assert.equal(next.format, MANIFEST_FORMAT_V3);
	assert.equal(next.prev_hash, V.manifest.hash);
	assert.deepEqual(
		next.allies.map((a) => a.name),
		['', '']
	);
});

test('format 2 manifests match Rust', () => {
	const pk = unb64(K.member_sign_pubkey);
	const seed = unb64(K.member_sign_seed);
	const m = V.manifest_v2.signed as Signed<RecipientManifest>;
	assert.equal(m.format, MANIFEST_FORMAT_V2);
	assert.equal(validateManifest(m), null);
	assert.equal(hex(manifestSigningBytes(m)), V.manifest_v2.signing_bytes_hex);
	assert.deepEqual(manifestRef(m), { version: m.version, hash: V.manifest_v2.hash });
	assert.equal(checkManifest(m, pk, V.ids.instance, V.ids.member), null);
	const { sig, ...body } = m;
	assert.equal(signWith(seed, body, manifestSigningBytes).sig, sig);

	// The name is signed: a false name next to a real key fails, and so
	// does relabelling the document as format 1 without its names.
	const forged = { ...m, allies: m.allies.map((a, i) => (i ? a : { ...a, name: 'Mallory' })) };
	assert.match(checkManifest(forged, pk, V.ids.instance, V.ids.member) ?? '', /signature/);
	const downgraded = {
		...m,
		format: MANIFEST_FORMAT_V1,
		allies: m.allies.map(({ ally_id, enc_pubkey }) => ({ ally_id, enc_pubkey }))
	};
	assert.match(checkManifest(downgraded, pk, V.ids.instance, V.ids.member) ?? '', /signature/);

	// Names must fit the format.
	const v1 = V.manifest.signed as Signed<RecipientManifest>;
	const named = { ...v1, allies: v1.allies.map((a) => ({ ...a, name: 'x' })) };
	assert.match(validateManifest(named) ?? '', /unsigned names/);
	const unnamed = {
		...m,
		allies: m.allies.map(({ ally_id, enc_pubkey }) => ({ ally_id, enc_pubkey }))
	};
	assert.match(validateManifest(unnamed) ?? '', /no name/);
	const long = { ...m, allies: m.allies.map((a) => ({ ...a, name: 'é'.repeat(129) })) };
	assert.match(validateManifest(long) ?? '', /too long/);
	assert.match(validateManifest({ ...m, format: 4 }) ?? '', /unknown format/);
	// The next version is format 3 and signs the names it is given,
	// sanitized.
	const next = nextManifest(
		m,
		m.allies.map((a, i) => ({ ...a, name: i ? ' Pat\u202e\n Lee ' : a.name })),
		0
	);
	assert.deepEqual(
		next.allies.map((a) => a.name),
		[m.allies[0].name, 'Pat Lee']
	);
	assert.equal(validateManifest(next), null);
});

test('format 3 manifests match Rust and link to the previous version', () => {
	const pk = unb64(K.member_sign_pubkey);
	const seed = unb64(K.member_sign_seed);
	const m = V.manifest_v3.signed as Signed<RecipientManifest>;
	const prev = V.manifest_v2.signed as Signed<RecipientManifest>;
	assert.equal(m.format, MANIFEST_FORMAT_V3);
	assert.equal(m.prev_hash, V.manifest_v2.hash);
	assert.equal(validateManifest(m), null);
	assert.equal(hex(manifestSigningBytes(m)), V.manifest_v3.signing_bytes_hex);
	assert.deepEqual(manifestRef(m), { version: m.version, hash: V.manifest_v3.hash });
	assert.equal(checkManifest(m, pk, V.ids.instance, V.ids.member), null);
	const { sig, ...body } = m;
	assert.equal(signWith(seed, body, manifestSigningBytes).sig, sig);
	// nextManifest builds exactly this from its predecessor.
	assert.deepEqual(nextManifest(prev, prev.allies, m.issued_at_ms), body);
	// The link is signed.
	const relinked = { ...m, prev_hash: V.manifest.hash };
	assert.match(checkManifest(relinked, pk, V.ids.instance, V.ids.member) ?? '', /signature/);
	// It is required above version 1 and refused at version 1 and in the
	// older formats.
	const { prev_hash: _, ...unlinked } = m;
	assert.match(validateManifest(unlinked) ?? '', /follows/);
	assert.match(validateManifest({ ...m, version: 1 }) ?? '', /unexpected prev_hash/);
	assert.match(validateManifest({ ...prev, prev_hash: V.manifest.hash }) ?? '', /unexpected/);
	assert.match(validateManifest({ ...m, prev_hash: 'b3:zz' }) ?? '', /malformed prev_hash/);
	// Version 1 signs 32 zero bytes in its place.
	const first: RecipientManifest = { ...unlinked, version: 1 };
	assert.equal(validateManifest(first), null);
	const bytes = hex(manifestSigningBytes(first));
	assert.ok(bytes.includes('0000000000000001' + '00'.repeat(32)), bytes);
});

test('ally names are sanitized exactly as in Rust', () => {
	assert.ok(V.ally_names.length > 10);
	// Inputs are UTF-8 hex: they hold bidi controls.
	for (const v of V.ally_names as { input_hex: string; output: string }[]) {
		const { output } = v;
		const input = fromUtf8(unhex(v.input_hex));
		assert.equal(sanitizeAllyName(input), output, JSON.stringify(input));
		// Stable: sanitizing again changes nothing.
		assert.equal(sanitizeAllyName(output), output);
		assert.ok(utf8(output).length <= MAX_ALLY_NAME_BYTES);
	}
	// A lone surrogate (impossible in Rust strings) becomes U+FFFD, which is
	// what UTF-8 encoding would have signed anyway.
	assert.equal(sanitizeAllyName('a\ud800b'), 'a\ufffdb');
});

test('recovery codes', () => {
	const c = generateRecoveryCode();
	assert.match(c, /^([0-9A-HJKMNP-TV-Z]{4}-){7}[0-9A-HJKMNP-TV-Z]{4}$/);
	assert.notEqual(c, generateRecoveryCode());
	assert.equal(normalizeRecoveryCode(c.toLowerCase().replaceAll('-', ' ')), c);
	assert.equal(
		normalizeRecoveryCode('oooo-iiii-llll-0000-0000-0000-0000-0000'),
		'0000-1111-1111-0000-0000-0000-0000-0000'
	);
	assert.equal(normalizeRecoveryCode('too short'), null);
	assert.equal(normalizeRecoveryCode('UUUU-0000-0000-0000-0000-0000-0000-0000'), null);
});

test('sealing round trips, and Rust opens what the web app sealed', () => {
	const ck = new Uint8Array(32).fill(9);
	assert.deepEqual(sealOpen(sealTo(unb64(K.ally_a_pubkey), ck), unb64(K.ally_a_secret)), ck);
	assert.throws(() => sealTo(new Uint8Array(32), ck), /unusable/);
	const aad = new Uint8Array([1, 2]);
	const item = sealItem(new Uint8Array([7, 7]), aad, [
		{ user_id: V.ids.ally_a, pubkey: unb64(K.ally_a_pubkey) },
		{ user_id: V.ids.member, pubkey: unb64(K.member_enc_pubkey) }
	]);
	assert.deepEqual(
		openItem(item, aad, V.ids.ally_a, unb64(K.ally_a_secret)),
		new Uint8Array([7, 7])
	);
	assert.deepEqual(
		openItem(item, aad, V.ids.member, unb64(K.member_enc_secret)),
		new Uint8Array([7, 7])
	);
});

test('group messages match Rust', () => {
	const pk = unb64(K.member_sign_pubkey);
	const seed = unb64(K.member_sign_seed);
	const cf = V.group_message.content_free.signed as Signed<GroupMessage>;
	assert.equal(validateGroupMessage(cf), null);
	assert.equal(hex(groupMessageSigningBytes(cf)), V.group_message.content_free.signing_bytes_hex);
	assert.equal(hex(groupMessageBodyAad(V.ids.instance, cf.item_id)), V.group_message.body_aad_hex);
	const { sig, ...body } = cf;
	assert.equal(signWith(seed, body, groupMessageSigningBytes).sig, sig);
	assert.equal(verifyGroupMessage(pk, { message: cf, body: null }), null);

	// Rust sealed and signed this one: it verifies, and opens for the author
	// and each recipient.
	const s = V.group_message_sealed.sealed as SealedGroupMessage;
	assert.equal(verifyGroupMessage(pk, s), null);
	const text = JSON.parse(V.group_message_sealed.plaintext).text;
	assert.equal(openGroupMessage(s, V.ids.ally_a, unb64(K.ally_a_secret)), text);
	assert.equal(openGroupMessage(s, V.ids.ally_b, unb64(K.ally_b_secret)), text);
	assert.equal(openGroupMessage(s, V.ids.member, unb64(K.member_enc_secret)), text);
});

test('whole-group check-ins and replies match Rust', () => {
	const pk = unb64(K.member_sign_pubkey);
	const seed = unb64(K.member_sign_seed);
	const E = V.group_message_epoch;
	const epochKey = unhex(E.epoch_key_hex);

	// The signed header and the wrap AAD are byte for byte Rust's.
	const cf = E.content_free.signed as Signed<GroupMessage>;
	assert.equal(validateGroupMessage(cf), null);
	assert.equal(cf.epoch, 3);
	assert.equal(hex(groupMessageSigningBytes(cf)), E.content_free.signing_bytes_hex);
	assert.equal(
		hex(groupMessageEpochAad(V.ids.instance, 'fedcba9876543210fedcba9876543210', cf.item_id, 3)),
		E.wrap_aad_hex
	);
	const { sig, ...body } = cf;
	assert.equal(signWith(seed, body, groupMessageSigningBytes).sig, sig);
	assert.equal(verifyGroupMessage(pk, { message: cf, body: null }), null);

	// Rust sealed this check-in: it verifies and opens with the epoch key only.
	const s = E.sealed as SealedGroupMessage;
	assert.equal(verifyGroupMessage(pk, s), null);
	const pt = openGroupMessageWithEpoch(s, epochKey)!;
	assert.deepEqual(parseCheckIn(pt), JSON.parse(E.plaintext));
	assert.throws(() => openGroupMessageWithEpoch(s, new Uint8Array(32).fill(1)), DecryptError);
	assert.throws(() => openGroupMessage(s, V.ids.member, unb64(K.member_enc_secret)));

	// Our own seal round-trips, and a moved or re-epoched copy doesn't open.
	const mine = sealGroupMessageToEpoch(seed, epochKey, body, checkInBytes({ scale: 5 }));
	assert.equal(verifyGroupMessage(pk, mine), null);
	assert.deepEqual(parseCheckIn(openGroupMessageWithEpoch(mine, epochKey)!), { scale: 5 });
	for (const edit of [{ epoch: 4 }, { item_id: 'dddddddddddddddddddddddddddddddd' }]) {
		const moved = { ...mine, message: { ...mine.message, ...edit } };
		assert.throws(() => openGroupMessageWithEpoch(moved, epochKey), DecryptError);
		assert.notEqual(verifyGroupMessage(pk, moved), null);
	}
	// A whole-group message may not name recipients, nor be sealed to people.
	assert.throws(() =>
		sealGroupMessageToEpoch(
			seed,
			epochKey,
			{ ...body, recipients: [{ user_id: V.ids.ally_a, enc_pubkey: K.ally_a_pubkey }] },
			null
		)
	);
	assert.throws(() => sealGroupMessage(seed, unb64(K.member_enc_pubkey), body, 'x'));

	// A reply signs the check-in it answers.
	const R = V.group_message_reply.signed as Signed<GroupMessage>;
	assert.equal(validateGroupMessage(R), null);
	assert.equal(hex(groupMessageSigningBytes(R)), V.group_message_reply.signing_bytes_hex);
	assert.equal(verifyGroupMessage(pk, { message: R, body: null }), null);
	const moved = { ...R, parent_id: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' };
	assert.notEqual(verifyGroupMessage(pk, { message: moved, body: null }), null);
	const { parent_id: _p, ...orphan } = R;
	assert.notEqual(validateGroupMessage(orphan as Signed<GroupMessage>), null);
});

test('check-in answers are limited', () => {
	assert.throws(() => checkInBytes({ scale: 0 as 1 }));
	assert.throws(() => checkInBytes({ scale: 3, ask: '  ' }));
	assert.throws(() => checkInBytes({ scale: 3, went_well: 'x'.repeat(501) }));
	assert.deepEqual(parseCheckIn(checkInBytes({ scale: 3, ask: 'a call' })), {
		scale: 3,
		ask: 'a call'
	});
});

test('forged and altered group messages are refused', () => {
	const pk = unb64(K.member_sign_pubkey);
	const s = V.group_message_sealed.sealed as SealedGroupMessage;
	// Signed by someone else (an operator holding only public keys can't do
	// better than this): the same message with another key's signature.
	const mallory = new Uint8Array(32).fill(0x99);
	const { sig: _sig, ...header } = s.message;
	const forged = { ...s, message: signWith(mallory, header, groupMessageSigningBytes) };
	assert.match(verifyGroupMessage(pk, forged) ?? '', /signature/);
	// Any edit to the signed header.
	for (const change of [
		{ issued_at_ms: header.issued_at_ms + 1 },
		{ group_id: null },
		{ kind: 'proposal_note' as const },
		{ author_id: 'usr_someone' },
		{ recipients: header.recipients.slice(1) }
	]) {
		const m = { ...s, message: { ...s.message, ...change } };
		assert.notEqual(verifyGroupMessage(pk, m), null, JSON.stringify(change));
	}
	// A swapped body, a dropped author copy, a garbage signature.
	const other = sealGroupMessage(
		unb64(K.member_sign_seed),
		unb64(K.member_enc_pubkey),
		{ ...header, item_id: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' },
		'another message'
	);
	assert.match(verifyGroupMessage(pk, { ...s, body: other.body }) ?? '', /signed/);
	assert.notEqual(
		verifyGroupMessage(pk, {
			...s,
			body: { ...s.body!, envelopes: s.body!.envelopes.filter((e) => e.recipient !== V.ids.member) }
		}),
		null
	);
	assert.notEqual(verifyGroupMessage(pk, { ...s, message: { ...s.message, sig: 'AAAA' } }), null);
	// A body moved to another item doesn't open there.
	const moved = { ...other, message: { ...other.message, item_id: s.message.item_id } };
	assert.throws(() => openGroupMessage(moved, V.ids.ally_a, unb64(K.ally_a_secret)));
	// No envelope for a stranger.
	assert.throws(
		() => openGroupMessage(s, 'usr_stranger', unb64(K.ally_a_secret)),
		(e: unknown) => e instanceof DecryptError && e.reason === 'no_envelope'
	);
});

test('sealing a group message checks its limits', () => {
	const seed = unb64(K.member_sign_seed);
	const base = {
		instance_id: V.ids.instance,
		group_id: null,
		item_id: 'cccccccccccccccccccccccccccccccc',
		kind: 'reach_out' as const,
		author_id: V.ids.member,
		issued_at_ms: 1,
		recipients: [{ user_id: V.ids.ally_a, enc_pubkey: K.ally_a_pubkey }]
	};
	const enc = unb64(K.member_enc_pubkey);
	assert.equal(sealGroupMessage(seed, enc, base, null).body, null);
	assert.throws(() => sealGroupMessage(seed, enc, base, ' '), /characters/);
	assert.throws(() => sealGroupMessage(seed, enc, base, 'x'.repeat(501)), /characters/);
	assert.ok(sealGroupMessage(seed, enc, base, 'é'.repeat(500)).body);
	assert.throws(() => sealGroupMessage(seed, enc, { ...base, recipients: [] }, null), /recipients/);
	const many = Array.from({ length: 33 }, (_, i) => ({
		user_id: `usr_${String(i).padStart(3, '0')}`,
		enc_pubkey: K.ally_a_pubkey
	}));
	assert.throws(() => sealGroupMessage(seed, enc, { ...base, recipients: many }, null), /many/);
	assert.throws(
		() => sealGroupMessage(seed, enc, { ...base, kind: 'join_request_note' }, 'hi'),
		/group/
	);
});
