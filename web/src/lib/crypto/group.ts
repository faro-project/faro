// Signed, encrypted group messages: reach outs and the notes on proposals
// and join requests (docs/PROTOCOL.md §9, GROUPS.md §10.2). A port of
// `faro_proto::group` and `faro_crypto::{seal,verify,open}_group_message`.
//
// The author seals the text to every recipient and to themself, and signs
// the header with their member signing key. A reader checks the structure,
// the body against the header and the author's signature before showing a
// word of it: the operator can serve anything, but can't forge this.

import { blake3 } from '@noble/hashes/blake3.js';
import { concat, fromUtf8, unb64, unb64Fixed, utf8, type Bytes } from './bytes.ts';
import { Canonical, hashFromString, hashToString } from './canonical.ts';
import { keyId } from './keys.ts';
import { compareIds, isWellFormedId, signWith, verifySigned, type Signed } from './proto.ts';
import { openItem, sealItem, type EncryptedItem } from './seal.ts';

export const MAX_MESSAGE_RECIPIENTS = 32;
export const MAX_MESSAGE_CHARS = 500;
export const MAX_MESSAGE_CIPHERTEXT = 4096;

export type GroupMessageKind = 'reach_out' | 'proposal_note' | 'join_request_note';
const KINDS: GroupMessageKind[] = ['reach_out', 'proposal_note', 'join_request_note'];

export interface MessageRecipient {
	user_id: string;
	/** base64url X25519 key the message is sealed to. */
	enc_pubkey: string;
}

/** `faro_proto::group::GroupMessage`. */
export interface GroupMessage {
	instance_id: string;
	group_id: string | null;
	item_id: string;
	kind: GroupMessageKind;
	author_id: string;
	issued_at_ms: number;
	recipients: MessageRecipient[];
	/** `b3:<hex>` of nonce ‖ ciphertext, or of 32 zero bytes when there's no body. */
	body_hash: string;
}

/** A message as uploaded and served. */
export interface SealedGroupMessage {
	message: Signed<GroupMessage>;
	body: EncryptedItem | null;
}

export const ZERO_HASH = hashToString(new Uint8Array(32));

/** 32 lowercase hex characters: an id in the instance's own form. */
export function isHexId(s: unknown): s is string {
	return typeof s === 'string' && /^[0-9a-f]{32}$/.test(s);
}

/** A fresh random item id. */
export function newItemId(): string {
	const b = new Uint8Array(16);
	crypto.getRandomValues(b);
	return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

/** `GroupMessage::validate`. Returns the reason it fails, or null. */
export function validateGroupMessage(m: GroupMessage): string | null {
	if (!isWellFormedId(m.instance_id, 'inst_')) return 'malformed instance id';
	if (!isWellFormedId(m.author_id, 'usr_')) return 'malformed author id';
	if (!isHexId(m.item_id)) return 'malformed item id';
	if (!KINDS.includes(m.kind)) return 'unknown kind';
	if (m.group_id != null && !isHexId(m.group_id)) return 'malformed group id';
	if (m.group_id == null && m.kind !== 'reach_out') return 'a note must name its group';
	if (!Number.isSafeInteger(m.issued_at_ms)) return 'malformed time';
	if (!Array.isArray(m.recipients) || m.recipients.length === 0) return 'no recipients';
	if (m.recipients.length > MAX_MESSAGE_RECIPIENTS) return 'too many recipients';
	if (m.kind === 'proposal_note' && m.recipients.length !== 1) {
		return 'a proposal note has one recipient';
	}
	for (let i = 0; i < m.recipients.length; i++) {
		const r = m.recipients[i];
		if (!isWellFormedId(r.user_id, 'usr_')) return 'malformed recipient id';
		if (r.user_id === m.author_id) return 'the author is listed as a recipient';
		if (i > 0 && compareIds(m.recipients[i - 1].user_id, r.user_id) >= 0) {
			return 'recipients are not sorted or not unique';
		}
	}
	return null;
}

export function groupMessageSigningBytes(m: GroupMessage): Bytes {
	const c = new Canonical('faro/group-message/v1')
		.str(m.instance_id)
		.str(m.group_id ?? '')
		.str(m.item_id)
		.str(m.kind)
		.str(m.author_id)
		.i64(m.issued_at_ms)
		.u64(m.recipients.length);
	for (const r of m.recipients) c.str(r.user_id).fixed(unb64Fixed(r.enc_pubkey, 32, 'enc_pubkey'));
	return c.fixed(hashFromString(m.body_hash)).finish();
}

/** The AAD of a message's body: binds the ciphertext to the item. */
export function groupMessageBodyAad(instanceId: string, itemId: string): Bytes {
	return new Canonical('faro/group-message-body/v1').str(instanceId).str(itemId).finish();
}

/** `EncryptedItem::body_hash`: BLAKE3(nonce ‖ ciphertext) as `b3:<hex>`. */
export function itemBodyHash(item: EncryptedItem): string {
	return hashToString(blake3(concat(unb64(item.nonce), unb64(item.ciphertext))));
}

/** `SealedGroupMessage::validate`: the header, then the body against it. */
export function validateSealedGroupMessage(s: SealedGroupMessage): string | null {
	const m = s?.message;
	if (!m || typeof m !== 'object') return 'no message';
	const bad = validateGroupMessage(m);
	if (bad) return bad;
	const body = s.body ?? null;
	if (!body) return m.body_hash === ZERO_HASH ? null : 'the body is missing';
	let hash: string;
	try {
		hash = itemBodyHash(body);
	} catch {
		return 'malformed body';
	}
	if (m.body_hash === ZERO_HASH || hash !== m.body_hash) return 'the body is not the signed one';
	if (body.alg !== 'xchacha20poly1305') return 'unsupported body';
	if (unb64(body.ciphertext).length > MAX_MESSAGE_CIPHERTEXT) return 'body too long';
	if (!Array.isArray(body.envelopes) || body.envelopes.length !== m.recipients.length + 1) {
		return 'envelopes do not match the recipients';
	}
	const seen = new Set<string>();
	for (const e of body.envelopes) {
		if (seen.has(e.recipient)) return 'envelopes do not match the recipients';
		seen.add(e.recipient);
		if (e.recipient === m.author_id) continue;
		const r = m.recipients.find((r) => r.user_id === e.recipient);
		if (!r) return 'envelopes do not match the recipients';
		try {
			if (e.key_id !== keyId(unb64Fixed(r.enc_pubkey, 32))) {
				return 'envelopes do not match the recipients';
			}
		} catch {
			return 'malformed recipient key';
		}
	}
	if (!seen.has(m.author_id)) return 'envelopes do not match the recipients';
	return null;
}

/**
 * Seal `text` (or nothing: a signed, content-free reach out) to the
 * recipients and the author's own key, and sign with the member signing
 * `seed`. `message.body_hash` is set here.
 */
export function sealGroupMessage(
	seed: Uint8Array,
	authorEncPk: Uint8Array,
	message: Omit<GroupMessage, 'body_hash'>,
	text: string | null
): SealedGroupMessage {
	const header: GroupMessage = {
		...message,
		recipients: [...message.recipients].sort((a, b) => compareIds(a.user_id, b.user_id)),
		body_hash: ZERO_HASH
	};
	const bad = validateGroupMessage(header);
	if (bad) throw new Error(bad);
	let body: EncryptedItem | null = null;
	if (text !== null) {
		if (!text.trim() || [...text].length > MAX_MESSAGE_CHARS) {
			throw new Error(`a message is 1 to ${MAX_MESSAGE_CHARS} characters`);
		}
		body = sealItem(
			utf8(JSON.stringify({ text })),
			groupMessageBodyAad(header.instance_id, header.item_id),
			[
				...header.recipients.map((r) => ({
					user_id: r.user_id,
					pubkey: unb64Fixed(r.enc_pubkey, 32)
				})),
				{ user_id: header.author_id, pubkey: authorEncPk }
			]
		);
		header.body_hash = itemBodyHash(body);
	}
	return { message: signWith(seed, header, groupMessageSigningBytes), body };
}

/**
 * Check a served message against the author's member signing key. Returns
 * the reason it must not be shown, or null.
 */
export function verifyGroupMessage(authorSignPk: Uint8Array, s: SealedGroupMessage): string | null {
	const bad = validateSealedGroupMessage(s);
	if (bad) return bad;
	if (!verifySigned(authorSignPk, s.message, groupMessageSigningBytes)) {
		return 'the signature does not verify';
	}
	return null;
}

/**
 * Open a verified message's text as `me` with the X25519 `secret`. Null for
 * a message without a body. Throws `DecryptError` if it can't be opened.
 */
export function openGroupMessage(
	s: SealedGroupMessage,
	me: string,
	secret: Uint8Array
): string | null {
	if (!s.body) return null;
	const m = s.message;
	const pt = openItem(s.body, groupMessageBodyAad(m.instance_id, m.item_id), me, secret);
	const v = JSON.parse(fromUtf8(pt)) as { text?: unknown };
	if (typeof v.text !== 'string' || [...v.text].length > MAX_MESSAGE_CHARS) {
		throw new Error('the message text is malformed');
	}
	return v.text;
}
