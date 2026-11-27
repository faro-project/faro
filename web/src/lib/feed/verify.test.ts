// What the browser catches when the instance lies about the feed: a forged
// item (sealed correctly, but not signed by the device), a replaced report,
// a dropped or withheld event, a rewritten history, and an unconfirmed or
// changed member key. Run with `npm test`.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { b64, unb64, utf8 } from '../crypto/bytes.ts';
import {
	chainHash,
	eventHeaderSigningBytes,
	genesisHash,
	reportHeaderSigningBytes,
	type EventHeader,
	type HeaderUrgency,
	type ReportHeader
} from '../crypto/event.ts';
import { itemBodyHash } from '../crypto/group.ts';
import { encPublicKey, sign, signPublicKey } from '../crypto/keys.ts';
import {
	deviceEndorsementSigningBytes,
	eventBodyAad,
	reportBodyAad,
	signWith,
	type DeviceEndorsement,
	type Signed
} from '../crypto/proto.ts';
import { sealItem, type EncryptedItem } from '../crypto/seal.ts';
import type { ChainLink, EventKind, FeedEntry, Urgency } from '../types.ts';
import { openFetched } from './open.ts';
import {
	allyMemberKey,
	chainRange,
	checkChain,
	checkEntry,
	deviceKeys,
	passed,
	type MemberKey
} from './verify.ts';

const INST = 'inst_test';
const MEMBER = 'usr_sam';
const DEV = 'dev_mac';
const memberSeed = new Uint8Array(32).fill(1);
const deviceSeed = new Uint8Array(32).fill(2);
const serverSeed = new Uint8Array(32).fill(3); // the instance's own key
const memberEnc = new Uint8Array(32).fill(4);
const memberPk = signPublicKey(memberSeed);
const own: MemberKey = { pk: memberPk, trust: 'own' };

const endorsement: Signed<DeviceEndorsement> = signWith(
	memberSeed,
	{
		instance_id: INST,
		member_id: MEMBER,
		device_id: DEV,
		device_sign_pubkey: b64(signPublicKey(deviceSeed)),
		endorsed_at_ms: 1,
		min_manifest: { version: 1, hash: `b3:${'0'.repeat(64)}` }
	},
	deviceEndorsementSigningBytes
);

const toMember = (pt: string, aad: Uint8Array) =>
	sealItem(utf8(pt), aad, [{ user_id: MEMBER, pubkey: encPublicKey(memberEnc) }]);

const RANK = { none: 0, normal: 1, urgent: 2 };
const floor = (k: string): HeaderUrgency =>
	k === 'tamper' || k === 'goodbye' ? 'urgent' : k === 'paused' ? 'normal' : 'none';
const shown = (u: HeaderUrgency, k: string): Urgency => (RANK[u] >= RANK[floor(k)] ? u : floor(k));

/** A device writing its chain; `seal` gives an event a body. */
class Device {
	links: ChainLink[] = [];
	entries: FeedEntry[] = [];
	items = new Map<number, EncryptedItem>();
	private prev = genesisHash(INST, DEV);
	private t = 1_000;

	event(kind: EventKind, urgency: HeaderUrgency, body?: string) {
		const seq = this.links.length;
		const item = body ? toMember(body, eventBodyAad(INST, DEV, seq)) : null;
		const h: EventHeader = {
			v: 1,
			instance_id: INST,
			device_id: DEV,
			seq,
			prev_hash: this.prev,
			ts_ms: 1_800_000_000_000 + seq,
			mono_ms: seq,
			boot_id: 'b',
			kind,
			urgency,
			body_hash: item ? itemBodyHash(item) : `b3:${'0'.repeat(64)}`,
			body_len: item ? unb64(item.ciphertext).length : 0
		};
		this.prev = chainHash(h);
		const sig = b64(sign(deviceSeed, eventHeaderSigningBytes(h)));
		this.t += 10;
		this.links.push({ received_at_ms: this.t, header: h, sig });
		if (item) this.items.set(seq, item);
		const eff = shown(urgency, kind);
		if (eff !== 'none') {
			this.entries.push({
				type: 'event',
				member_id: MEMBER,
				device_id: DEV,
				seq,
				ts_ms: h.ts_ms,
				kind,
				urgency: eff,
				blob_id: item ? `blob${seq}` : null,
				header: h,
				sig,
				received_at_ms: this.t
			});
		}
		return this;
	}

	report(first: number, last: number, body: object) {
		const [start, end] = [1_800_000_000_000, 1_800_086_400_000];
		const json = JSON.stringify({
			device_id: DEV,
			period_start_ms: start,
			period_end_ms: end,
			first_seq: first,
			last_seq: last,
			...body
		});
		const item = toMember(json, reportBodyAad(INST, DEV, start, end));
		const h: ReportHeader = {
			v: 1,
			instance_id: INST,
			member_id: MEMBER,
			device_id: DEV,
			period_start_ms: start,
			period_end_ms: end,
			first_seq: first,
			last_seq: last,
			body_hash: itemBodyHash(item),
			body_len: unb64(item.ciphertext).length
		};
		this.t += 10;
		const entry: FeedEntry = {
			type: 'report',
			member_id: MEMBER,
			device_id: DEV,
			report_id: 'rep1',
			period_start_ms: start,
			period_end_ms: end,
			blob_id: 'blobr',
			header: h,
			sig: b64(sign(deviceSeed, reportHeaderSigningBytes(h))),
			received_at_ms: this.t
		};
		return { entry, item };
	}
}

/** seq 0 boot, 1 urgent flag, 2 shutdown, 3 tamper (signed `none`), 4 normal flag. */
function sample() {
	return new Device()
		.event('boot', 'none')
		.event('flag', 'urgent', '{"type":"flag","rating":"high"}')
		.event('shutdown', 'none')
		.event('tamper', 'none', '{"type":"tamper"}')
		.event('flag', 'normal', '{"type":"flag","rating":"medium"}');
}

function check(
	entries: FeedEntry[],
	key: MemberKey | null = own,
	e: Record<string, Signed<DeviceEndorsement>> = { [DEV]: endorsement }
) {
	const keys = deviceKeys(key ?? own, INST, MEMBER, e);
	return entries.map((x) => checkEntry(x, key, keys, INST, MEMBER));
}

function chain(d: Device, entries: FeedEntry[], links = d.links, listedAfterMs = 0) {
	const ok = (x: FeedEntry) =>
		passed(checkEntry(x, own, deviceKeys(own, INST, MEMBER, { [DEV]: endorsement }), INST, MEMBER));
	const range = chainRange(entries, DEV, ok)!;
	return checkChain({
		instanceId: INST,
		deviceId: DEV,
		devicePk: signPublicKey(deviceSeed),
		range,
		links,
		complete: true,
		entries,
		listedAfterMs,
		ok
	});
}

test('a genuine feed verifies, has no gaps, and opens', () => {
	const d = sample();
	const r = d.report(0, 4, { counts: {} });
	const entries = [...d.entries, r.entry];
	assert.deepEqual(
		check(entries).map((c) => c.status),
		['verified', 'verified', 'verified', 'verified']
	);
	const c = chain(d, entries);
	assert.deepEqual(c.gaps, []);
	assert.equal(c.broken, null);
	assert.equal(c.notInChain.size, 0);
	const flag = d.entries[0];
	const o = openFetched(flag, d.items.get(1)!, INST, MEMBER, memberEnc);
	assert.equal(o.kind === 'event' && o.body.type, 'flag');
	const rep = openFetched(r.entry, r.item, INST, MEMBER, memberEnc);
	assert.equal(rep.kind, 'report');
});

test('a forged item with a valid seal but no or a bad signature is flagged', () => {
	// The instance knows the member's public key, so it can seal a "flag"
	// with a "blurred thumbnail" that decrypts fine.
	const item = toMember('{"type":"flag","rating":"high"}', eventBodyAad(INST, DEV, 7));
	const unsigned: FeedEntry = {
		type: 'event',
		member_id: MEMBER,
		device_id: DEV,
		seq: 7,
		ts_ms: 5,
		kind: 'flag',
		urgency: 'urgent',
		blob_id: 'b7',
		received_at_ms: 5
	};
	assert.equal(openFetched(unsigned, item, INST, MEMBER, memberEnc).kind, 'event');
	const [noSig] = check([unsigned]);
	assert.equal(noSig.status, 'failed');
	assert.match((noSig as { reason: string }).reason, /no signature/);

	// Signed, but by the instance's own key.
	const h: EventHeader = {
		v: 1,
		instance_id: INST,
		device_id: DEV,
		seq: 7,
		prev_hash: `b3:${'1'.repeat(64)}`,
		ts_ms: 5,
		mono_ms: 0,
		boot_id: 'b',
		kind: 'flag',
		urgency: 'urgent',
		body_hash: itemBodyHash(item),
		body_len: unb64(item.ciphertext).length
	};
	const badSig = { ...unsigned, header: h, sig: b64(sign(serverSeed, eventHeaderSigningBytes(h))) };
	const [bad] = check([badSig]);
	assert.equal(bad.status, 'failed');
	assert.match((bad as { reason: string }).reason, /signature does not match/);

	// Or a device the member never approved, with the instance's own
	// "endorsement".
	const fakeEndorsement = signWith(
		serverSeed,
		{ ...endorsement, device_id: 'dev_fake', sig: undefined } as unknown as DeviceEndorsement,
		deviceEndorsementSigningBytes
	);
	const onFake = { ...badSig, device_id: 'dev_fake', header: { ...h, device_id: 'dev_fake' } };
	assert.equal(check([onFake], own, { dev_fake: fakeEndorsement })[0].status, 'failed');
	assert.equal(check([onFake])[0].status, 'failed', 'no endorsement at all');
});

test('the instance changing the metadata or swapping a body is flagged', () => {
	const d = sample();
	const flag = d.entries[0] as Extract<FeedEntry, { type: 'event' }>;
	// Downgrading an urgent tamper to make it quiet, or changing the kind.
	const tamper = d.entries[1] as Extract<FeedEntry, { type: 'event' }>;
	assert.equal(tamper.urgency, 'urgent');
	assert.equal(check([{ ...tamper, urgency: 'none' }])[0].status, 'failed');
	assert.equal(check([{ ...flag, kind: 'paused' }])[0].status, 'failed');
	// A new body sealed by the instance under the right AAD.
	const swapped = toMember('{"type":"flag","rating":"clean"}', eventBodyAad(INST, DEV, 1));
	assert.throws(
		() => openFetched(flag, swapped, INST, MEMBER, memberEnc),
		(e) => e === 'tampered'
	);
});

test('a replaced report is flagged', () => {
	const d = sample();
	const real = d.report(0, 4, { flagged: [{ rating: 'high' }] });
	// The instance seals an "all clean" report of the same period itself.
	const clean = toMember(
		JSON.stringify({
			device_id: DEV,
			period_start_ms: real.entry.type === 'report' ? real.entry.period_start_ms : 0,
			period_end_ms: real.entry.type === 'report' ? real.entry.period_end_ms : 0,
			first_seq: 0,
			last_seq: 4,
			flagged: []
		}),
		reportBodyAad(INST, DEV, 1_800_000_000_000, 1_800_086_400_000)
	);
	// With the real header: the content doesn't match what was signed.
	assert.equal(check([real.entry])[0].status, 'verified');
	assert.throws(
		() => openFetched(real.entry, clean, INST, MEMBER, memberEnc),
		(e) => e === 'tampered'
	);
	// With a header to match: no device signature over it.
	if (real.entry.type !== 'report') throw new Error('a report');
	const forged: FeedEntry = {
		...real.entry,
		header: {
			...real.entry.header!,
			body_hash: itemBodyHash(clean),
			body_len: unb64(clean.ciphertext).length
		}
	};
	assert.equal(openFetched(forged, clean, INST, MEMBER, memberEnc).kind, 'report');
	assert.equal(check([forged])[0].status, 'failed');
	// Without a header at all.
	const bare = { ...real.entry, header: undefined, sig: undefined };
	assert.equal(check([bare])[0].status, 'failed');
	// A report whose content disagrees with its own header (seq range).
	const lying = d.report(0, 4, { last_seq: 3 });
	assert.throws(
		() => openFetched(lying.entry, lying.item, INST, MEMBER, memberEnc),
		(e) => e === 'tampered'
	);
});

test('a dropped event shows as a gap, also inside a report’s range', () => {
	const d = sample();
	const rep = d.report(0, 4, {});
	const entries = [...d.entries, rep.entry];
	// The instance deletes the shutdown (seq 2) from the chain it serves.
	const links = d.links.filter((l) => l.header.seq !== 2);
	const c = chain(d, entries, links);
	assert.deepEqual(c.gaps, [{ deviceId: DEV, from: 2, to: 2, kind: 'missing', inReport: true }]);
	// Dropping the urgent flag everywhere: the feed skips it and so does
	// the chain.
	const noFlag = entries.filter((e) => !(e.type === 'event' && e.seq === 1));
	const c2 = chain(
		d,
		noFlag,
		d.links.filter((l) => l.header.seq !== 1)
	);
	assert.deepEqual(
		c2.gaps.map((g) => [g.from, g.to, g.kind]),
		[[1, 1, 'missing']]
	);
	// Leaving it out of the feed only: the chain shows it was withheld.
	const c3 = chain(d, noFlag);
	assert.deepEqual(
		c3.gaps.map((g) => [g.from, g.kind, g.eventKind]),
		[[1, 'withheld', 'flag']]
	);
	// ...unless it was received before the window the feed covers.
	assert.deepEqual(chain(d, noFlag, d.links, d.links[1].received_at_ms).gaps, []);
	// The newest events missing below a report's last_seq.
	const c4 = chain(d, entries, d.links.slice(0, 3));
	assert.deepEqual(
		c4.gaps.map((g) => [g.from, g.to, g.kind]),
		[[3, 4, 'missing']]
	);
	assert.deepEqual([...c4.notInChain], [3, 4]);
});

test('a rewritten or forged history is caught', () => {
	const d = sample();
	// A link signed by someone else.
	const forged = d.links.map((l) =>
		l.header.seq === 2 ? { ...l, sig: b64(sign(serverSeed, eventHeaderSigningBytes(l.header))) } : l
	);
	const c = chain(d, d.entries, forged);
	assert.match(c.broken ?? '', /didn’t sign/);
	assert.deepEqual(
		c.gaps.map((g) => g.from),
		[2]
	);
	// A feed event that isn't the one in the chain.
	const other = sample();
	const c2 = chain(d, d.entries, other.links);
	assert.equal(c2.notInChain.size, d.entries.length);
	// prev_hash that doesn't link.
	const e = new Device().event('boot', 'none').event('flag', 'urgent', '{}');
	const broken = [...e.links];
	const h = { ...broken[1].header, prev_hash: genesisHash(INST, DEV) };
	broken[1] = { ...broken[1], header: h, sig: b64(sign(deviceSeed, eventHeaderSigningBytes(h))) };
	const entry = { ...e.entries[0], header: h, sig: broken[1].sig } as FeedEntry;
	assert.match(chain(e, [entry], broken).broken ?? '', /rewritten at event 1/);
});

test('the member key: compared, unconfirmed, changed', () => {
	const served = b64(memberPk);
	const other = b64(signPublicKey(serverSeed));
	assert.equal(allyMemberKey(served, served)?.trust, 'checked');
	assert.equal(allyMemberKey(served, null)?.trust, 'unchecked');
	assert.equal(allyMemberKey(null, null), null);
	const d = sample();
	// Not compared: every check passes, but it is only "unconfirmed".
	assert.deepEqual(
		check(d.entries, allyMemberKey(served, null)).map((c) => c.status),
		['unconfirmed', 'unconfirmed', 'unconfirmed']
	);
	// The server reports a new key, the ally compared the old one: checked
	// against the old one, whatever the server now signs fails.
	const changed = allyMemberKey(other, served)!;
	assert.equal(changed.trust, 'changed');
	assert.deepEqual(changed.pk, memberPk);
	assert.equal(check(d.entries, changed)[0].status, 'verified');
	const swapped = allyMemberKey(served, other)!;
	const [r] = check(d.entries, swapped);
	assert.equal(r.status, 'failed');
	assert.match((r as { reason: string }).reason, /key you compared/);
	// No key at all (locked): nothing is claimed either way.
	assert.equal(check(d.entries, null)[0].status, 'unchecked');
});
