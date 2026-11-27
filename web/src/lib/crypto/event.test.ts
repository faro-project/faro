// The event and report header port against the Rust vectors
// (crates/faro-crypto/tests/data/web-vectors.json, `event_chain` and
// `report_header`). Run with `npm test`.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { hex, unb64 } from './bytes.ts';
import {
	chainHash,
	effectiveUrgency,
	eventHeaderSigningBytes,
	genesisHash,
	reportHeaderSigningBytes,
	verifyHeader,
	type EventHeader
} from './event.ts';

const V = JSON.parse(
	readFileSync(
		join(import.meta.dirname, '../../../../crates/faro-crypto/tests/data/web-vectors.json'),
		'utf8'
	)
);
const devicePk = unb64(V.keys.device_sign_pubkey);

test('event headers encode, hash, chain and verify as in Rust', () => {
	const c = V.event_chain;
	assert.equal(genesisHash(V.ids.instance, V.ids.device), c.genesis_hash);
	let prev = c.genesis_hash;
	for (const l of c.links) {
		const h: EventHeader = l.header;
		assert.equal(hex(eventHeaderSigningBytes(h)), l.signing_bytes_hex);
		assert.equal(chainHash(h), l.chain_hash);
		assert.equal(h.prev_hash, prev);
		assert.ok(verifyHeader(devicePk, h, l.sig, eventHeaderSigningBytes));
		// Any change breaks the signature.
		assert.ok(
			!verifyHeader(
				devicePk,
				{ ...h, urgency: 'none' as const, seq: h.seq + 1 },
				l.sig,
				eventHeaderSigningBytes
			)
		);
		prev = l.chain_hash;
	}
	// The tamper was signed `none`; the floor raises it.
	const tamper = c.links[2].header;
	assert.equal(tamper.urgency, 'none');
	assert.equal(effectiveUrgency(tamper), 'urgent');
	assert.equal(effectiveUrgency(c.links[0].header), 'none');
});

test('report headers encode and verify as in Rust', () => {
	const r = V.report_header;
	assert.equal(hex(reportHeaderSigningBytes(r.header)), r.signing_bytes_hex);
	assert.ok(verifyHeader(devicePk, r.header, r.sig, reportHeaderSigningBytes));
	assert.ok(!verifyHeader(devicePk, { ...r.header, last_seq: 1 }, r.sig, reportHeaderSigningBytes));
	assert.ok(!verifyHeader(devicePk, r.header, 'not a signature', reportHeaderSigningBytes));
});
