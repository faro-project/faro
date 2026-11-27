// Wording for the iPhone bodies and tamper signals (docs/IOS.md §10.2, §11).
// Run with `npm test`.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import {
	bodyTitle,
	categoryCounts,
	describeBody,
	describeReason,
	describeTamper,
	hostsByCategory,
	IOS_LIMITS_NOTICE,
	reportSummary
} from './describe.ts';
import type { DailyReport, EventBody } from '../types.ts';

const IPHONE = 'iPhone-X';

const tamper = (signal: Extract<EventBody, { type: 'tamper' }>['signal']): EventBody => ({
	type: 'tamper',
	signal
});

test('Screen Time revoked says Faro can now be deleted', () => {
	const b = tamper({ signal: 'screen_time_revoked' });
	assert.equal(bodyTitle(b, IPHONE), 'Screen Time protection is off on iPhone-X');
	assert.match(describeBody(b)[0], /Faro can now be deleted/);
});

test('the web filter being off names each cause', () => {
	const causes = {
		vpn_disconnected: 'The VPN was switched off.',
		on_demand_off: 'Connect On Demand was turned off.',
		other_vpn: 'Another VPN took over.',
		profile_removed: 'The Faro VPN profile was deleted.',
		unknown: "The filter stopped reporting, and the iPhone doesn't say why."
	} as const;
	for (const [cause, text] of Object.entries(causes)) {
		const b = tamper({ signal: 'filter_off', cause: cause as keyof typeof causes });
		assert.equal(bodyTitle(b, IPHONE), "Faro's web filter is off on iPhone-X");
		assert.equal(describeBody(b)[0], `Faro's web filter is off. ${text}`);
	}
});

test('cleared Screen Time settings', () => {
	const b = tamper({ signal: 'settings_cleared' });
	assert.equal(bodyTitle(b, IPHONE), "Faro's Screen Time settings were changed on iPhone-X");
	assert.match(describeBody(b)[0], /still on/);
});

test('iPhone context signals are described for the report', () => {
	for (const signal of ['doh_dropped', 'other_vpn', 'jailbreak_suspected'] as const)
		assert.ok(describeTamper({ signal }).length > 0);
});

test('a blocked summary lists categories and grouped hosts', () => {
	const b: EventBody = {
		type: 'blocked_summary',
		bucket_start: 0,
		bucket_secs: 300,
		by_category: { adult: 5, gambling: 2 },
		hosts: [
			{ host: 'a.test', category: 'adult', count: 1 },
			{ host: 'b.test', category: 'adult', count: 4 },
			{ host: 'c.test', category: 'gambling', count: 2 }
		],
		other_hosts: 3
	};
	assert.equal(bodyTitle(b, IPHONE), 'Websites were blocked on iPhone-X');
	assert.deepEqual(describeBody(b), [
		'7 blocked lookups in 5 minutes: adult 5, gambling 2.',
		'Adult: b.test (4), a.test (1).',
		'Gambling: c.test (2).',
		'3 more lookups of other sites, not listed.'
	]);
});

test('a shield summary is counts only', () => {
	const b: EventBody = {
		type: 'shield_summary',
		bucket_start: 0,
		bucket_secs: 300,
		shown: 1,
		closed: 2
	};
	assert.equal(bodyTitle(b, IPHONE), 'Blocked apps were opened on iPhone-X');
	assert.deepEqual(describeBody(b), [
		'A blocked app was opened 1 time and the block screen was closed 2 times. Which apps is never recorded.'
	]);
});

test('a dns flag reason reads plainly', () => {
	assert.equal(
		describeReason({ source: 'dns', label: 'dns:adult ×6, 4 hosts, 3 min, screen on' }),
		'dns:adult ×6, 4 hosts, 3 min, screen on (from blocked lookups)'
	);
});

test('the limits notice is the spec wording', () => {
	assert.equal(
		IOS_LIMITS_NOTICE,
		"Faro on iPhone blocks; it doesn't see the screen. It can't block sites reached through some private DNS services or apps."
	);
});

test('pending loosening: asked for, applied and cancelled', () => {
	const now = new Date(2026, 10, 26, 21, 4).getTime();
	const tomorrow = new Date(2026, 10, 27, 21, 4).getTime();
	const changes = [{ key: 'gambling', old: 'blocked', new: 'allowed' }];
	const asked: EventBody = {
		type: 'settings_change',
		changes,
		requested_at: now,
		takes_effect_at: tomorrow,
		delay_secs: 86400
	};
	assert.equal(bodyTitle(asked, IPHONE), 'Protection on iPhone-X is being loosened');
	const [first, change] = describeBody(asked, IPHONE, now);
	assert.match(first, /^This will take effect on iPhone-X tomorrow at .*24 hours delay/);
	assert.match(first, /can still cancel/);
	assert.equal(change, 'gambling: blocked → allowed');

	const applied = describeBody(asked, IPHONE, tomorrow + 1000);
	assert.match(applied[0], /^This took effect on iPhone-X /);

	const cancelled: EventBody = { ...asked, cancelled_at: now + 3600_000 };
	assert.equal(bodyTitle(cancelled, IPHONE), 'A change to iPhone-X was cancelled');
	assert.match(describeBody(cancelled, IPHONE, now)[0], /cancelled this before it took effect/);

	// A settings_change without the pending fields reads as before.
	assert.deepEqual(describeBody({ type: 'settings_change', changes }, IPHONE, now), [
		'gambling: blocked → allowed'
	]);
});

// ---- the real shapes ------------------------------------------------------
// `crates/faro-core/tests/data/ios-reports.json` is written by the device's
// own report builder and event bodies (a Rust test checks it is current), so
// these tests read what an iPhone really sends.

const FIXTURE = JSON.parse(
	readFileSync(
		join(import.meta.dirname, '../../../../crates/faro-core/tests/data/ios-reports.json'),
		'utf8'
	)
) as { report: DailyReport; events: EventBody[] };

test('the device writes the iPhone section the web app reads', () => {
	const ios = FIXTURE.report.ios;
	assert.ok(ios, 'an iPhone report has the ios section');
	assert.deepEqual(
		ios.protection.map((p) => [p.screen_time, p.filter]),
		[
			[true, true],
			[null, false]
		]
	);
	assert.equal(ios.blocked.length, 1);
	assert.equal(categoryCounts(ios.blocked[0].by_category), 'adult 6, gambling 2, encrypted dns 1');
	assert.deepEqual(
		hostsByCategory(ios.blocked[0].hosts).map((g) => [
			g.category,
			g.hosts.map((h) => `${h.host} ${h.count}`)
		]),
		[
			['adult', ['a.example 5', 'b.example 1']],
			['gambling', ['casino.example 2']]
		]
	);
	assert.equal(ios.blocked[0].other_hosts, 3);
	assert.deepEqual(
		ios.shields.map((s) => [s.shown, s.closed]),
		[[3, 2]]
	);
	assert.match(ios.loosenings?.[0].text ?? '', /^Asked for \(after a delay of 24 hours\)/);
	// An iPhone report has no screen checks and no activity timeline.
	assert.deepEqual(FIXTURE.report.timeline, []);
});

test('an iPhone report summary counts what it blocks, not screen checks', () => {
	assert.equal(
		reportSummary(FIXTURE.report),
		'9 blocked lookups · 3 blocked apps opened · 1 burst flagged · 1 tamper signal'
	);
	const quiet: DailyReport = {
		...FIXTURE.report,
		flagged: [],
		health: { ...FIXTURE.report.health, tamper: [] },
		ios: { protection: [], blocked: [], shields: [] }
	};
	assert.equal(reportSummary(quiet), '0 blocked lookups · 0 blocked apps opened · nothing flagged');
});

test('the real event bodies read as the spec says', () => {
	const [blocked, shield, flag, loosening] = FIXTURE.events;
	assert.deepEqual(describeBody(blocked), [
		'7 blocked lookups in 10 minutes: adult 5, gambling 2.',
		'Adult: a.example (4), b.example (1).',
		'Gambling: casino.example (2).',
		'3 more lookups of other sites, not listed.'
	]);
	assert.deepEqual(describeBody(shield), [
		'A blocked app was opened 3 times and the block screen was closed 2 times. Which apps is never recorded.'
	]);
	assert.equal(flag.type, 'flag');
	assert.equal(
		describeBody(flag)[0],
		'Rated medium: dns:adult ×6, 4 hosts, 3 min, screen on (from blocked lookups).'
	);
	assert.ok(describeBody(flag).includes('Part of a burst of similar moments.'));
	assert.equal(describeBody(loosening, IPHONE, 0)[1], 'blocking.gambling: on → off');
});

test('the flagged burst in the report carries the dns reason', () => {
	const [moment] = FIXTURE.report.flagged;
	assert.equal(moment.rating, 'medium');
	assert.deepEqual(
		moment.reasons.map((r) => r.source),
		['dns']
	);
	assert.equal(moment.thumbnail, undefined);
});
