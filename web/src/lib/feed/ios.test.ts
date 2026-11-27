// Wording for the iPhone bodies and tamper signals (docs/IOS.md §10.2, §11).
// Run with `npm test`.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
	bodyTitle,
	describeBody,
	describeReason,
	describeTamper,
	IOS_LIMITS_NOTICE
} from './describe.ts';
import type { EventBody } from '../types.ts';

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
