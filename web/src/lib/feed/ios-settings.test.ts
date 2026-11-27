// Wording for iPhone setting keys (docs/IOS.md §9). Run with `npm test`.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bodyTitle, describeBody } from './describe.ts';
import { describeIosSetting, isIosKey } from './ios-settings.ts';
import type { EventBody } from '../types.ts';

const IPHONE = 'iPhone-X';
const now = new Date(2026, 10, 26, 21, 4).getTime();
const tomorrow = new Date(2026, 10, 27, 21, 4).getTime();
const HOUR = 3600_000;

const change = (key: string, old: string | undefined, nw: string | undefined) => ({
	key,
	old,
	new: nw
});

test('an opted-in category being loosened reads as the issue asks', () => {
	const body: EventBody = {
		type: 'settings_change',
		changes: [change('ios.category.gambling', 'blocked', 'allowed')],
		requested_at: now,
		takes_effect_at: tomorrow,
		delay_secs: 86400
	};
	const [first, second] = describeBody(body, IPHONE, now);
	assert.match(
		first,
		/^Gambling sites will be unblocked on iPhone-X tomorrow at (21:04|9:04\sPM)\.$/
	);
	assert.match(second, /after the member's 24 hours delay/);
	assert.match(second, /can still cancel/);
	assert.equal(bodyTitle(body, IPHONE), 'Protection on iPhone-X is being loosened');
});

test('after the time, it is past tense, and a cancelled one stays as it was', () => {
	const asked: EventBody = {
		type: 'settings_change',
		changes: [change('ios.category.gambling', 'blocked', 'allowed')],
		requested_at: now,
		takes_effect_at: tomorrow,
		delay_secs: 86400
	};
	const applied = describeBody(asked, IPHONE, tomorrow + HOUR);
	assert.match(applied[0], /^Gambling sites were unblocked on iPhone-X today at /);
	assert.ok(!applied.join(' ').includes('can still cancel'));

	const cancelled = describeBody({ ...asked, cancelled_at: now + HOUR }, IPHONE, now + 2 * HOUR);
	assert.match(cancelled[0], /cancelled this before it took effect/);
	assert.equal(cancelled[1], 'Gambling sites stay blocked on iPhone-X.');
});

test('tightening is plain and immediate', () => {
	assert.deepEqual(
		describeBody(
			{
				type: 'settings_change',
				changes: [
					change('ios.category.gambling', 'allowed', 'blocked'),
					change('ios.site', undefined, 'bad.example'),
					change('ios.explicit_media', 'off', 'on')
				]
			},
			IPHONE,
			now
		),
		[
			'Gambling sites are now blocked on iPhone-X.',
			'bad.example is now blocked on iPhone-X.',
			'Explicit media is now blocked on iPhone-X.'
		]
	);
});

test('sites, counts, the rating and the delay each have words', () => {
	const f = { when: 'future', at: 'tomorrow at 9:00 PM' } as const;
	assert.equal(
		describeIosSetting(change('ios.site', 'bad.example', undefined), IPHONE, f),
		'bad.example will be unblocked on iPhone-X tomorrow at 9:00 PM.'
	);
	assert.equal(
		describeIosSetting(change('ios.apps', '3', '2'), IPHONE, f),
		'The number of blocked apps on iPhone-X will change from 3 to 2 tomorrow at 9:00 PM.'
	);
	assert.equal(
		describeIosSetting(change('ios.app_rating', '12', 'off'), IPHONE),
		'The App Store age limit on iPhone-X changed from 12+ to no limit.'
	);
	assert.equal(
		describeIosSetting(change('ios.delay_hours', '24', '0'), IPHONE, f),
		'The wait before blocking less on iPhone-X will change from 24 hours to no wait tomorrow at 9:00 PM.'
	);
	assert.equal(
		describeIosSetting(change('ios.delay_hours', '24', '1'), IPHONE),
		'The wait before blocking less on iPhone-X changed from 24 hours to 1 hour.'
	);
	assert.equal(
		describeIosSetting(change('ios.app_removal_protection', 'on', 'off'), IPHONE, f),
		'Deleting Faro will be allowed on iPhone-X tomorrow at 9:00 PM.'
	);
});

test('other categories and unknown keys', () => {
	assert.equal(
		describeIosSetting(change('ios.category.proxy_vpn', 'blocked', 'allowed'), IPHONE),
		'Proxy and VPN sites are now unblocked on iPhone-X.'
	);
	assert.equal(describeIosSetting(change('ios.something_new', 'a', 'b'), IPHONE), undefined);
	assert.equal(isIosKey('ios.site'), true);
	assert.equal(isIosKey('gambling'), false);
	// An unknown key falls back to the plain line, and the lead sentence stays.
	const mixed = describeBody(
		{
			type: 'settings_change',
			changes: [change('ios.something_new', 'a', 'b')],
			requested_at: now,
			takes_effect_at: tomorrow
		},
		IPHONE,
		now
	);
	assert.match(mixed[0], /^This will take effect on iPhone-X tomorrow/);
	assert.equal(mixed[1], 'ios.something new: a → b');
});
