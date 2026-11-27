// Wording for decrypted tamper bodies. Run with `npm test`.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
	bodyTitle,
	describeBody,
	describeEntry,
	isIosBody,
	platformOf,
	HIDDEN_WINDOW_CONTEXT,
	SCREEN_RECORDING_FIX
} from './describe.ts';
import type { EventBody, FeedEntry } from '../types.ts';

const tamper = (signal: Extract<EventBody, { type: 'tamper' }>['signal']): EventBody => ({
	type: 'tamper',
	signal
});

test('Screen Recording never granted names the cause and the fix', () => {
	const b = tamper({
		signal: 'permission_revoked',
		permission: 'screen_recording',
		never_granted: true
	});
	assert.equal(bodyTitle(b, 'Laptop'), 'Screen Recording is off on Laptop');
	assert.deepEqual(describeBody(b), [
		"Faro doesn't have Screen Recording permission on this computer, so it can't see the screen.",
		SCREEN_RECORDING_FIX
	]);
});

test('Screen Recording turned off, including bodies from before never_granted', () => {
	const b = tamper({ signal: 'permission_revoked', permission: 'screen_recording' });
	assert.equal(bodyTitle(b, 'Laptop'), 'Screen Recording is off on Laptop');
	assert.deepEqual(describeBody(b), [
		"Screen Recording was turned off for Faro, so it can't see the screen.",
		SCREEN_RECORDING_FIX
	]);
});

test('other tamper signals keep the generic title', () => {
	const failing = tamper({ signal: 'capture_failing', consecutive_failures: 5 });
	assert.equal(bodyTitle(failing, 'Laptop'), undefined);
	assert.deepEqual(describeBody(failing), ["Faro couldn't see the screen 5 times in a row."]);
	const ax = tamper({ signal: 'permission_revoked', permission: 'accessibility' });
	assert.equal(bodyTitle(ax, 'Laptop'), undefined);
	assert.deepEqual(describeBody(ax), ['A permission Faro needs was turned off (accessibility).']);
});

test('a window hidden from capture names the app', () => {
	const b = tamper({ signal: 'window_hidden_from_capture', app: 'Viewer' });
	assert.equal(bodyTitle(b, 'Laptop'), 'A window was hidden from Faro on Laptop');
	assert.deepEqual(describeBody(b), [
		"“Viewer” kept a window out of Faro's screen captures, so Faro couldn't see what it showed.",
		HIDDEN_WINDOW_CONTEXT
	]);
});

const HOUR = 3600_000;
const missed = (detail: string): FeedEntry =>
	({
		type: 'alert',
		kind: 'missed_checkin',
		urgency: 'urgent',
		member_id: 'm1',
		alert_id: 'a1',
		detail,
		device_id: 'd1',
		ts_ms: 10 * HOUR,
		received_at_ms: 10 * HOUR
	}) as FeedEntry;

test('a computer that went quiet keeps the computer wording', () => {
	const d = describeEntry(
		missed(`last_state=sleeping;since_ms=${7 * HOUR}`),
		() => undefined,
		'Laptop',
		'macos'
	);
	assert.equal(d.title, 'Laptop stopped checking in');
	assert.match(d.text ?? '', /going to sleep.*computer is offline/);
	// With no platform known, it is worded for a computer.
	assert.equal(
		describeEntry(missed('last_state=idle;since_ms=0'), () => undefined, 'Laptop').title,
		'Laptop stopped checking in'
	);
});

test('an iPhone that went quiet says for how long, with its last state', () => {
	const d = describeEntry(
		missed(`last_state=idle;since_ms=${7 * HOUR}`),
		() => undefined,
		'iPhone-X',
		'ios'
	);
	assert.equal(d.title, "iPhone-X hasn't checked in for 3 hours");
	assert.match(d.text ?? '', /last report said it was idle/);
	assert.doesNotMatch(d.text ?? '', /computer/);
	assert.equal(d.tone, 'urgent');
});

test('an iPhone with no start of silence still avoids the computer wording', () => {
	const d = describeEntry(missed('last_state=unknown'), () => undefined, 'iPhone-X', 'ios');
	assert.equal(d.title, "iPhone-X hasn't checked in");
	assert.match(d.text ?? '', /was unknown/);
});

test('an iPhone coming back online reads the same as a computer', () => {
	const d = describeEntry(
		missed(`back_online;silent_ms=${4 * HOUR}`),
		() => undefined,
		'iPhone-X',
		'ios'
	);
	assert.equal(d.title, 'iPhone-X is back online');
});

test('goodbye: an iPhone was removed, a computer was uninstalled', () => {
	const bye: EventBody = { type: 'goodbye', reason: 'uninstalled' };
	assert.equal(bodyTitle(bye, 'iPhone-X', 'ios'), 'Faro was removed from iPhone-X');
	assert.deepEqual(describeBody(bye, 'iPhone-X', Date.now(), 'ios'), [
		'Faro was removed from iPhone-X.'
	]);
	assert.equal(bodyTitle(bye, 'Laptop', 'macos'), undefined);
	assert.deepEqual(describeBody(bye, 'Laptop', Date.now(), 'macos'), [
		'Faro was uninstalled from this computer.'
	]);
	assert.deepEqual(describeBody(bye), ['Faro was uninstalled from this computer.']);
	// Other reasons keep their words on either.
	const deleted: EventBody = { type: 'goodbye', reason: 'account_deleted' };
	assert.deepEqual(describeBody(deleted, 'iPhone-X', Date.now(), 'ios'), [
		'The member deleted their account.'
	]);
});

test('the goodbye entry before it is opened names an iPhone too', () => {
	const e = {
		type: 'event',
		kind: 'goodbye',
		urgency: 'urgent',
		device_id: 'd1',
		received_at_ms: 0
	} as FeedEntry;
	assert.equal(
		describeEntry(e, () => undefined, 'iPhone-X', 'ios').title,
		'Faro stopped on an iPhone'
	);
	assert.equal(
		describeEntry(e, () => undefined, 'Laptop', 'macos').title,
		'Faro stopped on a computer'
	);
});

test('only iPhone-only bodies mark a device as an iPhone', () => {
	assert.equal(isIosBody(tamper({ signal: 'filter_off', cause: 'unknown' })), true);
	assert.equal(isIosBody(tamper({ signal: 'capture_failing', consecutive_failures: 1 })), false);
	assert.equal(isIosBody({ type: 'goodbye', reason: 'uninstalled' }), false);
});

test("an ally's feed words an iPhone's goodbye and missed check-in from the feed's platforms", () => {
	// What an ally's page has: the feed's map, no device list and no iPhone body.
	const fromFeed = { d1: 'ios', d2: 'macos' } as const;
	const ally = (id: string | null) => platformOf(id, undefined, fromFeed);
	const goodbye = {
		type: 'event',
		kind: 'goodbye',
		urgency: 'urgent',
		device_id: 'd1',
		received_at_ms: 0
	} as FeedEntry;
	assert.equal(
		describeEntry(goodbye, () => undefined, 'iPhone-X', ally('d1')).title,
		'Faro stopped on an iPhone'
	);
	const bye: EventBody = { type: 'goodbye', reason: 'uninstalled' };
	assert.equal(bodyTitle(bye, 'iPhone-X', ally('d1')), 'Faro was removed from iPhone-X');
	const quiet = missed(`last_state=idle;since_ms=${7 * HOUR}`);
	assert.equal(
		describeEntry(quiet, () => undefined, 'iPhone-X', ally('d1')).title,
		"iPhone-X hasn't checked in for 3 hours"
	);
	// A computer, a device the feed doesn't list, and an older instance keep the computer wording.
	assert.equal(
		describeEntry(goodbye, () => undefined, 'Laptop', ally('d2')).title,
		'Faro stopped on a computer'
	);
	assert.equal(ally('d9'), undefined);
	assert.equal(platformOf('d1', undefined, undefined), undefined);
	// The member's own device list wins over the feed's map.
	assert.equal(platformOf('d1', { d1: 'macos' }, fromFeed), 'macos');
	// A device id can't reach into the object's prototype.
	assert.equal(platformOf('constructor', fromFeed), undefined);
});
