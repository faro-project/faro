// Wording for decrypted tamper bodies. Run with `npm test`.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bodyTitle, describeBody, SCREEN_RECORDING_FIX } from './describe.ts';
import type { EventBody } from '../types.ts';

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
