// Wording for the Android tamper and context signals (docs/ANDROID.md §8).
// Run with `npm test`.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bodyTitle, describeBody, describeTamper } from './describe.ts';
import type { EventBody } from '../types.ts';

const PHONE = 'Phone-X';

const tamper = (signal: Extract<EventBody, { type: 'tamper' }>['signal']): EventBody => ({
	type: 'tamper',
	signal
});

test('accessibility off says Faro cannot see the screen', () => {
	const off = tamper({ signal: 'permission_revoked', permission: 'accessibility_service' });
	assert.equal(bodyTitle(off, PHONE), 'Accessibility is off on Phone-X');
	assert.match(describeBody(off)[0], /accessibility service was turned off/);
	const never = tamper({
		signal: 'permission_revoked',
		permission: 'accessibility_service',
		never_granted: true
	});
	assert.match(describeBody(never)[0], /isn't on on this phone/);
});

test('device admin off warns that the app can now be removed', () => {
	const b = tamper({ signal: 'permission_revoked', permission: 'device_admin' });
	assert.equal(bodyTitle(b, PHONE), "Faro's uninstall protection is being turned off on Phone-X");
	assert.match(describeBody(b)[0], /can now be removed/);
});

test('the Android context signals have their own wording', () => {
	assert.match(describeTamper({ signal: 'battery_optimization_on' }), /Battery optimisation/);
	assert.equal(describeTamper({ signal: 'usb_debugging_on' }), 'USB debugging was on.');
});
