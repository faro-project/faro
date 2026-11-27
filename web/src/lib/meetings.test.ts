// Meeting wording. Run with `npm test`.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
	describeSchedule,
	formatMinute,
	fromTimeValue,
	nextMeetingText,
	nextStart,
	OFFSET_CHOICES,
	offsetLabel,
	toInput,
	toTimeValue
} from './meetings.ts';

test('times read like a clock', () => {
	assert.equal(formatMinute(1140), '7:00 pm');
	assert.equal(formatMinute(0), '12:00 am');
	assert.equal(formatMinute(720), '12:00 pm');
	assert.equal(formatMinute(9 * 60 + 5), '9:05 am');
});

test('offsets are named, with a proper minus', () => {
	assert.equal(offsetLabel(0), 'UTC');
	assert.equal(offsetLabel(-300), 'UTC−05:00');
	assert.equal(offsetLabel(330), 'UTC+05:30');
	assert.ok(OFFSET_CHOICES.includes(-300) && OFFSET_CHOICES.includes(345));
	assert.ok(OFFSET_CHOICES.every((m) => m >= -840 && m <= 840));
});

test('the schedule says the day with Monday first', () => {
	assert.equal(
		describeSchedule({ cadence: 'weekly', weekday: 1, minute_of_day: 1140, tz_offset_min: -300 }),
		'Every Tuesday at 7:00 pm (UTC−05:00)'
	);
	assert.equal(
		describeSchedule({ cadence: 'fortnightly', weekday: 6, minute_of_day: 600, tz_offset_min: 0 }),
		'Every other Sunday at 10:00 am (UTC)'
	);
});

test('time inputs round-trip and refuse nonsense', () => {
	assert.equal(toTimeValue(1140), '19:00');
	assert.equal(fromTimeValue('19:00'), 1140);
	assert.equal(fromTimeValue('7:05'), 425);
	assert.equal(fromTimeValue('24:00'), null);
	assert.equal(fromTimeValue(''), null);
});

test("the next meeting is Today, Tomorrow or a dated day, in the reader's time", () => {
	const now = new Date(2026, 10, 25, 9, 0).getTime(); // Wed 25 Nov 2026
	assert.equal(nextMeetingText(new Date(2026, 10, 25, 19, 0).getTime(), now), 'Today at 7:00 pm');
	assert.equal(
		nextMeetingText(new Date(2026, 10, 26, 8, 30).getTime(), now),
		'Tomorrow at 8:30 am'
	);
	assert.equal(
		nextMeetingText(new Date(2026, 11, 1, 19, 0).getTime(), now),
		'Tuesday 1 Dec at 7:00 pm'
	);
});

test('editing keeps the schedule and drops the server-owned anchor', () => {
	assert.deepEqual(
		toInput({
			cadence: 'weekly',
			weekday: 1,
			minute_of_day: 1140,
			tz_offset_min: 0,
			place: 'Room 104',
			anchor_ms: 5
		}),
		{ cadence: 'weekly', weekday: 1, minute_of_day: 1140, tz_offset_min: 0, place: 'Room 104' }
	);
});

test('the next start follows the anchor, weekly or every other week', () => {
	const DAY = 24 * 3600 * 1000;
	assert.equal(nextStart({ cadence: 'weekly', anchor_ms: 1000 }, 500), 1000);
	assert.equal(nextStart({ cadence: 'weekly', anchor_ms: 0 }, 1), 7 * DAY);
	assert.equal(nextStart({ cadence: 'weekly', anchor_ms: 0 }, 7 * DAY), 7 * DAY);
	assert.equal(nextStart({ cadence: 'fortnightly', anchor_ms: 0 }, 8 * DAY), 14 * DAY);
	assert.equal(nextStart({ cadence: 'weekly' }, 5), null);
});
