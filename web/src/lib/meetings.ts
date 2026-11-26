// Group meetings in words (docs/GROUPS.md §8.4). A meeting is a weekday, a
// time and a fixed UTC offset (the server has no time-zone database), so
// wording is built here from those numbers, in English and without Intl, so
// it reads the same everywhere. Kept free of the DOM so `npm test` covers it.

import type { Meeting, MeetingInput } from './types.ts';

export const WEEKDAYS = [
	'Monday',
	'Tuesday',
	'Wednesday',
	'Thursday',
	'Friday',
	'Saturday',
	'Sunday'
] as const;

/** 1140 → "7:00 pm". */
export function formatMinute(minuteOfDay: number): string {
	const h = Math.floor(minuteOfDay / 60) % 24;
	const m = minuteOfDay % 60;
	const hour12 = h % 12 === 0 ? 12 : h % 12;
	return `${hour12}:${String(m).padStart(2, '0')} ${h < 12 ? 'am' : 'pm'}`;
}

/** -300 → "UTC−05:00", 330 → "UTC+05:30", 0 → "UTC". */
export function offsetLabel(min: number): string {
	if (min === 0) return 'UTC';
	const sign = min < 0 ? '−' : '+';
	const abs = Math.abs(min);
	const hh = String(Math.floor(abs / 60)).padStart(2, '0');
	const mm = String(abs % 60).padStart(2, '0');
	return `UTC${sign}${hh}:${mm}`;
}

/** "Every Tuesday at 7:00 pm (UTC−05:00)", or "Every other Tuesday …". */
export function describeSchedule(
	m: Pick<Meeting, 'cadence' | 'weekday' | 'minute_of_day' | 'tz_offset_min'>
): string {
	const day = WEEKDAYS[m.weekday] ?? 'day';
	const every = m.cadence === 'weekly' ? `Every ${day}` : `Every other ${day}`;
	return `${every} at ${formatMinute(m.minute_of_day)} (${offsetLabel(m.tz_offset_min)})`;
}

/** "HH:MM" for an `<input type="time">`, and back. */
export function toTimeValue(minuteOfDay: number): string {
	const h = Math.floor(minuteOfDay / 60);
	return `${String(h).padStart(2, '0')}:${String(minuteOfDay % 60).padStart(2, '0')}`;
}

export function fromTimeValue(v: string): number | null {
	const m = /^(\d{1,2}):(\d{2})$/.exec(v.trim());
	if (!m) return null;
	const h = Number(m[1]);
	const min = Number(m[2]);
	return h < 24 && min < 60 ? h * 60 + min : null;
}

/** The offsets offered in the form: every quarter hour from UTC−12 to UTC+14. */
export const OFFSET_CHOICES: number[] = Array.from({ length: (14 + 12) * 4 + 1 }, (_, i) => {
	return -12 * 60 + i * 15;
});

/** This browser's offset east of UTC now, snapped to what the form offers. */
export function browserOffsetMin(now = new Date()): number {
	return -now.getTimezoneOffset() || 0;
}

/**
 * The next meeting as a sentence for someone looking at the clock: "Today at
 * 7:00 pm", "Tomorrow at …", "Tuesday 3 Dec at …" in the viewer's own time.
 */
export function nextMeetingText(atMs: number, now = Date.now()): string {
	const at = new Date(atMs);
	const startOfDay = (d: Date) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
	const days = Math.round((startOfDay(at) - startOfDay(new Date(now))) / (24 * 3600 * 1000));
	const time = formatMinute(at.getHours() * 60 + at.getMinutes());
	if (days === 0) return `Today at ${time}`;
	if (days === 1) return `Tomorrow at ${time}`;
	const day = WEEKDAYS[(at.getDay() + 6) % 7];
	const months = [
		'Jan',
		'Feb',
		'Mar',
		'Apr',
		'May',
		'Jun',
		'Jul',
		'Aug',
		'Sep',
		'Oct',
		'Nov',
		'Dec'
	];
	return `${day} ${at.getDate()} ${months[at.getMonth()]} at ${time}`;
}

/** A stored meeting as the form sends it (the server owns `anchor_ms`). */
export function toInput(m: Meeting): MeetingInput {
	return {
		cadence: m.cadence,
		weekday: m.weekday,
		minute_of_day: m.minute_of_day,
		tz_offset_min: m.tz_offset_min,
		place: m.place ?? null
	};
}

const DAY_MS = 24 * 3600 * 1000;

/**
 * The first start at or after `now`: the server's own rule (the anchor, then
 * every week or fortnight), so a list of groups can show it without asking
 * each one. `null` when the schedule has no anchor yet.
 */
export function nextStart(
	m: Pick<Meeting, 'cadence' | 'anchor_ms'>,
	now = Date.now()
): number | null {
	if (m.anchor_ms === undefined) return null;
	if (now <= m.anchor_ms) return m.anchor_ms;
	const period = (m.cadence === 'weekly' ? 7 : 14) * DAY_MS;
	return m.anchor_ms + Math.ceil((now - m.anchor_ms) / period) * period;
}
