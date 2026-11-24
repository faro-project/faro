// Display formatting shared by the pages.

const nf = new Intl.NumberFormat();

export function count(n: number): string {
	return nf.format(n);
}

/** `plural(1, 'member')` → "1 member", `plural(3, 'ally', 'allies')` → "3 allies". */
export function plural(n: number, one: string, many = `${one}s`): string {
	return `${nf.format(n)} ${n === 1 ? one : many}`;
}

/** 1536 → "1.5 KB" (decimal units, as disks and hosts report them). */
export function bytes(n: number): string {
	if (n < 1000) return `${nf.format(n)} B`;
	const units = ['KB', 'MB', 'GB', 'TB'];
	let v = n;
	let u = -1;
	do {
		v /= 1000;
		u++;
	} while (v >= 1000 && u < units.length - 1);
	return `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[u]}`;
}

/** A calendar date in the reader's locale, e.g. "24 Nov 2026". */
export function date(ms: number): string {
	return new Date(ms).toLocaleDateString(undefined, {
		day: 'numeric',
		month: 'short',
		year: 'numeric'
	});
}

/** Date and time, for tooltips. */
export function dateTime(ms: number): string {
	return new Date(ms).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

/** "5 minutes ago", "yesterday", "3 weeks ago". */
export function ago(ms: number, now = Date.now()): string {
	const s = Math.round((ms - now) / 1000);
	const abs = Math.abs(s);
	if (abs < 60) return rtf.format(0, 'second').replace(/^in /, '');
	if (abs < 3600) return rtf.format(Math.round(s / 60), 'minute');
	if (abs < 86400) return rtf.format(Math.round(s / 3600), 'hour');
	if (abs < 7 * 86400) return rtf.format(Math.round(s / 86400), 'day');
	if (abs < 60 * 86400) return rtf.format(Math.round(s / (7 * 86400)), 'week');
	if (abs < 365 * 86400) return rtf.format(Math.round(s / (30 * 86400)), 'month');
	return rtf.format(Math.round(s / (365 * 86400)), 'year');
}
