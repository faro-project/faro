// The keys of an iPhone settings_change (docs/IOS.md §9, docs/PROTOCOL.md §3)
// and the words for them. The iPhone app writes these keys
// (apps/ios/FaroKit/Sources/FaroKit/Choices.swift); a key or a value format
// changes there and here together.
//
//   ios.category.<name>      gambling, violence, proxy_vpn: blocked | allowed
//   ios.site                 old is the domain when it was unblocked, new when it was blocked
//   ios.apps, ios.app_categories, ios.web_domains, ios.web_domain_categories
//                            how many are blocked, as a number (which ones is never sent)
//   ios.explicit_media, ios.app_removal_protection, ios.automatic_time
//                            on | off
//   ios.app_rating           4 | 9 | 12 | 17 | off
//   ios.delay_hours          the wait before a loosening, 0 to 72

export interface SettingChangeEntry {
	key: string;
	old?: string;
	new?: string;
}

/** When a change happens, from the reader's side. */
export type Tense =
	/** No waiting involved: it is done. */
	| { when: 'done' }
	/** A loosening that will take effect at `at` (already worded, such as "tomorrow at 21:04"). */
	| { when: 'future'; at: string }
	/** A loosening that took effect at `at`. */
	| { when: 'past'; at: string }
	/** A loosening the member cancelled. */
	| { when: 'cancelled' };

const CATEGORY_PREFIX = 'ios.category.';

const CATEGORY_NAME: Record<string, string> = {
	gambling: 'Gambling sites',
	violence: 'Violent sites',
	proxy_vpn: 'Proxy and VPN sites'
};

/** Toggles: the thing, and the word for it being on and off. */
const TOGGLE: Record<string, { subject: string; on: string; off: string }> = {
	'ios.explicit_media': { subject: 'Explicit media', on: 'blocked', off: 'unblocked' },
	'ios.app_removal_protection': { subject: 'Deleting Faro', on: 'blocked', off: 'allowed' },
	'ios.automatic_time': {
		subject: 'Setting the date and time by hand',
		on: 'blocked',
		off: 'allowed'
	}
};

/** Counts of what the member picked. */
const COUNT: Record<string, string> = {
	'ios.apps': 'The number of blocked apps',
	'ios.app_categories': 'The number of blocked app categories',
	'ios.web_domains': 'The number of blocked websites picked from the list',
	'ios.web_domain_categories': 'The number of blocked website categories'
};

export function isIosKey(key: string): boolean {
	return key.startsWith('ios.');
}

function hours(h: string | undefined): string {
	const n = Number(h);
	if (!Number.isFinite(n)) return h ?? 'unset';
	return n === 0 ? 'no wait' : `${n} hour${n === 1 ? '' : 's'}`;
}

function rating(r: string | undefined): string {
	return r === undefined || r === 'off' ? 'no limit' : `${r}+`;
}

/** A name becoming blocked or unblocked, in the tense that fits. */
function state(
	subject: string,
	plural: boolean,
	device: string,
	blocked: boolean,
	word: { blocked: string; unblocked: string },
	t: Tense
): string {
	const now = blocked ? word.blocked : word.unblocked;
	const before = blocked ? word.unblocked : word.blocked;
	const be = plural ? 'are' : 'is';
	switch (t.when) {
		case 'done':
			return `${subject} ${be} now ${now} on ${device}.`;
		case 'future':
			return `${subject} will be ${now} on ${device} ${t.at}.`;
		case 'past':
			return `${subject} ${plural ? 'were' : 'was'} ${now} on ${device} ${t.at}.`;
		case 'cancelled':
			return `${subject} ${plural ? 'stay' : 'stays'} ${before} on ${device}.`;
	}
}

/** A number or limit changing from one value to another. */
function moved(subject: string, device: string, from: string, to: string, t: Tense): string {
	switch (t.when) {
		case 'done':
			return `${subject} on ${device} changed from ${from} to ${to}.`;
		case 'future':
			return `${subject} on ${device} will change from ${from} to ${to} ${t.at}.`;
		case 'past':
			return `${subject} on ${device} changed from ${from} to ${to} ${t.at}.`;
		case 'cancelled':
			return `${subject} on ${device} stays at ${from}.`;
	}
}

/**
 * One iPhone setting change in words, such as "Gambling sites will be
 * unblocked on iPhone-X tomorrow at 21:04.", or `undefined` for a key that
 * isn't in the vocabulary (the caller falls back to the plain key and values).
 */
export function describeIosSetting(
	c: SettingChangeEntry,
	device: string,
	t: Tense = { when: 'done' }
): string | undefined {
	if (c.key.startsWith(CATEGORY_PREFIX)) {
		const name = c.key.slice(CATEGORY_PREFIX.length);
		const subject = CATEGORY_NAME[name] ?? `${name.replaceAll('_', ' ')} sites`;
		return state(
			subject,
			true,
			device,
			c.new === 'blocked',
			{ blocked: 'blocked', unblocked: 'unblocked' },
			t
		);
	}
	if (c.key === 'ios.site') {
		const site = c.new ?? c.old;
		if (!site) return undefined;
		return state(
			site,
			false,
			device,
			c.new !== undefined,
			{ blocked: 'blocked', unblocked: 'unblocked' },
			t
		);
	}
	const toggle = TOGGLE[c.key];
	if (toggle) {
		return state(
			toggle.subject,
			false,
			device,
			c.new === 'on',
			{ blocked: toggle.on, unblocked: toggle.off },
			t
		);
	}
	if (COUNT[c.key]) return moved(COUNT[c.key], device, c.old ?? '0', c.new ?? '0', t);
	if (c.key === 'ios.app_rating')
		return moved('The App Store age limit', device, rating(c.old), rating(c.new), t);
	if (c.key === 'ios.delay_hours')
		return moved('The wait before blocking less', device, hours(c.old), hours(c.new), t);
	return undefined;
}
