// Plain-language wording for feed items and decrypted bodies.
//
// The feed itself is metadata (kinds, urgency, times); the details are only
// known after decrypting. Wording aims at an honest conversation between a
// member and their allies (ARCHITECTURE.md §6), not at alarm.

import type {
	BlockedHost,
	DailyReport,
	EventBody,
	EventKind,
	FilterOffCause,
	FeedEntry,
	Platform,
	Rating,
	Reason,
	ServerAlertKind,
	TamperSignal
} from '../types.ts';
import { date } from '../format.ts';
import { describeIosSetting, type Tense } from './ios-settings.ts';

export type Tone = 'urgent' | 'normal' | 'info' | 'good';

export const RATING_LABEL: Record<Rating, string> = {
	clean: 'Clean',
	low: 'Low',
	medium: 'Medium',
	high: 'High'
};

const EVENT_TITLE: Record<EventKind, string> = {
	capture: 'Screen checked',
	flag: 'Something was flagged',
	tamper: 'Possible tampering',
	settings_change: 'Faro settings changed',
	agent_restarted: 'Faro kept restarting',
	paused: 'Monitoring paused',
	resumed: 'Monitoring resumed',
	goodbye: 'Faro stopped on a computer',
	boot: 'Computer started',
	shutdown: 'Computer shut down'
};

function kv(detail: string | null): Record<string, string> {
	const out: Record<string, string> = {};
	for (const part of (detail ?? '').split(';')) {
		const i = part.indexOf('=');
		if (i > 0) out[part.slice(0, i)] = part.slice(i + 1);
		else if (part) out[part] = '';
	}
	return out;
}

function duration(ms: number): string {
	const m = Math.round(ms / 60000);
	if (m < 60) return `${m} minute${m === 1 ? '' : 's'}`;
	const h = Math.round(m / 60);
	if (h < 48) return `${h} hour${h === 1 ? '' : 's'}`;
	const d = Math.round(h / 24);
	return `${d} day${d === 1 ? '' : 's'}`;
}

const STATE_TEXT: Record<string, string> = {
	active: 'in use',
	idle: 'idle',
	locked: 'locked',
	paused: 'paused',
	sleeping: 'going to sleep',
	shutting_down: 'shutting down',
	unknown: 'unknown'
};

/** Who an id in an alert's detail is, if the page knows. */
export type NameOf = (userId: string) => string | undefined;

export interface Described {
	title: string;
	text?: string;
	tone: Tone;
}

/** A one-line description of a feed entry from its metadata alone. */
export function describeEntry(
	e: FeedEntry,
	nameOf: NameOf,
	device: string,
	platform?: Platform
): Described {
	const d = describeMeta(e, nameOf, device, platform);
	// "iPhone-X" keeps its small i.
	const title = /^i[A-Z]/.test(d.title)
		? d.title
		: d.title.charAt(0).toUpperCase() + d.title.slice(1);
	return { ...d, title };
}

function describeMeta(
	e: FeedEntry,
	nameOf: NameOf,
	device: string,
	platform: Platform | undefined
): Described {
	const tone: Tone = e.type !== 'report' && e.urgency === 'urgent' ? 'urgent' : 'normal';
	if (e.type === 'report') {
		return { title: 'Daily report', text: device, tone: 'info' };
	}
	if (e.type === 'event') {
		const title =
			platform === 'ios' && e.kind === 'goodbye'
				? 'Faro stopped on an iPhone'
				: (EVENT_TITLE[e.kind] ?? e.kind);
		return { title, text: device, tone };
	}
	return describeAlert(e, e.kind, e.detail, nameOf, device, tone, platform);
}

/**
 * Whether a decrypted body can only come from an iPhone. The instance can't
 * say what kind of device a feed entry is about (and an ally has no device
 * list), so the page learns it from what it has decrypted.
 */
export function isIosBody(b: EventBody): boolean {
	if (b.type === 'blocked_summary' || b.type === 'shield_summary') return true;
	if (b.type === 'tamper') {
		return (
			b.signal.signal === 'screen_time_revoked' ||
			b.signal.signal === 'filter_off' ||
			b.signal.signal === 'settings_cleared' ||
			b.signal.signal === 'jailbreak_suspected'
		);
	}
	return false;
}

function describeAlert(
	e: Extract<FeedEntry, { type: 'alert' }>,
	kind: ServerAlertKind,
	detail: string | null,
	nameOf: NameOf,
	device: string,
	tone: Tone,
	platform: Platform | undefined
): Described {
	const d = kv(detail);
	const who = (id: string | undefined) => (id ? nameOf(id) : undefined);
	const after = (prefix: string) =>
		detail?.startsWith(prefix) ? detail.slice(prefix.length) : undefined;
	switch (kind) {
		case 'missed_checkin':
			if ('back_online' in d) {
				return {
					title: `${device} is back online`,
					text: d.silent_ms ? `It was silent for ${duration(Number(d.silent_ms))}.` : undefined,
					tone: 'good'
				};
			}
			if (platform === 'ios') {
				// `since_ms` is when the silence began: the alert comes after the grace period.
				const since = Number(d.since_ms);
				const silent = since > 0 && e.ts_ms > since ? e.ts_ms - since : 0;
				return {
					title: silent
						? `${device} hasn't checked in for ${duration(silent)}`
						: `${device} hasn't checked in`,
					text: `Its last report said it was ${STATE_TEXT[d.last_state] ?? 'in an unknown state'}. The phone may be switched off or out of signal, or Faro may have been removed.`,
					tone
				};
			}
			return {
				title: `${device} stopped checking in`,
				text: `Its last report said it was ${STATE_TEXT[d.last_state] ?? 'in an unknown state'}. Faro may have been stopped, or the computer is offline.`,
				tone
			};
		case 'upload_stalled':
			return {
				title: `${device} isn't sending what it records`,
				text: 'It is online but holding back events. Something may be blocking Faro.',
				tone
			};
		case 'chain_gap':
			return {
				title: `Events from ${device} are missing`,
				text:
					detail === 'heartbeat_fork'
						? "Its history doesn't match what it sent before."
						: 'Some events never arrived, or were removed.',
				tone
			};
		case 'invalid_signature':
			return {
				title: `${device} sent something that didn't verify`,
				text:
					detail === 'bad_report_signature'
						? 'A daily report had an invalid signature.'
						: 'An event had an invalid signature.',
				tone
			};
		case 'clock_skew':
			return {
				title: `${device}'s clock is wrong`,
				text: 'Its time differs a lot from the server.',
				tone
			};
		case 'device_removed':
			return {
				title: `${device} was removed`,
				text:
					detail === 'removed_by_member'
						? 'The member removed it, so it no longer reports.'
						: 'It no longer reports.',
				tone
			};
		case 'ally_added': {
			const n = who(after('added:'));
			return { title: n ? `${n} became an ally` : 'A new ally was approved', tone: 'info' };
		}
		case 'ally_removed': {
			const left = after('left:');
			if (left) {
				const n = who(left);
				return { title: n ? `${n} stopped being an ally` : 'An ally left', tone: 'info' };
			}
			const n = who(after('removed:'));
			return { title: n ? `${n} was removed as an ally` : 'An ally was removed', tone: 'info' };
		}
		case 'member_settings_changed': {
			const which = after('retention_shortened:');
			return {
				title: 'History is kept for less time',
				text: which
					? `The member shortened how long ${which
							.split(',')
							.map((w) => RETENTION_NAME[w] ?? w)
							.join(', ')} are kept.`
					: 'The member changed a setting.',
				tone: 'normal'
			};
		}
		case 'account_disabled':
			return {
				title: 'The account was disabled by an admin',
				text: "They can't sign in. Their computers keep reporting.",
				tone
			};
		case 'account_enabled':
			return { title: 'The account was re-enabled by an admin', tone: 'info' };
		case 'ally_disabled': {
			const n = who(after('ally:'));
			return {
				title: n
					? `${n}'s account was disabled by an admin`
					: "An ally's account was disabled by an admin",
				text: "That ally can't sign in to see alerts.",
				tone
			};
		}
		case 'ally_enabled': {
			const n = who(after('ally:'));
			return {
				title: n ? `${n}'s account was re-enabled` : "An ally's account was re-enabled",
				tone: 'info'
			};
		}
		// `requested_by=admin`: the instance administrator asked, not the
		// person; `cancelled_by=admin`: an admin cancelled.
		case 'account_deleted': {
			const when = Number(d.purge_after);
			return {
				title:
					d.requested_by === 'admin'
						? 'The account is being deleted by the instance administrator'
						: 'The account is being deleted',
				text: when
					? `Until ${date(when)} nothing changes, and the deletion can be cancelled. Then everything about the account is removed from this server.`
					: 'After 7 days everything about the account is removed from this server.',
				tone
			};
		}
		case 'ally_deleted': {
			const n = who(d.ally);
			const when = Number(d.purge_after);
			if (d.requested_by === 'admin') {
				return {
					title: n
						? `${n}'s account is being deleted by the instance administrator`
						: "An ally's account is being deleted by the instance administrator",
					text: when
						? `They stop being an ally on ${date(when)}, unless the deletion is cancelled.`
						: 'They stop being an ally after 7 days, unless the deletion is cancelled.',
					tone
				};
			}
			return {
				title: n ? `${n} is deleting their account` : 'An ally is deleting their account',
				text: when
					? `They stop being an ally on ${date(when)}, unless they cancel.`
					: 'They stop being an ally after 7 days, unless they cancel.',
				tone
			};
		}
		case 'account_deletion_cancelled': {
			const n = who(d.ally);
			const asked = Number(d.requested);
			if (d.requested_by === 'admin') {
				const by =
					d.cancelled_by === 'admin'
						? 'The instance administrator'
						: d.ally
							? (n ?? 'The ally')
							: 'The member';
				return {
					title: d.ally
						? `The deletion of ${n ? `${n}'s` : "an ally's"} account was cancelled`
						: 'The account deletion was cancelled',
					text: asked
						? `The instance administrator asked for it on ${date(asked)}. ${by} cancelled it. Nothing will be deleted.`
						: `${by} cancelled it. Nothing will be deleted.`,
					tone: 'info'
				};
			}
			return {
				title: d.ally
					? `${n ?? 'An ally'} cancelled deleting their account`
					: 'The account deletion was cancelled',
				text: asked
					? `The deletion was asked for on ${date(asked)}. Nothing will be deleted.`
					: undefined,
				tone: 'info'
			};
		}
	}
	return { title: kind, tone };
}

const RETENTION_NAME: Record<string, string> = {
	event_header_days: 'activity records',
	blob_days: 'reports and details',
	alert_days: 'alerts'
};

/** What the member does when Screen Recording is off for Faro. */
export const SCREEN_RECORDING_FIX =
	'To fix it, the member opens System Settings → Privacy & Security → Screen & System Audio Recording on that computer and turns on Faro Agent. If it is already on (after Faro was reinstalled, for example), they remove it with the − button and add it again.';

/** Why an app might hide a window, so allies can judge a hidden-window alert. */
export const HIDDEN_WINDOW_CONTEXT =
	'Screenshots and screen recordings show whatever is behind such a window. Some apps do this on purpose, such as password managers, video players with copy protection and screen-sharing tools, but any app can, so it is also a way to get around Faro. The member was told on the computer too.';

function screenRecordingOff(s: TamperSignal): boolean {
	return s.signal === 'permission_revoked' && s.permission === 'screen_recording';
}

/**
 * A title for a decrypted event that says more than its kind's, or
 * `undefined` to keep the kind's ("Possible tampering").
 */
export function bodyTitle(b: EventBody, device: string, platform?: Platform): string | undefined {
	if (b.type === 'goodbye' && b.reason === 'uninstalled' && platform === 'ios')
		return `Faro was removed from ${device}`;
	if (b.type === 'tamper') {
		const s = b.signal;
		if (s.signal === 'screen_time_revoked') return `Screen Time protection is off on ${device}`;
		if (s.signal === 'filter_off') return `Faro's web filter is off on ${device}`;
		if (s.signal === 'settings_cleared')
			return `Faro's Screen Time settings were changed on ${device}`;
	}
	if (b.type === 'blocked_summary') return `Websites were blocked on ${device}`;
	if (b.type === 'shield_summary') return `Blocked apps were opened on ${device}`;
	if (b.type === 'settings_change' && b.requested_at !== undefined)
		return b.cancelled_at !== undefined
			? `A change to ${device} was cancelled`
			: `Protection on ${device} is being loosened`;
	if (b.type === 'tamper' && screenRecordingOff(b.signal))
		return `Screen Recording is off on ${device}`;
	if (b.type === 'tamper' && b.signal.signal === 'window_hidden_from_capture')
		return `A window was hidden from Faro on ${device}`;
	return undefined;
}

export function describeTamper(s: TamperSignal): string {
	switch (s.signal) {
		case 'permission_revoked':
			if (screenRecordingOff(s))
				return s.never_granted
					? "Faro doesn't have Screen Recording permission on this computer, so it can't see the screen."
					: "Screen Recording was turned off for Faro, so it can't see the screen.";
			return `A permission Faro needs was turned off (${s.permission.replaceAll('_', ' ')}).`;
		case 'agent_killed_repeatedly':
			return `Faro was stopped ${s.count} times in ${duration(s.window_secs * 1000)}.`;
		case 'integrity_failure':
			return `A part of Faro was changed or damaged (${s.component}).`;
		case 'clock_manipulation':
			return "The computer's clock was changed.";
		case 'wayland_token_lost':
			return 'Screen access was lost and needs approving again.';
		case 'capture_failing':
			return `Faro couldn't see the screen ${s.consecutive_failures} times in a row.`;
		case 'unmonitored_user_session':
			return `Someone used the account “${s.user}” while Faro wasn't running in it.`;
		case 'window_hidden_from_capture':
			return `“${s.app}” kept a window out of Faro's screen captures, so Faro couldn't see what it showed.`;
		case 'browser_without_extension':
			return `${s.browser} was used without the Faro extension.`;
		case 'vpn_active':
			return 'A VPN was on.';
		case 'virtual_machine':
			return 'A virtual machine was running.';
		case 'remote_desktop':
			return 'The computer was used over remote desktop.';
		case 'screen_time_revoked':
			return 'Screen Time access was turned off for Faro. The app blocks and shields are gone, and Faro can now be deleted from the iPhone.';
		case 'filter_off':
			return `Faro's web filter is off. ${FILTER_OFF_CAUSE[s.cause] ?? FILTER_OFF_CAUSE.unknown}`;
		case 'settings_cleared':
			return "Faro's Screen Time settings were cleared or changed, though Screen Time access is still on.";
		case 'doh_dropped':
			return 'Faro dropped connections to private DNS services that could get around the web filter.';
		case 'other_vpn':
			return 'Another VPN was connected.';
		case 'jailbreak_suspected':
			return 'The iPhone looks jailbroken, so Faro may not be able to protect it.';
	}
}

const FILTER_OFF_CAUSE: Record<FilterOffCause, string> = {
	vpn_disconnected: 'The VPN was switched off.',
	on_demand_off: 'Connect On Demand was turned off.',
	other_vpn: 'Another VPN took over.',
	profile_removed: 'The Faro VPN profile was deleted.',
	unknown: "The filter stopped reporting, and the iPhone doesn't say why."
};

/** Said in every iPhone report (docs/IOS.md §11). */
export const IOS_LIMITS_NOTICE =
	"Faro on iPhone blocks; it doesn't see the screen. It can't block sites reached through some private DNS services or apps.";

const CATEGORY_NAME: Record<string, string> = { adult: 'Adult', gambling: 'Gambling' };

export function categoryName(c: string): string {
	return CATEGORY_NAME[c] ?? c.replaceAll('_', ' ').replace(/^./, (m) => m.toUpperCase());
}

/** "adult 10, gambling 2", largest first. */
export function categoryCounts(by: Record<string, number>): string {
	return Object.entries(by)
		.sort((a, b) => b[1] - a[1])
		.map(([c, n]) => `${categoryName(c).toLowerCase()} ${n}`)
		.join(', ');
}

/** Hosts grouped by category, for a list: the host and how often it was blocked. */
export function hostsByCategory(
	hosts: BlockedHost[]
): { category: string; hosts: BlockedHost[] }[] {
	const out = new Map<string, BlockedHost[]>();
	for (const h of hosts) out.set(h.category, [...(out.get(h.category) ?? []), h]);
	return [...out].map(([category, hs]) => ({
		category,
		hosts: hs.sort((a, b) => b.count - a.count)
	}));
}

/** "today at 21:04", "tomorrow at 21:04", or a date and time. */
export function whenText(ms: number, now: number): string {
	const d = new Date(ms);
	const t = d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
	const n = new Date(now);
	const dayShift = Math.round(
		(new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime() -
			new Date(n.getFullYear(), n.getMonth(), n.getDate()).getTime()) /
			86400_000
	);
	if (dayShift === 0) return `today at ${t}`;
	if (dayShift === 1) return `tomorrow at ${t}`;
	if (dayShift === -1) return `yesterday at ${t}`;
	return `${date(ms)} at ${t}`;
}

function settingChange(c: { key: string; old?: string; new?: string }): string {
	return `${c.key.replaceAll('_', ' ')}: ${c.old ?? 'unset'} → ${c.new ?? 'unset'}`;
}

export function describeReason(r: Reason): string {
	const label = r.label.replaceAll('_', ' ');
	const src: Record<Reason['source'], string> = {
		image: 'what was on screen',
		domain: 'the website',
		title: 'the window title',
		app: 'the app',
		ocr: 'text on screen',
		context: 'context',
		dns: 'blocked lookups'
	};
	return `${label} (from ${src[r.source] ?? r.source})`;
}

/** Sentences for a decrypted event body. */
export function describeBody(
	b: EventBody,
	device = 'this device',
	now = Date.now(),
	platform?: Platform
): string[] {
	switch (b.type) {
		case 'flag': {
			const out = [
				`Rated ${RATING_LABEL[b.rating].toLowerCase()}: ${b.reasons.map(describeReason).join('; ') || 'no reason given'}.`
			];
			const where = b.app?.name ?? b.app?.id;
			if (where) out.push(`In ${where}${b.window_title ? `, “${b.window_title}”` : ''}.`);
			if (b.browser?.url)
				out.push(`Address: ${b.browser.url}${b.browser.incognito ? ' (private window)' : ''}`);
			if (b.burst) out.push('Part of a burst of similar moments.');
			if (b.account) out.push(`In the account “${b.account}”.`);
			return out;
		}
		case 'tamper':
			return [
				describeTamper(b.signal),
				...(b.account ? [`In the account “${b.account}”.`] : []),
				...(screenRecordingOff(b.signal) ? [SCREEN_RECORDING_FIX] : []),
				...(b.signal.signal === 'window_hidden_from_capture' ? [HIDDEN_WINDOW_CONTEXT] : [])
			];
		case 'settings_change': {
			const words = (tense: Tense) =>
				b.changes.map((c) => describeIosSetting(c, device, tense) ?? settingChange(c));
			if (b.requested_at === undefined && b.takes_effect_at === undefined)
				return words({ when: 'done' });
			const asked =
				b.requested_at !== undefined ? ` (asked for ${whenText(b.requested_at, now)})` : '';
			// iPhone settings read as sentences with the time in them; the
			// plain "key: old → new" lines still need a sentence to say when.
			const allWords = b.changes.every((c) => describeIosSetting(c, device) !== undefined);
			if (b.cancelled_at !== undefined) {
				const lead = `The member cancelled this before it took effect, on ${whenText(b.cancelled_at, now)}. Nothing changed on ${device}.${asked}`;
				return [lead, ...words({ when: 'cancelled' })];
			}
			if (b.takes_effect_at === undefined) return words({ when: 'done' });
			const delay = b.delay_secs
				? ` after the member's ${duration(b.delay_secs * 1000)} delay`
				: '';
			const future = b.takes_effect_at > now;
			const at = whenText(b.takes_effect_at, now);
			if (allWords)
				return [
					...words({ when: future ? 'future' : 'past', at }),
					future
						? `${delay ? `That is${delay}. ` : ''}The member can still cancel it.${asked}`
						: `${delay ? `That was${delay}.` : ''}${asked}`.trim()
				].filter(Boolean);
			return [
				future
					? `This will take effect on ${device} ${at}${delay}. The member can still cancel it.${asked}`
					: `This took effect on ${device} ${at}${delay}.${asked}`,
				...words({ when: 'done' })
			];
		}
		case 'blocked_summary': {
			const total = Object.values(b.by_category).reduce((a, n) => a + n, 0);
			const lines = [
				`${total} blocked lookup${total === 1 ? '' : 's'} in ${duration(b.bucket_secs * 1000)}${total ? `: ${categoryCounts(b.by_category)}` : ''}.`
			];
			for (const g of hostsByCategory(b.hosts))
				lines.push(
					`${categoryName(g.category)}: ${g.hosts.map((h) => `${h.host} (${h.count})`).join(', ')}.`
				);
			if (b.other_hosts) lines.push(`${b.other_hosts} more lookups of other sites, not listed.`);
			return lines;
		}
		case 'shield_summary':
			return [
				`A blocked app was opened ${b.shown} time${b.shown === 1 ? '' : 's'} and the block screen was closed ${b.closed} time${b.closed === 1 ? '' : 's'}. Which apps is never recorded.`
			];
		case 'agent_restarted':
			return [`Faro restarted ${b.count_last_hour} times in the last hour.`];
		case 'paused':
			return [
				b.reason ? `Reason given: ${b.reason}` : 'No reason given.',
				...(b.until_ms ? [`Until ${new Date(b.until_ms).toLocaleString()}.`] : [])
			];
		case 'resumed':
			return ['Monitoring is running again.'];
		case 'goodbye':
			if (b.reason === 'uninstalled')
				return [
					platform === 'ios'
						? `Faro was removed from ${device}.`
						: 'Faro was uninstalled from this computer.'
				];
			if (b.reason === 'account_deleted') return ['The member deleted their account.'];
			return [`Faro moved to another instance (${b.reason.moved_instance.new_instance_host}).`];
		case 'boot':
			return [`${b.os}, Faro ${b.client_version}.`];
		case 'capture':
			return [`${b.count} screen check${b.count === 1 ? '' : 's'}, rated ${b.rating}.`];
		case 'shutdown':
			return ['The computer shut down normally.'];
	}
}

/** Highlights of a daily report for its summary line. */
export function reportSummary(r: DailyReport): string {
	const parts: string[] = [];
	if (r.ios) {
		// An iPhone blocks; it has no screen checks to count.
		const blocked = r.ios.blocked.reduce(
			(n, d) => n + Object.values(d.by_category).reduce((a, b) => a + b, 0),
			0
		);
		const opened = r.ios.shields.reduce((n, d) => n + d.shown, 0);
		parts.push(`${blocked} blocked lookup${blocked === 1 ? '' : 's'}`);
		parts.push(`${opened} blocked app${opened === 1 ? '' : 's'} opened`);
		const bursts = r.flagged.length;
		parts.push(bursts ? `${bursts} burst${bursts === 1 ? '' : 's'} flagged` : 'nothing flagged');
	} else {
		const total = r.counts.clean + r.counts.low + r.counts.medium + r.counts.high;
		parts.push(`${total} screen check${total === 1 ? '' : 's'}`);
		const flagged = r.counts.medium + r.counts.high;
		parts.push(flagged ? `${flagged} flagged` : 'nothing flagged');
	}
	if (r.health.tamper.length)
		parts.push(`${r.health.tamper.length} tamper signal${r.health.tamper.length === 1 ? '' : 's'}`);
	return parts.join(' · ');
}
