// Plain-language wording for feed items and decrypted bodies.
//
// The feed itself is metadata (kinds, urgency, times); the details are only
// known after decrypting. Wording aims at an honest conversation between a
// member and their allies (ARCHITECTURE.md §6), not at alarm.

import type {
	DailyReport,
	EventBody,
	EventKind,
	FeedEntry,
	Rating,
	Reason,
	ServerAlertKind,
	TamperSignal
} from '../types.ts';
import { date } from '../format.ts';

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
export function describeEntry(e: FeedEntry, nameOf: NameOf, device: string): Described {
	const d = describeMeta(e, nameOf, device);
	return { ...d, title: d.title.charAt(0).toUpperCase() + d.title.slice(1) };
}

function describeMeta(e: FeedEntry, nameOf: NameOf, device: string): Described {
	const tone: Tone = e.type !== 'report' && e.urgency === 'urgent' ? 'urgent' : 'normal';
	if (e.type === 'report') {
		return { title: 'Daily report', text: device, tone: 'info' };
	}
	if (e.type === 'event') {
		return { title: EVENT_TITLE[e.kind] ?? e.kind, text: device, tone };
	}
	return describeAlert(e.kind, e.detail, nameOf, device, tone);
}

function describeAlert(
	kind: ServerAlertKind,
	detail: string | null,
	nameOf: NameOf,
	device: string,
	tone: Tone
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

export function describeTamper(s: TamperSignal): string {
	switch (s.signal) {
		case 'permission_revoked':
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
		case 'browser_without_extension':
			return `${s.browser} was used without the Faro extension.`;
		case 'vpn_active':
			return 'A VPN was on.';
		case 'virtual_machine':
			return 'A virtual machine was running.';
		case 'remote_desktop':
			return 'The computer was used over remote desktop.';
	}
}

export function describeReason(r: Reason): string {
	const label = r.label.replaceAll('_', ' ');
	const src: Record<Reason['source'], string> = {
		image: 'what was on screen',
		domain: 'the website',
		title: 'the window title',
		app: 'the app',
		ocr: 'text on screen',
		context: 'context'
	};
	return `${label} (from ${src[r.source] ?? r.source})`;
}

/** Sentences for a decrypted event body. */
export function describeBody(b: EventBody): string[] {
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
			return [describeTamper(b.signal), ...(b.account ? [`In the account “${b.account}”.`] : [])];
		case 'settings_change':
			return b.changes.map(
				(c) => `${c.key.replaceAll('_', ' ')}: ${c.old ?? 'unset'} → ${c.new ?? 'unset'}`
			);
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
			if (b.reason === 'uninstalled') return ['Faro was uninstalled from this computer.'];
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
	const total = r.counts.clean + r.counts.low + r.counts.medium + r.counts.high;
	const parts = [`${total} screen check${total === 1 ? '' : 's'}`];
	const flagged = r.counts.medium + r.counts.high;
	parts.push(flagged ? `${flagged} flagged` : 'nothing flagged');
	if (r.health.tamper.length)
		parts.push(`${r.health.tamper.length} tamper signal${r.health.tamper.length === 1 ? '' : 's'}`);
	return parts.join(' · ');
}
