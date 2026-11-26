// Groups: wording and logic shared by the pages (docs/GROUPS.md), kept free
// of the DOM and Svelte so `npm test` can cover it.

import type { GroupPerson, HistoryEntry, HistoryKind, RosterRelationship } from './types.ts';

/** Limits the server enforces (server/src/api/groups.rs). */
export const GROUP_LIMITS = { name: 100, description: 1000, invitesPerRequest: 50 } as const;

// ---- Names -----------------------------------------------------------------

/** ["Jo"] → "Jo"; ["Jo", "Alex"] → "Jo and Alex"; three → "Jo, Alex and Sam". */
export function joinNames(names: string[]): string {
	if (names.length <= 1) return names[0] ?? '';
	return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}

/**
 * The leave confirmation (GROUPS.md §9): alliances stay. `allies` are the
 * people in this group who are your allies or whose ally you are.
 */
export function leaveConfirmation(allies: string[]): string {
	const unique = [...new Set(allies)];
	if (unique.length === 0) {
		return "Alliances aren't affected by leaving a group. To end an alliance, go to Allies.";
	}
	return `You'll stay allies with ${joinNames(unique)}. To end an alliance, go to Allies.`;
}

// ---- Relationships ---------------------------------------------------------

export type Relationship = RosterRelationship;

export const RELATIONSHIP_LABEL: Record<Relationship, string> = {
	partners: 'Partners',
	your_ally: 'Your ally',
	their_ally: "You're their ally",
	waiting: 'Waiting for safety codes'
};

/**
 * What `GET /v1/me/allies` and `GET /v1/ally/members` say, reduced to user
 * ids. The roster gets each person's relationship from the server; this is
 * for what only your own alliances can say (who can still be proposed to).
 */
export interface Links {
	/** People who are your ally (you are their member). */
	myAllies: { id: string; state: string }[];
	/** People whose ally you are. */
	supporting: { id: string; state: string }[];
}

export function relationshipOf(userId: string, links: Links): Relationship | null {
	const mine = links.myAllies.find((a) => a.id === userId);
	const theirs = links.supporting.find((a) => a.id === userId);
	const mineActive = mine?.state === 'active';
	const theirsActive = theirs?.state === 'active';
	if (mineActive && theirsActive) return 'partners';
	if (mineActive) return 'your_ally';
	if (theirsActive) return 'their_ally';
	if (mine || theirs) return 'waiting';
	return null;
}

// ---- History ---------------------------------------------------------------

const DAY_MS = 24 * 3600 * 1000;
const WEEK_MS = 7 * DAY_MS;
/** A run of at least this many alike entries collapses into one line. */
export const COLLAPSE_AT = 3;

const COLLAPSIBLE: HistoryKind[] = ['joined', 'left', 'removed'];

export type HistoryItem =
	| { type: 'entry'; entry: HistoryEntry }
	| { type: 'run'; kind: HistoryKind; entries: HistoryEntry[] };

/**
 * Collapse runs of joins, leaves or removals ("14 people joined this week"):
 * consecutive entries of one kind within a week of the run's newest entry.
 * `entries` are newest first, as the server sends them.
 */
export function collapseHistory(entries: HistoryEntry[]): HistoryItem[] {
	const out: HistoryItem[] = [];
	let i = 0;
	while (i < entries.length) {
		const first = entries[i];
		let j = i + 1;
		if (COLLAPSIBLE.includes(first.kind)) {
			while (
				j < entries.length &&
				entries[j].kind === first.kind &&
				first.at_ms - entries[j].at_ms < WEEK_MS
			) {
				j++;
			}
		}
		if (j - i >= COLLAPSE_AT) {
			out.push({ type: 'run', kind: first.kind, entries: entries.slice(i, j) });
		} else {
			for (let k = i; k < j; k++) out.push({ type: 'entry', entry: entries[k] });
		}
		i = j;
	}
	return out;
}

const name = (p: GroupPerson | null) => p?.display_name ?? 'Someone';

/** One history line without its date: "Sam joined". */
export function describeHistory(e: HistoryEntry): string {
	const who = name(e.subject);
	const by = e.actor && e.actor.user_id !== e.subject?.user_id ? e.actor.display_name : null;
	switch (e.kind) {
		case 'joined':
			return by ? `${who} joined, invited by ${by}` : `${who} joined`;
		case 'left':
			return `${who} left`;
		case 'removed':
			return by ? `${who} was removed by ${by}` : `${who} was removed`;
		case 'facilitator_added':
			return by ? `${who} became a facilitator, made one by ${by}` : `${who} became a facilitator`;
		case 'facilitator_removed':
			return by ? `${who} stopped being a facilitator` : `${who} stepped down as a facilitator`;
		case 'renamed':
			return `${name(e.actor)} renamed the group`;
		case 'listed':
			return 'The group was listed in the directory';
		case 'unlisted':
			return 'The group was taken out of the directory';
		case 'archived':
			return 'The group was closed';
	}
}

/** "14 people joined that week" for a collapsed run. */
export function describeRun(kind: HistoryKind, entries: HistoryEntry[]): string {
	const n = entries.length;
	const people = `${n} ${n === 1 ? 'person' : 'people'}`;
	const spanDays = (entries[0].at_ms - entries[n - 1].at_ms) / DAY_MS;
	const when = spanDays < 1 ? 'in one day' : 'that week';
	switch (kind) {
		case 'joined':
			return `${people} joined ${when}`;
		case 'left':
			return `${people} left ${when}`;
		case 'removed':
			return `${people} ${n === 1 ? 'was' : 'were'} removed ${when}`;
		default:
			return `${n} changes ${when}`;
	}
}

// ---- Inviting --------------------------------------------------------------

const EMAIL = /^[^\s@,;<>]+@[^\s@,;<>]+\.[^\s@,;<>]+$/;

/**
 * Pasted addresses: separated by commas, semicolons, spaces or new lines,
 * and tolerant of `Name <a@b.org>`. Lower-cased, duplicates dropped.
 */
export function parseEmails(text: string): { emails: string[]; invalid: string[] } {
	const emails: string[] = [];
	const invalid: string[] = [];
	const seen = new Set<string>();
	for (const raw of text.split(/[\n,;]+/)) {
		let t = raw.trim();
		if (!t) continue;
		const angled = t.match(/<([^>]+)>/);
		if (angled) t = angled[1].trim();
		for (const part of t.split(/\s+/)) {
			const e = part.toLowerCase();
			if (!EMAIL.test(e)) {
				invalid.push(part);
			} else if (!seen.has(e)) {
				seen.add(e);
				emails.push(e);
			}
		}
	}
	return { emails, invalid };
}

/** The result of an invitation round, in plain words. */
export function describeInvited(sent: number, skipped: number): string {
	const s = `${sent} ${sent === 1 ? 'invitation' : 'invitations'} sent.`;
	if (!skipped) return s;
	return `${s} ${skipped} ${skipped === 1 ? 'was' : 'were'} left out: already in the group, already invited, or not an address Faro could use.`;
}

// ---- Errors ----------------------------------------------------------------

const MESSAGES: Record<string, string> = {
	groups_disabled: 'Groups are switched off on this instance.',
	group_archived: 'This group was closed and can only be read.',
	group_full: 'This group is full.',
	too_many_groups: 'You are in the most groups this instance allows. Leave one first.',
	group_creation_restricted: 'On this instance only admins can start a group.',
	last_facilitator:
		"You are the group's only facilitator. Make someone else a facilitator first, then you can step down or leave.",
	too_many_facilitators: 'A group can have at most 32 facilitators.',
	limit_below_size: 'The limit is below the number of people already in the group.',
	invalid_max_participants: 'The limit must be a whole number of at least 1.',
	invalid_name: 'A group name is 1 to 100 characters.',
	invalid_description: 'A description is at most 1000 characters.',
	not_allowed_by_instance: 'This instance only lets facilitators invite.',
	too_many_invites:
		'This group has too many open invitations. Wait for some to be answered or to expire.',
	too_many_invitees: 'Invite at most 50 people at a time.',
	invalid_email: 'One of those addresses could not be read.',
	already_participant: 'You are already in this group.',
	not_a_facilitator: 'Only a facilitator can do that.',
	already_requested: "You've already asked to join this group.",
	request_cooldown: 'You asked this group not long ago. You can ask again in a few weeks.',
	too_many_join_requests:
		'You have 5 requests waiting. Wait for answers, or take one back, before asking another group.',
	cannot_accept: "This person can't join right now. You can try again later, or say no.",
	listing_needs_admin: 'On this instance only an admin can list a group.',
	listing_disabled: 'Listing groups is switched off on this instance.',
	invalid_meeting: "That meeting time doesn't look right. Check the day, time and place."
};

/** A sentence for a groups API error code, or null when there is no special wording. */
export function groupErrorMessage(code: string, status: number): string | null {
	if (MESSAGES[code]) return MESSAGES[code];
	if (status === 404) return 'That is no longer available. It may have been closed or removed.';
	return null;
}

// ---- Invitation links ------------------------------------------------------

/** The emailed token (43 URL-safe characters) or an `invite_ref` from the list. */
const TOKEN_SHAPE = /^[A-Za-z0-9_-]{16,128}$/;

export function isInviteToken(t: string): boolean {
	return TOKEN_SHAPE.test(t);
}

/** `#token=…` from a location hash. */
export function tokenFromHash(hash: string): string {
	return (new URLSearchParams(hash.replace(/^#/, '')).get('token') ?? '').trim();
}

const PENDING_KEY = 'faro.pendingGroupInvite';
const PENDING_MAX_AGE_MS = 7 * DAY_MS;

/** Keep a group invitation across a sign-in (the link arrives by email). */
export function savePendingGroupInvite(token: string) {
	try {
		localStorage.setItem(PENDING_KEY, JSON.stringify({ token, saved_at: Date.now() }));
	} catch {
		// No storage: the person opens the link again after signing in.
	}
}

export function pendingGroupInvite(): string | null {
	try {
		const raw = localStorage.getItem(PENDING_KEY);
		if (!raw) return null;
		const v = JSON.parse(raw) as { token?: unknown; saved_at?: unknown };
		if (typeof v.token !== 'string' || typeof v.saved_at !== 'number') return null;
		if (Date.now() - v.saved_at > PENDING_MAX_AGE_MS) {
			clearPendingGroupInvite();
			return null;
		}
		return v.token;
	} catch {
		return null;
	}
}

export function clearPendingGroupInvite() {
	try {
		localStorage.removeItem(PENDING_KEY);
	} catch {
		// Nothing to clear.
	}
}
