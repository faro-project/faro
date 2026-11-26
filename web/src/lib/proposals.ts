// Alliance proposals inside a group (docs/GROUPS.md §7): wording, and which
// actions a roster row offers. Kept free of the DOM and Svelte so `npm test`
// can cover it.

import { date } from './format.ts';
import type { Links } from './groups.ts';
import type { IncomingProposal, OutgoingProposal, ProposalKind } from './types.ts';

// ---- Errors ----------------------------------------------------------------

const MESSAGES: Record<string, string> = {
	already_proposed: 'You already have a proposal waiting with this person.',
	proposal_cooldown: "You can't send this person that again just yet.",
	proposal_waiting:
		'This person already sent you a proposal for this. You can accept theirs instead; it is under "Waiting for you".',
	already_linked: 'You are already linked with this person that way.',
	too_many_proposals: "You've sent a lot of proposals today. Try again tomorrow.",
	too_many_invites:
		'You have a lot of invitations and proposals waiting. Wait for some to be answered or to expire.',
	too_many_allies: 'You already have the most allies one person can have (32).',
	member_keys_required:
		'To have an ally, you first set up your keys. You can do that under "Your keys".',
	cannot_propose: "That isn't available for this person right now.",
	ally_key_required:
		'Faro needs you to make your ally key first. Try again and choose a passphrase.',
	ally_key_mismatch: 'You already have an ally key. Reload the page and try again.',
	ally_key_not_needed: 'That kind of proposal does not need an ally key.',
	proposal_closed: 'This proposal is no longer open. It may have been withdrawn or have run out.',
	cannot_propose_to_self: "You can't be your own ally.",
	cannot_block_self: "You can't stop yourself from sending proposals."
};

/** A sentence for a proposals API error code, or null when there is no special wording. */
export function proposalErrorMessage(code: string): string | null {
	return MESSAGES[code] ?? null;
}

// ---- Wording ---------------------------------------------------------------

/** What an incoming proposal asks, in the words of the person who got it. */
export function describeIncoming(p: IncomingProposal): string {
	const who = p.from.display_name;
	switch (p.kind) {
		case 'request':
			return `${who} asks you to be their ally.`;
		case 'offer':
			return `${who} offers to be your ally.`;
		case 'partnership':
			return `${who} would like to partner up: you would each be the other's ally.`;
	}
}

/** What accepting means, in a line: nothing is shared until you approve. */
export function acceptNote(kind: ProposalKind): string {
	switch (kind) {
		case 'request':
			return 'If you accept, they compare a safety code with you and then approve you. Nothing is shared until they do.';
		case 'offer':
			return 'If you accept, you compare safety codes with them, and you approve them as your ally.';
		case 'partnership':
			return 'If you accept, you each compare safety codes and approve the other. Each of you approves your own side.';
	}
}

/** The sender's line for what they sent. */
export function describeOutgoing(p: OutgoingProposal): string {
	const who = p.to.display_name;
	switch (p.kind) {
		case 'request':
			return `You asked ${who} to be your ally.`;
		case 'offer':
			return `You offered to be ${who}'s ally.`;
		case 'partnership':
			return `You asked ${who} to partner up.`;
	}
}

/**
 * The sender's whole view of a proposal (§7.6): "Pending" until it is
 * answered or runs out, then "Not accepted" with the date they can ask
 * again, and nothing else. A decline and an expiry look the same.
 */
export function senderStatus(p: OutgoingProposal): { label: string; detail: string | null } {
	switch (p.state) {
		case 'open':
			return { label: 'Pending', detail: null };
		case 'accepted':
			return { label: 'Accepted', detail: null };
		case 'withdrawn':
			return { label: 'Withdrawn', detail: null };
		case 'not_accepted':
			return {
				label: 'Not accepted',
				detail: p.ask_again_at_ms ? `You can ask again on ${date(p.ask_again_at_ms)}.` : null
			};
	}
}

// ---- Which actions a roster row offers ---------------------------------------

/** Which way a proposal makes someone the other's ally. */
type Direction = 'theyAreMyAlly' | 'iAmTheirAlly';

/** What a proposal *I send* of this kind would create. */
function sentCovers(kind: ProposalKind): Direction[] {
	switch (kind) {
		case 'request':
			return ['theyAreMyAlly'];
		case 'offer':
			return ['iAmTheirAlly'];
		case 'partnership':
			return ['theyAreMyAlly', 'iAmTheirAlly'];
	}
}

/** What a proposal *sent to me* of this kind would create. */
function receivedCovers(kind: ProposalKind): Direction[] {
	switch (kind) {
		case 'request':
			return ['iAmTheirAlly'];
		case 'offer':
			return ['theyAreMyAlly'];
		case 'partnership':
			return ['theyAreMyAlly', 'iAmTheirAlly'];
	}
}

const overlaps = (a: Direction[], b: Direction[]) => a.some((d) => b.includes(d));

export interface RowActions {
	/** "Ask to be my ally" */
	request: boolean;
	/** "Offer to be their ally" */
	offer: boolean;
	/** "Partner up" */
	partner: boolean;
	/** "Don't let them send me proposals" */
	block: boolean;
	/** They have a proposal waiting for you to answer (shown under "Waiting for you"). */
	theirProposalWaiting: boolean;
	/** Not accepted yet: when you can ask again, per kind, for the row's note. */
	askAgainAt: number | null;
}

export interface RowInput {
	personId: string;
	/** The person's account is unavailable (disabled or being deleted). */
	unavailable: boolean;
	/** The group can't be changed (closed, or groups are switched off). */
	readOnly: boolean;
	/** Your own account is being deleted. */
	deleting: boolean;
	hasMemberKeys: boolean;
	links: Links;
	incoming: IncomingProposal[];
	outgoing: OutgoingProposal[];
	/** Ids of people you have stopped from sending you proposals. */
	blocked: string[];
	now: number;
}

/**
 * Which actions a person's row shows. An action that doesn't apply is simply
 * hidden, with no explanation (§7.1): a live link already that way, an open
 * proposal that covers it, a cool-down, or a missing key you have no way to
 * fix from here. The one exception is the cool-down date, which the sender
 * may always see.
 */
export function rowActions(i: RowInput): RowActions {
	const none: RowActions = {
		request: false,
		offer: false,
		partner: false,
		block: false,
		theirProposalWaiting: false,
		askAgainAt: null
	};
	if (i.unavailable || i.readOnly || i.deleting) return none;

	const theyAreMyAlly = i.links.myAllies.some((a) => a.id === i.personId);
	const iAmTheirAlly = i.links.supporting.some((a) => a.id === i.personId);
	const taken: Direction[] = [
		...(theyAreMyAlly ? (['theyAreMyAlly'] as const) : []),
		...(iAmTheirAlly ? (['iAmTheirAlly'] as const) : [])
	];

	const mineOpen = i.outgoing.filter(
		(p) => p.to.user_id === i.personId && p.state === 'open' && p.expires_at_ms > i.now
	);
	for (const p of mineOpen) taken.push(...sentCovers(p.kind));
	const theirs = i.incoming.filter(
		(p) => p.from.user_id === i.personId && p.state === 'open' && p.expires_at_ms > i.now
	);
	for (const p of theirs) taken.push(...receivedCovers(p.kind));

	// "You can ask again": the latest date among kinds not accepted lately.
	const cooling = i.outgoing.filter(
		(p) =>
			p.to.user_id === i.personId &&
			p.state === 'not_accepted' &&
			p.ask_again_at_ms !== null &&
			p.ask_again_at_ms > i.now
	);
	const coolingKinds = new Set(cooling.map((p) => p.kind));
	const askAgainAt = cooling.reduce<number | null>(
		(m, p) => (m === null || (p.ask_again_at_ms ?? 0) > m ? p.ask_again_at_ms : m),
		null
	);

	const free = (kind: ProposalKind) =>
		!overlaps(sentCovers(kind), taken) && !coolingKinds.has(kind);

	return {
		request: i.hasMemberKeys && free('request'),
		offer: free('offer'),
		partner: i.hasMemberKeys && free('partnership'),
		block: !i.blocked.includes(i.personId),
		theirProposalWaiting: theirs.length > 0,
		askAgainAt
	};
}

/** Button text for a kind of proposal, naming the other person (§17). */
export function actionLabel(kind: ProposalKind, name: string): string {
	switch (kind) {
		case 'request':
			return 'Ask to be my ally';
		case 'offer':
			return `Offer to be ${name}'s ally`;
		case 'partnership':
			return 'Partner up';
	}
}

/** The explanation shown before sending, in plain words. */
export function proposeExplanation(kind: ProposalKind, name: string): string {
	switch (kind) {
		case 'request':
			return `${name} gets a note asking if they'll be your ally. If they say yes, you compare a safety code and you approve them. Until then nothing is shared.`;
		case 'offer':
			return `${name} gets a note offering to be their ally. If they say yes, they compare a safety code with you and approve you. Until then nothing is shared.`;
		case 'partnership':
			return `${name} gets a note asking to partner up: you would each be the other's ally. If they say yes, you each compare codes and approve your own side.`;
	}
}
