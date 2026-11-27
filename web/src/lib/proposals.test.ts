// Alliance proposal wording and roster actions. Run with `npm test`.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
	acceptNote,
	describeIncoming,
	describeOutgoing,
	proposalErrorMessage,
	rowActions,
	senderStatus,
	type RowInput
} from './proposals.ts';
import type { IncomingProposal, OutgoingProposal } from './types.ts';

const NOW = 1_000_000_000_000;
const DAY = 24 * 3600 * 1000;

const out = (over: Partial<OutgoingProposal> = {}): OutgoingProposal => ({
	id: 'p1',
	group_id: 'g1',
	group_name: 'Tuesday group',
	to: { user_id: 'usr_jo', display_name: 'Jo' },
	kind: 'request',
	state: 'open',
	created_at_ms: NOW - DAY,
	expires_at_ms: NOW + 13 * DAY,
	accepted_at_ms: null,
	withdrawn_at_ms: null,
	ask_again_at_ms: null,
	...over
});

const inc = (over: Partial<IncomingProposal> = {}): IncomingProposal => ({
	id: 'p2',
	group_id: 'g1',
	group_name: 'Tuesday group',
	from: { user_id: 'usr_jo', display_name: 'Jo' },
	kind: 'request',
	state: 'open',
	created_at_ms: NOW - DAY,
	expires_at_ms: NOW + 13 * DAY,
	decided_at_ms: null,
	...over
});

const row = (over: Partial<RowInput> = {}): RowInput => ({
	personId: 'usr_jo',
	unavailable: false,
	readOnly: false,
	deleting: false,
	hasMemberKeys: true,
	links: { myAllies: [], supporting: [] },
	incoming: [],
	outgoing: [],
	blocked: [],
	now: NOW,
	...over
});

test('a stranger in the group offers all three proposals and blocking', () => {
	const a = rowActions(row());
	assert.deepEqual([a.request, a.offer, a.partner, a.block], [true, true, true, true]);
});

test('without member keys, nobody can be your ally yet, so those actions are hidden', () => {
	const a = rowActions(row({ hasMemberKeys: false }));
	assert.deepEqual([a.request, a.offer, a.partner], [false, true, false]);
});

test('a live link in one direction hides what would repeat it, and partnering', () => {
	const mine = rowActions(
		row({ links: { myAllies: [{ id: 'usr_jo', state: 'pending' }], supporting: [] } })
	);
	assert.deepEqual([mine.request, mine.offer, mine.partner], [false, true, false]);
	const theirs = rowActions(
		row({ links: { myAllies: [], supporting: [{ id: 'usr_jo', state: 'active' }] } })
	);
	assert.deepEqual([theirs.request, theirs.offer, theirs.partner], [true, false, false]);
	const both = rowActions(
		row({
			links: {
				myAllies: [{ id: 'usr_jo', state: 'active' }],
				supporting: [{ id: 'usr_jo', state: 'active' }]
			}
		})
	);
	assert.deepEqual([both.request, both.offer, both.partner], [false, false, false]);
});

test('an open proposal of mine hides what it covers', () => {
	const req = rowActions(row({ outgoing: [out({ kind: 'request' })] }));
	assert.deepEqual([req.request, req.offer, req.partner], [false, true, false]);
	const partner = rowActions(row({ outgoing: [out({ kind: 'partnership' })] }));
	assert.deepEqual([partner.request, partner.offer, partner.partner], [false, false, false]);
	// Someone else's proposal doesn't count.
	const other = rowActions(
		row({ outgoing: [out({ to: { user_id: 'usr_other', display_name: 'Al' } })] })
	);
	assert.equal(other.request, true);
});

test('their open proposal to me hides the same ask and points to answering it', () => {
	// Their request asks me to be their ally: my offer would repeat it.
	const a = rowActions(row({ incoming: [inc({ kind: 'request' })] }));
	assert.deepEqual([a.request, a.offer, a.partner], [true, false, false]);
	assert.equal(a.theirProposalWaiting, true);
	// A decided one doesn't.
	const done = rowActions(row({ incoming: [inc({ state: 'declined' })] }));
	assert.equal(done.theirProposalWaiting, false);
	assert.equal(done.offer, true);
});

test('after "not accepted" the same kind waits, and the date is offered', () => {
	const again = NOW + 20 * DAY;
	const a = rowActions(row({ outgoing: [out({ state: 'not_accepted', ask_again_at_ms: again })] }));
	assert.deepEqual([a.request, a.offer, a.partner], [false, true, true]);
	assert.equal(a.askAgainAt, again);
	// Once the date passes, the action is back.
	const later = rowActions(
		row({
			now: again + 1,
			outgoing: [out({ state: 'not_accepted', ask_again_at_ms: again })]
		})
	);
	assert.equal(later.request, true);
	assert.equal(later.askAgainAt, null);
});

test('blocked people, unavailable accounts, closed groups and deleting accounts show nothing', () => {
	assert.equal(rowActions(row({ blocked: ['usr_jo'] })).block, false);
	for (const over of [{ unavailable: true }, { readOnly: true }, { deleting: true }]) {
		const a = rowActions(row(over));
		assert.deepEqual([a.request, a.offer, a.partner, a.block], [false, false, false, false]);
	}
});

test('the sender sees Pending or Not accepted and the date, and never a decline', () => {
	assert.deepEqual(senderStatus(out()), { label: 'Pending', detail: null });
	const s = senderStatus(out({ state: 'not_accepted', ask_again_at_ms: NOW + DAY }));
	assert.equal(s.label, 'Not accepted');
	assert.match(s.detail ?? '', /^You can ask again on /);
	assert.equal(senderStatus(out({ state: 'not_accepted' })).detail, null);
	assert.ok(!/declin/i.test(JSON.stringify(s)));
});

test('proposals are worded for whoever reads them', () => {
	assert.equal(describeIncoming(inc()), 'Jo asks you to be their ally.');
	assert.equal(describeIncoming(inc({ kind: 'offer' })), 'Jo offers to be your ally.');
	assert.match(describeIncoming(inc({ kind: 'partnership' })), /partner up/);
	assert.equal(describeOutgoing(out()), 'You asked Jo to be your ally.');
	assert.equal(describeOutgoing(out({ kind: 'offer' })), "You offered to be Jo's ally.");
	assert.match(acceptNote('partnership'), /each of you approves your own side/i);
});

test('every proposal error code has kind wording', () => {
	for (const code of [
		'already_proposed',
		'proposal_cooldown',
		'proposal_waiting',
		'already_linked',
		'too_many_proposals',
		'too_many_invites',
		'too_many_allies',
		'member_keys_required',
		'cannot_propose',
		'ally_key_required',
		'ally_key_mismatch',
		'ally_key_not_needed',
		'proposal_closed',
		'cannot_propose_to_self',
		'cannot_block_self'
	]) {
		const m = proposalErrorMessage(code);
		assert.ok(m && m.length > 10 && !m.includes('_'), code);
	}
	assert.equal(proposalErrorMessage('internal'), null);
});
