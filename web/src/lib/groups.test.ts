// Groups wording and logic. Run with `npm test`.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
	collapseHistory,
	describeHistory,
	describeInvited,
	describeRun,
	groupErrorMessage,
	isInviteToken,
	joinNames,
	leaveConfirmation,
	parseEmails,
	relationshipOf,
	tokenFromHash
} from './groups.ts';
import type { HistoryEntry, HistoryKind } from './types.ts';

const DAY = 24 * 3600 * 1000;
const person = (n: string) => ({ user_id: `usr_${n}`, display_name: n });
const entry = (kind: HistoryKind, atDays: number, who = 'Sam'): HistoryEntry => ({
	id: `${kind}${atDays}${who}`,
	at_ms: atDays * DAY,
	kind,
	subject: person(who),
	actor: null
});

test('the leave confirmation says alliances stay, with the section 9 wording', () => {
	assert.equal(
		leaveConfirmation(['Jo', 'Alex']),
		"You'll stay allies with Jo and Alex. To end an alliance, go to Allies."
	);
	assert.equal(
		leaveConfirmation(['Jo', 'Alex', 'Sam']),
		"You'll stay allies with Jo, Alex and Sam. To end an alliance, go to Allies."
	);
	assert.equal(
		leaveConfirmation(['Jo', 'Jo']),
		"You'll stay allies with Jo. To end an alliance, go to Allies."
	);
	assert.match(leaveConfirmation([]), /Alliances aren't affected/);
	assert.match(leaveConfirmation([]), /go to Allies/);
});

test('joinNames', () => {
	assert.equal(joinNames([]), '');
	assert.equal(joinNames(['Jo']), 'Jo');
});

test('relationships are named from both directions', () => {
	const links = {
		myAllies: [
			{ id: 'usr_Jo', state: 'active' },
			{ id: 'usr_Pat', state: 'pending' },
			{ id: 'usr_Both', state: 'active' }
		],
		supporting: [
			{ id: 'usr_Alex', state: 'active' },
			{ id: 'usr_Both', state: 'active' }
		]
	};
	assert.equal(relationshipOf('usr_Jo', links), 'your_ally');
	assert.equal(relationshipOf('usr_Alex', links), 'their_ally');
	assert.equal(relationshipOf('usr_Both', links), 'partners');
	assert.equal(relationshipOf('usr_Pat', links), 'waiting');
	assert.equal(relationshipOf('usr_Nobody', links), null);
});

test('runs of joins in a week collapse, and short runs do not', () => {
	const entries = [
		entry('left', 20),
		entry('joined', 10, 'A'),
		entry('joined', 9, 'B'),
		entry('joined', 8, 'C'),
		entry('joined', 7.5, 'D'),
		entry('renamed', 5),
		entry('joined', 4, 'E'),
		entry('joined', 3, 'F')
	];
	const items = collapseHistory(entries);
	assert.deepEqual(
		items.map((i) => i.type),
		['entry', 'run', 'entry', 'entry', 'entry']
	);
	const run = items[1];
	assert.ok(run.type === 'run');
	assert.equal(run.entries.length, 4);
	assert.equal(describeRun('joined', run.entries), '4 people joined that week');
});

test('a run is broken by a week without joins', () => {
	const entries = [
		entry('joined', 40, 'A'),
		entry('joined', 39, 'B'),
		entry('joined', 20, 'C'),
		entry('joined', 19, 'D')
	];
	assert.ok(collapseHistory(entries).every((i) => i.type === 'entry'));
});

test('history lines name people, and "someone" when the account is gone', () => {
	assert.equal(describeHistory(entry('joined', 1)), 'Sam joined');
	assert.equal(describeHistory({ ...entry('joined', 1), subject: null }), 'Someone joined');
	assert.equal(
		describeHistory({ ...entry('removed', 1), actor: person('Jo') }),
		'Sam was removed by Jo'
	);
	assert.equal(
		describeHistory({ ...entry('renamed', 1), actor: person('Jo') }),
		'Jo renamed the group'
	);
	assert.equal(describeHistory(entry('archived', 1)), 'The group was closed');
});

test('pasted addresses are split, cleaned and de-duplicated', () => {
	const { emails, invalid } = parseEmails(
		'Jo@Example.org, alex@example.org\nSam Smith <sam@example.org>; jo@example.org  nonsense'
	);
	assert.deepEqual(emails, ['jo@example.org', 'alex@example.org', 'sam@example.org']);
	assert.deepEqual(invalid, ['nonsense']);
	assert.deepEqual(parseEmails('  \n '), { emails: [], invalid: [] });
});

test('the invitation result is stated plainly', () => {
	assert.equal(describeInvited(1, 0), '1 invitation sent.');
	assert.match(describeInvited(3, 2), /^3 invitations sent\. 2 were left out/);
});

test('API errors become sentences, never codes', () => {
	assert.equal(groupErrorMessage('group_full', 409), 'This group is full.');
	assert.match(groupErrorMessage('not_found', 404) ?? '', /no longer available/);
	assert.match(groupErrorMessage('last_facilitator', 409) ?? '', /only facilitator/);
	assert.equal(groupErrorMessage('internal', 500), null);
});

test('invitation tokens', () => {
	assert.equal(tokenFromHash('#token=abc_DEF-123'), 'abc_DEF-123');
	assert.equal(tokenFromHash(''), '');
	assert.ok(isInviteToken('a'.repeat(43)));
	assert.ok(!isInviteToken('short'));
	assert.ok(!isInviteToken('a'.repeat(43) + '!'));
});
