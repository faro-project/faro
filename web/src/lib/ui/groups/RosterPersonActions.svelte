<script lang="ts">
	// One person's action menu in the roster (GROUPS.md §7, §17): *Ask to be
	// my ally*, *Offer to be their ally*, *Partner up*, and *Don't let them
	// send me proposals*. Rendered by Roster.svelte next to every person
	// except you. An action that doesn't apply is simply not there, with no
	// explanation (§7.1); the only thing said about a past "no" is the date
	// you can ask again. Nothing here makes anyone an ally: a proposal is
	// only a question, and the person it goes to answers it (principle 3).
	import { api, seg } from '#lib/api.ts';
	import { date } from '#lib/format.ts';
	import { groupError } from '#lib/groups-api.ts';
	import { actionLabel, proposeExplanation, rowActions, senderStatus } from '#lib/proposals.ts';
	import { proposals } from '#lib/proposals.svelte.ts';
	import { session } from '#lib/session.svelte.ts';
	import type { ProposalKind, RosterEntry } from '#lib/types.ts';
	import AllyKeySetup from '../AllyKeySetup.svelte';
	import Modal from '../Modal.svelte';

	let {
		groupId,
		person,
		readOnly = false,
		onsent
	}: {
		groupId: string;
		person: Pick<RosterEntry, 'user_id' | 'display_name' | 'unavailable'>;
		readOnly?: boolean;
		/** Called after a proposal was sent (a pairing card dismisses itself). */
		onsent?: () => void;
	} = $props();

	let actions = $derived(
		rowActions({
			personId: person.user_id,
			unavailable: person.unavailable,
			readOnly,
			deleting: !!session.deletion,
			hasMemberKeys: session.hasMemberKeys,
			links: proposals.links,
			incoming: proposals.incoming,
			outgoing: proposals.outgoing,
			blocked: proposals.blocks.map((b) => b.user_id),
			now: Date.now()
		})
	);

	/** Your open proposal to this person, in the sender's words. */
	let pending = $derived(
		proposals.outgoing.find(
			(p) =>
				p.to.user_id === person.user_id &&
				p.group_id === groupId &&
				p.state === 'open' &&
				p.expires_at_ms > Date.now()
		)
	);

	let menu = $state<HTMLDetailsElement | null>(null);
	let dialog = $state<ProposalKind | 'block' | null>(null);
	let busy = $state(false);
	let error = $state('');
	let sent = $state(false);
	let blocked = $state(false);

	// Making an ally key first (offers and partnerships).
	let setup = $state<ReturnType<typeof AllyKeySetup> | null>(null);
	let setupReady = $state(false);
	let recovering = $state(false);

	function open(kind: ProposalKind | 'block') {
		dialog = kind;
		error = '';
		sent = false;
		blocked = false;
		setupReady = false;
		if (menu) menu.open = false;
	}

	function close() {
		dialog = null;
	}

	/** Open the proposal dialog for `kind` (a pairing card's prefilled proposal). */
	export function start(kind: ProposalKind) {
		open(kind);
	}

	/** Whether `kind` can be proposed to this person now. */
	export function can(kind: ProposalKind): boolean {
		return kind === 'partnership' ? actions.partner : actions[kind];
	}

	let needsAllyKey = $derived(dialog === 'offer' || dialog === 'partnership');

	async function send() {
		const kind = dialog;
		if (!kind || kind === 'block' || !session.user) return;
		busy = true;
		error = '';
		try {
			const allyKey = needsAllyKey ? await setup?.prepare() : null;
			if (allyKey === false) return;
			await api.post(`/v1/groups/${seg(groupId)}/proposals`, {
				to: person.user_id,
				kind,
				...(allyKey ? { ally_key: allyKey } : {})
			});
			sent = true;
			onsent?.();
			setup?.commit();
			await session.refresh().catch(() => {});
			if (session.user) await proposals.refresh(session.user.roles);
		} catch (e) {
			error = groupError(e);
			// "They already sent you one": show it under "Waiting for you".
			if (session.user) void proposals.refresh(session.user.roles);
		} finally {
			busy = false;
		}
	}

	async function block() {
		busy = true;
		error = '';
		try {
			await api.put(`/v1/me/proposal-blocks/${seg(person.user_id)}`, {});
			blocked = true;
			if (session.user) await proposals.refresh(session.user.roles);
		} catch (e) {
			error = groupError(e);
		} finally {
			busy = false;
		}
	}

	let any = $derived(actions.request || actions.offer || actions.partner || actions.block);
</script>

{#if actions.theirProposalWaiting}
	<span class="chip pending">Sent you a proposal</span>
{/if}
{#if pending}
	<span class="muted small">{senderStatus(pending).label}</span>
{:else if actions.askAgainAt}
	<span class="muted small">You can ask again on {date(actions.askAgainAt)}.</span>
{/if}

{#if any}
	<details class="menu" bind:this={menu}>
		<summary class="button secondary small">Ally…</summary>
		<div class="items">
			{#if actions.request}
				<button type="button" class="link" onclick={() => open('request')}>
					{actionLabel('request', person.display_name)}
				</button>
			{/if}
			{#if actions.offer}
				<button type="button" class="link" onclick={() => open('offer')}>
					{actionLabel('offer', person.display_name)}
				</button>
			{/if}
			{#if actions.partner}
				<button type="button" class="link" onclick={() => open('partnership')}>
					{actionLabel('partnership', person.display_name)}
				</button>
			{/if}
			{#if actions.block}
				<button type="button" class="link" onclick={() => open('block')}>
					Don't let them send me proposals
				</button>
			{/if}
		</div>
	</details>
{/if}

{#if dialog === 'block'}
	<Modal title="Stop {person.display_name} sending you proposals?" onclose={close}>
		{#if blocked}
			<p>✓ Done. {person.display_name} isn't told. You can undo this under Settings.</p>
			<div class="actions">
				<button class="secondary" type="button" onclick={close}>Close</button>
			</div>
		{:else}
			<p>
				They won't be able to ask you to be allies, in this group or any other, and they aren't
				told. Anything they have already sent you ends quietly. Allies you already have stay as they
				are.
			</p>
			{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
			<div class="actions">
				<button class="primary" type="button" disabled={busy} onclick={block}>
					{busy ? 'One moment…' : 'Stop them'}
				</button>
				<button class="secondary" type="button" onclick={close}>Cancel</button>
			</div>
		{/if}
	</Modal>
{:else if dialog && session.user}
	<Modal title={actionLabel(dialog, person.display_name)} onclose={close}>
		{#if !sent}
			<p>{proposeExplanation(dialog, person.display_name)}</p>
			<p class="muted small">
				Nobody becomes anyone's ally until the safety codes are compared and the member approves.
			</p>
		{/if}
		{#if needsAllyKey}
			<!-- Stays mounted after sending, so the recovery code can be shown and saved. -->
			<AllyKeySetup user={session.user} bind:this={setup} bind:ready={setupReady} bind:recovering />
		{/if}
		{#if sent && !recovering}
			<div class="notice ok" role="status">
				<p>
					✓ Sent. {person.display_name} sees it and chooses. You'll see "Pending" next to their name until
					they answer or it runs out in two weeks.
				</p>
			</div>
			<div class="actions">
				<button class="secondary" type="button" onclick={close}>Close</button>
			</div>
		{:else if !sent}
			{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
			<div class="actions">
				<button
					class="primary"
					type="button"
					disabled={busy || (needsAllyKey && !setupReady)}
					onclick={send}
				>
					{busy ? 'Sending…' : 'Send'}
				</button>
				<button class="secondary" type="button" onclick={close}>Cancel</button>
			</div>
		{/if}
	</Modal>
{/if}

<style>
	.menu {
		position: relative;
	}

	.menu summary {
		list-style: none;
		cursor: pointer;
		display: inline-block;
	}

	.menu summary::-webkit-details-marker {
		display: none;
	}

	.items {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: 0.35rem;
		margin-top: 0.4rem;
	}
</style>
