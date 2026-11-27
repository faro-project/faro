<script lang="ts">
	// The group page's "Waiting for you" area (GROUPS.md §7, §17): proposals
	// people sent you in this group, the ones you sent that are still
	// waiting (as the sender sees them: "Pending" or "Not accepted", nothing
	// more), and safety codes to compare at your next meeting. Everything
	// here is your own: the list of codes is built from your own alliances,
	// so it is visible only to the two people in each pair (§7.5).
	//
	// Pairing suggestions (§8.5) are separate cards: see PairingCards.svelte.
	import { api, seg } from '#lib/api.ts';
	import { date } from '#lib/format.ts';
	import { groupError } from '#lib/groups-api.ts';
	import { acceptNote, describeIncoming, describeOutgoing, senderStatus } from '#lib/proposals.ts';
	import { proposals } from '#lib/proposals.svelte.ts';
	import { session } from '#lib/session.svelte.ts';
	import type {
		AllyLink,
		IncomingProposal,
		MyAllies,
		ProposalAccepted,
		SupportedMember
	} from '#lib/types.ts';
	import { resolve } from '$app/paths';
	import AllyKeySetup from '../AllyKeySetup.svelte';
	import Modal from '../Modal.svelte';
	import SignedNote from '../SignedNote.svelte';
	import CompareCodes from './CompareCodes.svelte';

	let { groupId, readOnly = false }: { groupId: string; readOnly?: boolean } = $props();

	let incoming = $derived(
		proposals.incoming.filter(
			(p) => p.group_id === groupId && p.state === 'open' && p.expires_at_ms > Date.now()
		)
	);
	let outgoing = $derived(
		proposals.outgoing.filter(
			(p) =>
				p.group_id === groupId &&
				(p.state === 'open'
					? p.expires_at_ms > Date.now()
					: p.state === 'not_accepted' && !!p.ask_again_at_ms && p.ask_again_at_ms > Date.now())
		)
	);

	// Links from this group waiting for safety codes: yours, either way.
	let waiting = $state<{ id: string; name: string }[]>([]);

	async function loadWaiting() {
		const [allies, members] = await Promise.all([
			api.get<MyAllies>('/v1/me/allies').catch(() => null),
			api.get<SupportedMember[]>('/v1/ally/members').catch(() => null)
		]);
		const found = new Map<string, string>();
		const mine = (allies?.allies ?? []).filter(
			(a: AllyLink) => a.state === 'pending' && a.origin_group_id === groupId
		);
		for (const a of mine) found.set(a.ally_id, a.display_name);
		for (const m of (members ?? []).filter(
			(m) => m.state === 'pending' && m.origin_group_id === groupId
		)) {
			found.set(m.member_id, m.display_name);
		}
		waiting = [...found].map(([id, name]) => ({ id, name }));
	}

	$effect(() => {
		void proposals.version;
		void groupId;
		if (session.user) void loadWaiting();
	});

	async function reload() {
		if (session.user) await proposals.refresh(session.user.roles);
	}

	// Answering.
	let answering = $state<IncomingProposal | null>(null);
	let accepted = $state(false);
	let busy = $state(false);
	let error = $state('');
	let setup = $state<ReturnType<typeof AllyKeySetup> | null>(null);
	let setupReady = $state(false);
	let recovering = $state(false);

	function answer(p: IncomingProposal) {
		answering = p;
		accepted = false;
		error = '';
		setupReady = false;
	}

	/** Accepting a request or partnership makes you an ally, so you need an ally key. */
	let needsAllyKey = $derived(answering?.kind === 'request' || answering?.kind === 'partnership');
	/** Accepting an offer or partnership makes someone your ally: your keys come first. */
	let needsMemberKeys = $derived(
		(answering?.kind === 'offer' || answering?.kind === 'partnership') && !session.hasMemberKeys
	);

	async function accept() {
		const p = answering;
		if (!p) return;
		busy = true;
		error = '';
		try {
			const allyKey = needsAllyKey ? await setup?.prepare() : null;
			if (allyKey === false) return;
			await api.post<ProposalAccepted>(`/v1/proposals/${seg(p.id)}/accept`, {
				...(allyKey ? { ally_key: allyKey } : {})
			});
			accepted = true;
			setup?.commit();
			await session.refresh().catch(() => {});
			await reload();
		} catch (e) {
			error = groupError(e);
			void reload();
		} finally {
			busy = false;
		}
	}

	async function decline(p: IncomingProposal) {
		busy = true;
		error = '';
		try {
			await api.post<void>(`/v1/proposals/${seg(p.id)}/decline`);
			answering = null;
			await reload();
		} catch (e) {
			error = groupError(e);
		} finally {
			busy = false;
		}
	}

	async function withdraw(id: string) {
		busy = true;
		error = '';
		try {
			await api.delete<void>(`/v1/proposals/${seg(id)}`);
			await reload();
		} catch (e) {
			error = groupError(e);
		} finally {
			busy = false;
		}
	}

	// Comparing codes.
	let comparing = $state<{ id: string; name: string } | null>(null);

	let any = $derived(incoming.length > 0 || outgoing.length > 0 || waiting.length > 0);
</script>

{#if any}
	<section class="section waiting" aria-labelledby="waiting-h">
		<h2 id="waiting-h">Waiting for you</h2>

		{#if error && !answering}<div class="notice error" role="alert"><p>{error}</p></div>{/if}

		{#if incoming.length}
			<ul class="rows">
				{#each incoming as p (p.id)}
					<li>
						<div class="row-main">
							<div>
								<div class="row-title"><strong>{describeIncoming(p)}</strong></div>
								<div class="row-meta">Sent {date(p.created_at_ms)}</div>
								{#if p.note_id && session.user}
									<SignedNote messageId={p.note_id} user={session.user} author={p.from.user_id} />
								{/if}
							</div>
							{#if !readOnly}
								<div class="row-actions">
									<button class="primary small" type="button" onclick={() => answer(p)}>
										Look at it
									</button>
								</div>
							{/if}
						</div>
					</li>
				{/each}
			</ul>
		{/if}

		{#if waiting.length}
			<h3>Compare at your next meeting</h3>
			<p class="muted">
				These are waiting for a safety code to be compared in person. Only you and the other person
				see this.
			</p>
			<ul class="rows">
				{#each waiting as w (w.id)}
					<li>
						<div class="row-main">
							<div class="row-title"><strong>{w.name}</strong></div>
							<button class="secondary small" type="button" onclick={() => (comparing = w)}>
								Compare codes
							</button>
						</div>
					</li>
				{/each}
			</ul>
		{/if}

		{#if outgoing.length}
			<h3>What you've sent</h3>
			<ul class="rows">
				{#each outgoing as p (p.id)}
					{@const status = senderStatus(p)}
					<li>
						<div class="row-main">
							<div>
								<div class="row-title">
									{describeOutgoing(p)}
									<span class="chip {p.state === 'open' ? 'pending' : 'off'}">{status.label}</span>
								</div>
								{#if status.detail}<div class="row-meta">{status.detail}</div>{/if}
							</div>
							{#if p.state === 'open' && !readOnly}
								<button
									class="secondary small"
									type="button"
									disabled={busy}
									onclick={() => withdraw(p.id)}
								>
									Withdraw
								</button>
							{/if}
						</div>
					</li>
				{/each}
			</ul>
		{/if}
	</section>
{/if}

{#if answering && session.user}
	<Modal title={describeIncoming(answering)} onclose={() => (answering = null)}>
		{#if accepted}
			{#if !recovering}
				<p>
					✓ Accepted. Now you compare safety codes. You can do it now, or later at your next
					meeting: it will be waiting under "Compare at your next meeting".
				</p>
				<CompareCodes
					person={{ id: answering.from.user_id, name: answering.from.display_name }}
					user={session.user}
					ondone={reload}
				/>
				<div class="actions">
					<button class="secondary" type="button" onclick={() => (answering = null)}>Done</button>
				</div>
			{/if}
		{:else}
			{#if answering.note_id}
				<SignedNote
					messageId={answering.note_id}
					user={session.user}
					author={answering.from.user_id}
				/>
			{/if}
			<p>{acceptNote(answering.kind)}</p>
		{/if}
		{#if needsAllyKey}
			<!-- Stays mounted after accepting, so the recovery code can be shown and saved. -->
			<AllyKeySetup user={session.user} bind:this={setup} bind:ready={setupReady} bind:recovering />
		{/if}
		{#if !accepted}
			{#if needsMemberKeys}
				<div class="notice info">
					<p>
						To have someone as your ally you first need your keys. <a href={resolve('/keys')}>
							Set them up
						</a>, then come back here.
					</p>
				</div>
			{/if}
			{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
			<div class="actions">
				<button
					class="primary"
					type="button"
					disabled={busy || needsMemberKeys || (needsAllyKey && !setupReady)}
					onclick={accept}
				>
					{busy ? 'One moment…' : 'Accept'}
				</button>
				<button
					class="secondary"
					type="button"
					disabled={busy}
					onclick={() => answering && decline(answering)}
				>
					Not now
				</button>
				<button class="link" type="button" onclick={() => (answering = null)}>Decide later</button>
			</div>
			<p class="muted small">If you say no, they won't be told you said no.</p>
		{/if}
	</Modal>
{/if}

{#if comparing && session.user}
	<Modal title="Compare safety codes with {comparing.name}" onclose={() => (comparing = null)}>
		<CompareCodes person={comparing} user={session.user} ondone={reload} />
		<div class="actions">
			<button class="secondary" type="button" onclick={() => (comparing = null)}>Close</button>
		</div>
	</Modal>
{/if}

<style>
	.row-actions {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
	}

	h3 {
		margin: 1.25rem 0 0.4rem;
	}
</style>
