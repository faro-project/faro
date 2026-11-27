<script lang="ts">
	// One member, seen by their ally: /supporting/member?id=usr_…
	//
	// The id is read from the address in the browser (pages are prerendered,
	// so there is no server-side route per member).
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { api, describeError, seg } from '#lib/api.ts';
	import FeedView from '#lib/feed/FeedView.svelte';
	import { date } from '#lib/format.ts';
	import { session } from '#lib/session.svelte.ts';
	import type { SupportedMember } from '#lib/types.ts';
	import AllySafetyCode from '#lib/ui/AllySafetyCode.svelte';
	import Gate from '#lib/ui/Gate.svelte';
	import NotificationPrefs from '#lib/ui/NotificationPrefs.svelte';

	let memberId = $state('');
	let member = $state<SupportedMember | null>(null);
	let view = $state<'loading' | 'ok' | 'missing' | 'error'>('loading');
	let error = $state('');
	let tab = $state<'activity' | 'notifications' | 'code'>('activity');
	let leaveDialog = $state<HTMLDialogElement | null>(null);
	let leaveBusy = $state(false);
	let leaveError = $state('');
	let loadedFor = '';

	onMount(() => {
		memberId = new URLSearchParams(location.search).get('id') ?? '';
	});

	async function load() {
		view = 'loading';
		try {
			const all = await api.get<SupportedMember[]>('/v1/ally/members');
			member = all.find((m) => m.member_id === memberId) ?? null;
			view = member ? 'ok' : 'missing';
		} catch (e) {
			error = describeError(e);
			view = 'error';
		}
	}

	$effect(() => {
		const u = session.user;
		const k = `${u?.id}:${memberId}`;
		if (u?.roles.ally && memberId && k !== loadedFor) {
			loadedFor = k;
			void load();
		}
	});

	async function leave() {
		if (!member) return;
		leaveBusy = true;
		leaveError = '';
		try {
			await api.delete(`/v1/ally/members/${seg(member.member_id)}`);
			leaveDialog?.close();
			await goto(resolve('/supporting'));
		} catch (e) {
			leaveError = describeError(e);
		} finally {
			leaveBusy = false;
		}
	}
</script>

<svelte:head>
	<title>{member ? `${member.display_name} · ` : ''}Supporting · Faro</title>
</svelte:head>

<Gate role="ally">
	{#snippet children(user)}
		<p class="back"><a href={resolve('/supporting')}>← People you support</a></p>
		{#if view === 'loading'}
			<p class="muted" role="status">Loading…</p>
		{:else if view === 'error'}
			<div class="notice error" role="alert"><p>{error}</p></div>
		{:else if view === 'missing' || !member}
			<section class="card">
				<h1>Not found</h1>
				<p>
					You aren't an ally for this person (any more). They may have removed you, or the link is
					wrong.
				</p>
			</section>
		{:else}
			<div class="page-head">
				<h1>{member.display_name}</h1>
				<p>
					{member.state === 'active'
						? `You have been ${member.display_name}'s ally since ${date(member.activated_at_ms ?? member.created_at_ms)}.`
						: `${member.display_name} hasn't approved you yet.`}
				</p>
			</div>

			<div class="tabs" role="tablist" aria-label="Sections">
				<button
					role="tab"
					type="button"
					aria-selected={tab === 'activity'}
					onclick={() => (tab = 'activity')}
				>
					Activity
				</button>
				<button
					role="tab"
					type="button"
					aria-selected={tab === 'notifications'}
					onclick={() => (tab = 'notifications')}
				>
					Notifications
				</button>
				<button
					role="tab"
					type="button"
					aria-selected={tab === 'code'}
					onclick={() => (tab = 'code')}
				>
					Safety code
				</button>
			</div>

			{#if tab === 'activity'}
				{#if member.state === 'active'}
					<FeedView
						memberId={member.member_id}
						viewer={user}
						keyKind="ally"
						memberSignPk={member.member_sign_pubkey}
						nameOf={(id) => (id === user.id ? 'You' : undefined)}
					/>
				{:else}
					<div class="empty">
						<p>You'll see {member.display_name}'s activity once they approve you.</p>
					</div>
				{/if}
			{:else if tab === 'notifications'}
				<section class="card">
					<h2>Email notifications about {member.display_name}</h2>
					<p class="muted">
						Emails never contain details, only that something happened. Open Faro to read them.
					</p>
					<NotificationPrefs memberId={member.member_id} about={member.display_name} />
				</section>
			{:else}
				<section class="card">
					<h2>Safety code</h2>
					<AllySafetyCode {member} viewer={user} />
				</section>
			{/if}

			<section class="leave">
				<button
					class="link"
					type="button"
					onclick={() => {
						leaveError = '';
						leaveDialog?.showModal();
					}}
				>
					Stop being {member.display_name}'s ally…
				</button>
			</section>

			<dialog bind:this={leaveDialog} aria-labelledby="leave-title">
				<h2 id="leave-title">Stop being {member.display_name}'s ally?</h2>
				<p>
					You lose access to their reports and alerts right away. Faro tells {member.display_name} and
					their other allies.
				</p>
				{#if leaveError}<div class="notice error" role="alert"><p>{leaveError}</p></div>{/if}
				<div class="actions">
					<button class="danger" type="button" onclick={leave} disabled={leaveBusy}>
						{leaveBusy ? 'Leaving…' : 'Stop being their ally'}
					</button>
					<button class="secondary" type="button" onclick={() => leaveDialog?.close()}>
						Cancel
					</button>
				</div>
			</dialog>
		{/if}
	{/snippet}
</Gate>

<style>
	.back {
		margin: -0.75rem 0 1rem;
		font-size: 0.92rem;
	}

	.back a {
		text-decoration: none;
	}

	.tabs {
		display: flex;
		gap: 0.25rem;
		border-bottom: 1px solid var(--border);
		margin-bottom: 1.25rem;
		overflow-x: auto;
	}

	.tabs button {
		background: none;
		border: none;
		border-bottom: 2px solid transparent;
		border-radius: 0;
		color: var(--muted);
		padding: 0.5rem 0.8rem;
		margin-bottom: -1px;
		min-height: 0;
	}

	.tabs button[aria-selected='true'] {
		color: var(--text);
		border-bottom-color: var(--brand);
	}

	.leave {
		margin-top: 3rem;
		font-size: 0.92rem;
	}
</style>
