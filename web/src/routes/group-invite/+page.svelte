<script lang="ts">
	// Where group invitation emails link: /group-invite#token=… (GROUPS.md
	// §8.7). The same page opens from "Invitations" on the Groups page, with
	// the invitation's reference in place of the emailed token.
	//
	// Looking an invitation up needs a session for the invited person, so a
	// signed-out visitor is sent to sign in and the token is kept (as an ally
	// invitation's is) until the invitation is answered. Accepting is
	// always the person's own choice, and joining shares nothing about their
	// computer.
	//
	// "What this group can see about me" (#124) goes where SharingSettings is.

	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { api, ApiError, seg } from '#lib/api.ts';
	import { date } from '#lib/format.ts';
	import {
		clearPendingGroupInvite,
		isInviteToken,
		joinNames,
		pendingGroupInvite,
		savePendingGroupInvite,
		tokenFromHash
	} from '#lib/groups.ts';
	import { groupError } from '#lib/groups-api.ts';
	import { describeSchedule } from '#lib/meetings.ts';
	import { session } from '#lib/session.svelte.ts';
	import type { GroupInviteInfo, GroupView, MySharing } from '#lib/types.ts';
	import SharingSettings from '#lib/ui/groups/SharingSettings.svelte';

	type View = 'loading' | 'missing' | 'invalid' | 'signin' | 'ok' | 'error';

	let view = $state<View>('loading');
	let info = $state<GroupInviteInfo | null>(null);
	let error = $state('');
	let token = '';
	let busy = $state(false);
	let actionError = $state('');
	let declined = $state(false);
	/** What they chose to show the group, saved once they have joined. */
	let sharing = $state<MySharing>({ share_status: false, share_allies: false });

	function readToken() {
		// Keep the token out of the address bar (and history), but in memory.
		if (location.hash) {
			token = tokenFromHash(location.hash);
			history.replaceState(history.state, '', location.pathname + location.search);
		}
		if (!token) token = pendingGroupInvite() ?? '';
	}

	async function load() {
		if (!token) readToken();
		view = 'loading';
		if (!token) {
			view = 'missing';
			return;
		}
		if (!isInviteToken(token)) {
			view = 'invalid';
			return;
		}
		savePendingGroupInvite(token);
		if (!session.user) {
			view = 'signin';
			return;
		}
		try {
			info = await api.get<GroupInviteInfo>(`/v1/group-invites/${seg(token)}`);
			view = 'ok';
		} catch (e) {
			if (e instanceof ApiError && e.status === 404) {
				// Expired, used, closed, or meant for another address.
				view = 'invalid';
			} else {
				error = groupError(e);
				view = 'error';
			}
		}
	}

	let started = false;
	onMount(() => {
		readToken();
		void session.refresh().catch(() => {});
	});

	// Once the session is known, open the invitation (or ask to sign in).
	$effect(() => {
		if (session.loaded && !started) {
			started = true;
			void load();
		}
	});

	let deleting = $derived(!!session.deletion);

	async function accept() {
		if (!info) return;
		busy = true;
		actionError = '';
		try {
			const g = await api.post<GroupView>(`/v1/group-invites/${seg(token)}/accept`);
			clearPendingGroupInvite();
			// Only if they chose something: all off is already what joining does.
			if (sharing.share_status || sharing.share_allies) {
				await api.put(`/v1/groups/${seg(g.id)}/me/sharing`, sharing).catch(() => {
					// They are in the group; they can set it from the group page.
				});
			}
			await goto(`${resolve('/groups/view')}?id=${encodeURIComponent(g.id)}`);
		} catch (e) {
			actionError = groupError(e);
			if (e instanceof ApiError && e.status === 404) {
				clearPendingGroupInvite();
				view = 'invalid';
			}
		} finally {
			busy = false;
		}
	}

	async function decline() {
		busy = true;
		actionError = '';
		try {
			await api.post<void>(`/v1/group-invites/${seg(token)}/decline`);
			clearPendingGroupInvite();
			declined = true;
		} catch (e) {
			actionError = groupError(e);
		} finally {
			busy = false;
		}
	}

	async function switchAccount() {
		await session.signOut().catch(() => {});
		started = false;
		void load();
	}
</script>

<svelte:window onhashchange={() => location.hash && (readToken(), load())} />

<svelte:head>
	<title>Group invitation · Faro</title>
</svelte:head>

{#if view === 'loading'}
	<p class="muted" role="status">Opening the invitation…</p>
{:else if view === 'signin'}
	<h1>You're invited to a group</h1>
	<section class="card">
		<p>
			Sign in with the email address the invitation was sent to, and Faro shows you the group so you
			can say yes or no. There's no password: Faro emails you a sign-in link. Come back to this page
			afterwards; it remembers the invitation.
		</p>
		<p class="muted">
			Looking at an invitation shares nothing, and nobody is told until you accept.
		</p>
		<div class="actions">
			<a class="button primary" href={resolve('/signin')}>Sign in</a>
		</div>
	</section>
{:else if view === 'ok' && info}
	{#if declined}
		<h1>Invitation declined</h1>
		<section class="card">
			<p>
				You said no to {info.group_name}. Whoever invited you sees only that it wasn't accepted.
			</p>
			<div class="actions">
				<a class="button secondary" href={resolve('/groups')}>Your groups</a>
			</div>
		</section>
	{:else}
		<h1>Join {info.group_name}?</h1>
		<section class="card">
			<p>
				<strong>{info.inviter_display_name}</strong> invited you to join
				<strong>{info.group_name}</strong> on {info.instance_name}.
			</p>
			{#if info.group_description}
				<blockquote class="description">{info.group_description}</blockquote>
			{/if}
			{#if info.facilitators.length}
				<p class="fact">
					<strong>Facilitated by</strong>
					{joinNames(info.facilitators)}
				</p>
			{/if}
			{#if info.meeting}
				<p class="fact">
					<strong>Meets</strong>
					{describeSchedule(info.meeting)}{#if info.meeting.place}, {info.meeting.place}{/if}
				</p>
			{/if}

			<div class="notice info">
				<p>
					<strong>Joining shares nothing about your computer.</strong> Nobody in the group sees your reports,
					your alerts or whether Faro is running, unless you choose to below. Everyone in the group can
					see your name, and that you joined. You can leave at any time.
				</p>
			</div>

			<SharingSettings audience={info.participant_count} onchange={(s) => (sharing = s)} />

			<p class="muted">The invitation is valid until {date(info.expires_at_ms)}.</p>

			{#if actionError}<div class="notice error" role="alert"><p>{actionError}</p></div>{/if}
			{#if deleting}
				<div class="notice warn">
					<p>Your account is being deleted, so you can't join a group.</p>
				</div>
			{/if}
			<div class="actions">
				<button class="primary" type="button" onclick={accept} disabled={busy || deleting}>
					{busy ? 'Working…' : 'Join this group'}
				</button>
				<button class="secondary" type="button" onclick={decline} disabled={busy}>
					No thanks
				</button>
			</div>
		</section>
	{/if}
{:else if view === 'invalid'}
	<h1>This invitation no longer works</h1>
	<section class="card">
		<p>
			Invitations are valid for 7 days and work once. This one has expired, was already answered,
			the group was closed, or it was meant for a different email address than the one you're signed
			in with{#if session.user}
				(<strong>{session.user.email}</strong>){/if}. Ask the person who invited you to send a new
			one.
		</p>
		<div class="actions">
			<a class="button secondary" href={resolve('/groups')}>Your groups</a>
			{#if session.user}
				<button class="link" type="button" onclick={switchAccount}>
					Sign out and switch account
				</button>
			{/if}
		</div>
	</section>
{:else if view === 'missing'}
	<h1>Open the link from your invitation</h1>
	<section class="card">
		<p>
			This page opens the invitation in the link you were emailed, and that link is missing here.
			Open it again from the email, or look under Invitations on
			<a href={resolve('/groups')}>your Groups page</a>.
		</p>
	</section>
{:else}
	<h1>Invitation</h1>
	<div class="notice error" role="alert"><p>{error}</p></div>
	<button class="secondary" type="button" onclick={load}>Try again</button>
{/if}

<style>
	.description {
		margin: 1rem 0;
		padding: 0.3rem 0 0.3rem 0.9rem;
		border-left: 2px solid var(--border-strong);
		color: var(--muted);
		font-size: 0.95rem;
		white-space: pre-wrap;
	}

	/* "Facilitated by", "Meets": a small label before the value. */
	.fact {
		margin-bottom: 0.4rem;
	}

	.fact strong {
		font-family: var(--mono);
		font-size: 0.7rem;
		font-weight: 500;
		text-transform: uppercase;
		letter-spacing: 0.08em;
		color: var(--muted);
		margin-right: 0.4rem;
	}

	.fact + :not(.fact) {
		margin-top: 1rem;
	}
</style>
