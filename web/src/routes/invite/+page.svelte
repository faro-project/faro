<script lang="ts">
	// Where invitation emails link: /invite#token=….
	//
	// Looks the invitation up (GET /v1/invites/{token}) to say who sent it.
	// A member invitation is accepted by signing in with the invited address,
	// so this page hands over to /signin. Accepting an ally invitation also
	// creates the ally's encryption key in the browser, which the web app
	// can't do yet; the page says so rather than half-accepting.

	import { onMount } from 'svelte';
	import { resolve } from '$app/paths';
	import { api, ApiError, describeError } from '#lib/api.ts';
	import { date } from '#lib/format.ts';
	import type { InviteInfo } from '#lib/types.ts';

	type View = 'loading' | 'missing' | 'invalid' | 'ok' | 'error';

	let view = $state<View>('loading');
	let info = $state<InviteInfo | null>(null);
	let error = $state('');

	const TOKEN_SHAPE = /^[A-Za-z0-9_-]{43}$/;
	let token = '';

	async function load() {
		// Keep the token out of the address bar (and history), but in memory
		// so "Try again" still has it. A reload loses it.
		if (location.hash) {
			token = (new URLSearchParams(location.hash.slice(1)).get('token') ?? '').trim();
			history.replaceState(history.state, '', location.pathname + location.search);
		}
		view = 'loading';
		if (!token) {
			view = 'missing';
			return;
		}
		if (!TOKEN_SHAPE.test(token)) {
			view = 'invalid';
			return;
		}
		try {
			info = await api.get<InviteInfo>(`/v1/invites/${encodeURIComponent(token)}`);
			view = 'ok';
		} catch (e) {
			if (e instanceof ApiError && e.status === 404) {
				view = 'invalid';
			} else {
				error = describeError(e);
				view = 'error';
			}
		}
	}

	onMount(load);

	let signinHref = $derived(
		info ? `${resolve('/signin')}?email=${encodeURIComponent(info.email)}` : resolve('/signin')
	);
</script>

<svelte:window onhashchange={() => location.hash && load()} />

<svelte:head>
	<title>Invitation · Faro</title>
</svelte:head>

{#if view === 'loading'}
	<p class="muted" role="status">Opening the invitation…</p>
{:else if view === 'ok' && info}
	<h1>You're invited to {info.instance_name}</h1>
	<section class="card">
		{#if info.kind === 'member'}
			<p>
				<strong>{info.inviter_display_name}</strong> invited you to join {info.instance_name}, a
				Faro accountability instance.
			</p>
			<p>
				To accept, sign in with <strong>{info.email}</strong>. Faro emails you a sign-in link;
				there's no password. Your account is created the first time you sign in.
			</p>
			<p class="muted">The invitation is valid until {date(info.expires_at_ms)}.</p>
			<div class="actions">
				<a class="button primary" href={signinHref}>Sign in with {info.email}</a>
			</div>
		{:else}
			<p>
				<strong>{info.inviter_display_name}</strong> invited you to be their accountability ally on
				{info.instance_name}.
			</p>
			<div class="notice warn">
				<p>
					Accepting an ally invitation needs the ally pages of the Faro web app, which aren't ready
					yet. The invitation stays valid until {date(info.expires_at_ms)}; open this link again
					later, or ask {info.inviter_display_name} to send a new one when ally pages are available.
				</p>
			</div>
		{/if}
	</section>
{:else if view === 'invalid'}
	<h1>This invitation no longer works</h1>
	<section class="card">
		<p>
			Invitations are valid for 7 days and work once. This one has expired, was already used, or the
			link was not copied in full. Ask the person who invited you to send a new one.
		</p>
		<p>If you already have an account, you can <a href={resolve('/signin')}>sign in</a>.</p>
	</section>
{:else if view === 'missing'}
	<h1>Open the link from your invitation</h1>
	<section class="card">
		<p>
			This page opens the invitation in the link you were emailed, and that link is missing here.
			Open it again from the email.
		</p>
	</section>
{:else}
	<h1>Invitation</h1>
	<div class="notice error" role="alert"><p>{error}</p></div>
	<button class="secondary" type="button" onclick={load}>Try again</button>
{/if}
