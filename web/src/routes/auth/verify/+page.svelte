<script lang="ts">
	// Where sign-in emails link: /auth/verify#token=….
	//
	// The token is in the fragment, so it never reaches the server's logs or a
	// Referer header. The page takes it out of the address bar (and history)
	// as soon as it loads, and only spends it when the person clicks: some
	// mail filters open links, and run their scripts, to scan them, and
	// would otherwise use up the one-time link before its owner does.

	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { api, ApiError, describeError } from '#lib/api.ts';
	import { pendingInvite } from '#lib/keys/pending-invite.ts';
	import { session } from '#lib/session.svelte.ts';
	import type { VerifyResponse, WellKnown } from '#lib/types.ts';

	type State = 'loading' | 'missing' | 'ready' | 'verifying' | 'expired' | 'closed' | 'error';

	let view = $state<State>('loading');
	let error = $state('');
	let instanceName = $state('');
	let token = '';

	// Same shape check as the server: 32 random bytes, base64url.
	const TOKEN_SHAPE = /^[A-Za-z0-9_-]{43}$/;

	/** Take the token out of the fragment, and the fragment out of the URL. */
	function readToken() {
		if (!location.hash && view !== 'loading') return;
		const params = new URLSearchParams(location.hash.slice(1));
		token = (params.get('token') ?? '').trim();
		if (location.hash) {
			history.replaceState(history.state, '', location.pathname + location.search);
		}
		error = '';
		view = !token ? 'missing' : TOKEN_SHAPE.test(token) ? 'ready' : 'expired';
	}

	onMount(() => {
		readToken();
		api
			.get<WellKnown>('/.well-known/faro')
			.then((w) => (instanceName = w.name))
			.catch(() => {});
	});

	async function verify() {
		view = 'verifying';
		error = '';
		try {
			const res = await api.post<VerifyResponse>('/v1/auth/magic-link/verify', { token });
			token = '';
			session.signedIn(res.user);
			// Back to an invitation the person was accepting, if any.
			await goto(resolve(pendingInvite() ? '/invite' : '/'), { replaceState: true });
		} catch (e) {
			if (e instanceof ApiError && e.code === 'invalid_or_expired_link') {
				token = '';
				view = 'expired';
			} else if (e instanceof ApiError && e.code === 'registration_closed') {
				token = '';
				view = 'closed';
			} else {
				// Network trouble or rate limiting: the link may still be good.
				error = describeError(e);
				view = 'error';
			}
		}
	}
</script>

<!-- A second link opened in the same tab only changes the fragment. -->
<svelte:window onhashchange={readToken} />

<svelte:head>
	<title>Sign in · Faro</title>
</svelte:head>

<h1>Sign in{instanceName ? ` to ${instanceName}` : ''}</h1>

{#if view === 'ready' || view === 'verifying' || view === 'error'}
	<section class="card">
		{#if error}
			<div class="notice error" role="alert">{error}</div>
		{/if}
		<p>You opened a sign-in link. Continue to sign in on this browser.</p>
		<div class="actions">
			<button class="primary" type="button" onclick={verify} disabled={view === 'verifying'}>
				{view === 'verifying' ? 'Signing in…' : view === 'error' ? 'Try again' : 'Sign in'}
			</button>
		</div>
	</section>
{:else if view === 'expired'}
	<section class="card">
		<h2>This link no longer works</h2>
		<p>
			Sign-in links work once, for 15 minutes. This one has expired, was already used, or was not
			copied in full.
		</p>
		<div class="actions">
			<a class="button primary" href={resolve('/signin')}>Get a new link</a>
		</div>
	</section>
{:else if view === 'closed'}
	<section class="card">
		<h2>This instance isn't taking new accounts</h2>
		<p>
			There is no account for this address, and the instance stopped accepting new ones after the
			link was sent. If you were invited, ask the person who invited you to send a new invitation.
		</p>
	</section>
{:else if view === 'missing'}
	<section class="card">
		<h2>Open the link from your email</h2>
		<p>
			This page signs you in from the link in a sign-in email, and that link is missing here. Open
			it again from the email, or ask for a new one.
		</p>
		<div class="actions">
			<a class="button primary" href={resolve('/signin')}>Get a sign-in link</a>
		</div>
	</section>
{/if}
