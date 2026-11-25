<script lang="ts">
	// Email sign-in (docs/ARCHITECTURE.md §9 "Authentication"): ask for a
	// one-time link, which arrives by email and opens /auth/verify.
	//
	// The server answers the same way whether or not the address has an
	// account (or may create one), and so does this page: it never says
	// whether an account exists.

	import { onMount } from 'svelte';
	import { resolve } from '$app/paths';
	import Logo from '#lib/ui/Logo.svelte';
	import { api, ApiError, describeError } from '#lib/api.ts';
	import { session } from '#lib/session.svelte.ts';
	import type { MagicLinkResponse, WellKnown } from '#lib/types.ts';

	let email = $state('');
	let sentTo = $state('');
	let busy = $state(false);
	let error = $state('');
	let fieldError = $state('');
	let instanceName = $state('');

	onMount(() => {
		// The invitation page passes the invited address along.
		email = new URLSearchParams(location.search).get('email') ?? '';
		void session.refresh().catch(() => {});
		api
			.get<WellKnown>('/.well-known/faro')
			.then((w) => (instanceName = w.name))
			.catch(() => {});
	});

	async function send(e?: SubmitEvent) {
		e?.preventDefault();
		error = '';
		fieldError = '';
		const address = email.trim();
		if (!/^[^\s@]+@[^\s@]+$/.test(address)) {
			fieldError = 'Enter your email address.';
			return;
		}
		busy = true;
		try {
			await api.post<MagicLinkResponse>('/v1/auth/magic-link', { email: address });
			sentTo = address;
		} catch (err) {
			if (err instanceof ApiError && err.code === 'invalid_email') {
				fieldError = 'The server could not read this email address.';
			} else {
				error = describeError(err);
			}
		} finally {
			busy = false;
		}
	}

	function differentAddress() {
		sentTo = '';
		error = '';
	}

	async function signOut() {
		try {
			await session.signOut();
		} catch (err) {
			error = describeError(err);
		}
	}
</script>

<svelte:head>
	<title>Sign in · Faro</title>
</svelte:head>

<div class="brand-mark"><Logo height={56} /></div>

<h1>Sign in{instanceName ? ` to ${instanceName}` : ''}</h1>

{#if error}
	<div class="notice error" role="alert">{error}</div>
{/if}

{#if session.user}
	<section class="card">
		<h2>You are signed in</h2>
		<p>
			This browser is signed in as <strong>{session.user.display_name}</strong>
			({session.user.email}).
		</p>
		<div class="actions">
			<a class="button primary" href={resolve('/')}>Continue</a>
			<button class="secondary" type="button" onclick={signOut}>Sign out</button>
		</div>
	</section>
{:else if sentTo}
	<section class="card" aria-live="polite">
		<h2>Check your email</h2>
		<p>
			If <strong>{sentTo}</strong> can sign in here, a sign-in link is on its way. Open it on the device
			where you want to be signed in. It works once, for 15 minutes.
		</p>
		<p class="muted">
			Nothing after a few minutes? Check the spam folder, and that the address is the one you were
			invited with. Your instance's admin can check that email is working.
		</p>
		<div class="actions">
			<button class="secondary" type="button" onclick={() => send()} disabled={busy}>
				{busy ? 'Sending…' : 'Send another link'}
			</button>
			<button class="link" type="button" onclick={differentAddress}>Use a different address</button>
		</div>
	</section>
{:else}
	<form class="card" onsubmit={send} novalidate>
		<p>Enter your email address and we'll send you a link to sign in. There's no password.</p>
		<div class="field">
			<label for="signin-email">Email address</label>
			<input
				id="signin-email"
				type="email"
				bind:value={email}
				autocomplete="email"
				aria-invalid={fieldError ? 'true' : undefined}
				aria-describedby={fieldError ? 'signin-email-error' : undefined}
			/>
			{#if fieldError}
				<span class="field-error" id="signin-email-error">{fieldError}</span>
			{/if}
		</div>
		<div class="actions">
			<button class="primary" type="submit" disabled={busy}>
				{busy ? 'Sending…' : 'Email me a sign-in link'}
			</button>
		</div>
	</form>
{/if}

<style>
	.brand-mark {
		display: flex;
		justify-content: center;
		margin: 0.5rem 0 2rem;
	}
</style>
