<script lang="ts">
	import '../app.css';
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { asset, resolve } from '$app/paths';
	import { page } from '$app/state';
	import { session } from '#lib/session.svelte.ts';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();

	let signOutError = $state('');

	// The sign-in pages show their own state; a "Sign in" link there is noise.
	let onSignInPage = $derived(/\/(signin|auth\/verify)$/.test(page.url.pathname));

	onMount(() => {
		// Header only: pages that need the session handle errors themselves.
		session.refresh().catch(() => {});
	});

	async function signOut() {
		signOutError = '';
		try {
			await session.signOut();
			await goto(resolve('/signin'));
		} catch {
			signOutError = 'Could not sign out. Try again.';
		}
	}
</script>

<svelte:head>
	<link rel="icon" href={asset('favicon.svg')} type="image/svg+xml" />
</svelte:head>

<header class="site-header">
	<a class="brand" href={resolve('/')}>
		<img src={asset('favicon.svg')} alt="" width="24" height="24" />
		<span>Faro</span>
	</a>
	<nav class="account" aria-label="Account">
		{#if session.user}
			{#if session.user.roles.admin}
				<a href={resolve('/admin')}>Admin</a>
			{/if}
			<span class="who" title={session.user.email}>{session.user.display_name}</span>
			<button class="link" type="button" onclick={signOut}>Sign out</button>
		{:else if session.loaded && !onSignInPage}
			<a href={resolve('/signin')}>Sign in</a>
		{/if}
	</nav>
</header>

<main>
	{#if signOutError}
		<div class="notice error" role="alert">{signOutError}</div>
	{/if}
	{@render children()}
</main>

<style>
	.site-header {
		max-width: 44rem;
		margin: 0 auto;
		padding: 1.25rem 16px 0;
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
	}

	.brand {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		color: var(--text);
		text-decoration: none;
		font-weight: 700;
		font-size: 1.15rem;
		letter-spacing: 0.01em;
	}

	.account {
		display: flex;
		align-items: center;
		gap: 0.9rem;
		min-width: 0;
		font-size: 0.95rem;
	}

	.who {
		color: var(--muted);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	main {
		max-width: 44rem;
		margin: 0 auto;
		padding: 1.5rem 16px 4rem;
	}
</style>
