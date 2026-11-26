<script lang="ts">
	// The admin console (docs/ARCHITECTURE.md §4.3): instance configuration
	// and operational metadata only. Nothing here can show a report, a
	// thumbnail, a visited address or who is anyone's ally: the server has
	// no admin route to any of it.
	//
	// The pages render only for a signed-in admin. The API checks the role on
	// every request anyway; this is about showing the right page.

	import { onMount } from 'svelte';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import { describeError } from '#lib/api.ts';
	import { session } from '#lib/session.svelte.ts';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();

	let error = $state('');

	onMount(() => {
		session.refresh().catch((e) => (error = describeError(e)));
	});

	const SECTIONS = [
		{ path: '/admin', label: 'Overview' },
		{ path: '/admin/people', label: 'People' },
		{ path: '/admin/groups', label: 'Groups' },
		{ path: '/admin/settings', label: 'Settings' },
		{ path: '/admin/branding', label: 'Branding' },
		{ path: '/admin/email', label: 'Email' }
	] as const;

	function isCurrent(path: (typeof SECTIONS)[number]['path']) {
		return page.url.pathname === resolve(path);
	}
</script>

{#if error}
	<div class="notice error" role="alert">
		<p>{error}</p>
	</div>
{:else if !session.loaded}
	<p class="muted" role="status">Loading…</p>
{:else if !session.user}
	<section class="card">
		<h1>Admin console</h1>
		<p>Sign in with the admin account to manage this instance.</p>
		<div class="actions">
			<a class="button primary" href={resolve('/signin')}>Sign in</a>
		</div>
	</section>
{:else if !session.user.roles.admin}
	<section class="card">
		<h1>Admins only</h1>
		<p>
			You are signed in as <strong>{session.user.email}</strong>, which is not an admin of this
			instance.
		</p>
		<p><a href={resolve('/')}>Go to the start page</a></p>
	</section>
{:else}
	<nav class="sections" aria-label="Admin console">
		{#each SECTIONS as s (s.path)}
			<a href={resolve(s.path)} aria-current={isCurrent(s.path) ? 'page' : undefined}>{s.label}</a>
		{/each}
	</nav>
	{@render children()}
{/if}

<style>
	.sections {
		display: flex;
		flex-wrap: wrap;
		gap: 0.25rem;
		margin: -0.5rem 0 1.5rem;
		border-bottom: 1px solid var(--border);
	}

	.sections a {
		padding: 0.55rem 0.8rem;
		color: var(--muted);
		text-decoration: none;
		font-weight: 600;
		border-bottom: 2px solid transparent;
		margin-bottom: -1px;
	}

	.sections a:hover {
		color: var(--text);
	}

	.sections a[aria-current='page'] {
		color: var(--text);
		border-bottom-color: var(--accent);
	}
</style>
