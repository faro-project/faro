<script lang="ts">
	import { onMount } from 'svelte';
	import { resolve } from '$app/paths';
	import { api } from '#lib/api.ts';
	import { session } from '#lib/session.svelte.ts';
	import type { SetupStatus } from '#lib/types.ts';

	let needsSetup = $state<boolean | null>(null);

	onMount(async () => {
		try {
			needsSetup = (await api.get<SetupStatus>('/v1/setup')).needs_setup;
		} catch {
			needsSetup = null;
		}
	});

	let roles = $derived.by(() => {
		const r = session.user?.roles;
		if (!r) return '';
		const names = [r.admin && 'admin', r.member && 'member', r.ally && 'ally'].filter(Boolean);
		return names.join(', ');
	});
</script>

<svelte:head>
	<title>Faro</title>
</svelte:head>

<h1>Faro</h1>

{#if needsSetup}
	<div class="card">
		<h2>This instance needs setting up</h2>
		<p>Create the admin account with the one-time setup token from the server log.</p>
		<a class="button primary" href={resolve('/setup')}>Start setup</a>
	</div>
{:else if session.user}
	<section class="card">
		<h2>Welcome, {session.user.display_name}</h2>
		<p>
			Signed in as <strong>{session.user.email}</strong>{roles ? ` (${roles})` : ''}.
		</p>
		{#if session.user.roles.admin}
			<p>
				<a href={resolve('/admin')}>Admin console</a>: people, invitations, settings and email.
			</p>
		{/if}
		<p class="muted">Member and ally pages are coming soon.</p>
	</section>
{:else}
	<p>
		This is a Faro instance. Faro helps people stay accountable to allies they trust, with reports
		encrypted so only those allies can read them.
	</p>
	{#if session.loaded}
		<a class="button primary" href={resolve('/signin')}>Sign in</a>
	{/if}
{/if}
