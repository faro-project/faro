<script lang="ts">
	import { onMount } from 'svelte';
	import { api, describeError } from '#lib/api.ts';
	import SettingsForm from '#lib/admin/SettingsForm.svelte';
	import type { InstanceSettings } from '#lib/types.ts';

	let settings = $state<InstanceSettings | null>(null);
	let error = $state('');

	async function load() {
		error = '';
		try {
			settings = await api.get<InstanceSettings>('/admin/api/settings');
		} catch (e) {
			error = describeError(e);
		}
	}

	onMount(load);
</script>

<svelte:head>
	<title>Settings · Admin · Faro</title>
</svelte:head>

<h1>Settings</h1>
<p class="muted">
	The instance name, web address, mail server and HTTPS are set in faro.toml or FARO_* variables on
	the server.
</p>

{#if error}
	<div class="notice error" role="alert">{error}</div>
	<button class="secondary" type="button" onclick={load}>Try again</button>
{:else if !settings}
	<p class="muted" role="status">Loading…</p>
{:else}
	<SettingsForm
		{settings}
		heading="Registration, retention and check-ins"
		submitLabel="Save settings"
		showLiveness
		onsaved={(s) => (settings = s)}
	/>
{/if}
