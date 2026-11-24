<script lang="ts">
	import { onMount } from 'svelte';
	import { api, describeError } from '#lib/api.ts';
	import EmailCheck from '#lib/admin/EmailCheck.svelte';
	import { plural } from '#lib/format.ts';
	import { session } from '#lib/session.svelte.ts';
	import type { Overview } from '#lib/types.ts';

	let overview = $state<Overview | null>(null);
	let error = $state('');

	async function refresh() {
		overview = await api.get<Overview>('/admin/api/overview');
	}

	async function load() {
		error = '';
		try {
			await refresh();
		} catch (e) {
			error = describeError(e);
		}
	}

	onMount(load);
</script>

<svelte:head>
	<title>Email · Admin · Faro</title>
</svelte:head>

<h1>Email</h1>

{#if error}
	<div class="notice error" role="alert">{error}</div>
	<button class="secondary" type="button" onclick={load}>Try again</button>
{:else if !overview || !session.user}
	<p class="muted" role="status">Loading…</p>
{:else}
	<EmailCheck {overview} adminEmail={session.user.email} onrefresh={refresh} />
	{#if overview.notifications.failed > 0 || overview.notifications.retrying > 0}
		<section class="card delivery">
			<h2>Delivery</h2>
			<ul>
				<li>
					{plural(overview.notifications.failed, 'notification')} failed after repeated attempts.
				</li>
				<li>{plural(overview.notifications.retrying, 'notification')} being retried.</li>
			</ul>
			<p class="muted">
				Faro shows counts only. The server log has the error codes, never the messages or
				recipients.
			</p>
		</section>
	{/if}
{/if}

<style>
	.delivery {
		margin-top: 1rem;
	}
</style>
