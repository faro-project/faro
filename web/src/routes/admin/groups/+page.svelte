<script lang="ts">
	// Groups on this instance, as metadata only (docs/GROUPS.md §11): name,
	// size, facilitators, whether listed, and dates. Never a roster beyond
	// the facilitators, a description, or anything inside a group. An admin
	// can archive a group (for example over an abusive name): everyone in it
	// is told, and it goes into the admin log.
	import { onMount } from 'svelte';
	import { api, seg } from '#lib/api.ts';
	import { count, date, plural } from '#lib/format.ts';
	import { groupError } from '#lib/groups-api.ts';
	import type { AdminGroupRow } from '#lib/types.ts';

	let rows = $state<AdminGroupRow[] | null>(null);
	let error = $state('');
	let query = $state('');

	let dialog = $state<HTMLDialogElement | null>(null);
	let pending = $state<AdminGroupRow | null>(null);
	let busy = $state(false);
	let actionError = $state('');
	let done = $state('');

	async function load() {
		error = '';
		try {
			rows = await api.get<AdminGroupRow[]>('/admin/api/groups');
		} catch (e) {
			error = groupError(e);
		}
	}

	onMount(load);

	let shown = $derived(
		(rows ?? []).filter((g) => g.name.toLowerCase().includes(query.trim().toLowerCase()))
	);

	function confirmArchive(g: AdminGroupRow) {
		pending = g;
		actionError = '';
		dialog?.showModal();
	}

	async function archive() {
		const g = pending;
		if (!g) return;
		busy = true;
		actionError = '';
		try {
			await api.delete(`/admin/api/groups/${seg(g.id)}`);
			dialog?.close();
			done = `“${g.name}” was closed. Everyone in it was told, and it is in the admin log.`;
			await load();
		} catch (e) {
			actionError = groupError(e);
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head>
	<title>Groups · Admin · Faro</title>
</svelte:head>

<h1>Groups</h1>
<p class="muted">
	Names, sizes and facilitators only. Admins can't see who is in a group beyond its facilitators, or
	anything inside one. Group settings are under <a href="settings">Settings</a>.
</p>

{#if done}<div class="notice ok" role="status"><p>{done}</p></div>{/if}

{#if error}
	<div class="notice error" role="alert"><p>{error}</p></div>
	<button class="secondary" type="button" onclick={load}>Try again</button>
{:else if !rows}
	<p class="muted" role="status">Loading…</p>
{:else if rows.length === 0}
	<div class="empty"><p>Nobody has started a group yet.</p></div>
{:else}
	<div class="field">
		<label class="visually-hidden" for="group-filter">Filter groups by name</label>
		<input id="group-filter" type="search" placeholder="Filter by name" bind:value={query} />
	</div>
	<ul class="rows">
		{#each shown as g (g.id)}
			<li>
				<div class="row-main">
					<div>
						<div class="row-title">
							<strong>{g.name}</strong>
							{#if g.archived_at_ms}<span class="chip off">Closed</span>{/if}
							{#if g.no_facilitator}<span class="chip urgent">No facilitator</span>{/if}
							{#if g.listed}<span class="chip good">Listed</span>{/if}
						</div>
						<div class="row-meta">
							{plural(g.participant_count, 'person', 'people')} ·
							{#if g.facilitators.length}
								Facilitators: {g.facilitators.map((f) => f.display_name).join(', ')}
							{:else}
								No facilitators
							{/if}
							· Created {date(g.created_at_ms)}
							{#if g.archived_at_ms}
								· Closed {date(g.archived_at_ms)}{#if g.delete_after_ms}, deleted on {date(
										g.delete_after_ms
									)}{/if}
							{/if}
						</div>
					</div>
					{#if !g.archived_at_ms}
						<button class="secondary small" type="button" onclick={() => confirmArchive(g)}>
							Close…
						</button>
					{/if}
				</div>
			</li>
		{/each}
	</ul>
	{#if shown.length === 0}<div class="empty"><p>No group matches that name.</p></div>{/if}
	<p class="muted small">{count(rows.length)} in all.</p>
{/if}

<dialog bind:this={dialog} onclose={() => (pending = null)} aria-labelledby="archive-title">
	{#if pending}
		<h2 id="archive-title">Close “{pending.name}”?</h2>
		<p>
			Everyone in the group is told it was closed. It stays readable for 30 days, then it is
			deleted. Alliances between people in it stay. This goes into the admin log.
		</p>
		{#if actionError}<div class="notice error" role="alert"><p>{actionError}</p></div>{/if}
		<div class="actions">
			<button class="danger" type="button" onclick={archive} disabled={busy}>
				{busy ? 'Closing…' : 'Close the group'}
			</button>
			<button class="secondary" type="button" onclick={() => dialog?.close()}>Cancel</button>
		</div>
	{/if}
</dialog>
