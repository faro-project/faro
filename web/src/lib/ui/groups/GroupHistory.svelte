<script lang="ts">
	// The group history (GROUPS.md §8.1): joins, leaves and removals that
	// everyone in the group can see, so nobody can be added unseen. Runs of
	// changes collapse ("14 people joined that week") and expand on request.
	import { onMount } from 'svelte';
	import { api, seg } from '#lib/api.ts';
	import { date, dateTime } from '#lib/format.ts';
	import { collapseHistory, describeHistory, describeRun } from '#lib/groups.ts';
	import { groupError } from '#lib/groups-api.ts';
	import type { HistoryEntry, Page } from '#lib/types.ts';

	let { groupId, version = 0 }: { groupId: string; version?: number } = $props();

	let entries = $state<HistoryEntry[]>([]);
	let next = $state<string | null>(null);
	let loading = $state(true);
	let error = $state('');
	let open = $state(new Set<string>());
	let ran = -1;

	async function load(more: boolean) {
		loading = true;
		error = '';
		try {
			const cursor = more && next ? `?cursor=${encodeURIComponent(next)}` : '';
			const page = await api.get<Page<HistoryEntry>>(`/v1/groups/${seg(groupId)}/history${cursor}`);
			entries = more ? [...entries, ...page.items] : page.items;
			next = page.next_cursor;
		} catch (e) {
			error = groupError(e);
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		ran = version;
		void load(false);
	});

	$effect(() => {
		if (ran >= 0 && version !== ran) {
			ran = version;
			void load(false);
		}
	});

	let items = $derived(collapseHistory(entries));

	function toggle(id: string) {
		const s = new Set(open);
		if (s.has(id)) s.delete(id);
		else s.add(id);
		open = s;
	}
</script>

{#if error}
	<div class="notice error" role="alert"><p>{error}</p></div>
	<button class="secondary small" type="button" onclick={() => load(false)}>Try again</button>
{/if}

{#if items.length}
	<ul class="rows">
		{#each items as item (item.type === 'entry' ? item.entry.id : `run-${item.entries[0].id}`)}
			<li>
				{#if item.type === 'entry'}
					<div class="row-main">
						<span>{describeHistory(item.entry)}</span>
						<span class="muted small" title={dateTime(item.entry.at_ms)}>
							{date(item.entry.at_ms)}
						</span>
					</div>
				{:else}
					{@const id = `run-${item.entries[0].id}`}
					<div class="row-main">
						<span>{describeRun(item.kind, item.entries)}</span>
						<button
							class="link small"
							type="button"
							aria-expanded={open.has(id)}
							onclick={() => toggle(id)}
						>
							{open.has(id) ? 'Hide' : 'Show each'}
						</button>
					</div>
					{#if open.has(id)}
						<ul class="run">
							{#each item.entries as e (e.id)}
								<li class="row-main">
									<span>{describeHistory(e)}</span>
									<span class="muted small" title={dateTime(e.at_ms)}>{date(e.at_ms)}</span>
								</li>
							{/each}
						</ul>
					{/if}
				{/if}
			</li>
		{/each}
	</ul>
{:else if !loading && !error}
	<div class="empty"><p>Nothing has changed yet.</p></div>
{/if}

{#if loading}
	<p class="muted" role="status">Loading…</p>
{:else if next}
	<div class="actions">
		<button class="secondary" type="button" onclick={() => load(true)}>Show older changes</button>
	</div>
{/if}

<style>
	.run {
		list-style: none;
		margin: 0.5rem 0 0;
		padding: 0 0 0 1rem;
		border-left: 2px solid var(--border);
	}

	.run > li {
		padding: 0.25rem 0;
	}
</style>
