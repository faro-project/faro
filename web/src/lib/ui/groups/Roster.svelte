<script lang="ts">
	// A group's roster: search, paging, the Facilitator badge, and your
	// relationship to each person (GROUPS.md §8.1). People you have a
	// relationship with come first among the people loaded so far; the server
	// sends the rest oldest first. Never an email address.
	//
	// `actions` renders at the end of a row (the Manage tab's facilitator
	// buttons); the group page puts RosterPersonActions (#122) there.
	import type { Snippet } from 'svelte';
	import { api, seg } from '#lib/api.ts';
	import { date } from '#lib/format.ts';
	import { RELATIONSHIP_LABEL, relationshipOf, roster, type Links } from '#lib/groups.ts';
	import { groupError } from '#lib/groups-api.ts';
	import type { Page, RosterEntry } from '#lib/types.ts';

	let {
		groupId,
		myId,
		links,
		actions,
		version = 0,
		onloaded
	}: {
		groupId: string;
		myId: string;
		links: Links;
		actions?: Snippet<[RosterEntry]>;
		/** Change to reload the first page (after a role change or removal). */
		version?: number;
		/** Called with everyone loaded so far. */
		onloaded?: (entries: RosterEntry[]) => void;
	} = $props();

	let entries = $state<RosterEntry[]>([]);
	let next = $state<string | null>(null);
	let query = $state('');
	let loading = $state(true);
	let error = $state('');
	let ran = '';

	async function fetchPage(cursor: string | null, q: string): Promise<Page<RosterEntry>> {
		const params = new URLSearchParams();
		if (q) params.set('q', q);
		if (cursor) params.set('cursor', cursor);
		const qs = params.toString();
		return api.get<Page<RosterEntry>>(
			`/v1/groups/${seg(groupId)}/participants${qs ? `?${qs}` : ''}`
		);
	}

	async function load(more: boolean) {
		const q = query.trim();
		loading = true;
		error = '';
		try {
			const page = await fetchPage(more ? next : null, q);
			// A newer search replaced this one while it was loading.
			if (q !== query.trim()) return;
			entries = more ? [...entries, ...page.items] : page.items;
			next = page.next_cursor;
			onloaded?.(entries);
		} catch (e) {
			error = groupError(e);
		} finally {
			loading = false;
		}
	}

	// Reload on a new search (after a short pause) or a new `version`.
	$effect(() => {
		const key = `${query.trim()}|${version}`;
		if (key === ran) return;
		const first = ran === '';
		ran = key;
		const t = setTimeout(() => void load(false), first ? 0 : 250);
		return () => clearTimeout(t);
	});

	let shown = $derived(roster(entries, links));
</script>

<div class="field">
	<label class="visually-hidden" for="roster-search-{groupId}">Search people in this group</label>
	<input
		id="roster-search-{groupId}"
		type="search"
		placeholder="Search by name"
		bind:value={query}
		autocomplete="off"
	/>
</div>

{#if error}
	<div class="notice error" role="alert"><p>{error}</p></div>
	<button class="secondary small" type="button" onclick={() => load(false)}>Try again</button>
{/if}

{#if shown.length}
	<ul class="rows">
		{#each shown as p (p.user_id)}
			{@const rel = relationshipOf(p.user_id, links)}
			<li>
				<div class="row-main">
					<div>
						<div class="row-title">
							<strong>{p.display_name}</strong>
							{#if p.user_id === myId}<span class="chip normal">You</span>{/if}
							{#if p.role === 'facilitator'}<span class="chip good">Facilitator</span>{/if}
							{#if p.unavailable}<span class="chip off">Unavailable</span>{/if}
							{#if rel}<span class="chip pending">{RELATIONSHIP_LABEL[rel]}</span>{/if}
						</div>
						<div class="row-meta">Joined {date(p.joined_at_ms)}</div>
					</div>
					{#if p.user_id !== myId}
						<div class="row-actions">
							{#if actions}{@render actions(p)}{/if}
						</div>
					{/if}
				</div>
			</li>
		{/each}
	</ul>
{:else if !loading && !error}
	<div class="empty">
		<p>{query.trim() ? 'Nobody here matches that search.' : 'Nobody is in this group yet.'}</p>
	</div>
{/if}

{#if loading}
	<p class="muted" role="status">Loading…</p>
{:else if next}
	<div class="actions">
		<button class="secondary" type="button" onclick={() => load(true)}>Show more people</button>
	</div>
{/if}

<style>
	.row-actions {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
	}
</style>
