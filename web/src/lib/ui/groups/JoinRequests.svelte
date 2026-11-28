<script lang="ts">
	// People asking to join a listed group (GROUPS.md §8.8), for facilitators.
	// A name, when they asked and their note (if they wrote one, opened and
	// checked in the browser), and nothing else about them: not whether
	// they use Faro on their own computer, nor who their allies are. Saying
	// yes adds them (with nothing shared); saying no tells them only "Not
	// accepted", and they can't ask again for a while.
	import { api, seg } from '#lib/api.ts';
	import { ago, date } from '#lib/format.ts';
	import { groupError } from '#lib/groups-api.ts';
	import { session } from '#lib/session.svelte.ts';
	import type { GroupView, JoinRequestEntry, Page } from '#lib/types.ts';
	import SignedNote from '../SignedNote.svelte';

	let { group, onchanged }: { group: GroupView; onchanged: (g?: GroupView) => void } = $props();

	let entries = $state<JoinRequestEntry[]>([]);
	let next = $state<string | null>(null);
	let loading = $state(true);
	let loadError = $state('');
	let error = $state('');
	let busyId = $state('');
	let loadedFor = '';

	async function load(more: boolean) {
		loading = true;
		loadError = '';
		try {
			const qs = more && next ? `?cursor=${encodeURIComponent(next)}` : '';
			const page = await api.get<Page<JoinRequestEntry>>(
				`/v1/groups/${seg(group.id)}/join-requests${qs}`
			);
			entries = more ? [...entries, ...page.items] : page.items;
			next = page.next_cursor;
		} catch (e) {
			loadError = groupError(e);
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		if (group.id !== loadedFor) {
			loadedFor = group.id;
			void load(false);
		}
	});

	async function decide(r: JoinRequestEntry, yes: boolean) {
		busyId = r.id;
		error = '';
		try {
			await api.post(`/v1/join-requests/${seg(r.id)}/${yes ? 'accept' : 'decline'}`);
			entries = entries.filter((x) => x.id !== r.id);
			if (yes) onchanged();
		} catch (e) {
			error = groupError(e);
		} finally {
			busyId = '';
		}
	}
</script>

<section class="card section" aria-labelledby="requests-h">
	<h2 id="requests-h">Asking to join</h2>
	{#if loadError}
		<div class="notice error" role="alert"><p>{loadError}</p></div>
		<button class="secondary small" type="button" onclick={() => load(false)}>Try again</button>
	{:else if loading && entries.length === 0}
		<p class="muted" role="status">Loading…</p>
	{:else if entries.length === 0}
		<div class="empty"><p>Nobody is waiting to join right now.</p></div>
	{:else}
		<p class="muted">
			You see a name, when they asked, and a note if they wrote one. If you say no they are only
			told "Not accepted", and requests nobody answers end after 14 days.
		</p>
		{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
		<ul class="rows">
			{#each entries as r (r.id)}
				<li>
					<div class="row-main">
						<div>
							<div class="row-title"><strong>{r.display_name}</strong></div>
							<div class="row-meta">
								Asked {ago(r.created_at_ms)} · until {date(r.expires_at_ms)}
							</div>
							{#if r.note_id && session.user}
								<SignedNote messageId={r.note_id} user={session.user} />
							{/if}
						</div>
						<div class="row-actions">
							<button
								class="primary small"
								type="button"
								disabled={busyId === r.id}
								onclick={() => decide(r, true)}
							>
								Let them in
							</button>
							<button
								class="secondary small"
								type="button"
								disabled={busyId === r.id}
								onclick={() => decide(r, false)}
							>
								Not now
							</button>
						</div>
					</div>
				</li>
			{/each}
		</ul>
		{#if next}
			<div class="actions">
				<button class="secondary" type="button" disabled={loading} onclick={() => load(true)}>
					Show more
				</button>
			</div>
		{/if}
	{/if}
</section>
