<script lang="ts">
	// Your pairing suggestions in this group (GROUPS.md §8.5): cards only you
	// can see. A card offers a ready-made proposal ("Partner up with Jo?")
	// that goes through the same dialog as the roster's person menu; the
	// "Ally…" menu changes it to a one-way request or offer. Nothing is sent
	// until you act (principle 3), "Not now" just hides the card, and
	// facilitators are never told which you did.
	import { api, seg } from '#lib/api.ts';
	import { suggestionPrompt } from '#lib/groups.ts';
	import { groupError } from '#lib/groups-api.ts';
	import type { SuggestionCard } from '#lib/types.ts';
	import RosterPersonActions from './RosterPersonActions.svelte';

	let { groupId, readOnly = false }: { groupId: string; readOnly?: boolean } = $props();

	let cards = $state<SuggestionCard[]>([]);
	let error = $state('');
	let busyId = $state('');
	/** Cards you have sent a proposal from this visit (they stay to show it). */
	let sentIds = $state<string[]>([]);
	let actionRefs = $state<Record<string, ReturnType<typeof RosterPersonActions> | undefined>>({});
	let loadedFor = '';

	async function load() {
		try {
			cards = await api.get<SuggestionCard[]>(`/v1/groups/${seg(groupId)}/me/suggestions`);
		} catch {
			// Suggestions are a nicety: the page works without them.
			cards = [];
		}
	}

	$effect(() => {
		if (groupId !== loadedFor) {
			loadedFor = groupId;
			void load();
		}
	});

	async function dismiss(id: string, hide: boolean) {
		busyId = id;
		error = '';
		try {
			await api.post(`/v1/groups/${seg(groupId)}/me/suggestions/${seg(id)}/dismiss`);
			if (hide) cards = cards.filter((c) => c.id !== id);
		} catch (e) {
			error = groupError(e);
		} finally {
			busyId = '';
		}
	}

	function sent(id: string) {
		sentIds = [...sentIds, id];
		// The card has done its job; it won't come back next time.
		void dismiss(id, false);
	}
</script>

{#if cards.length}
	<section class="section" aria-labelledby="pairings-h">
		<h2 id="pairings-h">Suggested for you</h2>
		<p class="muted">
			A facilitator suggested {cards.length === 1 ? 'a pairing' : 'some pairings'}. Nothing is sent
			unless you choose, and nobody is told what you decide.
		</p>
		{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
		<ul class="rows">
			{#each cards as c (c.id)}
				<li>
					<div class="row-main">
						<div>
							<div class="row-title"><strong>{suggestionPrompt(c.other.display_name)}</strong></div>
							{#if sentIds.includes(c.id)}
								<div class="row-meta">You sent {c.other.display_name} a proposal.</div>
							{/if}
						</div>
						{#if !readOnly}
							<div class="row-actions">
								{#if !sentIds.includes(c.id) && actionRefs[c.id]?.can('partnership')}
									<button
										class="primary small"
										type="button"
										onclick={() => actionRefs[c.id]?.start('partnership')}
									>
										Partner up
									</button>
								{/if}
								<RosterPersonActions
									bind:this={actionRefs[c.id]}
									{groupId}
									person={{
										user_id: c.other.user_id,
										display_name: c.other.display_name,
										unavailable: false
									}}
									onsent={() => sent(c.id)}
								/>
								{#if !sentIds.includes(c.id)}
									<button
										class="secondary small"
										type="button"
										disabled={busyId === c.id}
										onclick={() => dismiss(c.id, true)}
									>
										Not now
									</button>
								{:else}
									<button
										class="link small"
										type="button"
										onclick={() => (cards = cards.filter((x) => x.id !== c.id))}
									>
										Hide
									</button>
								{/if}
							</div>
						{/if}
					</div>
				</li>
			{/each}
		</ul>
	</section>
{/if}

<style>
	.row-actions {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
		align-items: center;
	}
</style>
