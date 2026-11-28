<script lang="ts">
	// The directory listing card on the Manage tab (GROUPS.md §8.8): whether
	// the group is listed on this instance, and what the listing shows. A
	// listing never shows who is in the group or how many; people ask to
	// join and a facilitator says yes or no.
	import { api, seg } from '#lib/api.ts';
	import { groupError } from '#lib/groups-api.ts';
	import { instance } from '#lib/instance.svelte.ts';
	import type { GroupPatch, GroupView } from '#lib/types.ts';

	let { group, onchanged }: { group: GroupView; onchanged: (g?: GroupView) => void } = $props();

	let busy = $state(false);
	let error = $state('');

	let showTime = $derived(group.listing?.show_meeting_time ?? true);
	let showPlace = $derived(group.listing?.show_place ?? false);
	let instanceName = $derived(instance.info?.name ?? 'this instance');

	async function patch(change: GroupPatch) {
		busy = true;
		error = '';
		try {
			onchanged(await api.patch<GroupView>(`/v1/groups/${seg(group.id)}`, change));
		} catch (e) {
			error = groupError(e);
		} finally {
			busy = false;
		}
	}
</script>

<section class="card section" aria-labelledby="listing-h">
	<h2 id="listing-h">Listing</h2>
	<p class="muted">
		Anyone who is signed in to {instanceName} can find a listed group and ask to join. Every request comes
		to the facilitators, and nobody joins without a yes. A listing never shows who is in the group, or
		how many people.
	</p>
	<label class="check">
		<input
			type="checkbox"
			checked={group.listed}
			disabled={busy}
			onchange={(e) => patch({ listed: e.currentTarget.checked })}
		/>
		List this group on {instanceName}
	</label>

	{#if group.listed}
		<fieldset class="shows">
			<legend>The listing shows</legend>
			<p class="muted small">
				The name, the description and the facilitators' names, always. Choose what else:
			</p>
			<label class="check">
				<input
					type="checkbox"
					checked={showTime}
					disabled={busy || !group.meeting}
					onchange={(e) => patch({ listing: { show_meeting_time: e.currentTarget.checked } })}
				/>
				The meeting day and time{group.meeting ? '' : ' (set a meeting first)'}
			</label>
			<label class="check">
				<input
					type="checkbox"
					checked={showPlace}
					disabled={busy || !group.meeting?.place}
					onchange={(e) => patch({ listing: { show_place: e.currentTarget.checked } })}
				/>
				The meeting place{group.meeting?.place ? '' : ' (add a place first)'}
			</label>
			<p class="muted small">
				If you set a participant limit, the listing also says "Full" once it is reached.
			</p>
		</fieldset>
		<div class="notice info">
			<p>
				Choose a name that says who the group is for without naming the struggle: "Men, Tuesday
				evenings" rather than "Porn recovery, Tuesday". Everyone on the instance can read it.
			</p>
		</div>
	{/if}
	{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
</section>

<style>
	.shows {
		margin: 1.25rem 0 1rem;
	}

	.shows .check {
		margin-bottom: 0.5rem;
	}
</style>
