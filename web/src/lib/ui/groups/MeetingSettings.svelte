<script lang="ts">
	// The meeting card on the Manage tab (GROUPS.md §8.4): a weekly or
	// fortnightly weekday and time at a fixed UTC offset (the server has no
	// time-zone database), and an optional place. The place is plaintext
	// that the operator of this server can read, and the form says so.
	import { api, seg } from '#lib/api.ts';
	import { groupError } from '#lib/groups-api.ts';
	import {
		browserOffsetMin,
		fromTimeValue,
		OFFSET_CHOICES,
		offsetLabel,
		toTimeValue,
		WEEKDAYS
	} from '#lib/meetings.ts';
	import type { GroupPatch, GroupView } from '#lib/types.ts';
	import Icon from '#lib/ui/Icon.svelte';

	let { group, onchanged }: { group: GroupView; onchanged: (g?: GroupView) => void } = $props();

	// Seeded once; saving replaces `group` through `onchanged`.
	/* svelte-ignore state_referenced_locally */
	const m = group.meeting;
	/* svelte-ignore state_referenced_locally */
	let on = $state(!!m);
	let cadence = $state<'weekly' | 'fortnightly'>(m?.cadence ?? 'weekly');
	let weekday = $state(m?.weekday ?? 1);
	let time = $state(toTimeValue(m?.minute_of_day ?? 19 * 60));
	let offset = $state(m?.tz_offset_min ?? browserOffsetMin());
	let place = $state(m?.place ?? '');
	let busy = $state(false);
	let error = $state('');
	let saved = $state(false);

	async function save(e: SubmitEvent) {
		e.preventDefault();
		error = '';
		saved = false;
		let meeting: GroupPatch['meeting'] = null;
		if (on) {
			const minute = fromTimeValue(time);
			if (minute === null) {
				error = 'Choose the time the meeting starts.';
				return;
			}
			meeting = {
				cadence,
				weekday,
				minute_of_day: minute,
				tz_offset_min: offset,
				place: place.trim() || null
			};
		} else if (!group.meeting) {
			saved = true;
			return;
		}
		busy = true;
		try {
			const next = await api.patch<GroupView>(`/v1/groups/${seg(group.id)}`, { meeting });
			saved = true;
			onchanged(next);
		} catch (err) {
			error = groupError(err);
		} finally {
			busy = false;
		}
	}
</script>

<form class="card section" onsubmit={save} oninput={() => (saved = false)} novalidate>
	<h2>Meeting</h2>
	<p class="muted">
		Everyone in the group sees when you meet, and gets a reminder two hours before (they can switch
		it off). The reminder email says only that "your group" meets, never which group.
	</p>
	<label class="check">
		<input type="checkbox" bind:checked={on} />
		This group meets on a regular schedule
	</label>

	{#if on}
		<div class="grid">
			<div class="field">
				<label for="meeting-cadence">How often</label>
				<select id="meeting-cadence" bind:value={cadence}>
					<option value="weekly">Every week</option>
					<option value="fortnightly">Every other week</option>
				</select>
			</div>
			<div class="field">
				<label for="meeting-day">Day</label>
				<select id="meeting-day" bind:value={weekday}>
					{#each WEEKDAYS as d, i (d)}<option value={i}>{d}</option>{/each}
				</select>
			</div>
			<div class="field">
				<label for="meeting-time">Starts at</label>
				<input id="meeting-time" type="time" bind:value={time} />
			</div>
			<div class="field">
				<label for="meeting-offset">Time zone</label>
				<select id="meeting-offset" bind:value={offset}>
					{#each OFFSET_CHOICES as o (o)}<option value={o}>{offsetLabel(o)}</option>{/each}
				</select>
			</div>
		</div>
		<p class="muted small">
			Faro keeps a fixed offset from UTC, so when your clocks change you update it here.
		</p>
		<div class="field">
			<label for="meeting-place">
				Where
				<span class="hint">
					Optional, for example "Room 104" or "Zoom, see group chat". This is plain text: the person
					who runs this server can read it. Don't put anything private here.
				</span>
			</label>
			<input id="meeting-place" type="text" bind:value={place} maxlength="200" autocomplete="off" />
		</div>
	{/if}

	{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
	<div class="actions">
		<button class="primary" type="submit" disabled={busy}>
			{busy ? 'Saving…' : on ? 'Save the meeting' : group.meeting ? 'Remove the meeting' : 'Save'}
		</button>
		{#if saved}<span class="saved" role="status"><Icon name="check" /> Saved</span>{/if}
	</div>
</form>

<style>
	.grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
		gap: 0 1rem;
		margin-top: 1rem;
	}
</style>
