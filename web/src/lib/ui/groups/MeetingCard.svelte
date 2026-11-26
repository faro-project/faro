<script lang="ts">
	// The group page's meeting card (GROUPS.md §8.4): when the group meets,
	// where (if the facilitators said), the next meeting in your own time, and
	// your own reminder choices. `group.meeting` is null until a facilitator
	// sets a schedule, and then there is no card.
	import { api, seg } from '#lib/api.ts';
	import { groupError } from '#lib/groups-api.ts';
	import { describeSchedule, nextMeetingText } from '#lib/meetings.ts';
	import type { GroupView, MeetingReminders } from '#lib/types.ts';

	let { group }: { group: GroupView } = $props();

	// svelte-ignore state_referenced_locally
	let reminders = $state<MeetingReminders>(group.my_meeting_reminders);
	let error = $state('');
	let busy = $state(false);

	// A group that changed under us (a new copy of the view) brings its own.
	$effect(() => {
		reminders = group.my_meeting_reminders;
	});

	let readOnly = $derived(!!group.archived_at_ms || group.groups_disabled);

	async function set(change: { reminders?: boolean; email?: boolean }) {
		busy = true;
		error = '';
		try {
			reminders = await api.put<MeetingReminders>(
				`/v1/groups/${seg(group.id)}/me/meeting-reminders`,
				change
			);
		} catch (e) {
			error = groupError(e);
		} finally {
			busy = false;
		}
	}
</script>

{#if group.meeting && !group.archived_at_ms}
	<section class="card meeting" aria-labelledby="meeting-h">
		<h2 id="meeting-h">Meeting</h2>
		{#if group.next_meeting_at_ms}
			<p class="next"><strong>Next: {nextMeetingText(group.next_meeting_at_ms)}</strong></p>
		{/if}
		<p class="muted">
			{describeSchedule(group.meeting)}
			{#if group.meeting.place}· {group.meeting.place}{/if}
		</p>

		{#if !readOnly}
			<fieldset class="reminders">
				<legend class="visually-hidden">Reminders</legend>
				<label class="check">
					<input
						type="checkbox"
						checked={reminders.reminders}
						disabled={busy}
						onchange={(e) => set({ reminders: e.currentTarget.checked })}
					/>
					Remind me before each meeting
				</label>
				{#if reminders.reminders}
					<label class="check">
						<input
							type="checkbox"
							checked={reminders.email}
							disabled={busy}
							onchange={(e) => set({ email: e.currentTarget.checked })}
						/>
						Also email me
					</label>
					{#if !reminders.email_default}
						<p class="muted small">
							This is a large group, so email reminders start switched off. You still get the
							reminder in Faro.
						</p>
					{/if}
				{/if}
				<p class="muted small">
					The email says only that your group meets that day. It never names the group.
				</p>
			</fieldset>
		{/if}
		{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
	</section>
{/if}

<style>
	.meeting {
		margin-bottom: 1.5rem;
	}

	.next {
		font-size: 1.15rem;
		margin: 0 0 0.25rem;
	}

	.reminders {
		border: none;
		padding: 0;
		margin: 1rem 0 0;
	}
</style>
