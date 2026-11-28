<script lang="ts">
	// The Manage tab, for facilitators (GROUPS.md §6): details, who can
	// invite, the participant limit, the meeting, the directory listing and
	// join requests, invitations, facilitators, removing people, and
	// archiving.
	import { api, seg } from '#lib/api.ts';
	import { date } from '#lib/format.ts';
	import { GROUP_LIMITS } from '#lib/groups.ts';
	import { groupError } from '#lib/groups-api.ts';
	import type { GroupPatch, GroupView, RosterEntry, WhoCanInvite } from '#lib/types.ts';
	import Icon from '#lib/ui/Icon.svelte';
	import InvitePeople from './InvitePeople.svelte';
	import JoinRequests from './JoinRequests.svelte';
	import ListingSettings from './ListingSettings.svelte';
	import MeetingSettings from './MeetingSettings.svelte';
	import PairingSuggestions from './PairingSuggestions.svelte';
	import Roster from './Roster.svelte';

	let {
		group,
		myId,
		people,
		onchanged,
		onarchived
	}: {
		group: GroupView;
		myId: string;
		people: { id: string; name: string }[];
		/** The group changed: the page reloads its copy and its history. */
		onchanged: (g?: GroupView) => void;
		onarchived: () => void;
	} = $props();

	// Details. Seeded once; saving replaces `group` through `onchanged`.
	// svelte-ignore state_referenced_locally
	let name = $state(group.name);
	// svelte-ignore state_referenced_locally
	let description = $state(group.description);
	// The group's own choice, not what is in effect after the instance's limit.
	// svelte-ignore state_referenced_locally
	let whoCanInvite = $state<WhoCanInvite>(group.group_who_can_invite ?? group.who_can_invite);
	let instanceAllowsParticipants = $derived(group.instance_who_can_invite === 'participants');
	// svelte-ignore state_referenced_locally
	let limit = $state(group.max_participants === null ? '' : String(group.max_participants));
	let detailsBusy = $state(false);
	let detailsError = $state('');
	let detailsSaved = $state(false);

	async function saveDetails(e: SubmitEvent) {
		e.preventDefault();
		detailsError = '';
		detailsSaved = false;
		const n = name.trim();
		if (!n || n.length > GROUP_LIMITS.name) {
			detailsError = `A group's name is 1 to ${GROUP_LIMITS.name} characters.`;
			return;
		}
		const patch: GroupPatch = {};
		if (n !== group.name) patch.name = n;
		if (description.trim() !== group.description) patch.description = description.trim();
		if (whoCanInvite !== (group.group_who_can_invite ?? group.who_can_invite)) {
			patch.who_can_invite = whoCanInvite;
		}
		const raw = limit.trim();
		const max = raw === '' ? null : Number(raw);
		if (max !== null && (!Number.isInteger(max) || max < 1)) {
			detailsError = 'The limit must be a whole number of at least 1, or empty for no limit.';
			return;
		}
		if (max !== group.max_participants) patch.max_participants = max;
		if (Object.keys(patch).length === 0) {
			detailsSaved = true;
			return;
		}
		detailsBusy = true;
		try {
			const next = await api.patch<GroupView>(`/v1/groups/${seg(group.id)}`, patch);
			detailsSaved = true;
			onchanged(next);
		} catch (err) {
			detailsError = groupError(err);
		} finally {
			detailsBusy = false;
		}
	}

	// People: facilitators and removal.
	let rosterVersion = $state(0);
	let personBusy = $state('');
	let personError = $state('');
	let removeDialog = $state<HTMLDialogElement | null>(null);
	let removing = $state<RosterEntry | null>(null);

	async function setRole(p: RosterEntry, facilitator: boolean) {
		personBusy = p.user_id;
		personError = '';
		try {
			await api.put(`/v1/groups/${seg(group.id)}/participants/${seg(p.user_id)}/role`, {
				facilitator
			});
			rosterVersion++;
			onchanged();
		} catch (err) {
			personError = groupError(err);
		} finally {
			personBusy = '';
		}
	}

	function confirmRemove(p: RosterEntry) {
		removing = p;
		personError = '';
		removeDialog?.showModal();
	}

	async function remove() {
		const p = removing;
		if (!p) return;
		personBusy = p.user_id;
		try {
			await api.delete(`/v1/groups/${seg(group.id)}/participants/${seg(p.user_id)}`);
			removeDialog?.close();
			rosterVersion++;
			onchanged();
		} catch (err) {
			personError = groupError(err);
			removeDialog?.close();
		} finally {
			personBusy = '';
		}
	}

	// Archive.
	let archiveDialog = $state<HTMLDialogElement | null>(null);
	let archiveBusy = $state(false);
	let archiveError = $state('');

	async function archive() {
		archiveBusy = true;
		archiveError = '';
		try {
			await api.delete(`/v1/groups/${seg(group.id)}`);
			archiveDialog?.close();
			onarchived();
		} catch (err) {
			archiveError = groupError(err);
		} finally {
			archiveBusy = false;
		}
	}
</script>

<form class="card section" onsubmit={saveDetails} oninput={() => (detailsSaved = false)} novalidate>
	<h2>Details</h2>
	<div class="field">
		<label for="group-name">Name</label>
		<input id="group-name" type="text" bind:value={name} maxlength={GROUP_LIMITS.name} />
	</div>
	<div class="field">
		<label for="group-description">
			Description
			<span class="hint">Everyone in the group, and anyone you invite, can read this.</span>
		</label>
		<textarea
			id="group-description"
			rows="4"
			bind:value={description}
			maxlength={GROUP_LIMITS.description}></textarea>
	</div>
	<div class="field">
		<label for="group-who-invites">Who can invite people</label>
		<select id="group-who-invites" bind:value={whoCanInvite}>
			<option value="facilitators">Only facilitators</option>
			<option value="participants" disabled={!instanceAllowsParticipants}>Any participant</option>
		</select>
		{#if !instanceAllowsParticipants}
			<span class="hint">
				This instance only lets facilitators invite, so "Any participant" isn't available.
			</span>
		{/if}
	</div>
	<div class="field">
		<label for="group-limit">
			Participant limit
			<span class="hint">
				Leave empty for no limit. Once the group is full, invitations are refused with "This group
				is full".
			</span>
		</label>
		<input id="group-limit" type="number" min="1" step="1" bind:value={limit} />
	</div>
	{#if detailsError}<div class="notice error" role="alert"><p>{detailsError}</p></div>{/if}
	<div class="actions">
		<button class="primary" type="submit" disabled={detailsBusy}>
			{detailsBusy ? 'Saving…' : 'Save details'}
		</button>
		{#if detailsSaved}<span class="saved" role="status"><Icon name="check" /> Saved</span>{/if}
	</div>
</form>

<MeetingSettings {group} {onchanged} />

<ListingSettings {group} {onchanged} />

{#if group.listed}<JoinRequests {group} {onchanged} />{/if}

<InvitePeople {group} {people} />

<PairingSuggestions groupId={group.id} readOnly={!!group.archived_at_ms || group.groups_disabled} />

<section class="card section" aria-labelledby="people-h">
	<h2 id="people-h">Facilitators and people</h2>
	<p class="muted">
		A group has at least one facilitator and at most 32. Facilitators can edit the group, invite
		people, remove people and close the group. They can't see anyone's reports or alerts.
	</p>
	{#if personError}<div class="notice error" role="alert"><p>{personError}</p></div>{/if}
	<Roster groupId={group.id} {myId} version={rosterVersion}>
		{#snippet actions(p)}
			{#if p.role === 'facilitator'}
				<button
					class="secondary small"
					type="button"
					disabled={personBusy === p.user_id}
					onclick={() => setRole(p, false)}
				>
					Make a participant
				</button>
			{:else}
				<button
					class="secondary small"
					type="button"
					disabled={personBusy === p.user_id}
					onclick={() => setRole(p, true)}
				>
					Make a facilitator
				</button>
			{/if}
			<button class="secondary small" type="button" onclick={() => confirmRemove(p)}>
				Remove…
			</button>
		{/snippet}
	</Roster>
	{#if group.facilitators.some((f) => f.user_id === myId) && group.facilitators.length > 1}
		<p class="muted small">
			To step down yourself, ask another facilitator to make you a participant, or leave the group.
		</p>
	{/if}
</section>

<section class="card section danger-zone" aria-labelledby="archive-h">
	<h2 id="archive-h">Close this group</h2>
	<p>
		Closing tells everyone in the group. It stays readable for 30 days, then it is deleted.
		Alliances between people in it stay as they are.
	</p>
	<div class="actions">
		<button
			class="danger"
			type="button"
			onclick={() => {
				archiveError = '';
				archiveDialog?.showModal();
			}}
		>
			Close the group…
		</button>
	</div>
</section>

<dialog bind:this={removeDialog} onclose={() => (removing = null)} aria-labelledby="remove-title">
	{#if removing}
		<h2 id="remove-title">Remove {removing.display_name}?</h2>
		<p>
			They are told they were removed, and it appears in the group history. Alliances stay. They can
			be invited again.
		</p>
		<div class="actions">
			<button class="danger" type="button" onclick={remove} disabled={personBusy !== ''}>
				{personBusy ? 'Removing…' : 'Remove'}
			</button>
			<button class="secondary" type="button" onclick={() => removeDialog?.close()}>Cancel</button>
		</div>
	{/if}
</dialog>

<dialog bind:this={archiveDialog} aria-labelledby="archive-title">
	<h2 id="archive-title">Close {group.name}?</h2>
	<p>
		Everyone in the group is told. For 30 days (until {date(Date.now() + 30 * 24 * 3600 * 1000)})
		people can still read the roster and history, then the group is deleted. This can't be undone.
	</p>
	{#if archiveError}<div class="notice error" role="alert"><p>{archiveError}</p></div>{/if}
	<div class="actions">
		<button class="danger" type="button" onclick={archive} disabled={archiveBusy}>
			{archiveBusy ? 'Closing…' : 'Close the group'}
		</button>
		<button class="secondary" type="button" onclick={() => archiveDialog?.close()}>Cancel</button>
	</div>
</dialog>

<style>
	.danger-zone {
		border-color: color-mix(in srgb, var(--danger) 35%, var(--border));
	}

	.danger-zone h2 {
		color: var(--danger);
	}
</style>
