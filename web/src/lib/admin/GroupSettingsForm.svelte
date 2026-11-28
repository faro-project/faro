<script lang="ts">
	// Instance-wide group settings (docs/GROUPS.md §13), saved with
	// PATCH /admin/api/settings as `{ groups: { … } }`. Only what changed is
	// sent. There is deliberately no instance-wide group size limit.
	import { api, ApiError, describeError } from '#lib/api.ts';
	import type { GroupSettings, InstanceSettings, SettingsPatch } from '#lib/types.ts';
	import Icon from '#lib/ui/Icon.svelte';

	let {
		groups,
		onsaved
	}: {
		groups: GroupSettings;
		onsaved: (g: GroupSettings) => void;
	} = $props();

	/** Server limit (settings.rs `MAX_GROUPS_PER_USER_LIMIT`). */
	const MAX_PER_USER = 1000;

	// svelte-ignore state_referenced_locally
	let baseline = $state<GroupSettings>({ ...groups });
	// svelte-ignore state_referenced_locally
	let draft = $state<GroupSettings>({ ...groups });
	let busy = $state(false);
	let error = $state('');
	let saved = $state(false);

	let limitValid = $derived(
		Number.isInteger(draft.max_groups_per_user) &&
			draft.max_groups_per_user >= 1 &&
			draft.max_groups_per_user <= MAX_PER_USER
	);

	function changes(): Partial<GroupSettings> {
		const patch: Partial<GroupSettings> = {};
		for (const k of Object.keys(draft) as (keyof GroupSettings)[]) {
			if (draft[k] !== baseline[k]) Object.assign(patch, { [k]: draft[k] });
		}
		return patch;
	}

	async function save(e: SubmitEvent) {
		e.preventDefault();
		error = '';
		saved = false;
		if (!limitValid) return;
		const patch = changes();
		if (Object.keys(patch).length === 0) {
			saved = true;
			return;
		}
		busy = true;
		try {
			const body: SettingsPatch = { groups: patch };
			const next = await api.patch<InstanceSettings>('/admin/api/settings', body);
			baseline = { ...next.groups };
			draft = { ...next.groups };
			saved = true;
			onsaved(next.groups);
		} catch (err) {
			error =
				err instanceof ApiError && err.code === 'invalid_settings'
					? `The server rejected these settings: ${err.message}`
					: describeError(err);
		} finally {
			busy = false;
		}
	}
</script>

<form class="card" onsubmit={save} oninput={() => (saved = false)} novalidate>
	<h2>Groups</h2>
	<p class="muted">
		Groups let people who are doing this together meet, and find allies among themselves. Joining a
		group shares nothing about anyone's computer. There is no limit on how big a group can be.
	</p>

	{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}

	<label class="check">
		<input type="checkbox" bind:checked={draft.enabled} />
		<span>
			Groups are on
			<span class="hint">
				Turning this off hides groups. Existing groups become read-only and unlisted. Alliances are
				never affected.
			</span>
		</span>
	</label>

	<div class="field">
		<label for="g-create">Who can start a group</label>
		<select id="g-create" bind:value={draft.who_can_create}>
			<option value="anyone">Anyone with an account</option>
			<option value="admins">Admins only</option>
		</select>
	</div>

	<div class="field">
		<label for="g-list">Who can list a group in the directory</label>
		<select id="g-list" bind:value={draft.who_can_list}>
			<option value="facilitators">Facilitators</option>
			<option value="admins">Admins only (a facilitator asks, an admin lists)</option>
			<option value="nobody">Nobody (no directory)</option>
		</select>
	</div>

	<div class="field">
		<label for="g-invite">Who can invite people into a group</label>
		<select id="g-invite" bind:value={draft.who_can_invite}>
			<option value="facilitators">Facilitators</option>
			<option value="participants">Any participant</option>
		</select>
		<span class="hint">A facilitator can narrow this for their own group, never widen it.</span>
	</div>

	<label class="check">
		<input type="checkbox" bind:checked={draft.invites_create_accounts} />
		<span>
			Group invitations can create accounts
			<span class="hint">
				When registration is invite-only, whether an invitation to a group lets a new email address
				sign up, as an ally invitation does.
			</span>
		</span>
	</label>

	<div class="field">
		<label for="g-max">Most groups one person can be in</label>
		<input
			id="g-max"
			type="number"
			min="1"
			max={MAX_PER_USER}
			step="1"
			bind:value={draft.max_groups_per_user}
			aria-invalid={limitValid ? undefined : 'true'}
		/>
		{#if !limitValid}
			<span class="field-error">Use a whole number from 1 to {MAX_PER_USER}.</span>
		{/if}
	</div>

	<div class="actions">
		<button class="primary" type="submit" disabled={busy || !limitValid}>
			{busy ? 'Saving…' : 'Save group settings'}
		</button>
		{#if saved}<span class="saved" role="status"><Icon name="check" /> Saved</span>{/if}
	</div>
</form>

<style>
	/* A checkbox row gets the same room below it as a field. */
	.check {
		margin-bottom: 1.1rem;
	}
</style>
