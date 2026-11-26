<script lang="ts">
	// "What this group can see about me" (GROUPS.md §8.2): what you show the
	// group, all off by default. Two settings, each with how many people
	// would see it, so nobody shares with a big group by accident. Turning
	// one off hides it at once and tells nobody; the dot then reads "Not
	// shared", as if it had never been on. These change only what other
	// participants see: allies see what they always have.
	//
	// On the invitation page (before accepting, so `groupId` is null) the
	// choices are only kept in the page and handed to `onchange`; the page
	// saves them once the person has joined. On the group page each change
	// is saved straight away.
	import { api, seg } from '#lib/api.ts';
	import { audienceText } from '#lib/groups.ts';
	import { groupError } from '#lib/groups-api.ts';
	import type { MySharing } from '#lib/types.ts';

	let {
		groupId = null,
		audience,
		initial = { share_status: false, share_allies: false },
		readOnly = false,
		onchange
	}: {
		groupId?: string | null;
		/** People in the group now. */
		audience: number;
		initial?: MySharing;
		readOnly?: boolean;
		onchange?: (s: MySharing) => void;
	} = $props();

	// Seeded once: the pages mount this after the group has loaded.
	// svelte-ignore state_referenced_locally
	let status = $state(initial.share_status);
	// svelte-ignore state_referenced_locally
	let allies = $state(initial.share_allies);
	let busy = $state(false);
	let error = $state('');
	let saved = $state(false);

	async function change(next: MySharing) {
		const before = { share_status: status, share_allies: allies };
		status = next.share_status;
		allies = next.share_allies;
		saved = false;
		error = '';
		if (!groupId) {
			onchange?.(next);
			return;
		}
		busy = true;
		try {
			await api.put(`/v1/groups/${seg(groupId)}/me/sharing`, next);
			saved = true;
			onchange?.(next);
		} catch (e) {
			status = before.share_status;
			allies = before.share_allies;
			error = groupError(e);
		} finally {
			busy = false;
		}
	}
</script>

<section class="section" aria-labelledby="sharing-h-{groupId ?? 'invite'}">
	<h2 id="sharing-h-{groupId ?? 'invite'}">What this group can see about me</h2>
	<p class="muted">
		Nothing, unless you choose. You can change this at any time, and nobody is told when you do.
	</p>

	<div class="choice">
		<label>
			<input
				type="checkbox"
				checked={status}
				disabled={busy || readOnly}
				onchange={(e) => change({ share_status: e.currentTarget.checked, share_allies: allies })}
			/>
			<span>
				<strong>Show my status</strong>
				<span class="muted">
					A dot beside your name: Monitoring on, Paused, Not checked in or No computer yet. Never
					your reports, flags or anything about tampering.
				</span>
			</span>
		</label>
		<p class="audience small muted">{audienceText(audience)} would see this.</p>
	</div>

	<div class="choice">
		<label>
			<input
				type="checkbox"
				checked={allies}
				disabled={busy || readOnly}
				onchange={(e) => change({ share_status: status, share_allies: e.currentTarget.checked })}
			/>
			<span>
				<strong>Show my allies in this group</strong>
				<span class="muted">
					Which people in this group are your allies, and whose ally you are. Allies outside the
					group are never shown.
				</span>
			</span>
		</label>
		<p class="audience small muted">{audienceText(audience)} would see this.</p>
	</div>

	{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
	{#if saved}<p class="saved small" role="status">✓ Saved</p>{/if}
	<p class="muted small">
		This changes only what other people in the group see. Your allies keep seeing what they see
		today.
	</p>
</section>

<style>
	.choice {
		margin: 0.75rem 0;
	}
	label {
		display: flex;
		gap: 0.6rem;
		align-items: flex-start;
	}
	label span {
		display: flex;
		flex-direction: column;
		gap: 0.15rem;
	}
	.audience {
		margin: 0.2rem 0 0 1.7rem;
	}
</style>
