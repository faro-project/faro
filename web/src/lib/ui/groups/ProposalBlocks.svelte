<script lang="ts">
	// "Don't let them send me proposals" (GROUPS.md §7.6), the other half: the
	// people you stopped, with a way to let them again. Stopping someone is
	// private and works in every group. Shown on Settings.
	import { api, seg } from '#lib/api.ts';
	import { date } from '#lib/format.ts';
	import { groupError } from '#lib/groups-api.ts';
	import type { ProposalBlock } from '#lib/types.ts';

	let blocks = $state<ProposalBlock[] | null>(null);
	let error = $state('');
	let busyId = $state('');

	async function load() {
		error = '';
		try {
			blocks = await api.get<ProposalBlock[]>('/v1/me/proposal-blocks');
		} catch (e) {
			error = groupError(e);
		}
	}

	$effect(() => {
		void load();
	});

	async function unblock(b: ProposalBlock) {
		busyId = b.user_id;
		error = '';
		try {
			await api.delete(`/v1/me/proposal-blocks/${seg(b.user_id)}`);
			blocks = (blocks ?? []).filter((x) => x.user_id !== b.user_id);
		} catch (e) {
			error = groupError(e);
		} finally {
			busyId = '';
		}
	}
</script>

{#if blocks === null && !error}
	<p class="muted" role="status">Loading…</p>
{:else if blocks && blocks.length === 0}
	<p class="muted">You haven't stopped anyone from sending you proposals.</p>
{:else if blocks}
	<ul class="rows">
		{#each blocks as b (b.user_id)}
			<li>
				<div class="row-main">
					<div>
						<div class="row-title"><strong>{b.display_name}</strong></div>
						<div class="row-meta">Since {date(b.created_at_ms)}</div>
					</div>
					<button
						class="secondary small"
						type="button"
						disabled={busyId === b.user_id}
						onclick={() => unblock(b)}
					>
						Let them send proposals again
					</button>
				</div>
			</li>
		{/each}
	</ul>
{/if}
{#if error}
	<div class="notice error" role="alert"><p>{error}</p></div>
	<button class="secondary small" type="button" onclick={load}>Try again</button>
{/if}
