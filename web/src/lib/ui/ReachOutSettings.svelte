<script lang="ts">
	// How you hear about each person's reach outs (GROUPS.md §8.3, decision
	// 4): right away (the default), in the hourly digest, or not at all, and
	// whether they come through your quiet hours. People appear here once
	// you've changed something for them, for example "Let Sam's reach outs
	// through quiet hours" on a reach out on your home page. Reach outs
	// still show in Faro whatever you choose here.
	import {
		reachOutError,
		reachOutSettings,
		setQuietBypass,
		setReachOutMode
	} from '../reach-out-api.ts';
	import type { ReachOutMode, SenderSetting } from '../reach-out.ts';

	let rows = $state<SenderSetting[] | null>(null);
	let error = $state('');
	let busyId = $state('');

	async function load() {
		error = '';
		try {
			rows = await reachOutSettings();
		} catch (e) {
			error = reachOutError(e);
		}
	}

	$effect(() => {
		void load();
	});

	function update(id: string, change: Partial<SenderSetting>) {
		rows = (rows ?? []).map((r) => (r.user_id === id ? { ...r, ...change } : r));
	}

	async function bypass(r: SenderSetting, on: boolean) {
		busyId = r.user_id;
		error = '';
		try {
			await setQuietBypass(r.user_id, on);
			update(r.user_id, { quiet_hours_bypass: on });
		} catch (e) {
			error = reachOutError(e);
		} finally {
			busyId = '';
		}
	}

	async function mode(r: SenderSetting, m: ReachOutMode) {
		busyId = r.user_id;
		error = '';
		try {
			await setReachOutMode(r.user_id, m);
			update(r.user_id, { mode: m });
		} catch (e) {
			error = reachOutError(e);
		} finally {
			busyId = '';
		}
	}

	const MODES: { value: ReachOutMode; label: string }[] = [
		{ value: 'immediate', label: 'Right away' },
		{ value: 'digest', label: 'In the hourly digest' },
		{ value: 'off', label: 'Off (still shown in Faro)' }
	];
</script>

{#if rows === null && !error}
	<p class="muted" role="status">Loading…</p>
{:else if rows && rows.length === 0}
	<p class="muted">
		You haven't changed anything for anyone yet. When someone reaches out, you can let their reach
		outs through your quiet hours from the home page.
	</p>
{:else if rows}
	<ul class="rows">
		{#each rows as r (r.user_id)}
			<li>
				<div class="row-main">
					<div class="row-title"><strong>{r.display_name}</strong></div>
					<div class="controls">
						<label>
							<input
								type="checkbox"
								checked={r.quiet_hours_bypass}
								disabled={busyId === r.user_id}
								onchange={(e) => bypass(r, e.currentTarget.checked)}
							/>
							Let their reach outs through quiet hours
						</label>
						<label class="mode">
							<span class="visually-hidden">How you hear about {r.display_name}'s reach outs</span>
							<select
								value={r.mode}
								disabled={busyId === r.user_id}
								onchange={(e) => mode(r, e.currentTarget.value as ReachOutMode)}
							>
								{#each MODES as m (m.value)}
									<option value={m.value}>{m.label}</option>
								{/each}
							</select>
						</label>
					</div>
				</div>
			</li>
		{/each}
	</ul>
{/if}
{#if error}
	<div class="notice error" role="alert"><p>{error}</p></div>
	<button class="secondary small" type="button" onclick={load}>Try again</button>
{/if}

<style>
	.controls {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem 1rem;
		align-items: center;
	}
</style>
