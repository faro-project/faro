<script lang="ts">
	// How the viewer hears about one member (§5.4): per urgency, immediately,
	// in the hourly digest, or not at all, with optional quiet hours.
	// Tamper-class alerts (ARCHITECTURE.md §5.4) can't be switched off: with
	// "off" they still arrive in the digest, and the form says so.
	import { onMount } from 'svelte';
	import { api, describeError } from '../api.ts';
	import type { DeliveryMode, NotificationPrefs, QuietHours } from '../types.ts';

	let { memberId, about }: { memberId: string; about: string } = $props();

	let prefs = $state<NotificationPrefs | null>(null);
	let urgent = $state<DeliveryMode>('immediate');
	let normal = $state<DeliveryMode>('digest');
	let none = $state<DeliveryMode>('off');
	let quiet = $state(false);
	let quietStart = $state('22:00');
	let quietEnd = $state('07:00');
	let error = $state('');
	let saved = $state(false);
	let busy = $state(false);

	const MODES: { v: DeliveryMode; label: string }[] = [
		{ v: 'immediate', label: 'Right away' },
		{ v: 'digest', label: 'Hourly digest' },
		{ v: 'off', label: 'Off' }
	];

	const toTime = (min: number) =>
		`${String(Math.floor(min / 60)).padStart(2, '0')}:${String(min % 60).padStart(2, '0')}`;
	const toMin = (t: string) => {
		const [h, m] = t.split(':').map(Number);
		return (h || 0) * 60 + (m || 0);
	};

	function apply(p: NotificationPrefs) {
		prefs = p;
		urgent = p.urgent;
		normal = p.normal;
		none = p.none;
		quiet = !!p.quiet_hours;
		if (p.quiet_hours) {
			// Shown in the browser's own time zone.
			const shift = -new Date().getTimezoneOffset() - p.quiet_hours.tz_offset_min;
			quietStart = toTime((((p.quiet_hours.start_min + shift) % 1440) + 1440) % 1440);
			quietEnd = toTime((((p.quiet_hours.end_min + shift) % 1440) + 1440) % 1440);
		}
	}

	onMount(async () => {
		try {
			apply(
				await api.get<NotificationPrefs>(
					`/v1/me/notification-prefs?member_id=${encodeURIComponent(memberId)}`
				)
			);
		} catch (e) {
			error = describeError(e);
		}
	});

	async function save(e: SubmitEvent) {
		e.preventDefault();
		error = '';
		saved = false;
		busy = true;
		const quiet_hours: QuietHours | null = quiet
			? {
					start_min: toMin(quietStart),
					end_min: toMin(quietEnd),
					tz_offset_min: -new Date().getTimezoneOffset()
				}
			: null;
		try {
			apply(
				await api.put<NotificationPrefs>('/v1/me/notification-prefs', {
					member_id: memberId,
					urgent,
					normal,
					none,
					quiet_hours
				})
			);
			saved = true;
		} catch (err) {
			error = describeError(err);
		} finally {
			busy = false;
		}
	}
</script>

{#if error && !prefs}
	<div class="notice error" role="alert"><p>{error}</p></div>
{:else if !prefs}
	<p class="muted" role="status">Loading…</p>
{:else}
	<form onsubmit={save} novalidate>
		<fieldset>
			<legend class="visually-hidden">Email notifications about {about}</legend>
			{#each [{ id: 'urgent', label: 'Urgent', hint: 'Tamper, missed check-ins, high flags' }, { id: 'normal', label: 'Normal', hint: 'Medium flags, settings and ally changes' }, { id: 'none', label: 'Everything else', hint: 'Low-rated items' }] as row (row.id)}
				<div class="pref">
					<label for="pref-{row.id}-{memberId}">
						{row.label}
						<span class="hint">{row.hint}</span>
					</label>
					{#if row.id === 'urgent'}
						<select id="pref-urgent-{memberId}" bind:value={urgent}>
							{#each MODES as m (m.v)}<option value={m.v}>{m.label}</option>{/each}
						</select>
					{:else if row.id === 'normal'}
						<select id="pref-normal-{memberId}" bind:value={normal}>
							{#each MODES as m (m.v)}<option value={m.v}>{m.label}</option>{/each}
						</select>
					{:else}
						<select id="pref-none-{memberId}" bind:value={none}>
							{#each MODES as m (m.v)}<option value={m.v}>{m.label}</option>{/each}
						</select>
					{/if}
				</div>
			{/each}
		</fieldset>
		{#if urgent === 'off' || normal === 'off'}
			<p class="notice warn small">
				Some alerts can't be switched off: Faro being stopped, removed or interfered with, a
				computer that stops checking in or isn't sending what it records, missing or unverified
				records, a computer being removed, an ally being removed or leaving, and an account being
				disabled by an admin. With Off, they still arrive in the hourly digest.
			</p>
		{/if}
		<label class="check">
			<input type="checkbox" bind:checked={quiet} /> Quiet hours (hold emails until they end)
		</label>
		{#if quiet}
			<div class="quiet">
				<label for="q-start-{memberId}">From</label>
				<input id="q-start-{memberId}" type="time" bind:value={quietStart} />
				<label for="q-end-{memberId}">to</label>
				<input id="q-end-{memberId}" type="time" bind:value={quietEnd} />
			</div>
		{/if}
		{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
		<div class="actions">
			<button class="primary" type="submit" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
			{#if saved}<span class="saved" role="status">✓ Saved</span>{/if}
		</div>
	</form>
{/if}

<style>
	fieldset {
		border: none;
		padding: 0;
		margin: 0 0 0.75rem;
	}

	.pref {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 0.5rem 1rem;
		flex-wrap: wrap;
		padding: 0.55rem 0;
		border-bottom: 1px solid var(--border);
	}

	.pref label {
		margin: 0;
	}

	.quiet {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.5rem;
		margin-top: 0.6rem;
	}

	.quiet label {
		margin: 0;
		font-weight: 400;
	}

	.saved {
		color: var(--ok);
		font-weight: 600;
	}
</style>
