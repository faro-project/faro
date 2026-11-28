<script lang="ts">
	// Instance settings an admin may change (PATCH /admin/api/settings):
	// registration, retention and, optionally, the liveness grace period and
	// the update channel.
	// Used by the setup wizard and the admin console's Settings page.
	//
	// Only fields that differ from what is in effect are sent, so untouched
	// settings keep following faro.toml / FARO_* variables.

	import { onMount } from 'svelte';
	import { api, ApiError, describeError } from '#lib/api.ts';
	import type {
		InstanceSettings,
		RegistrationMode,
		SettingsPatch,
		UpdatesInfo
	} from '#lib/types.ts';
	import Icon from '#lib/ui/Icon.svelte';

	let {
		settings,
		onsaved,
		heading = 'Who can join, and how long data is kept',
		submitLabel = 'Save',
		showLiveness = false,
		showUpdates = false,
		onskip,
		skipLabel = 'Skip'
	}: {
		settings: InstanceSettings;
		onsaved: (s: InstanceSettings) => void;
		heading?: string;
		submitLabel?: string;
		showLiveness?: boolean;
		showUpdates?: boolean;
		onskip?: () => void;
		skipLabel?: string;
	} = $props();

	const MAX_DAYS = 3650;
	/** Server floor for retention set here (settings.rs): the same as a member's own minimum. */
	const MIN_DAYS = 7;
	/** Server limits (config.rs, settings.rs): 10 minutes to 7 days. */
	const MIN_GRACE_SECS = 600;
	const MAX_GRACE_SECS = 7 * 24 * 3600;

	// The settings in effect, and editable copies. Re-seeded after each save.
	// svelte-ignore state_referenced_locally
	const seed = structuredClone($state.snapshot(settings));
	let baseline = $state(seed);
	let mode = $state<RegistrationMode>(seed.registration.mode);
	let domains = $state(seed.registration.allowed_email_domains.join(', '));
	let eventDays = $state(seed.retention.event_header_days);
	let blobDays = $state(seed.retention.blob_days);
	let alertDays = $state(seed.retention.alert_days);
	let graceHours = $state(secsToHours(seed.liveness.grace_secs));
	let channel = $state(seed.updates.channel);
	/** Whether the mirror has a release to serve; null until known. */
	let updatesAvailable = $state<boolean | null>(null);
	let busy = $state(false);
	let error = $state('');
	let saved = $state(false);

	const MODES: { value: RegistrationMode; label: string; hint: string }[] = [
		{
			value: 'invite-only',
			label: 'Invite only',
			hint: 'You invite each member by email. Best for most churches and small groups.'
		},
		{
			value: 'open',
			label: 'Open to an email domain',
			hint: 'Anyone with an address at the domains you list can sign up, for example a college.'
		},
		{
			value: 'closed',
			label: 'Closed',
			hint: 'No new accounts. People who already have one can still sign in.'
		}
	];

	const CHANNELS: { value: string; label: string; hint: string }[] = [
		{
			value: 'stable',
			label: 'Stable',
			hint: 'Each new release, once the Faro project marks it stable. Best for most instances.'
		},
		{
			value: 'stable-1',
			label: 'One release behind',
			hint:
				'The newest release of the previous version, for managed computers (a college lab, say) ' +
				'that wait until a release has been out for a while. Computers already on a newer ' +
				'release keep it.'
		},
		{
			value: 'beta',
			label: 'Beta',
			hint: 'Releases before they are marked stable. Only for people who want to test them.'
		}
	];
	// A channel set in faro.toml that isn't one of the above stays selectable.
	let channels = $derived(
		CHANNELS.some((c) => c.value === baseline.updates.channel)
			? CHANNELS
			: [
					...CHANNELS,
					{
						value: baseline.updates.channel,
						label: baseline.updates.channel,
						hint: 'Set in faro.toml or FARO_UPDATES_CHANNEL.'
					}
				]
	);

	onMount(async () => {
		if (!showUpdates) return;
		try {
			updatesAvailable = (await api.get<UpdatesInfo>('/v1/updates')).available;
		} catch {
			updatesAvailable = null;
		}
	});

	function secsToHours(s: number): number {
		return Math.round((s / 3600) * 100) / 100;
	}

	function parseDomains(s: string): string[] {
		return s
			.split(/[\s,]+/)
			.map((d) => d.trim().replace(/^@/, '').toLowerCase())
			.filter(Boolean);
	}

	function sameList(a: string[], b: string[]) {
		return a.length === b.length && a.every((x, i) => x === b[i]);
	}

	function validDays(n: number) {
		return Number.isInteger(n) && n >= MIN_DAYS && n <= MAX_DAYS;
	}

	let parsedDomains = $derived(parseDomains(domains));
	let daysValid = $derived(validDays(eventDays) && validDays(blobDays) && validDays(alertDays));
	let domainsMissing = $derived(mode === 'open' && parsedDomains.length === 0);
	let graceSecs = $derived(Math.round(Number(graceHours) * 3600));
	let graceValid = $derived(
		!showLiveness ||
			(Number.isFinite(graceSecs) && graceSecs >= MIN_GRACE_SECS && graceSecs <= MAX_GRACE_SECS)
	);
	let valid = $derived(!domainsMissing && daysValid && graceValid);

	function buildPatch(): SettingsPatch {
		const patch: SettingsPatch = {};
		if (mode !== baseline.registration.mode) patch.registration_mode = mode;
		if (!sameList(parsedDomains, baseline.registration.allowed_email_domains)) {
			patch.allowed_email_domains = parsedDomains;
		}
		const r: NonNullable<SettingsPatch['retention']> = {};
		if (eventDays !== baseline.retention.event_header_days) r.event_header_days = eventDays;
		if (blobDays !== baseline.retention.blob_days) r.blob_days = blobDays;
		if (alertDays !== baseline.retention.alert_days) r.alert_days = alertDays;
		if (Object.keys(r).length) patch.retention = r;
		// Compare in the unit shown, so an untouched 2.5 h stays untouched.
		if (showLiveness && Number(graceHours) !== secsToHours(baseline.liveness.grace_secs)) {
			patch.liveness_grace_secs = graceSecs;
		}
		if (showUpdates && channel !== baseline.updates.channel) patch.update_channel = channel;
		return patch;
	}

	async function save(e: SubmitEvent) {
		e.preventDefault();
		error = '';
		saved = false;
		if (!valid) return;
		const patch = buildPatch();
		if (Object.keys(patch).length === 0) {
			saved = true;
			onsaved(baseline);
			return;
		}
		busy = true;
		try {
			const next = await api.patch<InstanceSettings>('/admin/api/settings', patch);
			baseline = next;
			domains = next.registration.allowed_email_domains.join(', ');
			graceHours = secsToHours(next.liveness.grace_secs);
			channel = next.updates.channel;
			saved = true;
			onsaved(next);
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
	<h2>{heading}</h2>
	<p class="muted">
		Settings saved here take priority over faro.toml and FARO_* variables from then on.
	</p>

	{#if error}
		<div class="notice error" role="alert">{error}</div>
	{/if}

	<fieldset>
		<legend>Registration</legend>
		{#each MODES as m (m.value)}
			<label class="choice">
				<input type="radio" name="registration" value={m.value} bind:group={mode} />
				<span>
					{m.label}
					<span class="hint">{m.hint}</span>
				</span>
			</label>
			{#if m.value === 'open' && mode === 'open'}
				<div class="field nested">
					<label for="domains">
						Allowed email domains
						<span class="hint">
							Separate with commas, e.g. <code>college.edu, staff.college.edu</code>. Use
							<code>*</code> for any domain.
						</span>
					</label>
					<input
						id="domains"
						type="text"
						bind:value={domains}
						autocapitalize="off"
						spellcheck="false"
						aria-invalid={domainsMissing ? 'true' : undefined}
					/>
					{#if domainsMissing}
						<span class="field-error">List at least one domain for open registration.</span>
					{/if}
				</div>
			{/if}
		{/each}
		<p class="hint">
			Unless registration is closed, people you invite can create an account with the invited
			address.
		</p>
	</fieldset>

	<fieldset>
		<legend>Retention (days, {MIN_DAYS} to {MAX_DAYS})</legend>
		<p class="hint">
			Members can choose shorter, never longer. The shortest you can set is {MIN_DAYS} days, so a flagged
			report is never gone before an ally can open it. A shorter period applies only to data received
			after you save: what is already stored keeps the period it arrived under. Saving a shorter period
			(or a longer missed check-in grace period) is written to the admin log, emailed to the other admins,
			and alerts every member's allies.
		</p>
		<div class="days">
			<div class="field">
				<label for="event-days">
					Activity log
					<span class="hint">What happened and when, without the details</span>
				</label>
				<input id="event-days" type="number" min={MIN_DAYS} max={MAX_DAYS} bind:value={eventDays} />
			</div>
			<div class="field">
				<label for="blob-days">
					Reports and details
					<span class="hint">Encrypted event details, reports and blurred images</span>
				</label>
				<input id="blob-days" type="number" min={MIN_DAYS} max={MAX_DAYS} bind:value={blobDays} />
			</div>
			<div class="field">
				<label for="alert-days">
					Alerts
					<span class="hint">Alerts and missed check-ins</span>
				</label>
				<input id="alert-days" type="number" min={MIN_DAYS} max={MAX_DAYS} bind:value={alertDays} />
			</div>
		</div>
		{#if !daysValid}
			<span class="field-error">
				Each value must be a whole number from {MIN_DAYS} to {MAX_DAYS}.
			</span>
		{/if}
	</fieldset>

	{#if showLiveness}
		<fieldset>
			<legend>Missed check-ins</legend>
			<div class="field">
				<label for="grace-hours">
					Grace period (hours)
					<span class="hint">
						How long a computer may stay silent before its member's allies are alerted. Computers
						check in every 5 minutes while on. Time this server was down never counts, and after a
						restart every computer gets a fresh grace period.
					</span>
				</label>
				<input
					id="grace-hours"
					type="number"
					min="0.17"
					max="168"
					step="any"
					bind:value={graceHours}
					aria-invalid={graceValid ? undefined : 'true'}
				/>
				{#if !graceValid}
					<span class="field-error">Use a value from 10 minutes (0.17) to 7 days (168).</span>
				{/if}
			</div>
		</fieldset>
	{/if}

	{#if showUpdates}
		<fieldset>
			<legend>Software updates</legend>
			<p class="hint">
				Computers get Faro updates through this server, which passes on releases signed by the Faro
				project. Each computer checks the project's signature itself, so this server can't change an
				update.
			</p>
			{#if updatesAvailable === false}
				<div class="notice" role="status">
					This server isn't passing on updates yet. Its administrator sets
					<code>updates.root</code> (and, unless the server is offline,
					<code>updates.upstream</code>) in faro.toml; <code>faro-server doctor</code> shows what is missing.
				</div>
			{/if}
			{#each channels as c (c.value)}
				<label class="choice">
					<input type="radio" name="update-channel" value={c.value} bind:group={channel} />
					<span>
						{c.label}
						<span class="hint">{c.hint}</span>
					</span>
				</label>
			{/each}
		</fieldset>
	{/if}

	<div class="actions">
		<button class="primary" type="submit" disabled={busy || !valid}>
			{busy ? 'Saving…' : submitLabel}
		</button>
		{#if onskip}
			<button class="link" type="button" onclick={onskip}>{skipLabel}</button>
		{/if}
		{#if saved}
			<span class="saved" role="status"><Icon name="check" /> Saved</span>
		{/if}
	</div>
</form>

<style>
	fieldset {
		margin-bottom: 1.5rem;
	}

	/* Each fieldset is a section of the form: a small letter-spaced label,
	 * quieter than the field labels inside it. */
	legend {
		font-size: 0.72rem;
		font-weight: 500;
		text-transform: uppercase;
		letter-spacing: 0.08em;
		color: var(--muted);
		margin-bottom: 0.5rem;
	}

	fieldset > .hint {
		margin: 0 0 0.85rem;
	}

	/* A radio and its option's name (interface, in the code face) with a
	 * sentence-long hint under it. */
	.choice {
		display: flex;
		gap: 0.6rem;
		align-items: flex-start;
		margin: 0;
		padding: 0.4rem 0;
		cursor: pointer;
	}

	.choice input {
		flex: none;
		margin-top: 0.2rem;
	}

	.nested {
		margin: 0.2rem 0 0.4rem 1.6rem;
	}

	.days {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr));
		gap: 0 1rem;
	}

	/* Line the inputs up even when the hints wrap differently. */
	.days .field {
		display: flex;
		flex-direction: column;
	}

	.days .field input {
		margin-top: auto;
	}
</style>
