<script lang="ts">
	// Instance settings an admin may change (PATCH /admin/api/settings):
	// registration, retention and, optionally, the liveness grace period.
	// Used by the setup wizard and the admin console's Settings page.
	//
	// Only fields that differ from what is in effect are sent, so untouched
	// settings keep following faro.toml / FARO_* variables.

	import { api, ApiError, describeError } from '#lib/api.ts';
	import type { InstanceSettings, RegistrationMode, SettingsPatch } from '#lib/types.ts';

	let {
		settings,
		onsaved,
		heading = 'Who can join, and how long data is kept',
		submitLabel = 'Save',
		showLiveness = false,
		onskip,
		skipLabel = 'Skip'
	}: {
		settings: InstanceSettings;
		onsaved: (s: InstanceSettings) => void;
		heading?: string;
		submitLabel?: string;
		showLiveness?: boolean;
		onskip?: () => void;
		skipLabel?: string;
	} = $props();

	const MAX_DAYS = 3650;
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
		return Number.isInteger(n) && n >= 1 && n <= MAX_DAYS;
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
		<legend>Retention (days, 1 to {MAX_DAYS})</legend>
		<p class="hint">
			Members can choose shorter, never longer. A change applies to data received from then on; what
			is already stored keeps the period it arrived under.
		</p>
		<div class="days">
			<div class="field">
				<label for="event-days">
					Activity log
					<span class="hint">What happened and when, without the details</span>
				</label>
				<input id="event-days" type="number" min="1" max={MAX_DAYS} bind:value={eventDays} />
			</div>
			<div class="field">
				<label for="blob-days">
					Reports and details
					<span class="hint">Encrypted event details, reports and blurred images</span>
				</label>
				<input id="blob-days" type="number" min="1" max={MAX_DAYS} bind:value={blobDays} />
			</div>
			<div class="field">
				<label for="alert-days">
					Alerts
					<span class="hint">Alerts and missed check-ins</span>
				</label>
				<input id="alert-days" type="number" min="1" max={MAX_DAYS} bind:value={alertDays} />
			</div>
		</div>
		{#if !daysValid}
			<span class="field-error">Each value must be a whole number from 1 to {MAX_DAYS}.</span>
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

	<div class="actions">
		<button class="primary" type="submit" disabled={busy || !valid}>
			{busy ? 'Saving…' : submitLabel}
		</button>
		{#if onskip}
			<button class="link" type="button" onclick={onskip}>{skipLabel}</button>
		{/if}
		{#if saved}
			<span class="saved" role="status">✓ Saved</span>
		{/if}
	</div>
</form>

<style>
	fieldset {
		border: none;
		margin: 0 0 1.25rem;
		padding: 0;
	}

	legend {
		font-weight: 700;
		margin-bottom: 0.6rem;
		padding: 0;
	}

	fieldset > .hint {
		margin: 0.25rem 0 0.9rem;
	}

	.choice {
		display: flex;
		gap: 0.6rem;
		align-items: flex-start;
		font-weight: 600;
		padding: 0.55rem 0;
		cursor: pointer;
	}

	.choice input {
		margin-top: 0.3rem;
		accent-color: var(--accent);
	}

	.nested {
		margin: 0.25rem 0 0 1.6rem;
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

	.saved {
		color: var(--ok);
		font-weight: 600;
	}
</style>
