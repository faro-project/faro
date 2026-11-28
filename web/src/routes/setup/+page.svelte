<script lang="ts">
	// First-run setup wizard (docs/ARCHITECTURE.md §7 "Instance admin").
	//
	// 1. Admin account: the one-time setup token from the server log, plus
	//    email and name (POST /v1/setup, which also signs the admin in).
	// 2. Email: send a test message (POST /admin/api/smtp-test).
	// 3. Registration mode and retention (PATCH /admin/api/settings).
	//
	// The instance name and the SMTP server itself live in faro.toml or
	// FARO_* variables, so the wizard shows and tests them but cannot set them.

	import { onMount } from 'svelte';
	import { resolve } from '$app/paths';
	import BrandMark from '#lib/ui/BrandMark.svelte';
	import Icon from '#lib/ui/Icon.svelte';
	import { api, describeError } from '#lib/api.ts';
	import { branding } from '#lib/branding.svelte.ts';
	import { session } from '#lib/session.svelte.ts';
	import AccountStep from '#lib/setup/AccountStep.svelte';
	import EmailCheck from '#lib/admin/EmailCheck.svelte';
	import SettingsForm from '#lib/admin/SettingsForm.svelte';
	import type { InstanceSettings, Overview, SetupStatus, User } from '#lib/types.ts';

	type Step = 'loading' | 'unreachable' | 'already' | 'account' | 'email' | 'policy' | 'done';

	let step = $state<Step>('loading');
	let loadError = $state('');
	let admin = $state<User | null>(null);
	let overview = $state<Overview | null>(null);

	const STEPS: { id: Step; label: string }[] = [
		{ id: 'account', label: 'Admin account' },
		{ id: 'email', label: 'Email' },
		{ id: 'policy', label: 'Registration and retention' }
	];
	let stepIndex = $derived(step === 'done' ? STEPS.length : STEPS.findIndex((s) => s.id === step));

	async function load() {
		step = 'loading';
		loadError = '';
		try {
			const status = await api.get<SetupStatus>('/v1/setup');
			if (status.needs_setup) {
				step = 'account';
				return;
			}
			// Already set up. If this browser is the admin's (for example after
			// a reload mid-wizard), offer the remaining steps.
			const user = await session.refresh();
			admin = user?.roles.admin ? user : null;
			step = 'already';
		} catch (e) {
			loadError = describeError(e);
			step = 'unreachable';
		}
	}

	async function loadOverview() {
		overview = await api.get<Overview>('/admin/api/overview');
	}

	async function goToEmail() {
		try {
			await loadOverview();
			step = 'email';
		} catch (e) {
			loadError = describeError(e);
			step = 'unreachable';
		}
	}

	function onCreated(user: User) {
		admin = user;
		session.signedIn(user);
		void goToEmail();
	}

	function onSettingsSaved(s: InstanceSettings) {
		if (overview) overview.settings = s;
		step = 'done';
	}

	onMount(() => {
		void load();
		void branding.load().catch(() => {});
	});
</script>

<svelte:head>
	<title>Set up Faro</title>
</svelte:head>

<div class="brand-mark">
	<BrandMark size="large" logo={branding.info?.logo} name={branding.info?.instance_name} />
</div>

<h1>Set up this Faro instance</h1>
{#if overview}
	<p class="muted">
		Instance “{overview.instance_name}” · faro-server {overview.server_version}
	</p>
{/if}

{#if stepIndex >= 0}
	<ol class="progress" aria-label="Setup steps">
		{#each STEPS as s, i (s.id)}
			<li
				class:current={i === stepIndex}
				class:complete={i < stepIndex}
				aria-current={i === stepIndex ? 'step' : undefined}
			>
				<span class="num" aria-hidden="true">
					{#if i < stepIndex}<Icon name="check" />{:else}0{i + 1}{/if}
				</span>
				<span>{s.label}</span>
			</li>
		{/each}
	</ol>
{/if}

{#if step === 'loading'}
	<p class="muted" role="status">Checking the instance…</p>
{:else if step === 'unreachable'}
	<div class="notice error" role="alert">
		<p>{loadError}</p>
	</div>
	<button class="secondary" type="button" onclick={load}>Try again</button>
{:else if step === 'already'}
	<section class="card">
		<h2>This instance is already set up</h2>
		{#if admin}
			<p>
				You are signed in as <strong>{admin.email}</strong>, the admin. You can go through the email
				and registration steps again.
			</p>
			<div class="actions">
				<button class="primary" type="button" onclick={goToEmail}>Review email and settings</button>
			</div>
		{:else if session.user}
			<p>
				It has an admin account, so the setup token no longer works. You are signed in as
				<strong>{session.user.email}</strong>, which is not the admin.
			</p>
		{:else}
			<p>
				It has an admin account, so the setup token no longer works. If you are the admin, sign in
				to review the email and registration settings.
			</p>
			<div class="actions">
				<a class="button primary" href={resolve('/signin')}>Sign in</a>
			</div>
		{/if}
	</section>
{:else if step === 'account'}
	<AccountStep oncreated={onCreated} onalreadysetup={load} />
{:else if step === 'email' && overview && admin}
	<EmailCheck
		{overview}
		adminEmail={admin.email}
		onrefresh={loadOverview}
		onnext={() => (step = 'policy')}
	/>
{:else if step === 'policy' && overview}
	<SettingsForm
		settings={overview.settings}
		onsaved={onSettingsSaved}
		submitLabel="Save and continue"
		onskip={() => (step = 'done')}
		skipLabel="Keep the defaults"
	/>
{:else if step === 'done' && overview}
	<section class="card">
		<h2>Your instance is ready</h2>
		<ul class="summary">
			<li>
				Admin: <strong>{admin?.email}</strong>
			</li>
			<li>
				Email: {overview.smtp_configured ? 'mail server configured' : 'not configured yet'}
			</li>
			<li>
				Registration: <strong>{overview.settings.registration.mode}</strong>
				{#if overview.settings.registration.mode === 'open'}
					({overview.settings.registration.allowed_email_domains.join(', ')})
				{/if}
			</li>
			<li>
				Retention: activity log {overview.settings.retention.event_header_days} days, reports and details
				{overview.settings.retention.blob_days} days, alerts
				{overview.settings.retention.alert_days} days
			</li>
		</ul>
		<h3>Next</h3>
		<p>
			Run <code>faro-server doctor</code> on the server to check the whole configuration. Then invite
			members from the admin console.
		</p>
		<div class="actions">
			<a class="button primary" href={resolve('/admin/people')}>Invite people</a>
			<a class="button secondary" href={resolve('/admin')}>Admin console</a>
		</div>
	</section>
{/if}

<style>
	.brand-mark {
		display: flex;
		justify-content: center;
		margin: 0.25rem 0 2rem;
	}

	.progress {
		list-style: none;
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 0.5rem;
		padding: 0;
		margin: 1.25rem 0 1.5rem;
		color: var(--muted);
		font-family: var(--mono);
		font-size: 0.78rem;
	}

	.progress li {
		display: flex;
		align-items: baseline;
		gap: 0.5rem;
		padding-top: 0.55rem;
		border-top: 2px solid var(--border);
		line-height: 1.35;
	}

	.num {
		font-weight: 600;
		font-variant-numeric: tabular-nums;
		flex: none;
	}

	.progress li.current {
		color: var(--text);
		font-weight: 500;
		border-top-color: var(--brand);
	}

	.progress li.current .num,
	.progress li.complete .num {
		color: var(--accent);
	}

	.progress li.complete {
		border-top-color: color-mix(in srgb, var(--brand) 45%, var(--border));
	}

	.summary {
		padding-left: 1.2rem;
		margin: 0 0 1.25rem;
	}

	.summary li {
		margin-bottom: 0.3rem;
	}

	h3 {
		margin-top: 1.25rem;
	}

	@media (max-width: 480px) {
		.progress {
			grid-template-columns: 1fr;
		}
	}
</style>
