<script lang="ts">
	// Instance branding (GET/PATCH /admin/api/branding, PUT/DELETE
	// /admin/api/branding/logo): a logo next to Faro's, and a few things to
	// show or hide. Everything here is plain text and shows only in page
	// chrome; see #lib/branding.ts.

	import { onMount } from 'svelte';
	import { api, ApiError, describeError } from '#lib/api.ts';
	import { branding } from '#lib/branding.svelte.ts';
	import BrandMark from '#lib/ui/BrandMark.svelte';
	import type { AdminBranding, BrandingPatch } from '#lib/types.ts';

	const MAX_BYTES = 1024 * 1024;
	const TYPES = ['image/png', 'image/jpeg', 'image/webp'];
	const MAX_CHARS = 200;

	let data = $state<AdminBranding | null>(null);
	let loadError = $state('');

	// Logo.
	let fileInput = $state<HTMLInputElement | null>(null);
	let file = $state<File | null>(null);
	let logoBusy = $state(false);
	let logoError = $state('');
	let logoDone = $state('');

	// Toggles and text.
	let showLogo = $state(true);
	let showName = $state(true);
	let welcomeEnabled = $state(false);
	let welcome = $state('');
	let supportEnabled = $state(false);
	let support = $state('');
	let busy = $state(false);
	let error = $state('');
	let saved = $state(false);

	function seed(b: AdminBranding) {
		data = b;
		showLogo = b.settings.show_logo;
		showName = b.settings.show_name;
		welcomeEnabled = b.settings.welcome_enabled;
		welcome = b.settings.welcome;
		supportEnabled = b.settings.support_enabled;
		support = b.settings.support;
	}

	async function load() {
		loadError = '';
		try {
			seed(await api.get<AdminBranding>('/admin/api/branding'));
		} catch (e) {
			loadError = describeError(e);
		}
	}

	onMount(load);

	function pick(e: Event) {
		logoError = '';
		logoDone = '';
		const f = (e.currentTarget as HTMLInputElement).files?.[0] ?? null;
		file = f;
		if (!f) return;
		if (!TYPES.includes(f.type)) {
			logoError = 'Choose a PNG, JPEG or WebP image. SVG files are not accepted.';
		} else if (f.size > MAX_BYTES) {
			logoError = 'This file is larger than 1 MB.';
		}
	}

	async function upload() {
		if (!file || logoError) return;
		logoBusy = true;
		logoError = '';
		logoDone = '';
		try {
			const replaced = !!data?.logo;
			seed(await api.putFile<AdminBranding>('/admin/api/branding/logo', file, file.type));
			logoDone = replaced ? 'Logo replaced.' : 'Logo uploaded.';
			file = null;
			if (fileInput) fileInput.value = '';
			await branding.reload();
		} catch (e) {
			logoError = e instanceof ApiError && e.status === 400 ? e.message : describeError(e);
		} finally {
			logoBusy = false;
		}
	}

	async function removeLogo() {
		logoBusy = true;
		logoError = '';
		logoDone = '';
		try {
			seed(await api.delete<AdminBranding>('/admin/api/branding/logo'));
			logoDone = 'Logo removed.';
			await branding.reload();
		} catch (e) {
			logoError = describeError(e);
		} finally {
			logoBusy = false;
		}
	}

	async function save(e: SubmitEvent) {
		e.preventDefault();
		error = '';
		saved = false;
		const patch: BrandingPatch = {
			show_logo: showLogo,
			show_name: showName,
			welcome_enabled: welcomeEnabled,
			welcome: welcome.trim(),
			support_enabled: supportEnabled,
			support: support.trim()
		};
		if (welcomeEnabled && !patch.welcome) {
			error = 'Write a welcome line, or turn it off.';
			return;
		}
		if (supportEnabled && !patch.support) {
			error = 'Enter a support contact, or turn it off.';
			return;
		}
		busy = true;
		try {
			seed(await api.patch<AdminBranding>('/admin/api/branding', patch));
			saved = true;
			await branding.reload();
		} catch (err) {
			error = err instanceof ApiError && err.status === 400 ? err.message : describeError(err);
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head>
	<title>Branding · Admin · Faro</title>
</svelte:head>

<h1>Branding</h1>
<p class="muted">
	Show your instance's logo next to Faro's, and choose what else to show. Faro's own logo always
	stays. Nothing here is shown in alerts, reports or safety codes, and nobody is notified when you
	change it.
</p>

{#if loadError}
	<div class="notice error" role="alert">{loadError}</div>
	<button class="secondary" type="button" onclick={load}>Try again</button>
{:else if !data}
	<p class="muted" role="status">Loading…</p>
{:else}
	<section class="card">
		<h2>Logo</h2>
		{#if data.logo}
			<div class="preview">
				<BrandMark size="large" logo={data.logo} name={data.instance_name} />
			</div>
			<p class="muted small">
				Stored at {data.logo.width} × {data.logo.height} pixels.
				{#if !showLogo}It is hidden: turn on "Show the logo" below.{/if}
			</p>
		{:else}
			<p class="muted">No logo yet.</p>
		{/if}
		<div class="field">
			<label for="logo-file">{data.logo ? 'Replace the logo' : 'Upload a logo'}</label>
			<input
				id="logo-file"
				type="file"
				accept="image/png,image/jpeg,image/webp"
				bind:this={fileInput}
				onchange={pick}
				aria-describedby="logo-hint"
			/>
			<span class="hint" id="logo-hint">
				PNG, JPEG or WebP, up to 1 MB and 4096 pixels on each side. SVG is not accepted. Faro makes
				its own copy, at most 512 pixels wide or high, without the file's metadata. Choose a logo
				that reads well on white: in the dark theme it is shown on a white background.
			</span>
		</div>
		{#if logoError}<p class="field-error" role="alert">{logoError}</p>{/if}
		{#if logoDone}<p class="ok-text" role="status">✓ {logoDone}</p>{/if}
		<div class="actions">
			<button
				class="primary"
				type="button"
				onclick={upload}
				disabled={logoBusy || !file || !!logoError}
			>
				{logoBusy ? 'Working…' : data.logo ? 'Replace logo' : 'Upload logo'}
			</button>
			{#if data.logo}
				<button class="secondary" type="button" onclick={removeLogo} disabled={logoBusy}>
					Remove logo
				</button>
			{/if}
		</div>
	</section>

	<form class="card" onsubmit={save} novalidate>
		<h2>What to show</h2>
		<p class="muted small">
			Text is shown exactly as you type it, as plain text, and labelled as coming from this
			instance's admins.
		</p>

		<label class="check">
			<input type="checkbox" bind:checked={showLogo} />
			<span>
				Show the logo next to Faro's
				<span class="hint">In the header and on the sign-in and setup pages.</span>
			</span>
		</label>

		<label class="check">
			<input type="checkbox" bind:checked={showName} />
			<span>
				Show the instance name in the header
				<span class="hint">“{data.instance_name}”, set in faro.toml.</span>
			</span>
		</label>

		<label class="check">
			<input type="checkbox" bind:checked={welcomeEnabled} />
			<span>
				Show a welcome line on the sign-in page
				<span class="hint">One line of plain text, up to {MAX_CHARS} characters.</span>
			</span>
		</label>
		<div class="field indent">
			<label class="visually-hidden" for="welcome">Welcome line</label>
			<input
				id="welcome"
				type="text"
				maxlength={MAX_CHARS}
				bind:value={welcome}
				placeholder="Welcome to the St. Mark's accountability group."
			/>
		</div>

		<label class="check">
			<input type="checkbox" bind:checked={supportEnabled} />
			<span>
				Show a support contact
				<span class="hint">
					In the footer and on the sign-in page. An email address or an https:// link.
				</span>
			</span>
		</label>
		<div class="field indent">
			<label class="visually-hidden" for="support">Support contact</label>
			<input
				id="support"
				type="text"
				maxlength={MAX_CHARS}
				bind:value={support}
				placeholder="help@example.org"
				autocomplete="off"
			/>
		</div>

		{#if error}<p class="field-error" role="alert">{error}</p>{/if}
		{#if saved}<p class="ok-text" role="status">✓ Saved.</p>{/if}
		<div class="actions">
			<button class="primary" type="submit" disabled={busy}>
				{busy ? 'Saving…' : 'Save'}
			</button>
		</div>
	</form>
{/if}

<style>
	.preview {
		display: flex;
		padding: 1rem;
		margin-bottom: 0.75rem;
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		background: var(--surface);
		overflow: hidden;
	}

	.check {
		margin-top: 1rem;
	}

	.indent {
		margin: 0.5rem 0 0 1.65rem;
	}

	.ok-text {
		color: var(--ok);
		margin: 0.5rem 0 0;
	}

	input[type='file'] {
		display: block;
		font: inherit;
		max-width: 100%;
	}
</style>
