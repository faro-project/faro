<script lang="ts">
	// Email check: shows whether SMTP is configured and sends a test message
	// to the signed-in admin (POST /admin/api/smtp-test). Used by the setup
	// wizard (with `onnext`) and the admin console's Email page.

	import { api, describeError } from '#lib/api.ts';
	import type { Overview, SmtpTestResult } from '#lib/types.ts';

	let {
		overview,
		adminEmail,
		onrefresh,
		onnext
	}: {
		overview: Overview;
		adminEmail: string;
		onrefresh: () => Promise<void>;
		/** The wizard's next step; without it there are no Continue/Skip buttons. */
		onnext?: () => void;
	} = $props();

	let busy = $state(false);
	let result = $state<SmtpTestResult | null>(null);
	let error = $state('');

	// The codes `POST /admin/api/smtp-test` returns (docs/SELF-HOSTING.md §7).
	const FIXES: Record<string, string> = {
		not_configured:
			'No mail server is set. Fill in FARO_SMTP_HOST and FARO_SMTP_FROM, then restart Faro.',
		rejected:
			'The mail server refused. Usually a wrong username or password (Google needs an app password), or a From address you may not send as.',
		connection:
			'Faro could not connect. Check the host name and port; some hosting providers block mail ports.',
		tls: 'Encryption failed. Port 587 goes with starttls, port 465 with tls.',
		timeout: 'The mail server did not answer in time: a wrong port, or a firewall.',
		temporary_rejection: 'The mail server said to try later. Wait a little and try again.',
		recipient_rejected: 'Your own address was refused. Check the admin account’s email address.',
		recipient_deferred: 'Your own address was postponed. Try again later.',
		invalid_address:
			'An address could not be read. Check FARO_SMTP_FROM, e.g. Faro <faro@example.org>.'
	};

	async function sendTest() {
		busy = true;
		error = '';
		result = null;
		try {
			result = await api.post<SmtpTestResult>('/admin/api/smtp-test');
		} catch (e) {
			error = describeError(e);
		} finally {
			busy = false;
		}
	}

	async function checkAgain() {
		busy = true;
		error = '';
		result = null;
		try {
			await onrefresh();
		} catch (e) {
			error = describeError(e);
		} finally {
			busy = false;
		}
	}
</script>

<section class="card">
	<h2>Check email</h2>
	<p class="muted">
		Faro sends sign-in links, invitations and alerts by email. Without working email you cannot sign
		in again once this session ends (after 30 days, or if you sign out).
	</p>

	{#if error}
		<div class="notice error" role="alert">{error}</div>
	{/if}

	{#if overview.smtp_configured}
		<p>Send a test message to <strong>{adminEmail}</strong> to check the mail settings.</p>

		{#if result?.ok}
			<div class="notice ok" role="status">
				<p>
					The test email was handed to your mail provider. Check the inbox (and the spam folder) of {result.sent_to}.
				</p>
			</div>
		{:else if result}
			<div class="notice error" role="alert">
				<p>
					<strong>The test email was not sent.</strong>
					{#if result.error}Error code: <code>{result.error}</code>{/if}
				</p>
				<p>
					{FIXES[result.error ?? ''] ?? 'See docs/SELF-HOSTING.md §7 for what this means.'} After changing
					the settings, restart Faro and test again.
				</p>
			</div>
		{/if}

		<div class="actions">
			<button
				class={result?.ok ? 'secondary' : 'primary'}
				type="button"
				onclick={sendTest}
				disabled={busy}
			>
				{busy ? 'Sending…' : result ? 'Send another test' : 'Send test email'}
			</button>
			{#if onnext && result?.ok}
				<button class="primary" type="button" onclick={onnext}>Continue</button>
			{:else if onnext}
				<button class="link" type="button" onclick={onnext}>Skip for now</button>
			{/if}
		</div>
	{:else}
		<div class="notice warn">
			<p><strong>No mail server is set up yet.</strong></p>
			<p>
				Set <code>FARO_SMTP_HOST</code>, <code>FARO_SMTP_PORT</code>, <code>FARO_SMTP_TLS</code>,
				<code>FARO_SMTP_USERNAME</code>, <code>FARO_SMTP_PASSWORD</code> and
				<code>FARO_SMTP_FROM</code> (or the <code>[smtp]</code> section of <code>faro.toml</code>),
				then restart Faro. Section 7 of docs/SELF-HOSTING.md lists the settings for common
				providers.
			</p>
		</div>
		<div class="actions">
			<button class="primary" type="button" onclick={checkAgain} disabled={busy}>
				{busy ? 'Checking…' : 'Check again'}
			</button>
			{#if onnext}
				<button class="link" type="button" onclick={onnext}>Skip for now</button>
			{/if}
		</div>
	{/if}
</section>
