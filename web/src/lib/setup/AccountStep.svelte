<script lang="ts">
	import { api, ApiError, describeError } from '#lib/api.ts';
	import type { SetupRequest, SetupResponse, User } from '#lib/types.ts';

	let {
		oncreated,
		onalreadysetup
	}: {
		oncreated: (user: User) => void;
		onalreadysetup: () => void;
	} = $props();

	let token = $state('');
	let email = $state('');
	let displayName = $state('');
	let busy = $state(false);
	let formError = $state('');
	let fieldErrors = $state<{ token?: string; email?: string; displayName?: string }>({});

	// Setup tokens are 32 random bytes, base64url without padding.
	const TOKEN_SHAPE = /^[A-Za-z0-9_-]{43}$/;

	function validate(): boolean {
		const errs: typeof fieldErrors = {};
		const t = token.trim();
		if (!t) errs.token = 'Paste the setup token from the server log.';
		else if (!TOKEN_SHAPE.test(t))
			errs.token = 'A setup token is 43 letters, digits, - and _. Check that you copied all of it.';
		if (!/^[^\s@]+@[^\s@]+$/.test(email.trim())) errs.email = 'Enter an email address.';
		const n = displayName.trim();
		if (!n) errs.displayName = 'Enter your name.';
		else if ([...n].length > 64) errs.displayName = 'Use 64 characters or fewer.';
		fieldErrors = errs;
		return Object.keys(errs).length === 0;
	}

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		formError = '';
		if (!validate()) return;
		busy = true;
		try {
			const body: SetupRequest = {
				setup_token: token.trim(),
				email: email.trim(),
				display_name: displayName.trim()
			};
			const res = await api.post<SetupResponse>('/v1/setup', body);
			token = '';
			oncreated(res.user);
		} catch (err) {
			if (err instanceof ApiError) {
				switch (err.code) {
					case 'invalid_setup_token':
						fieldErrors = {
							token:
								'This token was not accepted. It may be mistyped, already used, or more than 24 hours old. Run faro-server init on the server for a new one.'
						};
						return;
					case 'invalid_email':
						fieldErrors = { email: 'The server could not read this email address.' };
						return;
					case 'invalid_display_name':
						fieldErrors = { displayName: 'Use 1 to 64 characters.' };
						return;
					case 'email_in_use':
						fieldErrors = { email: 'An account with this email already exists.' };
						return;
					case 'already_set_up':
						onalreadysetup();
						return;
				}
			}
			formError = describeError(err);
		} finally {
			busy = false;
		}
	}
</script>

<form class="card" onsubmit={submit} novalidate>
	<h2>Create the admin account</h2>
	<p class="muted">
		The admin runs this instance: settings, email and invitations. Being admin gives no access to
		anyone's reports; those are encrypted for each member's allies only.
	</p>

	{#if formError}
		<div class="notice error" role="alert">{formError}</div>
	{/if}

	<div class="field">
		<label for="setup-token">
			Setup token
			<span class="hint">
				Printed in the server log when Faro first starts. Run <code>faro-server init</code> for a fresh
				one.
			</span>
		</label>
		<input
			id="setup-token"
			type="text"
			class="mono"
			bind:value={token}
			autocomplete="off"
			autocapitalize="off"
			spellcheck="false"
			aria-invalid={fieldErrors.token ? 'true' : undefined}
			aria-describedby={fieldErrors.token ? 'setup-token-error' : undefined}
		/>
		{#if fieldErrors.token}
			<span class="field-error" id="setup-token-error">{fieldErrors.token}</span>
		{/if}
	</div>

	<div class="field">
		<label for="admin-email">
			Your email address
			<span class="hint">Sign-in links and alerts about the instance go here.</span>
		</label>
		<input
			id="admin-email"
			type="email"
			bind:value={email}
			autocomplete="email"
			aria-invalid={fieldErrors.email ? 'true' : undefined}
			aria-describedby={fieldErrors.email ? 'admin-email-error' : undefined}
		/>
		{#if fieldErrors.email}
			<span class="field-error" id="admin-email-error">{fieldErrors.email}</span>
		{/if}
	</div>

	<div class="field">
		<label for="admin-name">Your name</label>
		<input
			id="admin-name"
			type="text"
			bind:value={displayName}
			autocomplete="name"
			maxlength="64"
			aria-invalid={fieldErrors.displayName ? 'true' : undefined}
			aria-describedby={fieldErrors.displayName ? 'admin-name-error' : undefined}
		/>
		{#if fieldErrors.displayName}
			<span class="field-error" id="admin-name-error">{fieldErrors.displayName}</span>
		{/if}
	</div>

	<div class="actions">
		<button class="primary" type="submit" disabled={busy}>
			{busy ? 'Creating account…' : 'Create admin account'}
		</button>
	</div>
</form>

<style>
	.mono {
		font-family: var(--mono);
	}
</style>
