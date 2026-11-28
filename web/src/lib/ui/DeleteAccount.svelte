<script lang="ts">
	// The settings card for deleting your own account (ARCHITECTURE.md §12):
	// what happens, who is told, and the confirmation the server requires (a
	// sign-in within the last 10 minutes, and the account's address typed
	// out). Nothing is removed for 7 days; the banner at the top of every
	// page offers to cancel until then.
	import { api, ApiError, describeError } from '../api.ts';
	import { date, plural } from '../format.ts';
	import { saveReturnTo } from '../return-to.ts';
	import { session } from '../session.svelte.ts';
	import type {
		DeletionRequested,
		MagicLinkResponse,
		MyAllies,
		SupportedMember,
		User
	} from '../types.ts';

	let { user }: { user: User } = $props();

	/** Must match `REAUTH_WINDOW_MS` and `HOLD_MS` in server/src/api/account.rs. */
	const REAUTH_MS = 10 * 60 * 1000;
	const HOLD_MS = 7 * 24 * 3600 * 1000;

	let allies = $state<string[] | null>(null);
	let members = $state<string[] | null>(null);
	let now = $state(Date.now());
	let confirmEmail = $state('');
	let fieldError = $state('');
	let error = $state('');
	let busy = $state(false);
	let linkSentAt = $state(0);
	let told = $state<DeletionRequested['told'] | null>(null);
	let loadedFor = '';

	$effect(() => {
		const t = setInterval(() => (now = Date.now()), 15_000);
		return () => clearInterval(t);
	});

	$effect(() => {
		if (user.id === loadedFor) return;
		loadedFor = user.id;
		if (user.roles.member) {
			api
				.get<MyAllies>('/v1/me/allies')
				.then(
					(m) => (allies = m.allies.filter((a) => a.state === 'active').map((a) => a.display_name))
				)
				.catch(() => (allies = []));
		}
		if (user.roles.ally) {
			api
				.get<SupportedMember[]>('/v1/ally/members')
				.then((ms) => (members = ms.filter((m) => m.state === 'active').map((m) => m.display_name)))
				.catch(() => (members = []));
		}
	});

	let fresh = $derived(session.startedAt > 0 && now - session.startedAt < REAUTH_MS);

	/** "pat", "pat and lee", "pat, lee and kim". */
	function names(list: string[]): string {
		if (list.length <= 1) return list.join('');
		return `${list.slice(0, -1).join(', ')} and ${list[list.length - 1]}`;
	}

	/** After signing in again in another tab, this one learns it on focus. */
	function recheck() {
		if (!fresh && linkSentAt) void session.refresh().catch(() => {});
	}

	async function confirmItsYou() {
		error = '';
		busy = true;
		try {
			saveReturnTo('delete-account');
			await api.post<MagicLinkResponse>('/v1/auth/magic-link', { email: user.email });
			linkSentAt = Date.now();
		} catch (e) {
			error = describeError(e);
		} finally {
			busy = false;
		}
	}

	async function deleteAccount(e: SubmitEvent) {
		e.preventDefault();
		error = '';
		fieldError = '';
		if (confirmEmail.trim().toLowerCase() !== user.email) {
			fieldError = "This isn't your account's email address.";
			return;
		}
		busy = true;
		try {
			const r = await api.delete<DeletionRequested>('/v1/me', {
				confirm_email: confirmEmail.trim()
			});
			told = r.told;
			confirmEmail = '';
			await session.refresh();
		} catch (err) {
			if (err instanceof ApiError && err.code === 'reauth_required') {
				// The clocks disagree; ask the server again.
				await session.refresh().catch(() => {});
				error = "Your sign-in is more than 10 minutes old. Confirm it's you first.";
			} else if (err instanceof ApiError && err.code === 'confirmation_mismatch') {
				fieldError = "This isn't your account's email address.";
			} else if (err instanceof ApiError && err.code === 'last_admin') {
				error =
					"You're the only admin of this instance, so your account can't be deleted. Make someone else an admin first, under Admin → People.";
			} else {
				error = describeError(err);
			}
		} finally {
			busy = false;
		}
	}
</script>

<svelte:window onfocus={recheck} />

<section class="card danger-zone" id="delete-account" aria-labelledby="delete-account-title">
	<h2 id="delete-account-title">Delete your account</h2>
	{#if session.deletion}
		<p>
			Your account will be deleted on <strong>{date(session.deletion.purge_after_ms)}</strong>.
			{#if session.deletion.by_admin}
				The instance administrator asked for this. If you don't know why, ask them.
			{/if}
			{#if told}
				{#if told.allies || told.members}
					{[
						told.allies && `${plural(told.allies, 'ally', 'allies')} of yours`,
						told.members && `${plural(told.members, 'person', 'people')} you support`
					]
						.filter(Boolean)
						.join(' and ')} have been told, with their other allies.
				{:else}
					You have been sent an email about it.
				{/if}
			{/if}
		</p>
		<p class="muted">
			Until then nothing changes, and you can cancel with the button at the top of the page.
		</p>
	{:else}
		<p>Deleting your account:</p>
		<ul class="effects">
			{#if user.roles.member}
				<li>
					<strong>Tells your allies now</strong>{allies?.length ? `: ${names(allies)}` : ''}. They
					get an email they can't switch off.
				</li>
				<li>
					<strong>Changes nothing for 7 days.</strong> Your computers are still monitored, your allies
					still get alerts and can open your reports, and you can still sign in and cancel.
				</li>
				<li>
					<strong>Then permanently deletes everything</strong> this server stores about you: your computers,
					activity, alerts, reports, keys, allies and settings. From then on this server refuses your
					computers, so uninstall Faro from them.
				</li>
			{/if}
			{#if user.roles.ally}
				<li>
					<strong>Tells {members?.length ? names(members) : 'the people you support'} now</strong>,
					and their other allies. After 7 days you stop being their ally, and your ally key,
					notification settings and account are deleted.
				</li>
			{/if}
			{#if !user.roles.member && !user.roles.ally}
				<li>Permanently deletes your account after 7 days. You can cancel until then.</li>
			{/if}
		</ul>
		<p class="muted small">
			While it waits, you can't invite allies, add computers or approve new ones. After {date(
				now + HOLD_MS
			)} you can create a new account with this address, if this server allows it. Copies in this server's
			backups last until the operator's backups are rotated out.
		</p>

		{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
		{#if !fresh}
			<p>
				To delete your account, first confirm it's you: Faro emails a sign-in link to
				<strong>{user.email}</strong>.
			</p>
			{#if linkSentAt}
				<div class="notice info" role="status">
					<p>Check your email and open the link. It brings you back here.</p>
				</div>
			{/if}
			<div class="actions">
				<button class="secondary" type="button" onclick={confirmItsYou} disabled={busy}>
					{busy ? 'Sending…' : linkSentAt ? 'Send another link' : "Confirm it's you"}
				</button>
			</div>
		{:else}
			<form onsubmit={deleteAccount} novalidate>
				<div class="field">
					<label for="delete-confirm">Type your email address to confirm</label>
					<input
						id="delete-confirm"
						type="email"
						autocomplete="off"
						placeholder={user.email}
						bind:value={confirmEmail}
						aria-invalid={fieldError ? 'true' : undefined}
						aria-describedby={fieldError ? 'delete-confirm-error' : undefined}
					/>
					{#if fieldError}
						<span class="field-error" id="delete-confirm-error">{fieldError}</span>
					{/if}
				</div>
				<div class="actions">
					<button class="danger" type="submit" disabled={busy || !confirmEmail.trim()}>
						{busy ? 'Deleting…' : 'Delete my account'}
					</button>
				</div>
			</form>
		{/if}
	{/if}
</section>

<style>
	.danger-zone {
		border-color: color-mix(in srgb, var(--danger) 40%, var(--border));
	}

	.danger-zone h2 {
		color: var(--danger);
	}

	.effects li + li {
		margin-top: 0.4rem;
	}
</style>
