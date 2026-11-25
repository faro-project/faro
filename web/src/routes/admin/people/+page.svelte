<script lang="ts">
	// Accounts on this instance (metadata only), member invitations,
	// disabling or re-enabling accounts, and granting or revoking the admin
	// role. GET /admin/api/users never includes who is anyone's ally,
	// devices' names or anything a member's devices sent.
	//
	// Admins are users like everyone else: any account but your own can be
	// disabled, and the server always emails the person and every
	// accountability partner. Any account but your own can be made an admin
	// or stop being one, and the server always emails the person and every
	// other admin (ARCHITECTURE.md §4.3). Any account but your own can be
	// deleted, disabled or not, with the same 7-day hold and emails as when
	// the person asks (§12); the person or any admin can cancel. The admin
	// log lists role changes and deletions.

	import { onMount } from 'svelte';
	import { api, ApiError, describeError } from '#lib/api.ts';
	import { ago, count, date, dateTime } from '#lib/format.ts';
	import { saveReturnTo } from '#lib/return-to.ts';
	import { session } from '#lib/session.svelte.ts';
	import type {
		AdminLogAccount,
		AdminLogEntry,
		AdminRole,
		AdminUserRow,
		DeletionCancelled,
		DeletionRequested,
		InstanceSettings,
		InviteCreated,
		MagicLinkResponse
	} from '#lib/types.ts';

	/** Must match `REAUTH_WINDOW_MS` and `HOLD_MS` in server/src/api/account.rs. */
	const REAUTH_MS = 10 * 60 * 1000;
	const HOLD_MS = 7 * 24 * 3600 * 1000;

	let users = $state<AdminUserRow[] | null>(null);
	let settings = $state<InstanceSettings | null>(null);
	let adminLog = $state<AdminLogEntry[] | null>(null);
	let logError = $state('');
	let loadError = $state('');

	let query = $state('');
	let role = $state<'all' | 'member' | 'ally' | 'admin' | 'disabled'>('all');

	let inviteEmail = $state('');
	let inviteBusy = $state(false);
	let inviteError = $state('');
	let invited = $state<InviteCreated[]>([]);

	// Disable / re-enable, grant / revoke the admin role, and delete an
	// account or cancel that, confirmed in a dialog.
	type Change = 'disable' | 'enable' | 'grant' | 'revoke' | 'delete' | 'cancel-deletion';
	let dialog = $state<HTMLDialogElement | null>(null);
	let pending = $state<{ user: AdminUserRow; change: Change } | null>(null);
	let statusBusy = $state(false);
	let statusError = $state('');
	let statusDone = $state('');

	// Deleting needs a sign-in within the last 10 minutes and the address
	// typed out, as when people delete their own account.
	let confirmEmail = $state('');
	let fieldError = $state('');
	let linkSentAt = $state(0);
	let now = $state(Date.now());
	let fresh = $derived(session.startedAt > 0 && now - session.startedAt < REAUTH_MS);

	$effect(() => {
		const t = setInterval(() => (now = Date.now()), 15_000);
		return () => clearInterval(t);
	});

	/** After signing in again in another tab, this one learns it on focus. */
	function recheck() {
		now = Date.now();
		if (!fresh && linkSentAt) void session.refresh().catch(() => {});
	}

	function confirmChange(user: AdminUserRow, change: Change) {
		pending = { user, change };
		statusError = '';
		fieldError = '';
		confirmEmail = '';
		now = Date.now();
		dialog?.showModal();
	}

	async function confirmItsYou() {
		if (!session.user) return;
		statusError = '';
		statusBusy = true;
		try {
			saveReturnTo('admin-people');
			await api.post<MagicLinkResponse>('/v1/auth/magic-link', { email: session.user.email });
			linkSentAt = Date.now();
		} catch (e) {
			statusError = describeError(e);
		} finally {
			statusBusy = false;
		}
	}

	async function deleteAccount(user: AdminUserRow): Promise<boolean> {
		if (confirmEmail.trim().toLowerCase() !== user.email) {
			fieldError = `Type ${user.email} exactly.`;
			return false;
		}
		const r = await api.delete<DeletionRequested>(
			`/admin/api/users/${encodeURIComponent(user.id)}`,
			{ confirm_email: confirmEmail.trim() }
		);
		const purge = r.deletion.purge_after_ms;
		if (users) {
			users = users.map((u) =>
				u.id === user.id ? { ...u, deletion_purge_after_ms: purge, deletion_by_admin: true } : u
			);
		}
		const name = user.display_name;
		statusDone = `${name}'s account will be deleted on ${date(purge)}. Faro is emailing ${name}, their accountability partners and every admin. Until then, ${name} or any admin can cancel.`;
		await loadLog();
		return true;
	}

	async function cancelDeletion(user: AdminUserRow) {
		await api.post<DeletionCancelled>(
			`/admin/api/users/${encodeURIComponent(user.id)}/deletion/cancel`,
			{}
		);
		if (users) {
			users = users.map((u) =>
				u.id === user.id ? { ...u, deletion_purge_after_ms: null, deletion_by_admin: false } : u
			);
		}
		const name = user.display_name;
		statusDone = `${name}'s account will not be deleted. Faro is emailing ${name}, their accountability partners and every admin.`;
		await loadLog();
	}

	function closeDialog() {
		dialog?.close();
		pending = null;
	}

	async function changeStatus(user: AdminUserRow, disable: boolean) {
		await api.post(
			`/admin/api/users/${encodeURIComponent(user.id)}/${disable ? 'disable' : 'enable'}`
		);
		if (users) {
			users = users.map((u) => (u.id === user.id ? { ...u, disabled: disable } : u));
		}
		statusDone = disable
			? `${user.display_name}'s account was disabled. Faro is emailing ${user.display_name} and their accountability partners.`
			: `${user.display_name}'s account was re-enabled. Faro is emailing ${user.display_name} and their accountability partners.`;
	}

	async function changeAdmin(user: AdminUserRow, admin: boolean) {
		await api.put<AdminRole>(`/admin/api/users/${encodeURIComponent(user.id)}/admin`, { admin });
		if (users) {
			users = users.map((u) => (u.id === user.id ? { ...u, roles: { ...u.roles, admin } } : u));
		}
		const name = user.display_name;
		// A disabled person isn't emailed.
		const told = user.disabled ? 'every other admin' : `${name} and every other admin`;
		statusDone = admin
			? `${name} is now an admin. Faro is emailing ${told}.`
			: `${name} is no longer an admin. Faro is emailing ${told}.`;
		await loadLog();
	}

	async function applyChange() {
		if (!pending) return;
		const { user, change } = pending;
		statusBusy = true;
		statusError = '';
		try {
			if (change === 'disable' || change === 'enable') {
				await changeStatus(user, change === 'disable');
			} else if (change === 'grant' || change === 'revoke') {
				await changeAdmin(user, change === 'grant');
			} else if (change === 'delete') {
				if (!(await deleteAccount(user))) return;
			} else {
				await cancelDeletion(user);
			}
			closeDialog();
		} catch (e) {
			if (
				e instanceof ApiError &&
				[
					'already_disabled',
					'not_disabled',
					'already_admin',
					'not_admin',
					'already_deleting',
					'not_deleting'
				].includes(e.code)
			) {
				// Someone else got there first: show the current state.
				closeDialog();
				await load();
			} else if (e instanceof ApiError && e.code === 'reauth_required') {
				// The clocks disagree; ask the server again.
				await session.refresh().catch(() => {});
				statusError = "Your sign-in is more than 10 minutes old. Confirm it's you first.";
			} else if (e instanceof ApiError && e.code === 'confirmation_mismatch') {
				fieldError = `Type ${user.email} exactly.`;
			} else if (e instanceof ApiError && e.code === 'cannot_delete_self') {
				statusError = 'To delete your own account, use Delete your account in Settings.';
			} else if (e instanceof ApiError && e.code === 'not_admin_deletion') {
				statusError = `${user.display_name} asked for this deletion themself, so only they can cancel it.`;
			} else if (e instanceof ApiError && e.code === 'deletion_in_progress') {
				statusError = 'The deletion has started and can no longer be cancelled.';
			} else if (e instanceof ApiError && e.code === 'cannot_disable_self') {
				statusError = 'You cannot disable your own account. Ask another admin.';
			} else if (e instanceof ApiError && e.code === 'cannot_change_own_role') {
				statusError = 'You cannot change your own admin role. Ask another admin.';
			} else if (e instanceof ApiError && e.code === 'last_admin') {
				statusError = 'The instance must keep at least one enabled admin.';
			} else if (e instanceof ApiError && e.code === 'account_disabled') {
				statusError = `${user.display_name}'s account is disabled. Re-enable it first.`;
			} else if (e instanceof ApiError && e.code === 'account_deleting') {
				statusError = `${user.display_name}'s account is being deleted, so it can't be changed now.`;
			} else {
				statusError = describeError(e);
			}
		} finally {
			statusBusy = false;
		}
	}

	async function load() {
		loadError = '';
		try {
			[users, settings] = await Promise.all([
				api.get<AdminUserRow[]>('/admin/api/users'),
				api.get<InstanceSettings>('/admin/api/settings')
			]);
		} catch (e) {
			loadError = describeError(e);
		}
		await loadLog();
	}

	async function loadLog() {
		logError = '';
		try {
			adminLog = await api.get<AdminLogEntry[]>('/admin/api/log');
		} catch (e) {
			logError = describeError(e);
		}
	}

	/** Who made an admin log change, as the start of a sentence. */
	function actorOf(e: AdminLogEntry): string {
		if (e.via === 'command_line') return 'Someone on the server';
		if (!e.actor) return 'A deleted account';
		return e.actor.id === session.user?.id ? 'You' : e.actor.display_name;
	}

	function nameOf(a: AdminLogAccount | null): string {
		if (!a) return 'a deleted account';
		return a.id === session.user?.id ? 'you' : a.display_name;
	}

	/** The account a deletion entry is about, as the end of a sentence. */
	function accountOf(e: AdminLogEntry): string {
		if (!e.user) return 'an account that has since been deleted';
		if (e.user.id === session.user?.id) return 'your account';
		if (e.actor?.id === e.user.id) return 'their account';
		return `${e.user.display_name}'s account`;
	}

	onMount(load);

	async function invite(e: SubmitEvent) {
		e.preventDefault();
		inviteError = '';
		const email = inviteEmail.trim();
		if (!/^[^\s@]+@[^\s@]+$/.test(email)) {
			inviteError = 'Enter an email address.';
			return;
		}
		inviteBusy = true;
		try {
			const created = await api.post<InviteCreated>('/admin/api/invites', { email });
			invited = [created, ...invited.filter((i) => i.email !== created.email)];
			inviteEmail = '';
		} catch (err) {
			if (err instanceof ApiError && err.code === 'already_member') {
				inviteError = `${email} already has a member account.`;
			} else if (err instanceof ApiError && err.code === 'too_many_invites') {
				inviteError =
					'You have 20 invitations waiting to be accepted. Wait until some are accepted or expire (after 7 days).';
			} else if (err instanceof ApiError && err.code === 'invalid_email') {
				inviteError = 'The server could not read this email address.';
			} else {
				inviteError = describeError(err);
			}
		} finally {
			inviteBusy = false;
		}
	}

	let shown = $derived.by(() => {
		if (!users) return [];
		const q = query.trim().toLowerCase();
		return users
			.filter((u) => {
				if (role === 'disabled') return u.disabled;
				if (role !== 'all' && !u.roles[role]) return false;
				return true;
			})
			.filter(
				(u) => !q || u.email.toLowerCase().includes(q) || u.display_name.toLowerCase().includes(q)
			)
			.sort((a, b) => a.display_name.localeCompare(b.display_name));
	});

	function rolesOf(u: AdminUserRow): string[] {
		return (['admin', 'member', 'ally'] as const).filter((r) => u.roles[r]);
	}
</script>

<svelte:window onfocus={recheck} />

<svelte:head>
	<title>People · Admin · Faro</title>
</svelte:head>

<h1>People</h1>

<form class="card invite" onsubmit={invite} novalidate>
	<h2>Invite a member</h2>
	<p class="muted">
		They get an email invitation, valid for 7 days, and join by signing in with that address.
		Members invite their own allies.
	</p>
	{#if settings?.registration.mode === 'closed'}
		<div class="notice warn">
			<p>
				<span aria-hidden="true">⚠</span> Registration is closed, so someone without an account can't
				accept an invitation until you change it in Settings.
			</p>
		</div>
	{/if}
	<div class="invite-row">
		<label class="visually-hidden" for="invite-email">Email address to invite</label>
		<input
			id="invite-email"
			type="email"
			placeholder="name@example.org"
			bind:value={inviteEmail}
			autocomplete="off"
			aria-invalid={inviteError ? 'true' : undefined}
			aria-describedby={inviteError ? 'invite-error' : undefined}
		/>
		<button class="primary" type="submit" disabled={inviteBusy}>
			{inviteBusy ? 'Sending…' : 'Send invitation'}
		</button>
	</div>
	{#if inviteError}
		<span class="field-error" id="invite-error">{inviteError}</span>
	{/if}
	{#if invited.length}
		<ul class="sent" aria-live="polite">
			{#each invited as i (i.email)}
				<li>
					<span aria-hidden="true">✓</span> Invitation sent to <strong>{i.email}</strong>, valid
					until
					{date(i.expires_at_ms)}.
				</li>
			{/each}
		</ul>
	{/if}
</form>

<section aria-labelledby="accounts">
	<div class="list-head">
		<h2 id="accounts">Accounts{users ? ` (${count(users.length)})` : ''}</h2>
		<div class="filters">
			<label class="visually-hidden" for="people-search">Search by name or email</label>
			<input id="people-search" type="search" placeholder="Search" bind:value={query} />
			<label class="visually-hidden" for="people-role">Show</label>
			<select id="people-role" bind:value={role}>
				<option value="all">Everyone</option>
				<option value="member">Members</option>
				<option value="ally">Allies</option>
				<option value="admin">Admins</option>
				<option value="disabled">Disabled</option>
			</select>
		</div>
	</div>

	{#if statusDone}
		<div class="notice ok" role="status"><p>✓ {statusDone}</p></div>
	{/if}
	{#if loadError}
		<div class="notice error" role="alert">{loadError}</div>
		<button class="secondary" type="button" onclick={load}>Try again</button>
	{:else if !users}
		<p class="muted" role="status">Loading…</p>
	{:else if shown.length === 0}
		<p class="muted">No accounts match.</p>
	{:else}
		<ul class="people">
			<li class="head" aria-hidden="true">
				<span>Name</span><span>Roles</span><span>Signed in</span><span>Computers</span><span></span>
			</li>
			{#each shown as u (u.id)}
				<li class:disabled={u.disabled}>
					<span class="who">
						<strong>{u.display_name}</strong>
						<span class="email">{u.email}</span>
					</span>
					<span class="roles">
						<span class="label">Roles</span>
						{#each rolesOf(u) as r (r)}<span class="chip">{r}</span>{/each}
						{#if u.disabled}<span class="chip off">disabled</span>{/if}
						{#if u.deletion_purge_after_ms}
							<span
								class="chip off"
								title={u.deletion_by_admin
									? 'An admin asked for this account to be deleted'
									: 'The person asked for their account to be deleted'}
							>
								being deleted {date(u.deletion_purge_after_ms)}
							</span>
							<span class="asked">
								{u.deletion_by_admin ? 'asked by an admin' : 'asked by the person'}
							</span>
						{/if}
					</span>
					<span class="when">
						<span class="label">Signed in</span>
						{#if u.last_login_at_ms}
							<span title={dateTime(u.last_login_at_ms)}>{ago(u.last_login_at_ms)}</span>
						{:else}
							<span class="muted">never</span>
						{/if}
						<span class="joined">joined {date(u.created_at_ms)}</span>
					</span>
					<span class="devices">
						<span class="label">Computers</span>
						{#if u.device_count === 0}
							<span class="muted">none</span>
						{:else}
							{count(u.device_count)}
							{#if u.devices_last_seen_at_ms}
								<span class="seen" title={dateTime(u.devices_last_seen_at_ms)}>
									checked in {ago(u.devices_last_seen_at_ms)}
								</span>
							{:else}
								<span class="seen">never checked in</span>
							{/if}
						{/if}
					</span>
					<span class="action">
						{#if u.id === session.user?.id}
							<span class="chip">you</span>
						{:else if u.deletion_purge_after_ms}
							<!-- The server refuses other changes meanwhile. A deletion the
							     person asked for is theirs to cancel. -->
							{#if u.deletion_by_admin}
								<button
									class="secondary small"
									type="button"
									onclick={() => confirmChange(u, 'cancel-deletion')}
								>
									Cancel deletion…
								</button>
							{/if}
						{:else}
							{#if u.disabled}
								<button
									class="secondary small"
									type="button"
									onclick={() => confirmChange(u, 'enable')}
								>
									Enable…
								</button>
							{:else}
								<button
									class="secondary small"
									type="button"
									onclick={() => confirmChange(u, 'disable')}
								>
									Disable…
								</button>
							{/if}
							{#if u.roles.admin}
								<button
									class="secondary small"
									type="button"
									onclick={() => confirmChange(u, 'revoke')}
								>
									Remove admin…
								</button>
							{:else if !u.disabled}
								<button
									class="secondary small"
									type="button"
									onclick={() => confirmChange(u, 'grant')}
								>
									Make admin…
								</button>
							{/if}
							<button
								class="secondary small"
								type="button"
								onclick={() => confirmChange(u, 'delete')}
							>
								Delete…
							</button>
						{/if}
					</span>
				</li>
			{/each}
		</ul>
	{/if}
</section>

<section class="log" aria-labelledby="admin-log">
	<h2 id="admin-log">Admin log</h2>
	<p class="muted">
		Every time someone is made an admin or stops being one, every deletion an admin asks for, and
		every account created from the command line. Faro emails the admins about each one. Entries are
		never removed, but a deleted account's name is taken out of them.
	</p>
	{#if logError}
		<div class="notice error" role="alert">{logError}</div>
	{:else if !adminLog}
		<p class="muted" role="status">Loading…</p>
	{:else if adminLog.length === 0}
		<p class="muted">Nothing yet.</p>
	{:else}
		<ul class="entries">
			{#each adminLog as e (e.id)}
				<li>
					<span class="at" title={dateTime(e.at_ms)}>{date(e.at_ms)}</span>
					<span>
						<strong title={e.actor?.email}>{actorOf(e)}</strong>
						{#if e.action === 'admin_granted'}
							made <strong title={e.user?.email}>{nameOf(e.user)}</strong> an admin
						{:else if e.action === 'admin_revoked'}
							removed the admin role from <strong title={e.user?.email}>{nameOf(e.user)}</strong>
						{:else if e.action === 'deletion_requested'}
							asked to delete <strong title={e.user?.email}>{accountOf(e)}</strong>
						{:else if e.action === 'account_created'}
							created <strong title={e.user?.email}>{accountOf(e)}</strong>
						{:else}
							cancelled the deletion of <strong title={e.user?.email}>{accountOf(e)}</strong>
						{/if}
						{#if e.via === 'command_line'}
							<span class="muted">(from the command line)</span>
						{/if}
					</span>
				</li>
			{/each}
		</ul>
	{/if}
</section>

<dialog bind:this={dialog} onclose={() => (pending = null)} aria-labelledby="status-title">
	{#if pending}
		{@const name = pending.user.display_name}
		{#if pending.change === 'grant'}
			<h2 id="status-title">Make {name} an admin?</h2>
			<p>
				{name} ({pending.user.email}) will be able to change this instance's settings, invite
				people, disable accounts and make other people admins.
			</p>
			<p>Faro will email {name} and every other admin right away.</p>
			<p class="muted">
				Being an admin gives no access to anyone's reports, alerts or screenshots.
			</p>
		{:else if pending.change === 'revoke'}
			<h2 id="status-title">Remove {name}'s admin role?</h2>
			<p>
				{name} ({pending.user.email}) won't be able to use the admin console any more. They can
				still sign in, and nothing else about their account changes.
			</p>
			<p>Faro will email {name} and every other admin right away.</p>
		{:else if pending.change === 'disable'}
			<h2 id="status-title">Disable {name}'s account?</h2>
			<p>
				{name} ({pending.user.email}) won't be able to sign in, and is signed out everywhere now.
			</p>
			<p>
				Faro will email {name} and everyone in an accountability partnership with them right away: their
				allies, and the members they are an ally for, with those members' other allies. These emails can't
				be switched off.
			</p>
			<p class="muted">
				Disabling doesn't stop monitoring: {name}'s computers keep reporting and alerting their
				allies.
			</p>
		{:else if pending.change === 'enable'}
			<h2 id="status-title">Re-enable {name}'s account?</h2>
			<p>
				{name} ({pending.user.email}) will be able to sign in again. Faro will email {name} and their
				accountability partners.
			</p>
		{:else if pending.change === 'delete'}
			<h2 id="status-title">Delete {name}'s account?</h2>
			<p>
				Faro will email {name} ({pending.user.email}) and everyone in an accountability partnership
				with them right away: their allies, and the members they are an ally for, with those
				members' other allies. The emails say the account is being deleted by the instance
				administrator, and they can't be switched off. Every admin is emailed too.
			</p>
			<p>
				Nothing changes for 7 days: {name}'s computers are still monitored and their allies still
				get alerts. Until {date(now + HOLD_MS)}, {name} or any admin can cancel.
				{#if pending.user.disabled}
					{name}'s account is disabled, so they can't sign in to cancel. The email tells them to
					contact you.
				{/if}
			</p>
			<p>
				Then everything this server stores about {name} is permanently deleted: their computers, activity,
				alerts, reports, keys, allies and settings. Copies in backups last until the backups are rotated
				out.
			</p>
			{#if !fresh}
				<p>
					To delete an account, first confirm it's you: Faro emails a sign-in link to
					<strong>{session.user?.email}</strong>.
				</p>
				{#if linkSentAt}
					<div class="notice info" role="status">
						<p>Check your email and open the link. It brings you back to this page.</p>
					</div>
				{/if}
			{:else}
				<div class="field">
					<label for="delete-confirm">Type {pending.user.email} to confirm</label>
					<input
						id="delete-confirm"
						type="email"
						autocomplete="off"
						placeholder={pending.user.email}
						bind:value={confirmEmail}
						aria-invalid={fieldError ? 'true' : undefined}
						aria-describedby={fieldError ? 'delete-confirm-error' : undefined}
					/>
					{#if fieldError}
						<span class="field-error" id="delete-confirm-error">{fieldError}</span>
					{/if}
				</div>
			{/if}
		{:else}
			<h2 id="status-title">Cancel the deletion of {name}'s account?</h2>
			<p>
				Nothing will be deleted. Faro will email {name} ({pending.user.email}), everyone in an
				accountability partnership with them, and every admin.
			</p>
		{/if}
		{#if statusError}
			<div class="notice error" role="alert">{statusError}</div>
		{/if}
		<div class="actions">
			{#if pending.change === 'delete' && !fresh}
				<button class="primary" type="button" onclick={confirmItsYou} disabled={statusBusy}>
					{statusBusy ? 'Sending…' : linkSentAt ? 'Send another link' : "Confirm it's you"}
				</button>
			{:else}
				<button
					class={['disable', 'revoke', 'delete'].includes(pending.change) ? 'danger' : 'primary'}
					type="button"
					onclick={applyChange}
					disabled={statusBusy || (pending.change === 'delete' && !confirmEmail.trim())}
				>
					{#if statusBusy}
						Saving…
					{:else if pending.change === 'disable'}
						Disable account
					{:else if pending.change === 'enable'}
						Re-enable account
					{:else if pending.change === 'grant'}
						Make admin
					{:else if pending.change === 'revoke'}
						Remove admin role
					{:else if pending.change === 'delete'}
						Delete account
					{:else}
						Cancel deletion
					{/if}
				</button>
			{/if}
			<button class="secondary" type="button" onclick={closeDialog}>
				{pending.change === 'cancel-deletion' ? 'Back' : 'Cancel'}
			</button>
		</div>
	{/if}
</dialog>

<style>
	.invite {
		margin-bottom: 2rem;
	}

	.invite-row {
		display: flex;
		gap: 0.6rem;
		flex-wrap: wrap;
	}

	.invite-row input {
		flex: 1 1 14rem;
		width: auto;
	}

	.sent {
		list-style: none;
		padding: 0;
		margin: 1rem 0 0;
		color: var(--ok);
	}

	.list-head {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: 0.75rem;
		margin-bottom: 0.75rem;
	}

	.list-head h2 {
		margin: 0;
	}

	.filters {
		display: flex;
		gap: 0.5rem;
		flex: 1 1 16rem;
		max-width: 24rem;
	}

	.filters input {
		flex: 1;
		min-width: 0;
	}

	select {
		font: inherit;
		color: var(--text);
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: 8px;
		padding: 0.55rem 0.6rem;
	}

	input[type='search'] {
		font: inherit;
		color: var(--text);
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: 8px;
		padding: 0.55rem 0.75rem;
	}

	.people {
		list-style: none;
		padding: 0;
		margin: 0;
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
	}

	.people li {
		display: grid;
		grid-template-columns:
			minmax(0, 2.2fr) minmax(0, 1.2fr) minmax(0, 1.3fr) minmax(0, 1.3fr)
			8.5rem;
		gap: 0.75rem;
		padding: 0.75rem 1rem;
		border-top: 1px solid var(--border);
		align-items: start;
	}

	.people li:first-child {
		border-top: none;
	}

	.people li.head {
		font-size: 0.8rem;
		font-weight: 600;
		color: var(--muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		padding-top: 0.6rem;
		padding-bottom: 0.6rem;
	}

	.people li.disabled .who {
		opacity: 0.65;
	}

	.who,
	.when,
	.devices {
		display: flex;
		flex-direction: column;
		min-width: 0;
	}

	.email,
	.joined,
	.seen {
		color: var(--muted);
		font-size: 0.88rem;
		overflow-wrap: anywhere;
	}

	.roles {
		display: flex;
		flex-wrap: wrap;
		gap: 0.3rem;
		align-items: center;
	}

	.chip {
		font-size: 0.78rem;
		font-weight: 600;
		padding: 0.1rem 0.5rem;
		border-radius: 999px;
		background: var(--surface-2);
		border: 1px solid var(--border);
	}

	.chip.off {
		color: var(--danger);
		border-color: color-mix(in srgb, var(--danger) 35%, transparent);
	}

	.asked {
		color: var(--muted);
		font-size: 0.8rem;
	}

	.label {
		display: none;
	}

	.action {
		display: flex;
		flex-direction: column;
		align-items: flex-end;
		gap: 0.35rem;
	}

	.log {
		margin-top: 2rem;
	}

	.entries {
		list-style: none;
		padding: 0;
		margin: 0;
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
	}

	.entries li {
		display: flex;
		flex-wrap: wrap;
		gap: 0 0.75rem;
		padding: 0.6rem 1rem;
		border-top: 1px solid var(--border);
		overflow-wrap: anywhere;
	}

	.entries li:first-child {
		border-top: none;
	}

	.entries .at {
		color: var(--muted);
		font-size: 0.88rem;
		min-width: 6.5rem;
	}

	dialog h2 {
		font-size: 1.15rem;
	}

	@media (max-width: 640px) {
		.people li.head {
			display: none;
		}

		.people li {
			grid-template-columns: 1fr;
			gap: 0.35rem;
		}

		.people li:nth-child(2) {
			border-top: none;
		}

		.label {
			display: inline;
			color: var(--muted);
			font-size: 0.85rem;
			margin-right: 0.35rem;
		}

		.action {
			flex-direction: row;
			flex-wrap: wrap;
			align-items: flex-start;
			margin-top: 0.25rem;
		}

		.when,
		.devices {
			flex-direction: row;
			flex-wrap: wrap;
			gap: 0 0.4rem;
			align-items: baseline;
		}
	}
</style>
