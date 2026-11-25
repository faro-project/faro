<script lang="ts">
	// Accounts on this instance (metadata only), member invitations, and
	// disabling or re-enabling accounts. GET /admin/api/users never includes
	// who is anyone's ally, devices' names or anything a member's devices
	// sent.
	//
	// Admins are users like everyone else: any account but your own can be
	// disabled, and the server always emails the person and every
	// accountability partner (ARCHITECTURE.md §4.3).

	import { onMount } from 'svelte';
	import { api, ApiError, describeError } from '#lib/api.ts';
	import { ago, count, date, dateTime } from '#lib/format.ts';
	import { session } from '#lib/session.svelte.ts';
	import type { AdminUserRow, InstanceSettings, InviteCreated } from '#lib/types.ts';

	let users = $state<AdminUserRow[] | null>(null);
	let settings = $state<InstanceSettings | null>(null);
	let loadError = $state('');

	let query = $state('');
	let role = $state<'all' | 'member' | 'ally' | 'admin' | 'disabled'>('all');

	let inviteEmail = $state('');
	let inviteBusy = $state(false);
	let inviteError = $state('');
	let invited = $state<InviteCreated[]>([]);

	// Disable / re-enable, confirmed in a dialog.
	let dialog = $state<HTMLDialogElement | null>(null);
	let pending = $state<{ user: AdminUserRow; disable: boolean } | null>(null);
	let statusBusy = $state(false);
	let statusError = $state('');
	let statusDone = $state('');

	function confirmStatus(user: AdminUserRow, disable: boolean) {
		pending = { user, disable };
		statusError = '';
		dialog?.showModal();
	}

	function closeDialog() {
		dialog?.close();
		pending = null;
	}

	async function changeStatus() {
		if (!pending) return;
		const { user, disable } = pending;
		statusBusy = true;
		statusError = '';
		try {
			await api.post(
				`/admin/api/users/${encodeURIComponent(user.id)}/${disable ? 'disable' : 'enable'}`
			);
			if (users) {
				users = users.map((u) => (u.id === user.id ? { ...u, disabled: disable } : u));
			}
			statusDone = disable
				? `${user.display_name}'s account was disabled. Faro is emailing ${user.display_name} and their accountability partners.`
				: `${user.display_name}'s account was re-enabled. Faro is emailing ${user.display_name} and their accountability partners.`;
			closeDialog();
		} catch (e) {
			if (e instanceof ApiError && (e.code === 'already_disabled' || e.code === 'not_disabled')) {
				// Someone else got there first: show the current state.
				closeDialog();
				await load();
			} else if (e instanceof ApiError && e.code === 'cannot_disable_self') {
				statusError = 'You cannot disable your own account. Ask another admin.';
			} else if (e instanceof ApiError && e.code === 'last_admin') {
				statusError = 'The instance must keep at least one enabled admin.';
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
							<span class="chip off" title="The person asked for their account to be deleted">
								being deleted {date(u.deletion_purge_after_ms)}
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
							<!-- The person may still cancel; the server refuses changes meanwhile. -->
						{:else if u.disabled}
							<button class="secondary small" type="button" onclick={() => confirmStatus(u, false)}>
								Enable…
							</button>
						{:else}
							<button class="secondary small" type="button" onclick={() => confirmStatus(u, true)}>
								Disable…
							</button>
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
		{#if pending.disable}
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
		{:else}
			<h2 id="status-title">Re-enable {name}'s account?</h2>
			<p>
				{name} ({pending.user.email}) will be able to sign in again. Faro will email {name} and their
				accountability partners.
			</p>
		{/if}
		{#if statusError}
			<div class="notice error" role="alert">{statusError}</div>
		{/if}
		<div class="actions">
			<button
				class={pending.disable ? 'danger' : 'primary'}
				type="button"
				onclick={changeStatus}
				disabled={statusBusy}
			>
				{#if statusBusy}Saving…{:else if pending.disable}Disable account{:else}Re-enable account{/if}
			</button>
			<button class="secondary" type="button" onclick={closeDialog}>Cancel</button>
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
			6.5rem;
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

	.label {
		display: none;
	}

	.action {
		display: flex;
		justify-content: flex-end;
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
			justify-content: flex-start;
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
