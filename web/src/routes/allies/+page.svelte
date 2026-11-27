<script lang="ts">
	// The member's allies (ARCHITECTURE.md §5.2 steps 1, 2 and 4; §7 step 4).
	//
	// * Invite by email. The invitee signs in with that address, creates
	//   their ally key in their own browser and accepts.
	// * They then wait here. The member and the ally compare a safety code
	//   computed from the member's signing key (taken from the unlocked key,
	//   not from the server) and the ally's encryption key; if it matches,
	//   approving signs an endorsement of the ally's key and the next
	//   recipient list with the ally added, and the server stores both in one
	//   transaction.
	// * Removing an approved ally signs the next list without them; the
	//   server tells them and the other allies. When an ally leaves on their
	//   own, the list still names them until the member signs a new one.
	// * Every list is signed in format 2, with each ally's current display
	//   name as this page shows it (`withNames`), so phones can name allies
	//   without trusting the server (PROTOCOL.md §5.1).

	import { resolve } from '$app/paths';
	import { api, ApiError, describeError, seg } from '#lib/api.ts';
	import { nextManifest, type ManifestAlly } from '#lib/crypto/proto.ts';
	import { ago, date, dateTime } from '#lib/format.ts';
	import { instance } from '#lib/instance.svelte.ts';
	import { approveAlly, approveErrorMessage, codeForAlly } from '#lib/keys/approve.ts';
	import { keyring, type MemberKeys } from '#lib/keys/keyring.svelte.ts';
	import { ensureManifest, signManifest } from '#lib/keys/member.ts';
	import { session } from '#lib/session.svelte.ts';
	import type { AllyLink, InviteCreated, MyAllies } from '#lib/types.ts';
	import Gate from '#lib/ui/Gate.svelte';
	import UnlockKeys from '#lib/ui/UnlockKeys.svelte';

	let mine = $state<MyAllies | null>(null);
	/** Names of the groups links came from, for the "From Tuesday group" label. */
	let groupNames = $state<Record<string, string>>({});
	let loadError = $state('');
	let loadedFor = '';

	let inviteEmail = $state('');
	let inviteBusy = $state(false);
	let inviteError = $state('');
	let invited = $state<InviteCreated[]>([]);

	let reviewing = $state<string | null>(null);
	let codesMatch = $state(false);
	let busy = $state(false);
	let actionError = $state('');
	let done = $state('');

	let removeDialog = $state<HTMLDialogElement | null>(null);
	let removing = $state<AllyLink | null>(null);
	let removeError = $state('');

	async function load() {
		loadError = '';
		try {
			mine = await api.get<MyAllies>('/v1/me/allies');
			if (mine.allies.some((a) => a.origin_group_id)) {
				api
					.get<{ id: string; name: string }[]>('/v1/groups')
					.then((gs) => (groupNames = Object.fromEntries(gs.map((g) => [g.id, g.name]))))
					.catch(() => {});
			}
		} catch (e) {
			loadError = describeError(e);
		}
	}

	$effect(() => {
		const u = session.user;
		if (u?.roles.member && u.id !== loadedFor) {
			loadedFor = u.id;
			void load();
		}
	});

	let pending = $derived(mine?.allies.filter((a) => a.state === 'pending') ?? []);
	let active = $derived(
		(mine?.allies.filter((a) => a.state === 'active') ?? []).sort((a, b) =>
			a.display_name.localeCompare(b.display_name)
		)
	);

	const message = approveErrorMessage;

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
			const created = await api.post<InviteCreated>('/v1/me/invites', { email });
			invited = [created, ...invited.filter((i) => i.email !== created.email)];
			inviteEmail = '';
		} catch (err) {
			const codes: Record<string, string> = {
				cannot_invite_self: "You can't be your own ally.",
				already_linked: `${email} is already your ally, or has accepted an invitation.`,
				too_many_allies: 'You have the most allies one person can have (32).',
				too_many_invites:
					'You have 20 invitations waiting. Wait until some are accepted or expire (after 7 days).',
				invalid_email: 'The server could not read this email address.'
			};
			inviteError =
				err instanceof ApiError && codes[err.code] ? codes[err.code] : describeError(err);
		} finally {
			inviteBusy = false;
		}
	}

	// While the account is being deleted, nothing new joins it (§12).
	let deleting = $derived(!!session.deletion);

	let copied = $state('');
	async function copy(text: string) {
		try {
			await navigator.clipboard.writeText(text);
			copied = text;
			setTimeout(() => (copied = ''), 2500);
		} catch {
			copied = '';
		}
	}

	function keysOrNull(): MemberKeys | null {
		return keyring.memberFor(session.user?.id);
	}

	async function activeAllyEntries() {
		return active
			.filter((a) => a.ally_enc_pubkey)
			.map((a) => ({ ally_id: a.ally_id, enc_pubkey: a.ally_enc_pubkey!, name: a.display_name }));
	}

	/**
	 * The entries with each ally's current name, as this page shows it, so
	 * every list the member signs names allies as they are called now (a
	 * rename is picked up by the next re-sign, and never forces one).
	 * Phones show these names (docs/PROTOCOL.md §5.1); `nextManifest`
	 * sanitizes them.
	 */
	function currentNames(): Map<string, string> {
		return new Map((mine?.allies ?? []).map((l) => [l.ally_id, l.display_name]));
	}

	function withNames(allies: ManifestAlly[]): ManifestAlly[] {
		const names = currentNames();
		return allies.map((a) => ({ ...a, name: names.get(a.ally_id) ?? a.name ?? '' }));
	}

	async function approve(a: AllyLink) {
		const keys = keysOrNull();
		const inst = instance.info;
		if (!keys || !inst || !a.ally_enc_pubkey) return;
		busy = true;
		actionError = '';
		try {
			await approveAlly(keys, inst.instance_id, a, activeAllyEntries, currentNames());
			done = `${a.display_name} is now your ally. Your computers start encrypting to them within a few minutes.`;
			reviewing = null;
			await load();
		} catch (e) {
			actionError = message(e);
		} finally {
			busy = false;
		}
	}

	function confirmRemove(a: AllyLink) {
		removing = a;
		removeError = '';
		removeDialog?.showModal();
	}

	async function remove() {
		const a = removing;
		if (!a) return;
		busy = true;
		removeError = '';
		try {
			if (a.state === 'active') {
				const keys = keysOrNull();
				const inst = instance.info;
				if (!keys || !inst) return;
				const latest = await ensureManifest(keys, inst.instance_id, activeAllyEntries);
				const manifest = signManifest(
					keys,
					nextManifest(latest, withNames(latest.allies.filter((x) => x.ally_id !== a.ally_id)))
				);
				await api.delete(`/v1/me/allies/${seg(a.ally_id)}`, { manifest });
				done = `${a.display_name} is no longer your ally. They and your other allies are being told.`;
			} else {
				await api.delete(`/v1/me/allies/${seg(a.ally_id)}`);
				done = `You declined ${a.display_name}.`;
			}
			removeDialog?.close();
			if (reviewing === a.ally_id) reviewing = null;
			await load();
		} catch (e) {
			removeError = message(e);
		} finally {
			busy = false;
		}
	}

	async function refreshList() {
		const keys = keysOrNull();
		const inst = instance.info;
		if (!keys || !inst || !mine?.manifest) return;
		busy = true;
		actionError = '';
		try {
			const latest = await ensureManifest(keys, inst.instance_id, activeAllyEntries);
			const departed = new Set(mine.manifest.departed);
			const m = signManifest(
				keys,
				nextManifest(latest, withNames(latest.allies.filter((x) => !departed.has(x.ally_id))))
			);
			await api.put('/v1/me/recipient-manifest', m);
			done =
				'Your recipient list is up to date. Your computers stop encrypting to anyone who left.';
			await load();
		} catch (e) {
			actionError = message(e);
		} finally {
			busy = false;
		}
	}

	/** The safety code from the unlocked member key and the ally's key. */
	function codeFor(a: AllyLink): string | null {
		return codeForAlly(keyring.member, a);
	}
</script>

<svelte:head>
	<title>Allies · Faro</title>
</svelte:head>

<Gate role="member">
	{#snippet children(user)}
		<div class="page-head">
			<h1>Your allies</h1>
			<p>
				Allies are people you trust to see your reports and alerts. Everything is encrypted to them
				and to you only; the people who run this server can't read it.
			</p>
		</div>

		{#if done}<div class="notice ok" role="status"><p>✓ {done}</p></div>{/if}
		{#if actionError && !reviewing}<div class="notice error" role="alert">
				<p>{actionError}</p>
			</div>{/if}

		{#if deleting}
			<div class="notice warn">
				<p>
					Your account is being deleted, so you can't invite or approve allies. Your allies keep
					getting your alerts until the deletion.
				</p>
			</div>
		{:else if !session.hasMemberKeys}
			<div class="notice info">
				<p>
					You can invite allies now; to approve them, first <a href={resolve('/keys')}>
						set up your keys
					</a>.
				</p>
			</div>
		{/if}

		{#if mine?.manifest?.needs_update}
			<section class="card attention" aria-labelledby="refresh">
				<h2 id="refresh">Confirm your updated ally list</h2>
				<p>
					{mine.manifest.departed.length === 1
						? 'An ally'
						: `${mine.manifest.departed.length} allies`} stopped being your ally. They can no longer see
					anything here, but your computers keep encrypting new items to them until you sign your updated
					list.
				</p>
				{#if keyring.memberFor(user.id)}
					<button class="primary" type="button" onclick={refreshList} disabled={busy}>
						{busy ? 'Signing…' : 'Sign the updated list'}
					</button>
				{:else}
					<UnlockKeys kind="member" {user}>
						{#snippet intro()}<h3>Unlock your keys to sign it</h3>{/snippet}
					</UnlockKeys>
				{/if}
			</section>
		{/if}

		{#if pending.length}
			<section class="section" aria-labelledby="waiting">
				<h2 id="waiting">Waiting for your approval</h2>
				<ul class="rows">
					{#each pending as a (a.ally_id)}
						<li>
							<div class="row-main">
								<div>
									<div class="row-title">
										<strong>{a.display_name}</strong>
										<span class="chip pending">
											{a.origin_group_id ? 'Accepted your proposal' : 'Accepted your invitation'}
										</span>
										{#if a.origin_group_id && groupNames[a.origin_group_id]}
											<span class="chip normal">From {groupNames[a.origin_group_id]}</span>
										{/if}
										{#if a.deletion_purge_after_ms}
											<span class="chip off">Account being deleted</span>
										{/if}
									</div>
									<div class="row-meta">
										{a.email} ·
										<span title={dateTime(a.created_at_ms)}>{ago(a.created_at_ms)}</span>
									</div>
								</div>
								<div class="row-actions">
									{#if reviewing !== a.ally_id && !deleting && !a.deletion_purge_after_ms}
										<button
											class="primary small"
											type="button"
											onclick={() => {
												reviewing = a.ally_id;
												codesMatch = false;
												actionError = '';
												done = '';
											}}
										>
											Compare codes and approve
										</button>
									{/if}
									<button class="secondary small" type="button" onclick={() => confirmRemove(a)}>
										Decline
									</button>
								</div>
							</div>
							{#if reviewing === a.ally_id && !deleting}
								<div class="review">
									{#if !keyring.memberFor(user.id)}
										<UnlockKeys kind="member" {user}>
											{#snippet intro()}
												<h3>Unlock your keys</h3>
												<p class="muted">
													The safety code is computed from your own key, so it needs unlocking.
												</p>
											{/snippet}
										</UnlockKeys>
									{:else}
										{@const code = codeFor(a)}
										<p>
											Ask <strong>{a.display_name}</strong> to open Faro and read you their safety code
											for you, in person or on a call (not by email or text). It must be exactly:
										</p>
										{#if code}
											<p class="code-display digits" aria-label="Safety code">
												{#each code.split(' ') as g, i (i)}<span>{g}</span>{/each}
											</p>
										{:else}
											<div class="notice error">
												<p>
													{a.display_name} has no key yet. Ask them to accept the invitation again.
												</p>
											</div>
										{/if}
										<p class="muted small">
											Matching codes prove that the key you approve is really theirs, and not one
											the server swapped in.
										</p>
										<label class="check">
											<input type="checkbox" bind:checked={codesMatch} />
											{a.display_name}'s code is the same
										</label>
										{#if actionError}<div class="notice error" role="alert">
												<p>{actionError}</p>
											</div>{/if}
										<div class="actions">
											<button
												class="primary"
												type="button"
												disabled={!codesMatch || busy || !code}
												onclick={() => approve(a)}
											>
												{busy ? 'Approving…' : `Approve ${a.display_name}`}
											</button>
											<button class="secondary" type="button" onclick={() => (reviewing = null)}>
												Cancel
											</button>
										</div>
									{/if}
								</div>
							{/if}
						</li>
					{/each}
				</ul>
			</section>
		{/if}

		<section class="section" aria-labelledby="current">
			<h2 id="current">Allies</h2>
			{#if loadError}
				<div class="notice error" role="alert"><p>{loadError}</p></div>
				<button class="secondary" type="button" onclick={load}>Try again</button>
			{:else if !mine}
				<p class="muted" role="status">Loading…</p>
			{:else if active.length === 0}
				<div class="empty"><p>No allies yet. Invite someone you trust below.</p></div>
			{:else}
				<ul class="rows">
					{#each active as a (a.ally_id)}
						<li>
							<div class="row-main">
								<div>
									<div class="row-title">
										<strong>{a.display_name}</strong><span class="chip good">Ally</span>
										{#if a.origin_group_id && groupNames[a.origin_group_id]}
											<span class="chip normal">From {groupNames[a.origin_group_id]}</span>
										{/if}
										{#if a.deletion_purge_after_ms}
											<span class="chip normal">Leaving {date(a.deletion_purge_after_ms)}</span>
										{/if}
									</div>
									<div class="row-meta">
										{a.email} · since {date(a.activated_at_ms ?? a.created_at_ms)}
									</div>
									{#if a.deletion_purge_after_ms}
										<div class="row-meta">
											{a.display_name}'s account is being deleted. They stay your ally until {date(
												a.deletion_purge_after_ms
											)}; then confirm your updated ally list here.
										</div>
									{/if}
								</div>
								<button class="secondary small" type="button" onclick={() => confirmRemove(a)}>
									Remove…
								</button>
							</div>
						</li>
					{/each}
				</ul>
			{/if}
		</section>

		{#if !deleting}
			<form class="card section" onsubmit={invite} novalidate>
				<h2>Invite an ally</h2>
				<p class="muted">
					They get an email invitation, valid for 7 days, and accept it by signing in with that
					address. You approve them after comparing a safety code.
				</p>
				<div class="invite-row">
					<label class="visually-hidden" for="ally-email">Ally's email address</label>
					<input
						id="ally-email"
						type="email"
						placeholder="name@example.org"
						bind:value={inviteEmail}
						autocomplete="off"
						aria-invalid={inviteError ? 'true' : undefined}
						aria-describedby={inviteError ? 'ally-email-error' : undefined}
					/>
					<button class="primary" type="submit" disabled={inviteBusy}>
						{inviteBusy ? 'Sending…' : 'Send invitation'}
					</button>
				</div>
				{#if inviteError}<span class="field-error" id="ally-email-error">{inviteError}</span>{/if}
				{#if invited.length}
					<ul class="sent" aria-live="polite">
						{#each invited as i (i.email)}
							<li>
								<span>
									✓ Invitation sent to <strong>{i.email}</strong>, valid until {date(
										i.expires_at_ms
									)}.
								</span>
								<button class="link small" type="button" onclick={() => copy(i.invite_url)}>
									{copied === i.invite_url ? 'Copied' : 'Copy the link'}
								</button>
							</li>
						{/each}
					</ul>
					<p class="muted small">
						Only {invited.length === 1 ? 'that address' : 'those addresses'} can accept, so sharing the
						link another way is safe.
					</p>
				{/if}
			</form>
		{/if}
	{/snippet}
</Gate>

<dialog bind:this={removeDialog} onclose={() => (removing = null)} aria-labelledby="remove-title">
	{#if removing}
		{#if removing.state === 'active'}
			<h2 id="remove-title">Remove {removing.display_name} as your ally?</h2>
			<p>
				They lose access to your reports and alerts now. Faro tells them and your other allies. You
				sign a new recipient list without them, so your computers stop encrypting to them.
			</p>
			<p class="muted">They can still read what was shared with them before.</p>
			{#if session.user && !keyring.memberFor(session.user.id)}
				<UnlockKeys kind="member" user={session.user}>
					{#snippet intro()}<h3>Unlock your keys to sign the new list</h3>{/snippet}
				</UnlockKeys>
			{/if}
		{:else}
			<h2 id="remove-title">Decline {removing.display_name}?</h2>
			<p>
				They accepted your invitation but were never approved, so they have never seen anything.
			</p>
		{/if}
		{#if removeError}<div class="notice error" role="alert"><p>{removeError}</p></div>{/if}
		<div class="actions">
			<button
				class="danger"
				type="button"
				onclick={remove}
				disabled={busy || (removing.state === 'active' && !keyring.memberFor(session.user?.id))}
			>
				{busy ? 'Removing…' : removing.state === 'active' ? 'Remove ally' : 'Decline'}
			</button>
			<button class="secondary" type="button" onclick={() => removeDialog?.close()}>Cancel</button>
		</div>
	{/if}
</dialog>

<style>
	.attention {
		border-color: color-mix(in srgb, var(--warn) 45%, var(--border));
		margin-bottom: 2rem;
	}

	.row-actions {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
	}

	.review {
		margin-top: 1rem;
		padding-top: 1rem;
		border-top: 1px dashed var(--border);
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
		margin: 1rem 0 0.5rem;
		color: var(--ok);
	}

	.sent li {
		display: flex;
		flex-wrap: wrap;
		gap: 0.25rem 0.75rem;
		align-items: baseline;
	}
</style>
