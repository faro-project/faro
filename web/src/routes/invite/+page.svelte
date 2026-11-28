<script lang="ts">
	// Where invitation emails link: /invite#token=….
	//
	// Looks the invitation up (GET /v1/invites/{token}) to say who sent it.
	//
	// * A member invitation is accepted by signing in with the invited
	//   address, so this page hands over to /signin.
	// * An ally invitation needs a session for the invited address, then the
	//   ally's encryption key: created here (wrapped with a passphrase they
	//   choose, plus a recovery code) on their first invitation, or unlocked
	//   if they already have one. `POST /v1/invites/{token}/accept` uploads
	//   the public key and the wrapped private key. Afterwards the page shows
	//   the safety code to read to the member.
	//
	// The token leaves the address bar as soon as the page loads. It is kept
	// in localStorage across the sign-in (see pending-invite.ts).

	import { onMount } from 'svelte';
	import { resolve } from '$app/paths';
	import { api, ApiError, describeError, seg } from '#lib/api.ts';
	import { b64 } from '#lib/crypto/bytes.ts';
	import { date } from '#lib/format.ts';
	import { getAllyKey, newAllyKey } from '#lib/keys/ally.ts';
	import { keyring } from '#lib/keys/keyring.svelte.ts';
	import {
		clearPendingInvite,
		pendingInvite,
		savePendingInvite
	} from '#lib/keys/pending-invite.ts';
	import { session } from '#lib/session.svelte.ts';
	import type { AllyKeyBlob, InviteAccepted, InviteInfo, SupportedMember } from '#lib/types.ts';
	import AllySafetyCode from '#lib/ui/AllySafetyCode.svelte';
	import DisplayName from '#lib/ui/DisplayName.svelte';
	import NewPassphrase from '#lib/ui/NewPassphrase.svelte';
	import RecoveryCode from '#lib/ui/RecoveryCode.svelte';
	import UnlockKeys from '#lib/ui/UnlockKeys.svelte';

	type View = 'loading' | 'missing' | 'invalid' | 'ok' | 'error';

	let view = $state<View>('loading');
	let info = $state<InviteInfo | null>(null);
	let error = $state('');

	const TOKEN_SHAPE = /^[A-Za-z0-9_-]{43}$/;
	let token = '';

	// Ally acceptance.
	let existingKey = $state<AllyKeyBlob | null | undefined>(undefined);
	let passphrase = $state('');
	let picker = $state<ReturnType<typeof NewPassphrase> | null>(null);
	let namer = $state<ReturnType<typeof DisplayName> | null>(null);
	let busy = $state(false);
	let progress = $state(0);
	let acceptError = $state('');
	let recoveryCode = $state('');
	let accepted = $state<SupportedMember | null>(null);

	async function load() {
		// Keep the token out of the address bar (and history), but in memory
		// so "Try again" still has it.
		if (location.hash) {
			token = (new URLSearchParams(location.hash.slice(1)).get('token') ?? '').trim();
			history.replaceState(history.state, '', location.pathname + location.search);
		}
		if (!token) token = pendingInvite() ?? '';
		view = 'loading';
		if (!token) {
			view = 'missing';
			return;
		}
		if (!TOKEN_SHAPE.test(token)) {
			view = 'invalid';
			return;
		}
		try {
			info = await api.get<InviteInfo>(`/v1/invites/${seg(token)}`);
			view = 'ok';
			if (info.kind === 'ally') savePendingInvite(token);
		} catch (e) {
			if (e instanceof ApiError && e.status === 404) {
				clearPendingInvite();
				view = 'invalid';
			} else {
				error = describeError(e);
				view = 'error';
			}
		}
	}

	onMount(() => {
		void session.refresh().catch(() => {});
		void load();
	});

	let signinHref = $derived(
		info ? `${resolve('/signin')}?email=${encodeURIComponent(info.email)}` : resolve('/signin')
	);

	let rightAccount = $derived(
		!!info && !!session.user && session.user.email.toLowerCase() === info.email.toLowerCase()
	);

	// Once signed in as the invitee, see whether they already have an ally key.
	$effect(() => {
		if (rightAccount && info?.kind === 'ally' && existingKey === undefined) {
			getAllyKey()
				.then((k) => (existingKey = k))
				.catch((e) => (acceptError = describeError(e)));
		}
	});

	async function upload(encPk: Uint8Array, wrapped: unknown) {
		const res = await api.post<InviteAccepted>(`/v1/invites/${seg(token)}/accept`, {
			enc_pubkey: b64(encPk),
			wrapped_privkey: wrapped
		});
		clearPendingInvite();
		await session.refresh();
		const members = await api.get<SupportedMember[]>('/v1/ally/members');
		accepted = members.find((m) => m.member_id === res.member_id) ?? null;
	}

	function acceptMessage(err: unknown): string {
		if (err instanceof ApiError) {
			switch (err.code) {
				case 'invite_email_mismatch':
					return `This invitation is for ${info?.email}. Sign in with that address.`;
				case 'already_linked':
					return `You are already ${info?.inviter_display_name}'s ally.`;
				case 'ally_key_mismatch':
					return 'You already have an ally key. Reload this page and unlock it instead.';
				case 'cannot_invite_self':
					return "You can't be your own ally.";
			}
			if (err.status === 404) return 'This invitation has expired or was already used.';
		}
		return describeError(err);
	}

	async function acceptNew(e: SubmitEvent) {
		e.preventDefault();
		const user = session.user;
		if (!user || !picker?.check()) return;
		if (namer && !(await namer.save())) return;
		busy = true;
		acceptError = '';
		progress = 0;
		try {
			const k = await newAllyKey(user.id, passphrase, (f) => (progress = f));
			await upload(k.key.encPk, k.wrapped);
			passphrase = '';
			keyring.setAlly(k.key);
			recoveryCode = k.recoveryCode;
		} catch (err) {
			acceptError = acceptMessage(err);
		} finally {
			busy = false;
		}
	}

	async function acceptExisting() {
		const k = keyring.allyFor(session.user?.id);
		if (!k || !existingKey) return;
		busy = true;
		acceptError = '';
		try {
			await upload(k.encPk, existingKey.wrapped_privkey);
		} catch (err) {
			acceptError = acceptMessage(err);
		} finally {
			busy = false;
		}
	}

	async function switchAccount() {
		await session.signOut().catch(() => {});
	}
</script>

<svelte:window onhashchange={() => location.hash && load()} />

<svelte:head>
	<title>Invitation · Faro</title>
</svelte:head>

{#if view === 'loading'}
	<p class="muted" role="status">Opening the invitation…</p>
{:else if view === 'ok' && info}
	<h1>
		{info.kind === 'ally' && accepted
			? 'Invitation accepted'
			: `You're invited to ${info.instance_name}`}
	</h1>
	{#if info.kind === 'member'}
		<section class="card">
			<p>
				<strong>{info.inviter_display_name}</strong> invited you to join {info.instance_name}, a
				Faro accountability instance.
			</p>
			<p>
				To accept, sign in with <strong>{info.email}</strong>. Faro emails you a sign-in link;
				there's no password. Your account is created the first time you sign in.
			</p>
			<p class="muted">The invitation is valid until {date(info.expires_at_ms)}.</p>
			<div class="actions">
				<a class="button primary" href={signinHref}>Sign in with {info.email}</a>
			</div>
		</section>
	{:else if recoveryCode}
		<RecoveryCode
			code={recoveryCode}
			ondone={() => (recoveryCode = '')}
			doneLabel="Show my safety code"
		/>
	{:else if accepted}
		<section class="card">
			<p>
				You accepted <strong>{info.inviter_display_name}</strong>'s invitation. Before you see
				anything, they approve you, after you both compare this safety code.
			</p>
			{#if session.user}<AllySafetyCode member={accepted} viewer={session.user} />{/if}
			<div class="actions">
				<a class="button secondary" href={resolve('/supporting')}>People you support</a>
			</div>
		</section>
	{:else}
		<section class="card">
			<p>
				<strong>{info.inviter_display_name}</strong> invited you to be their accountability ally on
				{info.instance_name}.
			</p>
			<p class="muted">
				As an ally you're told when something needs attention, and you can read what
				{info.inviter_display_name} shares with you after unlocking it with your own passphrase. The people
				who run this server can't read it. Valid until {date(info.expires_at_ms)}.
			</p>

			{#if !session.loaded}
				<p class="muted" role="status">Checking your sign-in…</p>
			{:else if !session.user}
				<p>
					First, sign in with <strong>{info.email}</strong>. Come back to this page afterwards; it
					remembers the invitation.
				</p>
				<div class="actions">
					<a class="button primary" href={signinHref}>Sign in with {info.email}</a>
				</div>
			{:else if !rightAccount}
				<div class="notice warn">
					<p>
						You're signed in as <strong>{session.user.email}</strong>, but this invitation is for
						<strong>{info.email}</strong>.
					</p>
				</div>
				<div class="actions">
					<button class="secondary" type="button" onclick={switchAccount}>
						Sign out and switch
					</button>
				</div>
			{:else if existingKey === undefined}
				<p class="muted" role="status">Loading…</p>
			{:else if existingKey}
				{#if !keyring.allyFor(session.user.id)}
					<UnlockKeys kind="ally" user={session.user}>
						{#snippet intro()}
							<h2>Unlock your ally key</h2>
							<p class="muted">
								You already have an ally key from another invitation. You use the same key for
								everyone you support.
							</p>
						{/snippet}
					</UnlockKeys>
				{:else}
					{#if acceptError}<div class="notice error" role="alert"><p>{acceptError}</p></div>{/if}
					<div class="actions">
						<button class="primary" type="button" onclick={acceptExisting} disabled={busy}>
							{busy ? 'Accepting…' : `Accept ${info.inviter_display_name}'s invitation`}
						</button>
					</div>
				{/if}
			{:else}
				<form onsubmit={acceptNew} novalidate>
					<h2>Set up your ally key</h2>
					<p class="muted">
						Your ally key is made in this browser. It opens what the people you support share with
						you. The server keeps it locked with this passphrase, which it never sees.
					</p>
					<DisplayName
						bind:this={namer}
						label="Your name"
						hint="{info.inviter_display_name} sees it when approving you."
						onsaved={() => {}}
					/>
					<NewPassphrase bind:this={picker} bind:value={passphrase} id="ally-passphrase" />
					{#if busy}<progress max="1" value={progress} aria-label="Creating your key"
						></progress>{/if}
					{#if acceptError}<div class="notice error" role="alert"><p>{acceptError}</p></div>{/if}
					<div class="actions">
						<button class="primary" type="submit" disabled={busy}>
							{busy ? 'Creating your key…' : 'Create my key and accept'}
						</button>
					</div>
				</form>
			{/if}
		</section>
	{/if}
{:else if view === 'invalid'}
	<h1>This invitation no longer works</h1>
	<section class="card">
		<p>
			Invitations are valid for 7 days and work once. This one has expired, was already used, or the
			link was not copied in full. Ask the person who invited you to send a new one.
		</p>
		<p>If you already have an account, you can <a href={resolve('/signin')}>sign in</a>.</p>
	</section>
{:else if view === 'missing'}
	<h1>Open the link from your invitation</h1>
	<section class="card">
		<p>
			This page opens the invitation in the link you were emailed, and that link is missing here.
			Open it again from the email.
		</p>
	</section>
{:else}
	<h1>Invitation</h1>
	<div class="notice error" role="alert"><p>{error}</p></div>
	<button class="secondary" type="button" onclick={load}>Try again</button>
{/if}

<style>
	h1 {
		margin-bottom: 1rem;
	}

	progress {
		margin-top: 0.5rem;
	}
</style>
