<script lang="ts">
	// Account settings: who you are here, your keys and their passphrases,
	// (for members) how long your history is kept and how you hear about
	// your own alerts, and deleting your account.
	import { resolve } from '$app/paths';
	import { api, describeError } from '#lib/api.ts';
	import { unb64 } from '#lib/crypto/bytes.ts';
	import { keyId } from '#lib/crypto/keys.ts';
	import { date } from '#lib/format.ts';
	import { getAllyKey } from '#lib/keys/ally.ts';
	import { keyring } from '#lib/keys/keyring.svelte.ts';
	import { getMemberKeys } from '#lib/keys/member.ts';
	import { session } from '#lib/session.svelte.ts';
	import type { AllyKeyBlob, MemberKeysBlob, RetentionView, RetentionWindows } from '#lib/types.ts';
	import ChangePassphrase from '#lib/ui/ChangePassphrase.svelte';
	import DeleteAccount from '#lib/ui/DeleteAccount.svelte';
	import DisplayName from '#lib/ui/DisplayName.svelte';
	import Gate from '#lib/ui/Gate.svelte';
	import NotificationPrefs from '#lib/ui/NotificationPrefs.svelte';
	import ProposalBlocks from '#lib/ui/groups/ProposalBlocks.svelte';
	import ReachOutSettings from '#lib/ui/ReachOutSettings.svelte';

	let memberKeys = $state<MemberKeysBlob | null | undefined>(undefined);
	let allyKey = $state<AllyKeyBlob | null | undefined>(undefined);
	let retention = $state<RetentionView | null>(null);
	let days = $state<RetentionWindows>({ event_header_days: 0, blob_days: 0, alert_days: 0 });
	let retentionError = $state('');
	let retentionSaved = $state(false);
	let retentionBusy = $state(false);
	let loadedFor = '';

	$effect(() => {
		const u = session.user;
		if (!u || u.id === loadedFor) return;
		loadedFor = u.id;
		if (u.roles.member) {
			getMemberKeys()
				.then((k) => (memberKeys = k))
				.catch(() => (memberKeys = null));
			api
				.get<RetentionView>('/v1/me/retention')
				.then((r) => {
					retention = r;
					days = { ...r.effective };
				})
				.catch((e) => (retentionError = describeError(e)));
		}
		if (u.roles.ally)
			getAllyKey()
				.then((k) => (allyKey = k))
				.catch(() => (allyKey = null));
	});

	const WINDOWS: { key: keyof RetentionWindows; label: string; hint: string }[] = [
		{
			key: 'blob_days',
			label: 'Reports and details',
			hint: 'Encrypted daily reports, flagged moments and thumbnails'
		},
		{ key: 'alert_days', label: 'Alerts', hint: 'Missed check-ins, tamper and other alerts' },
		{
			key: 'event_header_days',
			label: 'Activity records',
			hint: 'What kind of thing happened and when (no details)'
		}
	];

	let shortened = $derived(
		!!retention && WINDOWS.some((w) => days[w.key] < retention!.effective[w.key])
	);

	async function saveRetention(e: SubmitEvent) {
		e.preventDefault();
		if (!retention) return;
		retentionError = '';
		retentionSaved = false;
		retentionBusy = true;
		try {
			// A window at the instance's maximum is stored as "no choice".
			const body = Object.fromEntries(
				WINDOWS.map((w) => [w.key, days[w.key] >= retention!.instance[w.key] ? null : days[w.key]])
			);
			retention = await api.put<RetentionView>('/v1/me/retention', body);
			days = { ...retention.effective };
			retentionSaved = true;
		} catch (err) {
			retentionError = describeError(err);
		} finally {
			retentionBusy = false;
		}
	}
</script>

<svelte:head>
	<title>Settings · Faro</title>
</svelte:head>

<Gate>
	{#snippet children(user)}
		<div class="page-head">
			<h1>Settings</h1>
		</div>

		<section class="card">
			<h2>Your account</h2>
			<DisplayName />
			<dl class="facts">
				<dt>Email</dt>
				<dd>{user.email}</dd>
				<dt>Here as</dt>
				<dd>
					{[user.roles.member && 'member', user.roles.ally && 'ally', user.roles.admin && 'admin']
						.filter(Boolean)
						.join(', ') || 'no role yet'}
				</dd>
				<dt>Joined</dt>
				<dd>{date(user.created_at_ms)}</dd>
			</dl>
		</section>

		<section class="card">
			<h2>Your keys</h2>
			{#if user.roles.member}
				<h3>Member key</h3>
				{#if memberKeys === undefined}
					<p class="muted">Loading…</p>
				{:else if memberKeys}
					<p>
						Fingerprint <code>{keyId(unb64(memberKeys.sign_pubkey))}</code>, created {date(
							memberKeys.created_at_ms
						)}.
						{keyring.memberFor(user.id) ? 'Unlocked in this tab.' : 'Locked.'}
					</p>
				{:else}
					<p>Not set up yet. <a href={resolve('/keys')}>Set up your keys</a></p>
				{/if}
			{/if}
			{#if user.roles.ally}
				<h3>Ally key</h3>
				{#if allyKey === undefined}
					<p class="muted">Loading…</p>
				{:else if allyKey}
					<p>
						Fingerprint <code>{allyKey.key_id}</code>, created {date(allyKey.created_at_ms)}.
						{keyring.allyFor(user.id) ? 'Unlocked in this tab.' : 'Locked.'}
					</p>
				{:else}
					<p class="muted">No ally key yet.</p>
				{/if}
			{/if}
			{#if keyring.unlocked}
				<button class="secondary small" type="button" onclick={() => keyring.lock()}>
					Lock my keys now
				</button>
			{/if}
			{#if user.roles.member && memberKeys}
				<h3>{user.roles.ally && allyKey ? 'Member key passphrase' : 'Passphrase'}</h3>
				<ChangePassphrase {user} kind="member" />
			{/if}
			{#if user.roles.ally && allyKey}
				<h3>{user.roles.member && memberKeys ? 'Ally key passphrase' : 'Passphrase'}</h3>
				<ChangePassphrase {user} kind="ally" />
			{/if}
			<p class="muted small">
				Keys unlock in one browser tab at a time and lock again after 30 idle minutes. Forgot your
				passphrase? Unlock with your recovery code instead.
			</p>
		</section>

		{#if user.roles.member}
			<form class="card" onsubmit={saveRetention} novalidate>
				<h2>How long your history is kept</h2>
				<p class="muted">
					You can keep things for less time than this instance does, never longer. Your allies are
					told when you shorten a window. A change applies to what arrives from now on.
				</p>
				{#if retention}
					{#each WINDOWS as w (w.key)}
						<div class="field days">
							<label for="ret-{w.key}">
								{w.label}
								<span class="hint">
									{w.hint}. Between {Math.min(retention.min_days, retention.instance[w.key])} and {retention
										.instance[w.key]} days.
								</span>
							</label>
							<input
								id="ret-{w.key}"
								type="number"
								min={Math.min(retention.min_days, retention.instance[w.key])}
								max={retention.instance[w.key]}
								bind:value={days[w.key]}
							/>
						</div>
					{/each}
					{#if shortened}
						<p class="notice warn small">Shortening a window sends your allies a notice.</p>
					{/if}
					{#if retentionError}<div class="notice error" role="alert">
							<p>{retentionError}</p>
						</div>{/if}
					<div class="actions">
						<button class="primary" type="submit" disabled={retentionBusy}>
							{retentionBusy ? 'Saving…' : 'Save'}
						</button>
						{#if retentionSaved}<span class="ok" role="status">✓ Saved</span>{/if}
					</div>
				{:else if retentionError}
					<div class="notice error" role="alert"><p>{retentionError}</p></div>
				{:else}
					<p class="muted">Loading…</p>
				{/if}
			</form>

			<section class="card">
				<h2>Emails about your own activity</h2>
				<p class="muted">You get the same alerts your allies do. Choose how you hear about them.</p>
				<NotificationPrefs memberId={user.id} about="yourself" />
			</section>
		{/if}

		<section class="card">
			<h2>Group proposals</h2>
			<p class="muted">
				People in your groups can ask you to be allies. If someone's proposals aren't welcome, you
				can stop them from sending any, in any group. They aren't told.
			</p>
			<ProposalBlocks />
		</section>

		<section class="card">
			<h2>Reach outs</h2>
			<p class="muted">
				When someone reaches out to you, you're told right away, after your quiet hours. For each
				person you can let their reach outs through quiet hours, move them to the digest, or switch
				them off.
			</p>
			<ReachOutSettings />
		</section>

		<DeleteAccount {user} />
	{/snippet}
</Gate>

<style>
	h3 {
		font-size: 0.95rem;
		margin-top: 0.75rem;
	}

	.days input {
		max-width: 8rem;
	}

	.ok {
		color: var(--ok);
		font-weight: 600;
	}
</style>
