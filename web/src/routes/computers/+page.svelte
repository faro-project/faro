<script lang="ts">
	// The member's computers (ARCHITECTURE.md §7 "Member" steps 2 and 3).
	//
	// 1. "Add a computer" creates a one-time code (10 minutes) and shows the
	//    enrollment link, with `m`, the fingerprint of the member key, taken
	//    from the *unlocked* key so a server can't swap in its own.
	// 2. The computer enrolls and shows its own key's fingerprint. It appears
	//    here as waiting; the member compares the fingerprints and approves,
	//    which signs a device endorsement anchored to the current recipient
	//    list (`min_manifest`). That list is checked against the highest one
	//    this browser has signed or seen (no rollback to a list that still
	//    names a removed ally) and shown, names and key ids, before approving.
	// 3. Removing an active computer stops its monitoring, so the server
	//    alerts the member's allies (urgent, can't be switched off).

	import { onDestroy } from 'svelte';
	import { resolve } from '$app/paths';
	import { api, ApiError, describeError, seg } from '#lib/api.ts';
	import { unb64 } from '#lib/crypto/bytes.ts';
	import { keyId } from '#lib/crypto/keys.ts';
	import {
		deviceEndorsementSigningBytes,
		manifestRef,
		signWith,
		type RecipientManifest,
		type Signed
	} from '#lib/crypto/proto.ts';
	import { ago, date, dateTime } from '#lib/format.ts';
	import { buildEnrollLink } from '#lib/enroll-link.ts';
	import { instance } from '#lib/instance.svelte.ts';
	import { keyring } from '#lib/keys/keyring.svelte.ts';
	import { ensureManifest, latestManifest } from '#lib/keys/member.ts';
	import { session } from '#lib/session.svelte.ts';
	import type { DeviceSummary, EnrollCode, Platform } from '#lib/types.ts';
	import Gate from '#lib/ui/Gate.svelte';
	import Icon from '#lib/ui/Icon.svelte';
	import QrCode from '#lib/ui/QrCode.svelte';
	import RecipientList from '#lib/ui/RecipientList.svelte';
	import UnlockKeys from '#lib/ui/UnlockKeys.svelte';

	let devices = $state<DeviceSummary[] | null>(null);
	let loadError = $state('');
	let loadedFor = '';

	// What is being added: a computer, or an iPhone (docs/IOS.md §14).
	let adding = $state<'computer' | 'iphone' | null>(null);
	let code = $state<EnrollCode | null>(null);
	let codeBusy = $state(false);
	let codeError = $state('');
	let now = $state(Date.now());

	let approving = $state<DeviceSummary | null>(null);
	let matches = $state(false);
	let approveBusy = $state(false);
	let approveError = $state('');
	let done = $state('');
	/** The checked list the device being approved is anchored to, as shown. */
	let anchor = $state<Signed<RecipientManifest> | null>(null);
	let anchorFor = $state('');
	let anchorError = $state('');

	let removeDialog = $state<HTMLDialogElement | null>(null);
	let removing = $state<DeviceSummary | null>(null);
	let removeBusy = $state(false);
	let removeError = $state('');

	const PLATFORM: Record<Platform, string> = {
		macos: 'Mac',
		windows: 'Windows',
		linux: 'Linux',
		ios: 'iPhone',
		android: 'Android'
	};

	async function load() {
		loadError = '';
		try {
			devices = await api.get<DeviceSummary[]>('/v1/me/devices');
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

	// While a code is showing, tick the clock and look for the new computer.
	let ticks = 0;
	const tick = setInterval(() => {
		now = Date.now();
		if (code && now < code.expires_at_ms && ++ticks % 5 === 0) void load();
	}, 1000);
	onDestroy(() => clearInterval(tick));

	let pending = $derived(devices?.filter((d) => d.status === 'pending_endorsement') ?? []);
	// While the account is being deleted, nothing new joins it (§12).
	let deleting = $derived(!!session.deletion);
	let active = $derived(
		(devices?.filter((d) => d.status === 'active') ?? []).sort((a, b) =>
			a.name.localeCompare(b.name)
		)
	);

	async function newCode() {
		const keys = keyring.memberFor(session.user?.id);
		const inst = instance.info;
		if (!keys || !inst) return;
		codeBusy = true;
		codeError = '';
		try {
			// A computer can't start without a recipient list to bootstrap from.
			await ensureManifest(keys, inst.instance_id);
			code = await api.post<EnrollCode>('/v1/me/enroll-codes');
			now = Date.now();
		} catch (e) {
			if (e instanceof ApiError && e.code === 'too_many_codes') {
				codeError = 'You have 5 unused codes. Wait 10 minutes for them to expire.';
			} else {
				codeError = e instanceof Error && !(e instanceof ApiError) ? e.message : describeError(e);
			}
		} finally {
			codeBusy = false;
		}
	}

	/** The link with the member key fingerprint, from the unlocked key. */
	let linkState = $derived.by(() => {
		const keys = keyring.member;
		if (!code || !keys) return { link: '', error: '' };
		try {
			// Built here, not from the server's `enroll_url`: the server must not
			// be able to choose the fingerprint the device checks (#179).
			return {
				link: buildEnrollLink(window.location.origin, code.enroll_url, keyId(keys.signPk)),
				error: ''
			};
		} catch (e) {
			return { link: '', error: e instanceof Error ? e.message : 'Could not build the link.' };
		}
	});
	let link = $derived(linkState.link);

	let remaining = $derived(code ? Math.max(0, code.expires_at_ms - now) : 0);
	let remainingText = $derived(
		`${Math.floor(remaining / 60000)}:${String(Math.floor((remaining % 60000) / 1000)).padStart(2, '0')}`
	);

	let copied = $state('');
	async function copy(text: string, what: string) {
		try {
			await navigator.clipboard.writeText(text);
			copied = what;
			setTimeout(() => (copied = ''), 2500);
		} catch {
			copied = '';
		}
	}

	function startApprove(d: DeviceSummary) {
		approving = d;
		matches = false;
		approveError = '';
		done = '';
		anchor = null;
		anchorFor = '';
		anchorError = '';
	}

	/** Load (again) the list a device would be anchored to. */
	async function loadAnchor(deviceId: string) {
		const keys = keyring.memberFor(session.user?.id);
		const inst = instance.info;
		if (!keys || !inst) return;
		anchorFor = deviceId;
		anchorError = '';
		try {
			const m = await latestManifest(keys, inst.instance_id);
			if (!m) throw new Error('Sign your recipient list first (Your keys page).');
			if (approving?.device_id === deviceId) anchor = m;
		} catch (e) {
			anchor = null;
			anchorError = e instanceof Error && !(e instanceof ApiError) ? e.message : describeError(e);
		}
	}

	// Once the keys are unlocked, fetch and check the list to show.
	$effect(() => {
		const d = approving;
		if (d && keyring.memberFor(session.user?.id) && anchorFor !== d.device_id) {
			void loadAnchor(d.device_id);
		}
	});

	async function approve() {
		const d = approving;
		const keys = keyring.memberFor(session.user?.id);
		const inst = instance.info;
		// Anchored to exactly the list shown, which was checked when loaded.
		const m = anchor;
		if (!d || !keys || !inst || !m) return;
		approveBusy = true;
		approveError = '';
		try {
			const body = signWith(
				keys.signSeed,
				{
					instance_id: inst.instance_id,
					member_id: keys.userId,
					device_id: d.device_id,
					device_sign_pubkey: d.sign_pubkey,
					endorsed_at_ms: Date.now(),
					min_manifest: manifestRef(m)
				},
				deviceEndorsementSigningBytes
			);
			try {
				await api.post(`/v1/devices/${seg(d.device_id)}/endorse`, body);
			} catch (e) {
				// The list changed after it was shown: show the new one.
				if (e instanceof ApiError && e.code === 'stale_min_manifest') {
					anchor = null;
					await loadAnchor(d.device_id);
					throw new Error('Your recipient list changed. Check the new list and approve again.');
				}
				throw e;
			}
			done = `${d.name} is approved. It starts monitoring within a minute.`;
			approving = null;
			await load();
		} catch (e) {
			if (e instanceof ApiError && e.code === 'already_endorsed') {
				approving = null;
				await load();
			} else {
				approveError =
					e instanceof Error && !(e instanceof ApiError) ? e.message : describeError(e);
			}
		} finally {
			approveBusy = false;
		}
	}

	function confirmRemove(d: DeviceSummary) {
		removing = d;
		removeError = '';
		removeDialog?.showModal();
	}

	async function remove() {
		const d = removing;
		if (!d) return;
		removeBusy = true;
		removeError = '';
		try {
			await api.delete(`/v1/me/devices/${seg(d.device_id)}`);
			done =
				d.status === 'active'
					? `${d.name} was removed. Your allies are being told.`
					: `${d.name} was removed.`;
			removeDialog?.close();
			if (approving?.device_id === d.device_id) approving = null;
			await load();
		} catch (e) {
			removeError = describeError(e);
		} finally {
			removeBusy = false;
		}
	}

	function seen(d: DeviceSummary): { text: string; stale: boolean } {
		if (!d.last_seen_at_ms) return { text: 'Has not checked in yet', stale: true };
		const stale = now - d.last_seen_at_ms > 30 * 60 * 1000;
		return { text: `Checked in ${ago(d.last_seen_at_ms, now)}`, stale };
	}
</script>

<svelte:head>
	<title>Computers · Faro</title>
</svelte:head>

<Gate role="member">
	{#snippet children(user)}
		<div class="page-head">
			<h1>Your computers</h1>
			<p>
				Each computer you add monitors every account on it, and reports to you and your allies.
				Everyone who uses it is told.
			</p>
		</div>

		{#if done}<div class="notice ok" role="status"><p>{done}</p></div>{/if}

		{#if deleting}
			<div class="notice warn">
				<p>
					Your account is being deleted, so you can't add or approve computers. Your computers are
					still monitored until the deletion.
				</p>
			</div>
		{:else if !session.hasMemberKeys}
			<div class="notice info">
				<p>
					Before adding a computer, <a href={resolve('/keys')}>set up your keys</a>. They approve
					your computers.
				</p>
			</div>
		{/if}

		{#if pending.length}
			<section class="section" aria-labelledby="waiting">
				<h2 id="waiting">Waiting for your approval</h2>
				<ul class="rows">
					{#each pending as d (d.device_id)}
						<li>
							<div class="row-main">
								<div>
									<div class="row-title">
										<strong>{d.name}</strong>
										<span class="chip pending">Waiting</span>
										<span class="chip">{PLATFORM[d.platform]}</span>
									</div>
									<div class="row-meta">
										Enrolled <span title={dateTime(d.enrolled_at_ms)}>
											{ago(d.enrolled_at_ms, now)}
										</span>
									</div>
								</div>
								<div class="row-actions">
									{#if approving?.device_id !== d.device_id && !deleting}
										<button class="primary small" type="button" onclick={() => startApprove(d)}>
											Review and approve
										</button>
									{/if}
									<button class="secondary small" type="button" onclick={() => confirmRemove(d)}>
										Not mine
									</button>
								</div>
							</div>
							{#if approving?.device_id === d.device_id && !deleting}
								<div class="approve">
									{#if !keyring.memberFor(user.id)}
										<UnlockKeys kind="member" {user}>
											{#snippet intro()}
												<h3>Unlock your keys to approve {d.name}</h3>
												<p class="muted">
													Approving signs this computer's key with your member key.
												</p>
											{/snippet}
										</UnlockKeys>
									{:else}
										<p>
											On <strong>{d.name}</strong>, Faro showed a <em>device key fingerprint</em> when
											it enrolled. Check that it is exactly:
										</p>
										<p class="code-display">{keyId(unb64(d.sign_pubkey))}</p>
										<p class="muted small">
											If it's different, or you didn't just set up this computer, don't approve it:
											choose "Not mine".
										</p>
										{#if anchor}
											<RecipientList title="{d.name} will encrypt to" list={anchor} />
										{:else if anchorError}
											<div class="notice error" role="alert"><p>{anchorError}</p></div>
										{:else}
											<p class="muted" role="status">Checking your recipient list…</p>
										{/if}
										<label class="check">
											<input type="checkbox" bind:checked={matches} />
											The fingerprint on the computer is the same, and so is the list above
										</label>
										{#if approveError}<div class="notice error" role="alert">
												<p>{approveError}</p>
											</div>{/if}
										<div class="actions">
											<button
												class="primary"
												type="button"
												disabled={!matches || approveBusy || !anchor}
												onclick={approve}
											>
												{approveBusy ? 'Approving…' : `Approve ${d.name}`}
											</button>
											<button class="secondary" type="button" onclick={() => (approving = null)}>
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

		<section class="section" aria-labelledby="add">
			<div class="section-head">
				<h2 id="add">Add a computer or an iPhone</h2>
				{#if !adding && session.hasMemberKeys && !deleting}
					<div class="actions inline">
						<button class="primary small" type="button" onclick={() => (adding = 'computer')}>
							Add a computer
						</button>
						<button class="primary small" type="button" onclick={() => (adding = 'iphone')}>
							Add an iPhone
						</button>
					</div>
				{/if}
			</div>
			{#if adding && !deleting}
				<div class="card">
					{#if !keyring.memberFor(user.id)}
						<UnlockKeys kind="member" {user}>
							{#snippet intro()}
								<h3>Unlock your keys</h3>
								<p class="muted">
									The enrollment link carries your key's fingerprint, so the {adding === 'iphone'
										? 'iPhone'
										: 'computer'} can check it is joining your account. It is read from your unlocked
									key.
								</p>
							{/snippet}
						</UnlockKeys>
					{:else}
						{#if adding === 'iphone'}
							<ol class="steps">
								<li>
									<strong>Install Faro</strong> on the iPhone from the App Store (or TestFlight in the
									beta), open it and read the first page.
								</li>
								<li>
									<strong>Get the enrollment link to the iPhone</strong> with a one-time code.
									{#if !code || remaining === 0}
										{#if codeError}<div class="notice error" role="alert">
												<p>{codeError}</p>
											</div>{/if}
										<div class="actions inline">
											<button class="primary" type="button" onclick={newCode} disabled={codeBusy}>
												{codeBusy
													? 'Creating…'
													: code
														? 'Create a new code'
														: 'Create an enrollment code'}
											</button>
										</div>
										{#if code}<p class="muted small">The last code expired.</p>{/if}
									{:else}
										<p class="muted small">Works once, for the next {remainingText}.</p>
										{#if linkState.error}<div class="notice error" role="alert">
												<p>{linkState.error}</p>
											</div>{/if}
										<p>In Faro on the iPhone, scan this code with the camera on the link screen:</p>
										<QrCode text={link} label="QR code for the iPhone enrollment link" />
										<p class="muted small">
											The code is made in this browser. The link is never sent anywhere to make it.
										</p>
										<p>Or copy the link and paste it into Faro on the iPhone:</p>
										<pre class="command"><code>{link}</code></pre>
										<div class="actions inline">
											<a class="button primary small" href={link}>Open in Faro</a>
											<button
												class="secondary small"
												type="button"
												onclick={() => copy(link, 'link')}
											>
												{#if copied === 'link'}
													<Icon name="check" /> Copied
												{:else}
													<Icon name="copy" /> Copy link
												{/if}
											</button>
										</div>
										<p class="muted small">
											"Open in Faro" works when this page is open on the iPhone itself.
										</p>
									{/if}
								</li>
								<li>
									<strong>Approve it here.</strong> It appears above as waiting, with a fingerprint to
									compare.
								</li>
							</ol>
						{:else}
							<ol class="steps">
								<li>
									<strong>Install Faro</strong> on the computer from the official, project-signed installer.
									The installer explains what is monitored.
								</li>
								<li>
									<strong>Enroll it</strong> with a one-time code.
									{#if !code || remaining === 0}
										{#if codeError}<div class="notice error" role="alert">
												<p>{codeError}</p>
											</div>{/if}
										<div class="actions inline">
											<button class="primary" type="button" onclick={newCode} disabled={codeBusy}>
												{codeBusy
													? 'Creating…'
													: code
														? 'Create a new code'
														: 'Create an enrollment code'}
											</button>
										</div>
										{#if code}<p class="muted small">The last code expired.</p>{/if}
									{:else}
										<p class="code-display big">{code.code}</p>
										<p class="muted small">Works once, for the next {remainingText}.</p>
										{#if linkState.error}<div class="notice error" role="alert">
												<p>{linkState.error}</p>
											</div>{/if}
										<p>On the computer, with Faro installed, open the enrollment link:</p>
										<div class="actions inline">
											<a class="button primary small" href={link}>Open in Faro</a>
											<button
												class="secondary small"
												type="button"
												onclick={() => copy(link, 'link')}
											>
												{#if copied === 'link'}
													<Icon name="check" /> Copied
												{:else}
													<Icon name="copy" /> Copy link
												{/if}
											</button>
										</div>
										<p class="muted small">
											Using another device? Copy the link and send it to the computer. There, choose
											<strong>Enroll this computer…</strong> from the Faro icon (in the menu bar on a
											Mac, the tray icon in the notification area on Windows) and paste it. An administrator
											of the computer approves: on a Mac with their name and password, on Windows in the
											administrator prompt.
										</p>
										<details>
											<summary>Or use a terminal</summary>
											<p>On a Mac, run this in Terminal:</p>
											<pre class="command"><code
													>sudo /Library/Faro/bin/faro-service enroll --link '{link}'</code
												></pre>
											<div class="actions inline">
												<button
													class="secondary small"
													type="button"
													onclick={() =>
														copy(
															`sudo /Library/Faro/bin/faro-service enroll --link '${link}'`,
															'command'
														)}
												>
													{#if copied === 'command'}
														<Icon name="check" /> Copied
													{:else}
														<Icon name="copy" /> Copy command
													{/if}
												</button>
											</div>
											<p>On Windows, run this in a terminal opened as administrator:</p>
											<pre class="command"><code
													>&amp; "C:\Program Files\Faro\faro-service.exe" enroll --link '{link}'</code
												></pre>
											<div class="actions inline">
												<button
													class="secondary small"
													type="button"
													onclick={() =>
														copy(
															`& "C:\\Program Files\\Faro\\faro-service.exe" enroll --link '${link}'`,
															'command-windows'
														)}
												>
													{#if copied === 'command-windows'}
														<Icon name="check" /> Copied
													{:else}
														<Icon name="copy" /> Copy command
													{/if}
												</button>
											</div>
										</details>
									{/if}
								</li>
								<li>
									<strong>Approve it here.</strong> It appears above as waiting, with a fingerprint to
									compare.
								</li>
							</ol>
						{/if}
						<button
							class="link"
							type="button"
							onclick={() => {
								adding = null;
								code = null;
							}}
						>
							Done
						</button>
					{/if}
				</div>
			{/if}
		</section>

		<section class="section" aria-labelledby="active">
			<h2 id="active">Monitored computers</h2>
			{#if loadError}
				<div class="notice error" role="alert"><p>{loadError}</p></div>
				<button class="secondary" type="button" onclick={load}>Try again</button>
			{:else if !devices}
				<p class="muted" role="status">Loading…</p>
			{:else if active.length === 0}
				<div class="empty"><p>No computers yet.</p></div>
			{:else}
				<ul class="rows">
					{#each active as d (d.device_id)}
						{@const s = seen(d)}
						<li>
							<div class="row-main">
								<div>
									<div class="row-title">
										<strong>{d.name}</strong>
										<span class="chip">{PLATFORM[d.platform]}</span>
										{#if d.platform === 'ios'}<span
												class="chip"
												title="It blocks sites and apps. It can't see the screen."
											>
												Blocks, doesn't watch
											</span>{/if}
										{#if s.stale}<span class="chip normal">Quiet</span>{:else}<span
												class="chip good"
											>
												Online
											</span>{/if}
									</div>
									<div class="row-meta">
										<span title={d.last_seen_at_ms ? dateTime(d.last_seen_at_ms) : undefined}>
											{s.text}
										</span>
										· added {date(d.enrolled_at_ms)} · key
										<code>{keyId(unb64(d.sign_pubkey))}</code>
									</div>
								</div>
								<button class="secondary small" type="button" onclick={() => confirmRemove(d)}>
									Remove…
								</button>
							</div>
						</li>
					{/each}
				</ul>
			{/if}
		</section>
	{/snippet}
</Gate>

<dialog bind:this={removeDialog} onclose={() => (removing = null)} aria-labelledby="remove-title">
	{#if removing}
		<h2 id="remove-title">Remove {removing.name}?</h2>
		{#if removing.status === 'active'}
			<p>
				It stops reporting, and its key stops working on this server. Your allies get an urgent
				alert that a computer was removed.
			</p>
			<p class="muted">To stop monitoring for good, also uninstall Faro on that computer.</p>
		{:else}
			<p>
				It was never approved, so it never monitored anything. Removing it cancels its enrollment.
				If you don't recognise it, removing it is the right thing to do.
			</p>
		{/if}
		{#if removeError}<div class="notice error" role="alert"><p>{removeError}</p></div>{/if}
		<div class="actions">
			<button class="danger" type="button" onclick={remove} disabled={removeBusy}>
				{removeBusy ? 'Removing…' : 'Remove'}
			</button>
			<button class="secondary" type="button" onclick={() => removeDialog?.close()}>Cancel</button>
		</div>
	{/if}
</dialog>

<style>
	.section-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
		margin-bottom: 0.75rem;
	}

	.section-head h2 {
		margin: 0;
	}

	.approve {
		margin-top: 1rem;
		padding-top: 1rem;
		border-top: 1px dashed var(--border);
	}

	/* Device names, check-in times and dates are data: the code face. */
	.row-meta {
		font-family: var(--mono);
		font-size: 0.78rem;
		letter-spacing: -0.01em;
	}

	.row-meta code {
		font-size: inherit;
	}

	.big {
		font-size: 1.6rem;
		letter-spacing: 0.14em;
		width: fit-content;
		margin: 0.6rem 0 0.25rem;
	}

	.command {
		margin: 0;
	}

	details {
		margin-top: 0.9rem;
	}

	summary {
		font-family: var(--mono);
		font-size: 0.8rem;
		color: var(--muted);
	}

	summary:hover {
		color: var(--text);
	}

	details[open] summary {
		margin-bottom: 0.6rem;
	}

	.actions.inline {
		margin-top: 0.75rem;
	}
</style>
