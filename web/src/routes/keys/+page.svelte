<script lang="ts">
	// Member keys (ARCHITECTURE.md §5.2, §7 "Member" step 1).
	//
	// A member's signing key is the root of trust for their setup: it
	// approves their computers and allies and signs the recipient list their
	// computers encrypt to. It is generated here, wrapped with the member's
	// passphrase (and a recovery code) and only then uploaded, so the server
	// never sees it. Right after, the browser signs the first recipient
	// list (version 1, no allies yet), which enrolling a computer needs.

	import { resolve } from '$app/paths';
	import { ApiError, describeError } from '#lib/api.ts';
	import type { RecipientManifest } from '#lib/crypto/proto.ts';
	import { formatKeyId, keyId } from '#lib/crypto/keys.ts';
	import { unb64 } from '#lib/crypto/bytes.ts';
	import { date } from '#lib/format.ts';
	import { instance } from '#lib/instance.svelte.ts';
	import { keyring } from '#lib/keys/keyring.svelte.ts';
	import {
		createMemberKeys,
		ensureManifest,
		getMemberKeys,
		latestManifest
	} from '#lib/keys/member.ts';
	import { session } from '#lib/session.svelte.ts';
	import type { MemberKeysBlob, User, WellKnown } from '#lib/types.ts';
	import Gate from '#lib/ui/Gate.svelte';
	import NewPassphrase from '#lib/ui/NewPassphrase.svelte';
	import RecipientList from '#lib/ui/RecipientList.svelte';
	import RecoveryCode from '#lib/ui/RecoveryCode.svelte';
	import UnlockKeys from '#lib/ui/UnlockKeys.svelte';

	type View = 'loading' | 'create' | 'recovery' | 'existing' | 'error';

	let view = $state<View>('loading');
	let blob = $state<MemberKeysBlob | null>(null);
	let error = $state('');
	let passphrase = $state('');
	let picker = $state<ReturnType<typeof NewPassphrase> | null>(null);
	let busy = $state(false);
	let progress = $state(0);
	let recoveryCode = $state('');
	let manifestState = $state<'unknown' | 'checking' | 'missing' | 'ok' | 'error'>('unknown');
	let manifestError = $state('');
	let current = $state<RecipientManifest | null>(null);
	let loadedFor = '';

	async function load(user: User) {
		loadedFor = user.id;
		view = 'loading';
		error = '';
		try {
			blob = await getMemberKeys();
			view = blob ? 'existing' : 'create';
		} catch (e) {
			error = describeError(e);
			view = 'error';
		}
	}

	async function create(e: SubmitEvent, user: User, inst: WellKnown) {
		e.preventDefault();
		error = '';
		if (!picker?.check()) return;
		busy = true;
		progress = 0;
		try {
			const created = await createMemberKeys(
				user,
				inst.instance_id,
				passphrase,
				(f) => (progress = f)
			);
			passphrase = '';
			keyring.setMember(created.keys);
			session.hasMemberKeys = true;
			recoveryCode = created.recoveryCode;
			view = 'recovery';
			// Sign the first recipient list while they read the code.
			void checkManifest(user, inst, true);
		} catch (err) {
			if (err instanceof ApiError && err.code === 'keys_already_set') {
				await load(user);
				error = 'Your keys were already set up, perhaps in another tab. Unlock them below.';
			} else {
				error = describeError(err);
			}
		} finally {
			busy = false;
		}
	}

	async function checkManifest(user: User, inst: WellKnown, create: boolean) {
		const keys = keyring.memberFor(user.id);
		if (!keys) return;
		manifestState = 'checking';
		manifestError = '';
		try {
			// The first list names only the member: allies are added by
			// approving them, never from what the server lists.
			current = create
				? await ensureManifest(keys, inst.instance_id)
				: await latestManifest(keys, inst.instance_id);
			manifestState = current ? 'ok' : 'missing';
		} catch (e) {
			manifestError = e instanceof Error && !(e instanceof ApiError) ? e.message : describeError(e);
			manifestState = 'error';
		}
	}

	$effect(() => {
		const u = session.user;
		if (u?.roles.member && u.id !== loadedFor) void load(u);
	});

	// Once the keys are unlocked, check the recipient list.
	$effect(() => {
		const u = session.user;
		const inst = instance.info;
		if (u && inst && view === 'existing' && keyring.member && manifestState === 'unknown') {
			void checkManifest(u, inst, false);
		}
	});

	async function recoveryDone() {
		recoveryCode = '';
		const user = session.user;
		if (user) await load(user);
	}
</script>

<svelte:head>
	<title>Your keys · Faro</title>
</svelte:head>

<Gate role="member">
	{#snippet children(user, inst)}
		<div class="page-head">
			<h1>Your keys</h1>
			<p>
				Your keys are made and kept in your browser. They approve your computers and allies, and
				open your reports. The server stores them locked with your passphrase, which it never sees.
			</p>
		</div>

		{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}

		{#if view === 'loading'}
			<p class="muted" role="status">Loading…</p>
		{:else if view === 'create'}
			<form class="card" onsubmit={(e) => create(e, user, inst)} novalidate>
				<h2>Choose a passphrase</h2>
				<p>
					You'll type it when you approve a computer or an ally, or read your reports. After this
					you'll get a recovery code in case you forget it.
				</p>
				<NewPassphrase bind:this={picker} bind:value={passphrase} />
				{#if busy}
					<progress max="1" value={progress} aria-label="Creating your keys"></progress>
				{/if}
				<div class="actions">
					<button class="primary" type="submit" disabled={busy}>
						{busy ? 'Creating your keys…' : 'Create my keys'}
					</button>
				</div>
			</form>
		{:else if view === 'recovery'}
			<RecoveryCode code={recoveryCode} ondone={recoveryDone} />
		{:else if view === 'existing' && blob}
			<section class="card">
				<h2>Your member key</h2>
				<dl class="facts">
					<dt>Fingerprint</dt>
					<dd><code>{formatKeyId(keyId(unb64(blob.sign_pubkey)))}</code></dd>
					<dt>Created</dt>
					<dd>{date(blob.created_at_ms)}</dd>
					<dt>In this tab</dt>
					<dd>{keyring.memberFor(user.id) ? 'Unlocked' : 'Locked'}</dd>
				</dl>
				<p class="muted small">
					When you set up Faro on a computer, it checks that it is talking to this key. The
					enrollment link shown on the Computers page carries the fingerprint.
				</p>
			</section>

			{#if !keyring.memberFor(user.id)}
				<div class="section-gap">
					<UnlockKeys kind="member" {user} />
				</div>
			{:else}
				<section class="card">
					<h2>Recipient list</h2>
					{#if manifestState === 'unknown' || manifestState === 'checking'}
						<p class="muted" role="status">Checking…</p>
					{:else if manifestState === 'ok'}
						<p>
							<span class="chip good">✓ Signed</span> Your computers encrypt to you and to the allies
							you have approved, as listed in the recipient list you signed.
						</p>
						{#if current}
							<RecipientList title="Your computers encrypt to" list={current} />
						{/if}
						<div class="actions">
							<a class="button primary" href={resolve('/computers')}>Add a computer</a>
							<a class="button secondary" href={resolve('/allies')}>Invite an ally</a>
						</div>
					{:else if manifestState === 'missing'}
						<p>
							Your computers need a recipient list signed by you before they can start. Sign the
							first one now.
						</p>
						<div class="actions">
							<button class="primary" type="button" onclick={() => checkManifest(user, inst, true)}>
								Sign my recipient list
							</button>
						</div>
					{:else}
						<div class="notice error" role="alert"><p>{manifestError}</p></div>
						<button
							class="secondary"
							type="button"
							onclick={() => checkManifest(user, inst, false)}
						>
							Try again
						</button>
					{/if}
				</section>
			{/if}
		{/if}
	{/snippet}
</Gate>

<style>
	.section-gap {
		margin-top: 1rem;
	}

	progress {
		margin-top: 0.5rem;
	}
</style>
