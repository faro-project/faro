<script lang="ts">
	// "Group encryption" (GROUPS.md §10.3, §10.5): the group's signed member
	// list, the keys people need for it, and the roster work facilitators'
	// browsers do.
	//
	// * Everyone: the roster is checked against this browser's checkpoint
	//   (`roster-sync.ts`). Anything that doesn't check out is refused, the
	//   last accepted list is kept, and a warning is shown.
	// * Someone with no encryption key creates one (passphrase and recovery
	//   code, stored like an ally key).
	// * Facilitators: once their keys are unlocked, their browser signs what
	//   is pending (leaves and removals) and rotates the group key. Joins,
	//   other people's new keys and role changes are shown for approval
	//   first: they add a reader with a key from the server, or change who
	//   signs the member list, on the server's word. An ally-only
	//   facilitator first makes a group signing key (decision 6).
	// * While someone who left is still in the signed list, whole-group
	//   posting waits: "Waiting for a facilitator to update the group".
	import { onDestroy, untrack } from 'svelte';
	import { api, describeError, seg } from '../../api.ts';
	import { b64, unb64, wipe, type Bytes } from '../../crypto/bytes.ts';
	import { formatKeyId, keyId, signPublicKey } from '../../crypto/keys.ts';
	import { checkpointOf, type RosterChange, type RosterState } from '../../crypto/roster.ts';
	import { getAllyKey, newAllyKey } from '../../keys/ally.ts';
	import { keyring } from '../../keys/keyring.svelte.ts';
	import { getMemberKeys } from '../../keys/member.ts';
	import {
		canSign,
		createGroupSignKey,
		getGroupSignKey,
		loadRoster,
		openGroupSignKey,
		rosterPending,
		signPendingWork,
		type Signer
	} from '../../roster-api.ts';
	import { changeKey, type RosterPending } from '../../roster-sync.ts';
	import type { GroupView, Page, RosterEntry as Person, User } from '../../types.ts';
	import NewPassphrase from '../NewPassphrase.svelte';
	import RecoveryCode from '../RecoveryCode.svelte';
	import UnlockKeys from '../UnlockKeys.svelte';

	let {
		group,
		user,
		onstatus
	}: {
		group: GroupView;
		user: User;
		/** Whole-group posting must wait while `postingPaused`. */
		onstatus?: (s: { postingPaused: boolean; roster: RosterState | null }) => void;
	} = $props();

	let keyKind = $state<'member' | 'ally' | 'none' | null>(null);
	let roster = $state.raw<RosterState | null>(null);
	let warning = $state('');
	let pending = $state.raw<RosterPending | null>(null);
	let needsApproval = $state.raw<RosterChange[]>([]);
	let refused = $state.raw<RosterChange[]>([]);
	let names = $state<Record<string, string>>({});
	let hasSignKey = $state<boolean | null>(null);
	let signSeed = $state.raw<Bytes | null>(null);
	let busy = $state(false);
	let error = $state('');
	let loadError = $state('');
	let autoRanFor = '';

	let isFacilitator = $derived(
		group.my_role === 'facilitator' && !group.archived_at_ms && !group.groups_disabled
	);
	let inRoster = $derived(!!roster && Object.hasOwn(roster.members, user.id));
	let memberCount = $derived(roster ? Object.keys(roster.members).length : 0);

	async function refresh() {
		loadError = '';
		try {
			if (keyKind === null || keyKind === 'none') {
				keyKind = (await getMemberKeys()) ? 'member' : (await getAllyKey()) ? 'ally' : 'none';
			}
			const r = await loadRoster(group.id, user.id);
			roster = r.state;
			warning = r.warning ?? '';
			pending = await rosterPending(group.id);
			onstatus?.({ postingPaused: pending.posting_paused, roster });
		} catch (e) {
			loadError = describeError(e);
		}
	}

	$effect(() => {
		if (group.id && user.id) untrack(() => void refresh());
	});

	onDestroy(() => wipe(signSeed));

	// An ally-only facilitator's group signing key, opened with the ally key.
	$effect(() => {
		const ally = keyring.allyFor(user.id);
		if (!isFacilitator || keyKind !== 'ally' || !ally || signSeed) return;
		getGroupSignKey()
			.then((blob) => {
				hasSignKey = !!blob;
				if (blob) signSeed = openGroupSignKey(blob, ally);
			})
			.catch((e) => (error = e instanceof Error ? e.message : describeError(e)));
	});

	function signer(): Signer | null {
		if (keyKind === 'member') {
			const k = keyring.memberFor(user.id);
			return k ? { userId: user.id, seed: k.signSeed, encPk: k.encPk } : null;
		}
		if (keyKind === 'ally') {
			const a = keyring.allyFor(user.id);
			return a && signSeed ? { userId: user.id, seed: signSeed, encPk: a.encPk } : null;
		}
		return null;
	}

	let unlocked = $derived(
		keyKind === 'member' ? !!keyring.member : keyKind === 'ally' ? !!keyring.ally : false
	);
	let signerNow = $derived(unlocked && (keyKind === 'member' || !!signSeed) ? signer() : null);
	let mayAct = $derived(!!signerNow && !!roster && canSign(roster, signerNow));

	async function work(approved?: Set<string>) {
		const s = signer();
		if (!s || !roster || warning) return;
		busy = true;
		error = '';
		try {
			const r = await signPendingWork(group.id, roster, s, approved);
			roster = r.state;
			pending = r.pending;
			needsApproval = r.needsApproval;
			refused = r.refused;
			onstatus?.({ postingPaused: pending.posting_paused, roster });
		} catch (e) {
			error =
				e instanceof Error && !(e as { status?: number }).status ? e.message : describeError(e);
		} finally {
			busy = false;
		}
	}

	// Pending work is done automatically when a facilitator's keys are open.
	$effect(() => {
		if (!isFacilitator || !mayAct || !pending || warning || busy) return;
		const key = `${checkpointOf(roster!)?.seq ?? -1}:${pending.changes.length}`;
		if (key === autoRanFor || pending.changes.length === 0) return;
		autoRanFor = key;
		void work();
	});

	// Names for the approval list.
	$effect(() => {
		const ids = needsApproval.map((c) => c.user_id).filter((id) => !(id in names));
		if (!ids.length) return;
		void (async () => {
			const found: Record<string, string> = {};
			let cursor: string | null = null;
			for (let i = 0; i < 50 && ids.some((id) => !(id in found)); i++) {
				const qs: string = cursor ? `?cursor=${encodeURIComponent(cursor)}` : '';
				const page: Page<Person> = await api
					.get<Page<Person>>(`/v1/groups/${seg(group.id)}/participants${qs}`)
					.catch(() => ({ items: [], next_cursor: null }));
				for (const p of page.items) found[p.user_id] = p.display_name;
				cursor = page.next_cursor;
				if (!cursor) break;
			}
			// Asked once per person, found or not.
			for (const id of ids) found[id] ??= 'Someone no longer in the group';
			names = { ...names, ...found };
		})();
	});

	function describe(c: RosterChange): string {
		switch (c.kind) {
			case 'join':
				return c.role === 'facilitator' ? 'joins, as a facilitator' : 'joins';
			case 'keys':
				return 'has a new key';
			case 'role':
				return c.role === 'facilitator' ? 'becomes a facilitator' : 'stops being a facilitator';
			case 'leave':
				return 'leaves the group';
			case 'remove':
				return 'is removed from the group';
		}
	}

	function keyOf(c: RosterChange): string {
		if (c.kind !== 'join' && c.kind !== 'keys') return '';
		try {
			return formatKeyId(keyId(unb64(c.enc_pubkey)));
		} catch {
			return '?';
		}
	}

	// Someone with no encryption key makes one.
	let passphrase = $state('');
	let picker = $state<ReturnType<typeof NewPassphrase> | null>(null);
	let progress = $state(0);
	let recoveryCode = $state('');

	async function createEncKey(e: SubmitEvent) {
		e.preventDefault();
		if (!picker?.check()) return;
		busy = true;
		error = '';
		progress = 0;
		try {
			const k = await newAllyKey(user.id, passphrase, (f) => (progress = f));
			await api.put('/v1/me/ally-key', {
				enc_pubkey: b64(k.key.encPk),
				wrapped_privkey: k.wrapped
			});
			passphrase = '';
			keyring.setAlly(k.key);
			keyKind = 'ally';
			recoveryCode = k.recoveryCode;
		} catch (err) {
			error = describeError(err);
		} finally {
			busy = false;
		}
	}

	// An ally-only facilitator makes a group signing key.
	async function createSignKey() {
		const ally = keyring.allyFor(user.id);
		if (!ally) return;
		busy = true;
		error = '';
		try {
			signSeed = await createGroupSignKey(ally);
			hasSignKey = true;
			await refresh();
		} catch (err) {
			error = describeError(err);
		} finally {
			busy = false;
		}
	}

	let mySignListed = $derived(
		!!roster && !!signSeed && roster.members[user.id]?.sign_pubkey === b64(signPublicKey(signSeed))
	);
</script>

<section class="section" aria-labelledby="group-keys-h">
	<h2 id="group-keys-h">Group encryption</h2>

	{#if warning}
		<div class="notice warn" role="alert"><p>{warning}</p></div>
	{/if}
	{#if loadError}
		<div class="notice error" role="alert"><p>{loadError}</p></div>
	{/if}
	{#if pending?.posting_paused}
		<div class="notice info" role="status">
			<p>
				Waiting for a facilitator to update the group. Posts to the whole group are paused until
				then; you can still send to people by name.
			</p>
		</div>
	{/if}

	{#if recoveryCode}
		<RecoveryCode
			code={recoveryCode}
			ondone={() => {
				recoveryCode = '';
				void refresh();
			}}
		/>
	{:else if keyKind === 'none'}
		<form class="card" onsubmit={createEncKey} novalidate>
			<h3>Create your encryption key</h3>
			<p>
				What people share with the whole group is encrypted in their browsers, so only people in the
				group can read it. To receive it, you need a key of your own. Choose a passphrase to protect
				it; Faro then shows you a recovery code.
			</p>
			<NewPassphrase bind:this={picker} bind:value={passphrase} id="group-enc-passphrase" />
			{#if busy}<progress max="1" value={progress} aria-label="Creating your key"></progress>{/if}
			{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
			<div class="actions">
				<button class="primary" type="submit" disabled={busy}>Create my key</button>
			</div>
		</form>
	{:else if roster}
		<p class="muted">
			{#if inRoster}
				This browser checked the group's signed member list: {memberCount}
				{memberCount === 1 ? 'person' : 'people'}, update {roster.next_seq}.
			{:else if roster.next_seq === 0}
				The group's member list hasn't been signed yet.
			{:else}
				Waiting for a facilitator to add you to the group's encryption.
			{/if}
		</p>
	{/if}

	{#if isFacilitator && keyKind && keyKind !== 'none' && !recoveryCode}
		{#if !unlocked}
			{#if pending && (pending.changes.length > 0 || pending.snapshot_due)}
				<UnlockKeys kind={keyKind} {user}>
					{#snippet intro()}
						<h3>Update the group</h3>
						<p class="muted">
							The group's member list has changes to sign. Unlock your
							{keyKind === 'member' ? 'keys' : 'key'} and your browser signs them and makes a new group
							key, so people who left can't read what comes next.
						</p>
					{/snippet}
				</UnlockKeys>
			{/if}
		{:else if keyKind === 'ally' && hasSignKey === false}
			<div class="card">
				<h3>Make your signing key</h3>
				<p>
					As a facilitator, you sign the group's member list, so everyone can check that the server
					didn't add anyone. That needs a signing key. Faro makes it in your browser and keeps it
					locked with your encryption key, under the same passphrase and recovery code.
				</p>
				{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
				<div class="actions">
					<button class="primary" type="button" disabled={busy} onclick={createSignKey}>
						Make my signing key
					</button>
				</div>
			</div>
		{:else if signerNow && roster && !mayAct}
			<p class="muted small">
				{#if keyKind === 'ally' && !mySignListed}
					Another facilitator's browser adds your signing key to the group the next time they open
					it. Until then, they sign the group's changes.
				{:else}
					Another facilitator's browser signs the group's changes.
				{/if}
			</p>
		{:else if mayAct}
			{#if busy}<p class="muted" role="status">Updating the group…</p>{/if}
			{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
			{#if refused.length}
				<div class="notice warn" role="alert">
					<p>
						The server offered keys for you that aren't the ones in your browser. They weren't
						signed. Ask the person who runs this instance.
					</p>
				</div>
			{/if}
			{#if needsApproval.length}
				<div class="card">
					<h3>Changes to the group's member list</h3>
					<p>
						The server says these changes are due. Each one changes who can read what the group
						shares, or who facilitates it, so your browser signs it only once you approve. Check
						that each is something the group expects. Key ids are shown so you can compare them.
					</p>
					<ul class="approve">
						{#each needsApproval as c (c.user_id)}
							<li>
								<strong>{c.user_id === user.id ? 'You' : (names[c.user_id] ?? c.user_id)}</strong>
								{describe(c)}
								<span class="mono small">{keyOf(c)}</span>
							</li>
						{/each}
					</ul>
					<div class="actions">
						<button
							class="primary"
							type="button"
							disabled={busy}
							onclick={() => work(new Set(needsApproval.map(changeKey)))}
						>
							Approve {needsApproval.length === 1 ? 'it' : `all ${needsApproval.length}`}
						</button>
					</div>
				</div>
			{/if}
		{/if}
		{#if pending?.waiting_for_keys.length}
			<p class="muted small">
				{pending.waiting_for_keys.length}
				{pending.waiting_for_keys.length === 1 ? 'person has' : 'people have'} no encryption key yet.
				They're added once they open the group and make one.
			</p>
		{/if}
	{/if}
</section>

<style>
	.approve {
		padding-left: 1.2rem;
	}

	.approve li {
		margin: 0.25rem 0;
	}
</style>
