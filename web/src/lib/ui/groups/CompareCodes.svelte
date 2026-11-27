<script lang="ts">
	// Comparing safety codes with one person (GROUPS.md §7.4, §7.5), on one
	// screen: if they are your ally and waiting for you, you compare their
	// code and approve them; if you are their ally and waiting for them, you
	// read them your code and they approve you on their side. A partnership
	// shows both. Each person approves only their own side, and approving
	// is the same signing the Allies page does (keys/approve.ts), so nothing
	// here can make a link active some other way. The list it signs is built
	// on the checked latest one and shown first; other allies keep the names
	// it signed (a new name is confirmed on the Allies page).
	import { api } from '#lib/api.ts';
	import type { RecipientManifest, Signed } from '#lib/crypto/proto.ts';
	import { instance } from '#lib/instance.svelte.ts';
	import {
		approvalManifest,
		approveAlly,
		approveErrorMessage,
		codeForAlly
	} from '#lib/keys/approve.ts';
	import { keyring } from '#lib/keys/keyring.svelte.ts';
	import { ensureManifest } from '#lib/keys/member.ts';
	import type { AllyLink, MyAllies, SupportedMember, User } from '#lib/types.ts';
	import AllySafetyCode from '../AllySafetyCode.svelte';
	import RecipientList from '../RecipientList.svelte';
	import UnlockKeys from '../UnlockKeys.svelte';

	let {
		person,
		user,
		ondone
	}: {
		person: { id: string; name: string };
		user: User;
		/** Something changed (an approval): reload what depends on it. */
		ondone?: () => void;
	} = $props();

	let mine = $state<AllyLink | null>(null);
	let theirs = $state<SupportedMember | null>(null);
	let loaded = $state(false);
	/** The checked latest list, which approving builds on. */
	let base = $state<Signed<RecipientManifest> | null>(null);
	let baseFor = '';
	let error = $state('');
	let match = $state(false);
	let busy = $state(false);
	let approved = $state(false);

	async function load() {
		error = '';
		try {
			const [allies, members] = await Promise.all([
				api.get<MyAllies>('/v1/me/allies').catch(() => null),
				api.get<SupportedMember[]>('/v1/ally/members').catch(() => null)
			]);
			mine = allies?.allies.find((a) => a.ally_id === person.id && a.state === 'pending') ?? null;
			theirs = members?.find((m) => m.member_id === person.id && m.state === 'pending') ?? null;
		} catch (e) {
			error = approveErrorMessage(e);
		}
		loaded = true;
	}

	$effect(() => {
		void person.id;
		void load();
	});

	let keys = $derived(keyring.memberFor(user.id));
	let code = $derived(mine ? codeForAlly(keys, mine) : null);
	let next = $derived(base && mine?.ally_enc_pubkey ? approvalManifest(base, mine) : null);

	async function loadBase() {
		const inst = instance.info;
		if (!keys || !inst) return;
		baseFor = person.id;
		try {
			base = await ensureManifest(keys, inst.instance_id);
		} catch (e) {
			base = null;
			error = approveErrorMessage(e);
		}
	}

	$effect(() => {
		if (keys && code && !base && baseFor !== person.id) void loadBase();
	});

	async function approve() {
		const link = mine;
		const inst = instance.info;
		if (!link || !keys || !inst || !base) return;
		busy = true;
		error = '';
		try {
			await approveAlly(keys, inst.instance_id, link, base);
			base = null;
			baseFor = '';
			approved = true;
			match = false;
			ondone?.();
			await load();
		} catch (e) {
			error = approveErrorMessage(e);
			// The list may have changed meanwhile: check it again.
			base = null;
			baseFor = '';
		} finally {
			busy = false;
		}
	}
</script>

{#if !loaded}
	<p class="muted" role="status">Loading…</p>
{:else}
	{#if approved}
		<div class="notice ok" role="status">
			<p>
				✓ {person.name} is now your ally. Your computers start encrypting to them within a few minutes.
			</p>
		</div>
	{/if}

	{#if mine && theirs}
		<p>
			You're partnering up with <strong>{person.name}</strong>. You each compare a code and approve
			the other. <strong>Each of you approves only your own side:</strong> you approve {person.name},
			and
			{person.name} approves you.
		</p>
	{/if}

	{#if mine}
		<section class="side" aria-labelledby="approve-h">
			<h3 id="approve-h">Approve {person.name} as your ally</h3>
			{#if !keys}
				<UnlockKeys kind="member" {user}>
					{#snippet intro()}
						<p class="muted">
							The safety code is worked out from your own key, so it needs unlocking.
						</p>
					{/snippet}
				</UnlockKeys>
			{:else if !code}
				<div class="notice error">
					<p>{person.name} has no key yet. Ask them to accept again.</p>
				</div>
			{:else}
				<p>
					Ask <strong>{person.name}</strong> to open Faro and read you their safety code, in person or
					on a call (not by email or text). It must be exactly:
				</p>
				<p class="code-display digits" aria-label="Safety code to match">
					{#each code.split(' ') as g, i (i)}<span>{g}</span>{/each}
				</p>
				{#if next && base}
					<RecipientList title="Your recipient list with {person.name}" list={next} {base} />
				{:else}
					<p class="muted" role="status">Checking your recipient list…</p>
				{/if}
				<label class="check">
					<input type="checkbox" bind:checked={match} />
					{person.name}'s code is the same
				</label>
				<div class="actions">
					<button
						class="primary"
						type="button"
						disabled={!match || busy || !next}
						onclick={approve}
					>
						{busy ? 'Approving…' : `Approve ${person.name}`}
					</button>
				</div>
			{/if}
		</section>
	{/if}

	{#if theirs}
		<section class="side" aria-labelledby="show-h">
			<h3 id="show-h">{person.name} approves you</h3>
			<AllySafetyCode member={theirs} viewer={user} />
		</section>
	{/if}

	{#if !mine && !theirs && !approved}
		<p class="muted">There is nothing waiting to compare with {person.name} right now.</p>
	{/if}
	{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
{/if}

<style>
	.side {
		margin: 1rem 0;
		padding-top: 1rem;
		border-top: 1px dashed var(--border);
	}

	.side h3 {
		margin-top: 0;
	}
</style>
