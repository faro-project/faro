<script lang="ts">
	// A signed, encrypted message (a reach out's text, or a note on a
	// proposal or join request), opened here in the browser (GROUPS.md
	// §10.2). It is shown only if the author's signature checks out; the
	// server can't read it or write one in someone's name. Whether the key
	// is really the author's is what comparing safety codes tells you.
	import { epochKeyFor } from '../check-in-api.ts';
	import { instance } from '../instance.svelte.ts';
	import { keyring } from '../keys/keyring.svelte.ts';
	import { getMessage, reachOutError } from '../reach-out-api.ts';
	import { readMessage, type MessageView } from '../reach-out.ts';
	import { loadRoster } from '../roster-api.ts';
	import type { User } from '../types.ts';
	import UnlockKeys from './UnlockKeys.svelte';

	let {
		messageId,
		user,
		author = null
	}: {
		messageId: string;
		user: User;
		/** Who the page says wrote it: anything signed by someone else is refused. */
		author?: string | null;
	} = $props();

	let view = $state<MessageView | null>(null);
	let error = $state('');
	let unlocking = $state(false);
	let unlockKind = $state<'member' | 'ally'>('member');
	let loadedFor = '';
	/** The key of a whole-group message's epoch, opened against the verified roster. */
	let epochKey = $state.raw<Uint8Array | null>(null);
	let epochTried = '';

	$effect(() => {
		if (messageId === loadedFor) return;
		loadedFor = messageId;
		view = null;
		error = '';
		void instance.load().catch(() => {});
		getMessage(messageId)
			.then((v) => (view = v))
			.catch((e) => (error = reachOutError(e)));
	});

	$effect(() => {
		unlockKind = user.roles.member ? 'member' : 'ally';
	});

	// A whole-group message opens with its epoch's key: once something is
	// unlocked, check the group's roster and open this browser's copy of it.
	$effect(() => {
		const m = view?.message;
		const unlockedNow = !!keyring.memberFor(user.id) || !!keyring.allyFor(user.id);
		if (!m || m.epoch == null || !m.group_id || !unlockedNow) return;
		const key = `${m.item_id}:${m.epoch}`;
		if (epochTried === key) return;
		epochTried = key;
		const { group_id, epoch } = m;
		void loadRoster(group_id, user.id)
			.then((r) => epochKeyFor(group_id, user.id, r.state, epoch))
			.then((k) => (epochKey = k?.key ?? null))
			.catch(() => {
				epochTried = '';
			});
	});

	let result = $derived(
		view
			? readMessage(
					view,
					user.id,
					{ member: keyring.member, ally: keyring.ally, epochKey },
					instance.info?.instance_id,
					author
				)
			: null
	);

	$effect(() => {
		if (result?.status === 'invalid') console.warn('refused a group message:', result.reason);
	});
</script>

{#if error}
	<p class="muted small">The message couldn't be loaded. {error}</p>
{:else if !view || !result}
	<p class="muted small" role="status">Loading the message…</p>
{:else if result.status === 'invalid'}
	<div class="notice warn small" role="alert">
		<p>This message's signature doesn't check out, so it isn't shown.</p>
	</div>
{:else if result.status === 'locked'}
	{#if unlocking}
		<UnlockKeys kind={unlockKind} {user} onunlocked={() => (unlocking = false)}>
			{#snippet intro()}
				<h3>Unlock to read</h3>
				<p class="muted small">
					The message is encrypted for you. Your passphrase opens it here, in this tab.
				</p>
			{/snippet}
		</UnlockKeys>
		{#if user.roles.member && user.roles.ally}
			<button
				class="link small"
				type="button"
				onclick={() => (unlockKind = unlockKind === 'member' ? 'ally' : 'member')}
			>
				{unlockKind === 'member' ? 'Use my ally key instead' : 'Use my member key instead'}
			</button>
		{/if}
	{:else}
		<p class="small">
			{view.author.display_name} wrote a message.
			<button class="link" type="button" onclick={() => (unlocking = true)}>Unlock to read</button>
		</p>
	{/if}
{:else if result.status === 'unreadable'}
	<p class="muted small">None of your unlocked keys opens this message.</p>
{:else}
	{#if result.text !== null}
		<blockquote class="note">{result.text}</blockquote>
	{/if}
	<p class="muted small">
		{#if result.verified === 'verified'}
			✓ Signed by {view.author.display_name}, whose key you checked with a safety code.
		{:else if result.verified === 'changed'}
			<span class="warn">
				Signed with a key that isn't the one you checked with {view.author.display_name}. They may
				have set up new keys; compare safety codes again to be sure.
			</span>
		{:else if view.author.user_id === user.id}
			Signed by you.
		{:else}
			Signed with {view.author.display_name}'s key. Not yet verified: comparing safety codes in
			person confirms it's theirs.
		{/if}
	</p>
{/if}

<style>
	.note {
		margin: 0.4rem 0 0.2rem;
		padding: 0.5rem 0.75rem;
		border-left: 3px solid var(--border-strong);
		white-space: pre-wrap;
		overflow-wrap: anywhere;
	}

	.warn {
		color: var(--warn, inherit);
	}
</style>
