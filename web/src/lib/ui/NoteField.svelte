<script lang="ts">
	// An optional short message, signed with your member key and encrypted
	// to the people it is for (GROUPS.md §10.2). Writing one needs your keys
	// unlocked, to sign it; without member keys there is no message field,
	// only a line saying why.
	import { keyring } from '../keys/keyring.svelte.ts';
	import { MAX_NOTE_CHARS, noteLength } from '../reach-out.ts';
	import type { User } from '../types.ts';
	import UnlockKeys from './UnlockKeys.svelte';

	let {
		user,
		text = $bindable(''),
		canSign,
		alwaysSign = false,
		label = 'Add a note (optional)',
		placeholder = '',
		id = `note-${Math.random().toString(36).slice(2, 8)}`
	}: {
		user: User;
		text?: string;
		/** You have member keys. */
		canSign: boolean;
		/** Offer to unlock even with no text (what is sent is signed either way). */
		alwaysSign?: boolean;
		label?: string;
		placeholder?: string;
		id?: string;
	} = $props();

	let n = $derived(noteLength(text));
	let unlocked = $derived(!!keyring.memberFor(user.id));
</script>

{#if canSign}
	<div class="field">
		<label for={id}>{label}</label>
		<textarea
			{id}
			rows="3"
			bind:value={text}
			{placeholder}
			aria-describedby="{id}-count"
			aria-invalid={n > MAX_NOTE_CHARS ? 'true' : undefined}></textarea>
		<span class="hint" id="{id}-count" class:over={n > MAX_NOTE_CHARS}>
			<span class="count">{n} / {MAX_NOTE_CHARS}</span>. Encrypted to them and signed by you: the
			server can't read it.
		</span>
	</div>
	{#if (alwaysSign || text.trim()) && !unlocked}
		<UnlockKeys kind="member" {user}>
			{#snippet intro()}
				<h3>Unlock your keys to sign it</h3>
				<p class="muted small">Your signature shows it really comes from you.</p>
			{/snippet}
		</UnlockKeys>
	{/if}
{:else}
	<p class="muted small">
		Notes are signed with member keys, which you don't have, so this goes without one.
	</p>
{/if}

<style>
	.count {
		font-family: var(--mono);
		font-size: 0.8rem;
		font-variant-numeric: tabular-nums;
	}

	.over {
		color: var(--danger);
	}

	.over .count {
		font-weight: 600;
	}
</style>
