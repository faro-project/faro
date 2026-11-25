<script lang="ts">
	// Unlock the member keys or the ally key with the passphrase (or the
	// recovery code). Decryption happens here, in the browser; the server
	// only ever sees the wrapped form.
	import { onMount, type Snippet } from 'svelte';
	import { resolve } from '$app/paths';
	import { describeError } from '../api.ts';
	import { normalizeRecoveryCode, UnwrapError } from '../crypto/passphrase.ts';
	import { getAllyKey, unlockAllyKey } from '../keys/ally.ts';
	import { keyring } from '../keys/keyring.svelte.ts';
	import { getMemberKeys, unlockMemberKeys } from '../keys/member.ts';
	import type { AllyKeyBlob, MemberKeysBlob, User } from '../types.ts';

	let {
		kind,
		user,
		onunlocked,
		intro
	}: {
		kind: 'member' | 'ally';
		user: User;
		onunlocked?: () => void;
		intro?: Snippet;
	} = $props();

	let view = $state<'loading' | 'none' | 'ready' | 'error'>('loading');
	let memberBlob: MemberKeysBlob | null = null;
	let allyBlob: AllyKeyBlob | null = null;
	let secret = $state('');
	let useRecovery = $state(false);
	let busy = $state(false);
	let progress = $state(0);
	let error = $state('');
	let fieldError = $state('');

	const id = $derived(`unlock-${kind}`);

	async function load() {
		view = 'loading';
		error = '';
		try {
			if (kind === 'member') memberBlob = await getMemberKeys();
			else allyBlob = await getAllyKey();
			view = (kind === 'member' ? memberBlob : allyBlob) ? 'ready' : 'none';
		} catch (e) {
			error = describeError(e);
			view = 'error';
		}
	}

	onMount(load);

	async function unlock(e: SubmitEvent) {
		e.preventDefault();
		fieldError = '';
		error = '';
		let input = secret;
		if (useRecovery) {
			const n = normalizeRecoveryCode(secret);
			if (!n) {
				fieldError = 'A recovery code is 32 letters and digits, in 8 groups of 4.';
				return;
			}
			input = n;
		} else if (!secret) {
			fieldError = 'Enter your passphrase.';
			return;
		}
		busy = true;
		progress = 0;
		try {
			if (kind === 'member' && memberBlob) {
				keyring.setMember(
					await unlockMemberKeys(memberBlob, user.id, input, useRecovery, (f) => (progress = f)),
					useRecovery
				);
			} else if (kind === 'ally' && allyBlob) {
				keyring.setAlly(
					await unlockAllyKey(allyBlob, user.id, input, useRecovery, (f) => (progress = f))
				);
			}
			secret = '';
			onunlocked?.();
		} catch (err) {
			if (err instanceof UnwrapError && err.reason === 'wrong_passphrase') {
				fieldError = useRecovery
					? 'That recovery code does not unlock these keys.'
					: 'That passphrase does not unlock these keys.';
			} else if (err instanceof UnwrapError) {
				error = err.message;
			} else {
				error = describeError(err);
			}
		} finally {
			busy = false;
		}
	}
</script>

{#if view === 'loading'}
	<p class="muted" role="status">Loading your keys…</p>
{:else if view === 'error'}
	<div class="notice error" role="alert"><p>{error}</p></div>
	<button class="secondary" type="button" onclick={load}>Try again</button>
{:else if view === 'none'}
	<div class="notice info">
		{#if kind === 'member'}
			<p>
				You haven't set up your keys yet. <a href={resolve('/keys')}>Set up your keys</a> to add computers
				and allies.
			</p>
		{:else}
			<p>
				You don't have an ally key yet. It is created when you accept your first invitation to be
				someone's ally.
			</p>
		{/if}
	</div>
{:else}
	<form class="card unlock" onsubmit={unlock} novalidate>
		{#if intro}
			{@render intro()}
		{:else}
			<h2>Unlock your {kind === 'member' ? 'keys' : 'ally key'}</h2>
			<p class="muted">
				{kind === 'member'
					? 'Your passphrase unlocks the keys that approve your computers and allies and open your reports.'
					: 'Your passphrase unlocks the key that opens what the people you support share with you.'}
				They stay unlocked in this tab until you lock them, sign out, or leave it for 30 minutes.
			</p>
		{/if}
		{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
		<div class="field">
			<label for={id}>{useRecovery ? 'Recovery code' : 'Passphrase'}</label>
			<input
				{id}
				type={useRecovery ? 'text' : 'password'}
				class:mono={useRecovery}
				bind:value={secret}
				autocomplete={useRecovery ? 'off' : 'current-password'}
				autocapitalize="off"
				spellcheck="false"
				aria-invalid={fieldError ? 'true' : undefined}
				aria-describedby={fieldError ? `${id}-error` : undefined}
			/>
			{#if fieldError}<span class="field-error" id="{id}-error">{fieldError}</span>{/if}
		</div>
		{#if busy}
			<progress max="1" value={progress} aria-label="Unlocking"></progress>
		{/if}
		<div class="actions">
			<button class="primary" type="submit" disabled={busy}>
				{busy ? 'Unlocking…' : 'Unlock'}
			</button>
			<button
				class="link"
				type="button"
				onclick={() => {
					useRecovery = !useRecovery;
					secret = '';
					fieldError = '';
				}}
			>
				{useRecovery ? 'Use my passphrase' : 'Forgot it? Use the recovery code'}
			</button>
		</div>
	</form>
{/if}

<style>
	.unlock {
		max-width: 34rem;
	}

	progress {
		margin-top: 0.25rem;
	}
</style>
