<script lang="ts">
	// The ally key a proposal needs (GROUPS.md §7.1): sending an offer or a
	// partnership, or accepting a request or partnership, makes someone an
	// ally, and an ally has one encryption key. If this person already has
	// one, this renders nothing and `prepare()` says so. If not, it asks for
	// a passphrase (the key is made in this browser and the server keeps it
	// locked with that passphrase), exactly as accepting an email invitation
	// does (routes/invite). The caller sends the returned upload with its
	// request, then calls `commit()`, which keeps the key unlocked for this
	// session and shows the recovery code.
	import { onMount } from 'svelte';
	import { describeError } from '../api.ts';
	import { b64 } from '../crypto/bytes.ts';
	import { getAllyKey, newAllyKey, type NewAllyKey } from '../keys/ally.ts';
	import { keyring } from '../keys/keyring.svelte.ts';
	import type { AllyKeyUpload, User } from '../types.ts';
	import NewPassphrase from './NewPassphrase.svelte';
	import RecoveryCode from './RecoveryCode.svelte';

	let {
		user,
		ready = $bindable(false),
		recovering = $bindable(false),
		onrecovered
	}: {
		user: User;
		/** True once it is known whether a key must be made. */
		ready?: boolean;
		/** True while the recovery code is showing: finish before moving on. */
		recovering?: boolean;
		/** The recovery code was saved. */
		onrecovered?: () => void;
	} = $props();

	let need = $state(false);
	let error = $state('');
	let passphrase = $state('');
	let picker = $state<ReturnType<typeof NewPassphrase> | null>(null);
	let busy = $state(false);
	let progress = $state(0);
	let pending: NewAllyKey | null = null;
	let recoveryCode = $state('');

	onMount(async () => {
		try {
			need = (await getAllyKey()) === null;
		} catch (e) {
			error = describeError(e);
		}
		ready = true;
	});

	/**
	 * The key to send, `null` when there is already one on the server, or
	 * `false` when the passphrase isn't acceptable yet (the form says why).
	 */
	export async function prepare(): Promise<AllyKeyUpload | null | false> {
		if (!need) return null;
		if (pending) return upload(pending);
		if (!picker?.check()) return false;
		busy = true;
		error = '';
		progress = 0;
		try {
			pending = await newAllyKey(user.id, passphrase, (f) => (progress = f));
			return upload(pending);
		} catch (e) {
			error = describeError(e);
			return false;
		} finally {
			busy = false;
		}
	}

	function upload(k: NewAllyKey): AllyKeyUpload {
		return { enc_pubkey: b64(k.key.encPk), wrapped_privkey: k.wrapped };
	}

	/** The server accepted the key: keep it unlocked and show the recovery code. */
	export function commit() {
		if (!pending) return;
		keyring.setAlly(pending.key);
		recoveryCode = pending.recoveryCode;
		recovering = true;
		pending = null;
		passphrase = '';
		need = false;
	}
</script>

{#if recoveryCode}
	<RecoveryCode
		code={recoveryCode}
		ondone={() => {
			recoveryCode = '';
			recovering = false;
			onrecovered?.();
		}}
	/>
{:else if need}
	<div class="ally-key">
		<h3>Make your ally key</h3>
		<p class="muted">
			Being someone's ally needs a key that opens what they share with you. It is made in this
			browser and locked with a passphrase only you know. The people who run this server can't read
			it.
		</p>
		<NewPassphrase bind:this={picker} bind:value={passphrase} id="proposal-ally-passphrase" />
		{#if busy}<progress max="1" value={progress} aria-label="Creating your key"></progress>{/if}
	</div>
{/if}
{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}

<style>
	.ally-key {
		margin: 1rem 0;
	}
</style>
