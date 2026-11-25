<script lang="ts">
	// A new passphrase (and optionally a new recovery code) for the member
	// keys. The keys stay the same; only their wrapped copies on the server
	// change, in a request signed by the member key.
	import { ApiError, describeError } from '../api.ts';
	import { instance } from '../instance.svelte.ts';
	import { keyring } from '../keys/keyring.svelte.ts';
	import { rewrapMemberKeys } from '../keys/member.ts';
	import type { User } from '../types.ts';
	import NewPassphrase from './NewPassphrase.svelte';
	import RecoveryCode from './RecoveryCode.svelte';
	import UnlockKeys from './UnlockKeys.svelte';

	let { user }: { user: User } = $props();

	let open = $state(false);
	let passphrase = $state('');
	let newRecovery = $state(false);
	let picker = $state<ReturnType<typeof NewPassphrase> | null>(null);
	let busy = $state(false);
	let progress = $state(0);
	let error = $state('');
	let done = $state('');
	let recoveryCode = $state('');

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		const keys = keyring.memberFor(user.id);
		const inst = instance.info;
		if (!keys || !inst || !picker?.check()) return;
		busy = true;
		error = '';
		progress = 0;
		try {
			const code = await rewrapMemberKeys(
				keys,
				inst.instance_id,
				passphrase,
				newRecovery,
				(f) => (progress = f)
			);
			passphrase = '';
			keyring.memberRecovered = false;
			done = code
				? 'Your passphrase and recovery code are changed. Your old recovery code no longer works.'
				: 'Your passphrase is changed. Your recovery code still works.';
			if (code) recoveryCode = code;
			open = false;
		} catch (err) {
			error =
				err instanceof ApiError && err.code === 'stale_request'
					? "The server refused the change because this computer's clock is off. Check the date and time, then try again."
					: err instanceof Error && !(err instanceof ApiError)
						? err.message
						: describeError(err);
		} finally {
			busy = false;
		}
	}
</script>

{#if recoveryCode}
	<RecoveryCode code={recoveryCode} ondone={() => (recoveryCode = '')} doneLabel="Done" />
{:else}
	{#if done}<div class="notice ok" role="status"><p>✓ {done}</p></div>{/if}
	{#if !open}
		<button class="secondary" type="button" onclick={() => ((open = true), (done = ''))}>
			Change my passphrase…
		</button>
	{:else if !keyring.memberFor(user.id)}
		<UnlockKeys kind="member" {user}>
			{#snippet intro()}
				<h3>Unlock your keys first</h3>
				<p class="muted">With your current passphrase, or your recovery code if you forgot it.</p>
			{/snippet}
		</UnlockKeys>
	{:else}
		<form onsubmit={submit} novalidate>
			<NewPassphrase
				bind:this={picker}
				bind:value={passphrase}
				id="changed-passphrase"
				label="New passphrase"
			/>
			<label class="check">
				<input type="checkbox" bind:checked={newRecovery} />
				Also make a new recovery code (the old one stops working)
			</label>
			{#if busy}<progress max="1" value={progress} aria-label="Changing your passphrase"
				></progress>{/if}
			{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
			<div class="actions">
				<button class="primary" type="submit" disabled={busy}>
					{busy ? 'Changing…' : 'Change passphrase'}
				</button>
				<button class="secondary" type="button" onclick={() => (open = false)}>Cancel</button>
			</div>
		</form>
	{/if}
{/if}

<style>
	progress {
		margin-top: 0.75rem;
	}
</style>
