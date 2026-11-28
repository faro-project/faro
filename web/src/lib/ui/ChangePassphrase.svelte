<script lang="ts">
	// A new passphrase, a new recovery code, or both, for the member keys or
	// the ally key. The keys stay the same; only their wrapped copies on the
	// server change (PROTOCOL.md §4.3), so nobody else sees a difference.
	import { ApiError, describeError } from '../api.ts';
	import { instance } from '../instance.svelte.ts';
	import { rewrapAllyKey } from '../keys/ally.ts';
	import { keyring } from '../keys/keyring.svelte.ts';
	import { rewrapMemberKeys } from '../keys/member.ts';
	import type { RewrapChoice } from '../keys/wrapping.ts';
	import type { User } from '../types.ts';
	import NewPassphrase from './NewPassphrase.svelte';
	import RecoveryCode from './RecoveryCode.svelte';
	import UnlockKeys from './UnlockKeys.svelte';

	let { user, kind }: { user: User; kind: 'member' | 'ally' } = $props();

	const recovered = () => (kind === 'member' ? keyring.memberRecovered : keyring.allyRecovered);
	const unlocked = () =>
		kind === 'member' ? keyring.memberFor(user.id) : keyring.allyFor(user.id);

	// Unlocked with the recovery code: offer a new passphrase straight away.
	let mode = $state<'passphrase' | 'recovery' | null>(recovered() ? 'passphrase' : null);
	let passphrase = $state('');
	let newRecovery = $state(false);
	let picker = $state<ReturnType<typeof NewPassphrase> | null>(null);
	let busy = $state(false);
	let progress = $state(0);
	let error = $state('');
	let done = $state('');
	let recoveryCode = $state('');

	function explain(err: unknown): string {
		if (err instanceof ApiError && err.code === 'stale_request') {
			return kind === 'member'
				? "The server refused the change because this computer's clock is off. Check the date and time, then try again."
				: 'That took too long and the server stopped waiting. Try again.';
		}
		if (err instanceof ApiError && err.code === 'bad_rewrap_proof') {
			return "The server didn't accept the proof that this is your key. Nothing was changed. Try again.";
		}
		return err instanceof Error && !(err instanceof ApiError) ? err.message : describeError(err);
	}

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		const inst = instance.info;
		if (!inst || !mode) return;
		if (mode === 'passphrase' && !picker?.check()) return;
		const choice: RewrapChoice =
			mode === 'passphrase' ? { passphrase, newRecovery } : { passphrase: null, newRecovery: true };
		busy = true;
		error = '';
		progress = 0;
		const onProgress = (f: number) => (progress = f);
		try {
			let code: string | null;
			if (kind === 'member') {
				const keys = keyring.memberFor(user.id);
				if (!keys) return;
				code = await rewrapMemberKeys(keys, inst.instance_id, choice, onProgress);
				keyring.memberRecovered = false;
			} else {
				const key = keyring.allyFor(user.id);
				if (!key) return;
				code = await rewrapAllyKey(key, inst.instance_id, choice, onProgress);
				keyring.allyRecovered = false;
			}
			passphrase = '';
			done = !choice.passphrase
				? 'You have a new recovery code. Your old one no longer works, and your passphrase is unchanged.'
				: code
					? 'Your passphrase and recovery code are changed. Your old recovery code no longer works.'
					: 'Your passphrase is changed. Your recovery code still works.';
			if (code) recoveryCode = code;
			mode = null;
		} catch (err) {
			error = explain(err);
		} finally {
			busy = false;
		}
	}

	function start(m: 'passphrase' | 'recovery') {
		mode = m;
		done = '';
		error = '';
	}
</script>

{#if recoveryCode}
	<RecoveryCode code={recoveryCode} ondone={() => (recoveryCode = '')} doneLabel="Done" />
{:else}
	{#if done}<div class="notice ok" role="status"><p>{done}</p></div>{/if}
	{#if !mode}
		<div class="actions">
			<button class="secondary" type="button" onclick={() => start('passphrase')}>
				Change my passphrase…
			</button>
			<button class="secondary" type="button" onclick={() => start('recovery')}>
				Get a new recovery code…
			</button>
		</div>
	{:else if !unlocked()}
		<UnlockKeys {kind} {user}>
			{#snippet intro()}
				<h3>Unlock your {kind === 'member' ? 'keys' : 'ally key'} first</h3>
				<p class="muted">With your current passphrase, or your recovery code if you forgot it.</p>
			{/snippet}
		</UnlockKeys>
		<button class="link" type="button" onclick={() => (mode = null)}>Cancel</button>
	{:else}
		<form onsubmit={submit} novalidate>
			{#if mode === 'passphrase'}
				{#if recovered()}
					<p class="notice warn">
						You unlocked with your recovery code. Choose a new passphrase so you don't need it next
						time.
					</p>
				{/if}
				<NewPassphrase
					bind:this={picker}
					bind:value={passphrase}
					id="{kind}-changed-passphrase"
					label="New passphrase"
				/>
				<label class="check">
					<input type="checkbox" bind:checked={newRecovery} />
					Also make a new recovery code (the old one stops working)
				</label>
			{:else}
				<p>
					A new recovery code replaces the one you have, which stops working. Your passphrase stays
					the same. Use this if you lost your recovery code or think someone else has seen it.
				</p>
			{/if}
			{#if busy}<progress
					max="1"
					value={progress}
					aria-label={mode === 'passphrase'
						? 'Changing your passphrase'
						: 'Making a new recovery code'}
				></progress>{/if}
			{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
			<div class="actions">
				<button class="primary" type="submit" disabled={busy}>
					{#if mode === 'passphrase'}
						{busy ? 'Changing…' : 'Change passphrase'}
					{:else}
						{busy ? 'Making a new code…' : 'Make a new recovery code'}
					{/if}
				</button>
				<button class="secondary" type="button" disabled={busy} onclick={() => (mode = null)}>
					Cancel
				</button>
			</div>
		</form>
	{/if}
{/if}

<style>
	progress {
		margin-top: 0.75rem;
	}
</style>
