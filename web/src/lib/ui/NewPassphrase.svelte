<script lang="ts">
	// Choose a passphrase, typed twice. The parent calls `check()` before
	// using `value`.
	import { passphraseProblem } from '../keys/member.ts';

	let {
		value = $bindable(''),
		id = 'new-passphrase',
		label = 'Passphrase'
	}: { value?: string; id?: string; label?: string } = $props();

	let confirm = $state('');
	let show = $state(false);
	let error = $state('');
	let confirmError = $state('');

	/** Validate; shows the problem and returns false if there is one. */
	export function check(): boolean {
		error = passphraseProblem(value) ?? '';
		confirmError = !error && confirm !== value ? 'The two passphrases are different.' : '';
		return !error && !confirmError;
	}
</script>

<div class="field">
	<label for={id}>
		{label}
		<span class="hint">
			At least 10 characters. A few unrelated words are easy to remember and hard to guess. Nobody,
			including whoever runs this server, can reset it for you.
		</span>
	</label>
	<input
		{id}
		type={show ? 'text' : 'password'}
		bind:value
		autocomplete="new-password"
		spellcheck="false"
		aria-invalid={error ? 'true' : undefined}
		aria-describedby={error ? `${id}-error` : undefined}
	/>
	{#if error}<span class="field-error" id="{id}-error">{error}</span>{/if}
</div>
<div class="field">
	<label for="{id}-confirm">Type it again</label>
	<input
		id="{id}-confirm"
		type={show ? 'text' : 'password'}
		bind:value={confirm}
		autocomplete="new-password"
		spellcheck="false"
		aria-invalid={confirmError ? 'true' : undefined}
		aria-describedby={confirmError ? `${id}-confirm-error` : undefined}
	/>
	{#if confirmError}<span class="field-error" id="{id}-confirm-error">{confirmError}</span>{/if}
</div>
<label class="check small">
	<input type="checkbox" bind:checked={show} /> Show passphrase
</label>
