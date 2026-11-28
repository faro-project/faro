<script lang="ts">
	// Show a freshly generated recovery code once, and make the person
	// confirm they kept it before moving on.
	import Icon from './Icon.svelte';

	let {
		code,
		ondone,
		doneLabel = 'Continue'
	}: { code: string; ondone: () => void; doneLabel?: string } = $props();

	let saved = $state(false);
	let copied = $state(false);

	async function copy() {
		try {
			await navigator.clipboard.writeText(code);
			copied = true;
			setTimeout(() => (copied = false), 2500);
		} catch {
			copied = false;
		}
	}
</script>

<section class="card" aria-labelledby="recovery-title">
	<h2 id="recovery-title">Save your recovery code</h2>
	<p>
		If you forget your passphrase, this code is the only way to unlock your keys. Write it down or
		keep it in a password manager, somewhere other than this computer.
	</p>
	<p class="code-display" aria-label="Recovery code">{code}</p>
	<div class="actions">
		<button class="secondary small" type="button" onclick={copy}>
			{#if copied}
				<Icon name="check" /> Copied
			{:else}
				<Icon name="copy" /> Copy
			{/if}
		</button>
		<button class="secondary small" type="button" onclick={() => window.print()}>Print</button>
	</div>
	<p class="muted small">
		This page shows it once. It can't be shown again or reset by the server's operator.
	</p>
	<label class="check">
		<input type="checkbox" bind:checked={saved} />
		I have saved my recovery code somewhere safe
	</label>
	<div class="actions">
		<button class="primary" type="button" disabled={!saved} onclick={ondone}>{doneLabel}</button>
	</div>
</section>
