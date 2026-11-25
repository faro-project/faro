<script lang="ts">
	// A line of text from the instance's admins (the sign-in page's welcome
	// line). Plain text, always labelled as theirs, and styled as quiet page
	// chrome: never as one of Faro's notices, never announced to screen
	// readers as an alert. See branding.ts.

	import { OPERATOR_LABEL, operatorText } from '#lib/branding.ts';

	let { text }: { text: string | null | undefined } = $props();

	let shown = $derived(operatorText(text));
</script>

{#if shown}
	<p class="operator-note">
		<span class="from">{OPERATOR_LABEL}:</span>
		{shown}
	</p>
{/if}

<style>
	.operator-note {
		color: var(--muted);
		font-size: 0.92rem;
		margin: 0 0 1.25rem;
		padding-left: 0.75rem;
		border-left: 2px solid var(--border);
		overflow-wrap: anywhere;
	}

	.from {
		display: block;
		font-size: 0.8rem;
	}
</style>
