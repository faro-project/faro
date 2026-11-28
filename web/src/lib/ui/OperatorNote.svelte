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
		line-height: 1.55;
		margin: 0 0 1.25rem;
		padding: 0.1rem 0 0.1rem 0.8rem;
		border-left: 1px solid var(--border-strong);
		overflow-wrap: anywhere;
	}

	/* Who the line is from: a small label in the code face. */
	.from {
		display: block;
		font-family: var(--mono);
		font-size: 0.68rem;
		font-weight: 500;
		text-transform: uppercase;
		letter-spacing: 0.08em;
		margin-bottom: 0.15rem;
	}
</style>
