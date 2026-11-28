<script lang="ts">
	// The support contact the instance's admins set: an email address or an
	// https:// link, labelled as theirs. See branding.ts.

	import { supportLink } from '#lib/branding.ts';
	import type { SupportContact } from '#lib/types.ts';

	let { contact }: { contact: SupportContact | null | undefined } = $props();

	let link = $derived(supportLink(contact));
</script>

{#if link}
	<span class="support">
		Help from this instance's admins:
		<a href={link.href} rel="noreferrer">{link.text}</a>
	</span>
{/if}

<style>
	.support {
		overflow-wrap: anywhere;
	}

	/* An address or a link: shown in the code face, as typed. */
	.support a {
		font-family: var(--mono);
		font-size: var(--mono-size);
	}
</style>
