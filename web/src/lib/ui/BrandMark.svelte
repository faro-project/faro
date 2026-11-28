<script lang="ts">
	// The instance's logo, a thin divider, then Faro's logo. The instance's
	// logo only ever sits next to Faro's: it never replaces, covers or
	// recolours it (assets/brand/README.md). Its alt text and tooltip are
	// the instance's name, so it reads as the instance's, not Faro's.
	//
	// The logo is the PNG the server re-encoded, served from this origin.
	// In the dark theme it sits on a white plate (--logo-plate), so a logo
	// made for a light background stays readable.

	import { apiUrl } from '#lib/api.ts';
	import { logoPath, logoWidth } from '#lib/branding.ts';
	import type { BrandingLogo } from '#lib/types.ts';
	import Logo from './Logo.svelte';

	let {
		logo = null,
		name = '',
		size = 'header'
	}: { logo?: BrandingLogo | null; name?: string; size?: 'header' | 'large' } = $props();

	let height = $derived(size === 'header' ? 22 : 56);
	let path = $derived(logoPath(logo));
</script>

<span class="brand-mark {size}">
	{#if logo && path}
		<img
			class="instance-logo"
			src={apiUrl(path)}
			alt={name}
			title={name}
			width={logoWidth(logo, height)}
			{height}
			decoding="async"
		/>
		<span class="divider" aria-hidden="true"></span>
	{/if}
	<Logo {height} alt="Faro" />
</span>

<style>
	.brand-mark {
		display: inline-flex;
		align-items: center;
		gap: 0.75rem;
		min-width: 0;
	}

	.large {
		gap: 1.25rem;
	}

	.instance-logo {
		display: block;
		flex: none;
		height: auto;
		max-width: 8rem;
		object-fit: contain;
		padding: 2px 4px;
		border-radius: 4px;
		background: var(--logo-plate);
		box-sizing: content-box;
	}

	.large .instance-logo {
		max-width: 14rem;
		padding: 4px 8px;
		border-radius: 6px;
	}

	.divider {
		align-self: stretch;
		width: 1px;
		background: var(--border-strong);
		flex: none;
	}

	@media (max-width: 560px) {
		.instance-logo {
			max-width: 4.5rem;
		}

		.large .instance-logo {
			max-width: 9rem;
		}
	}
</style>
