<script lang="ts">
	// The Faro logo, from the brand files in assets/brand (never redrawn or
	// recoloured; see assets/brand/README.md). The wordmark is the full
	// logo; the icon is the lighthouse mark alone.
	import icon from '$brand/faro-icon.svg';
	import wordmark from '$brand/faro-wordmark.svg';

	let {
		variant = 'wordmark',
		height = 28,
		alt = 'Faro'
	}: { variant?: 'wordmark' | 'icon'; height?: number; alt?: string } = $props();

	// The files' own aspect ratios (viewBox), so the image never stretches.
	const RATIO = { wordmark: 544.6 / 173.6, icon: 567.6 / 556.1 };
	let width = $derived(Math.round(height * RATIO[variant]));
</script>

<img
	class="logo"
	src={variant === 'wordmark' ? wordmark : icon}
	{alt}
	{width}
	{height}
	decoding="async"
/>

<style>
	.logo {
		display: block;
		flex: none;
	}
</style>
