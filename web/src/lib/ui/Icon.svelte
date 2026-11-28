<script lang="ts" module>
	export type IconName =
		'check' | 'alert' | 'lock' | 'unlock' | 'arrow-left' | 'arrow-right' | 'copy' | 'shield-check';
</script>

<script lang="ts">
	// Line icons drawn for Faro on a 24-unit grid: 2-unit strokes, round caps,
	// in the current text colour. They size with the text (1em) unless given a
	// size. Decorative by default; pass `label` when the icon alone carries
	// meaning.
	let {
		name,
		size = '1em',
		label = ''
	}: { name: IconName; size?: string; label?: string } = $props();
</script>

<svg
	class="icon"
	width={size}
	height={size}
	viewBox="0 0 24 24"
	fill="none"
	stroke="currentColor"
	stroke-width="2"
	stroke-linecap="round"
	stroke-linejoin="round"
	focusable="false"
	role={label ? 'img' : undefined}
	aria-label={label || undefined}
	aria-hidden={label ? undefined : 'true'}
>
	{#if name === 'check'}
		<path d="M5 12.5l4.5 4.5L19 7.5" />
	{:else if name === 'alert'}
		<path
			d="M10.3 4.2 2.7 17.6A2 2 0 0 0 4.4 20.6h15.2a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0Z"
		/>
		<path d="M12 9.5v4M12 16.9v.01" />
	{:else if name === 'lock'}
		<rect x="4.5" y="10.5" width="15" height="10" rx="2" />
		<path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
	{:else if name === 'unlock'}
		<rect x="4.5" y="10.5" width="15" height="10" rx="2" />
		<path d="M8 10.5V7.5a4 4 0 0 1 7.6-1.75" />
	{:else if name === 'arrow-left'}
		<path d="M19 12H5M11 6l-6 6 6 6" />
	{:else if name === 'arrow-right'}
		<path d="M5 12h14M13 6l6 6-6 6" />
	{:else if name === 'copy'}
		<rect x="8.5" y="8.5" width="12" height="12" rx="2" />
		<path d="M15.5 8.5V5.5a2 2 0 0 0-2-2h-8a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h3" />
	{:else if name === 'shield-check'}
		<path d="M12 3 4.5 6v5.5c0 4.5 3.2 8.2 7.5 9.5 4.3-1.3 7.5-5 7.5-9.5V6L12 3Z" />
		<path d="M8.75 12.25l2.25 2.25 4.25-4.5" />
	{/if}
</svg>

<style>
	.icon {
		display: inline-block;
		flex: none;
		vertical-align: -0.14em;
	}
</style>
