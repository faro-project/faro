<script lang="ts">
	// A QR code for `text`, drawn here in the browser. The text can hold a
	// one-time enrollment code, so it never goes to another service.
	import { encodeQr, qrPath } from '#lib/qr.ts';

	let { text, label }: { text: string; label: string } = $props();

	let shape = $derived.by(() => {
		try {
			return qrPath(encodeQr(text));
		} catch {
			return null;
		}
	});
</script>

{#if shape}
	<svg
		class="qr"
		viewBox="0 0 {shape.side} {shape.side}"
		role="img"
		aria-label={label}
		shape-rendering="crispEdges"
	>
		<rect width={shape.side} height={shape.side} fill="#fff" />
		<path d={shape.d} fill="#000" />
	</svg>
{:else}
	<p class="muted small">The link is too long for a QR code. Use the link instead.</p>
{/if}

<style>
	.qr {
		display: block;
		width: 14rem;
		max-width: 100%;
		height: auto;
		border: 1px solid var(--border, #ccc);
		border-radius: 0.5rem;
	}
</style>
