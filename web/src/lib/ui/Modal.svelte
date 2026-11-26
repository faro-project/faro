<script lang="ts">
	// A dialog that opens as soon as it is rendered: put it in `{#if open}` so
	// a long list (a roster) pays for a dialog only while one is showing.
	import { onMount, type Snippet } from 'svelte';

	let { title, onclose, children }: { title: string; onclose: () => void; children: Snippet } =
		$props();

	let el = $state<HTMLDialogElement | null>(null);
	const id = `modal-${Math.random().toString(36).slice(2, 8)}`;

	onMount(() => {
		el?.showModal();
	});
</script>

<dialog bind:this={el} {onclose} aria-labelledby="{id}-title">
	<h2 id="{id}-title">{title}</h2>
	{@render children()}
</dialog>
