<script lang="ts">
	// PLACEHOLDER for #122: the group page's "Waiting for you" area
	// (GROUPS.md §17): proposals to answer, pairing suggestions and safety
	// codes to compare. Renders nothing until then. Used by
	// routes/groups/view/+page.svelte, above the roster.
	let { groupId }: { groupId: string } = $props();
</script>

<!-- WAITING-FOR-YOU (#122): group {groupId} -->
