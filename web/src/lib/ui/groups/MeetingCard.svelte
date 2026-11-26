<script lang="ts">
	// PLACEHOLDER for #122: the group page's meeting card (GROUPS.md §8.4).
	// `group.meeting` is the meeting data from `GET /v1/groups/{id}` (null
	// until a facilitator sets a schedule). Renders nothing until then. Used by
	// routes/groups/view/+page.svelte, above the roster.
	import type { GroupView } from '#lib/types.ts';

	let { group }: { group: GroupView } = $props();
</script>

<!-- MEETING-CARD (#122): group {group.id} -->
