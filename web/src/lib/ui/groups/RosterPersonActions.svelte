<script lang="ts">
	// PLACEHOLDER for #122: one person's action menu in the roster (*Ask to
	// be my ally*, *Offer to be their ally*, *Partner up*, *Don't let them
	// send me proposals*; GROUPS.md §17). Rendered by Roster.svelte next to
	// every person except you. Renders nothing until then.
	import type { RosterEntry } from '#lib/types.ts';

	let { groupId, person }: { groupId: string; person: RosterEntry } = $props();
</script>

<!-- ROSTER-PERSON-ACTIONS (#122): {groupId} / {person.user_id} -->
