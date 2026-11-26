<script lang="ts">
	// PLACEHOLDER for #124: "What this group can see about me" (GROUPS.md
	// §8.2): what you share with the group, all off by default. Shown on the
	// invitation page (before accepting, so `groupId` is null) and on the
	// group page. Renders nothing until then.
	let { groupId = null }: { groupId?: string | null } = $props();
</script>

<!-- SHARING-SETTINGS (#124): {groupId ?? 'invitation'} -->
