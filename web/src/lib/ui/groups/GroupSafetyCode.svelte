<script lang="ts">
	// The group safety code (GROUPS.md §10.3 item 5, PROTOCOL.md §10.8): a
	// fingerprint of the member-list history this browser checked, up to its
	// latest entry. Every entry is signed by a facilitator, so comparing it
	// with any one facilitator, in person or on a call, shows you hold the
	// same history they do: a server that showed you a made-up member list
	// would give you a different code.
	import { checkpointOf, groupSafetyCode, type RosterState } from '../../crypto/roster.ts';

	let { roster }: { roster: RosterState | null } = $props();

	let head = $derived(roster ? checkpointOf(roster) : null);
	let code = $derived(
		roster && head ? groupSafetyCode(roster.instance_id, roster.group_id, head) : null
	);
</script>

<section class="section" aria-labelledby="group-code-h">
	<h2 id="group-code-h">Group safety code</h2>
	{#if code && head}
		<p>
			Compare this code with any facilitator, in person or on a call (not by email or text). If it
			matches, you hold the same member-list history, so the server isn't showing you a different
			group.
		</p>
		<p class="code-display digits" aria-label="Group safety code">
			{#each code.split(' ') as g, i (i)}<span>{g}</span>{/each}
		</p>
		<p class="muted small">
			Update {head.seq} of the signed member list. It changes whenever someone joins or leaves, so compare
			it on the same day.
		</p>
	{:else}
		<p class="muted">
			There's no code yet: the group's member list hasn't been signed. A facilitator's browser signs
			it when they open the group.
		</p>
	{/if}
</section>
