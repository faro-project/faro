<script lang="ts">
	// The member's own feed: exactly what their allies see (§6, §12 "full
	// transparency"), opened with the member's own key. Every item a
	// computer encrypts is sealed to the member as well as to the allies.
	import { resolve } from '$app/paths';
	import { api } from '#lib/api.ts';
	import FeedView from '#lib/feed/FeedView.svelte';
	import { session } from '#lib/session.svelte.ts';
	import type { DeviceSummary, MyAllies } from '#lib/types.ts';
	import Gate from '#lib/ui/Gate.svelte';

	let deviceNames = $state<Record<string, string>>({});
	let allyNames = $state<Record<string, string>>({});
	let loadedFor = '';

	$effect(() => {
		const u = session.user;
		if (!u?.roles.member || u.id === loadedFor) return;
		loadedFor = u.id;
		api
			.get<DeviceSummary[]>('/v1/me/devices')
			.then((ds) => (deviceNames = Object.fromEntries(ds.map((d) => [d.device_id, d.name]))))
			.catch(() => {});
		api
			.get<MyAllies>('/v1/me/allies')
			.then(
				(m) => (allyNames = Object.fromEntries(m.allies.map((a) => [a.ally_id, a.display_name])))
			)
			.catch(() => {});
	});
</script>

<svelte:head>
	<title>Activity · Faro</title>
</svelte:head>

<Gate role="member">
	{#snippet children(user)}
		<div class="page-head">
			<h1>Your activity</h1>
			<p>
				This is exactly what your allies see: alerts, flagged moments and daily reports from your
				computers. If something was flagged by mistake, tell your allies; that conversation is the
				point.
			</p>
		</div>
		{#if !session.hasMemberKeys}
			<div class="notice info">
				<p>
					Nothing to show yet. <a href={resolve('/keys')}>Set up your keys</a>, then
					<a href={resolve('/computers')}>add a computer</a>.
				</p>
			</div>
		{:else}
			<FeedView
				memberId={user.id}
				viewer={user}
				keyKind="member"
				{deviceNames}
				nameOf={(id) => allyNames[id]}
			/>
		{/if}
	{/snippet}
</Gate>
