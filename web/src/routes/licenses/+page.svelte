<script lang="ts">
	// Third-party licences, public: the npm packages in this web app's
	// bundle with their licence texts. `npm run build` writes them to
	// /third-party-licenses.txt (scripts/third-party.ts); this page shows
	// that file. The programs' own notices ship with them.
	import { onMount } from 'svelte';

	const NOTICES = '/third-party-licenses.txt';

	let text = $state<string | null>(null);
	let error = $state('');

	onMount(async () => {
		try {
			const r = await fetch(NOTICES, { cache: 'no-cache' });
			if (!r.ok) throw new Error(`${r.status}`);
			text = await r.text();
		} catch {
			error = 'The licence notices could not be loaded. A development build has none.';
		}
	});
</script>

<svelte:head>
	<title>Licences · Faro</title>
</svelte:head>

<div class="page-head">
	<h1>Licences</h1>
	<p>
		Faro is free software under the Apache License 2.0. It is built on open-source work by others,
		whose licences ask that their copyright notices and licence texts travel with it.
	</p>
</div>

<section class="card">
	<h2>This web app</h2>
	<p>
		The pages you are using include the packages below. The same text is available as a
		<a href={NOTICES} download>plain text file</a>.
	</p>
	{#if error}
		<div class="notice error" role="alert"><p>{error}</p></div>
	{:else if text === null}
		<p class="muted" role="status">Loading…</p>
	{:else}
		<pre class="notices">{text}</pre>
	{/if}
</section>

<section class="card">
	<h2>Faro's programs</h2>
	<p>
		The instance's server and the Mac app list the software they are built from next to the
		programs: in <code>/usr/share/faro/notices</code> in the server's container image (and as a
		download next to each release's server binaries), and in <code>/Library/Faro/notices</code> on a Mac.
	</p>
</section>

<style>
	.notices {
		max-height: 32rem;
		overflow: auto;
		white-space: pre-wrap;
		overflow-wrap: anywhere;
		font-size: 0.8rem;
		margin: 0.75rem 0 0;
		padding: 0.75rem;
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		background: var(--bg);
	}
</style>
