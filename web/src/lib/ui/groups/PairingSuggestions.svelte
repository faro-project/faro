<script lang="ts">
	// Pairing suggestions, for facilitators (GROUPS.md §8.5): "This month:
	// Sam and Jo, Alex and Riley". One pair or a pasted list, a pair per
	// line. Each person sees only their own card and decides; nothing is
	// sent for them, and you are never shown who acted on one.
	import { api, seg } from '#lib/api.ts';
	import { date } from '#lib/format.ts';
	import { parsePairs } from '#lib/groups.ts';
	import { groupError } from '#lib/groups-api.ts';
	import type { Page, PostedSuggestion, RosterEntry } from '#lib/types.ts';

	let { groupId, readOnly = false }: { groupId: string; readOnly?: boolean } = $props();

	let text = $state('');
	let busy = $state(false);
	let error = $state('');
	let problems = $state<string[]>([]);
	let done = $state('');
	let posted = $state<PostedSuggestion[]>([]);
	let loadedFor = '';

	async function loadPosted() {
		try {
			posted = await api.get<PostedSuggestion[]>(`/v1/groups/${seg(groupId)}/suggestions`);
		} catch (e) {
			error = groupError(e);
		}
	}

	$effect(() => {
		if (groupId !== loadedFor) {
			loadedFor = groupId;
			void loadPosted();
		}
	});

	/** The one person here whose name is `name`, or why not. */
	async function find(name: string, cache: Map<string, string>): Promise<string> {
		const key = name.toLowerCase();
		const hit = cache.get(key);
		if (hit) return hit;
		const page = await api.get<Page<RosterEntry>>(
			`/v1/groups/${seg(groupId)}/participants?q=${encodeURIComponent(name)}`
		);
		const exact = page.items.filter((p) => p.display_name.toLowerCase() === key);
		const pool = exact.length ? exact : page.items;
		if (pool.length === 0) throw new Error(`Nobody in this group is called "${name}".`);
		if (pool.length > 1) throw new Error(`More than one person matches "${name}".`);
		cache.set(key, pool[0].user_id);
		return pool[0].user_id;
	}

	async function post() {
		error = '';
		done = '';
		problems = [];
		const { pairs, bad } = parsePairs(text);
		if (bad.length) {
			problems = bad.map((n) => `Line ${n}: write two different names, like "Sam, Jo".`);
		}
		if (!pairs.length) {
			if (!bad.length) error = 'Write at least one pair, like "Sam, Jo".';
			return;
		}
		busy = true;
		try {
			const cache = new Map<string, string>();
			const body: { a: string; b: string }[] = [];
			for (const [x, y] of pairs) {
				try {
					body.push({ a: await find(x, cache), b: await find(y, cache) });
				} catch (e) {
					if (e instanceof Error && !('status' in e)) problems = [...problems, e.message];
					else throw e;
				}
			}
			if (problems.length || !body.length) return;
			const r = await api.post<{ posted: number }>(`/v1/groups/${seg(groupId)}/suggestions`, body);
			done =
				r.posted === 0
					? 'Those pairs were already suggested.'
					: `Suggested ${r.posted} ${r.posted === 1 ? 'pairing' : 'pairings'}.`;
			text = '';
			await loadPosted();
		} catch (e) {
			error = groupError(e);
		} finally {
			busy = false;
		}
	}

	async function withdraw(id: string) {
		error = '';
		try {
			await api.delete<void>(`/v1/groups/${seg(groupId)}/suggestions/${seg(id)}`);
			posted = posted.filter((p) => p.id !== id);
		} catch (e) {
			error = groupError(e);
		}
	}
</script>

<section class="card section" aria-labelledby="pairings-h">
	<h2 id="pairings-h">Suggest pairings</h2>
	<p class="muted">
		Suggest who might partner up this month, one pair per line (for example "Sam, Jo"). Each person
		sees only their own suggestion, as a card they can accept, change to a one-way request or offer,
		or ignore. Nothing is sent for them, and you won't see who acted.
	</p>
	{#if !readOnly}
		<div class="field">
			<label for="pairs-{groupId}">Pairs</label>
			<textarea
				id="pairs-{groupId}"
				rows="4"
				bind:value={text}
				placeholder={'Sam, Jo\nAlex, Riley'}
				disabled={busy}></textarea>
		</div>
		{#if problems.length}
			<div class="notice error" role="alert">
				{#each problems as p (p)}<p>{p}</p>{/each}
			</div>
		{/if}
		{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
		{#if done}<p class="saved" role="status">✓ {done}</p>{/if}
		<div class="actions">
			<button class="primary" type="button" disabled={busy || !text.trim()} onclick={post}>
				{busy ? 'Suggesting…' : 'Suggest'}
			</button>
		</div>
	{/if}

	{#if posted.length}
		<h3>Suggested so far</h3>
		<ul class="rows">
			{#each posted as p (p.id)}
				<li>
					<div class="row-main">
						<div>
							<div class="row-title">
								<strong>{p.a.display_name}</strong> and <strong>{p.b.display_name}</strong>
							</div>
							<div class="row-meta">Suggested {date(p.created_at_ms)}</div>
						</div>
						{#if !readOnly}
							<button class="secondary small" type="button" onclick={() => withdraw(p.id)}>
								Withdraw
							</button>
						{/if}
					</div>
				</li>
			{/each}
		</ul>
	{/if}
</section>
