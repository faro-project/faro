<script lang="ts">
	// "Find a group" on the Groups page (GROUPS.md §8.8, §17): the instance's
	// listed groups, with search and paging. It shows nothing at all when the
	// instance lists no groups. A listing says who facilitates, when and
	// (if the facilitators chose) where the group meets, and whether it is
	// full: never who is in it or how many. Asking to join is a request that
	// only the group's facilitators see; each needs a facilitator's yes.
	import { resolve } from '$app/paths';
	import { api, ApiError, seg } from '#lib/api.ts';
	import { joinNames } from '#lib/groups.ts';
	import { groupError } from '#lib/groups-api.ts';
	import { describeSchedule } from '#lib/meetings.ts';
	import { keyring } from '#lib/keys/keyring.svelte.ts';
	import { loadRecipients } from '#lib/reach-out-api.ts';
	import { composeMessage, MAX_NOTE_CHARS, noteLength, sealable } from '#lib/reach-out.ts';
	import { session } from '#lib/session.svelte.ts';
	import type { DirectoryEntry, MyJoinRequest, Page } from '#lib/types.ts';
	import Modal from '../Modal.svelte';
	import NoteField from '../NoteField.svelte';

	let { onjoined }: { onjoined?: () => void } = $props();

	let entries = $state<DirectoryEntry[]>([]);
	let next = $state<string | null>(null);
	let query = $state('');
	let loading = $state(true);
	let error = $state('');
	let actionError = $state('');
	/** Anything is listed at all (an empty search is not "nothing listed"). */
	let anyListed = $state(false);
	let notAccepted = $state(new Set<string>());
	let busyId = $state('');
	let ran = '';

	async function fetchPage(cursor: string | null, q: string): Promise<Page<DirectoryEntry>> {
		const params = new URLSearchParams();
		if (q) params.set('q', q);
		if (cursor) params.set('cursor', cursor);
		const qs = params.toString();
		return api.get<Page<DirectoryEntry>>(`/v1/group-directory${qs ? `?${qs}` : ''}`);
	}

	async function load(more: boolean) {
		const q = query.trim();
		loading = true;
		error = '';
		try {
			const page = await fetchPage(more ? next : null, q);
			if (q !== query.trim()) return;
			entries = more ? [...entries, ...page.items] : page.items;
			next = page.next_cursor;
			if (page.items.length) anyListed = true;
		} catch (e) {
			error = groupError(e);
		} finally {
			loading = false;
		}
	}

	async function loadMine() {
		try {
			const mine = await api.get<MyJoinRequest[]>('/v1/me/join-requests');
			notAccepted = new Set(mine.filter((r) => r.state === 'not_accepted').map((r) => r.group_id));
		} catch {
			notAccepted = new Set();
		}
	}

	$effect(() => {
		const u = session.user;
		const key = `${u?.id}|${query.trim()}`;
		if (!u || key === ran) return;
		const first = ran === '';
		ran = key;
		const t = setTimeout(
			() => {
				void load(false);
				if (first) void loadMine();
			},
			first ? 0 : 250
		);
		return () => clearTimeout(t);
	});

	function set(id: string, change: Partial<DirectoryEntry>) {
		entries = entries.map((e) => (e.id === id ? { ...e, ...change } : e));
	}

	// Asking, with an optional note to the facilitators: signed with your
	// member key and sealed to each facilitator's key (GROUPS.md §10.2).
	let asking = $state<DirectoryEntry | null>(null);
	let note = $state('');
	let askError = $state('');
	let noteTooLong = $derived(noteLength(note) > MAX_NOTE_CHARS);

	function startAsk(e: DirectoryEntry) {
		asking = e;
		note = '';
		askError = '';
		actionError = '';
	}

	async function ask() {
		const e = asking;
		const u = session.user;
		if (!e || !u) return;
		busyId = e.id;
		askError = '';
		try {
			let message = null;
			if (note.trim()) {
				const keys = keyring.memberFor(u.id);
				if (!keys) {
					askError = 'Unlock your keys to sign the note, or remove it.';
					return;
				}
				const r = await loadRecipients('join_request_note', { groupId: e.id });
				if (!sealable(r).length) {
					askError = "The facilitators can't receive a note yet. Ask without one.";
					return;
				}
				message = composeMessage(keys, r, 'join_request_note', e.id, note);
			}
			await api.post(`/v1/groups/${seg(e.id)}/join-requests`, message ? { note: message } : {});
			set(e.id, { requested: true });
			asking = null;
			onjoined?.();
		} catch (err) {
			askError = err instanceof Error && !(err instanceof ApiError) ? err.message : groupError(err);
		} finally {
			busyId = '';
		}
	}

	async function takeBack(e: DirectoryEntry) {
		busyId = e.id;
		actionError = '';
		try {
			await api.delete(`/v1/groups/${seg(e.id)}/join-requests/me`);
			set(e.id, { requested: false });
		} catch (err) {
			actionError = groupError(err);
		} finally {
			busyId = '';
		}
	}

	let deleting = $derived(!!session.deletion);
</script>

{#if anyListed || query.trim()}
	<section class="section" id="find-a-group" aria-labelledby="find-h">
		<h2 id="find-h">Find a group</h2>
		<p class="muted">
			These groups are listed on this instance. Asking to join sends a request that only the group's
			facilitators see, and they say yes or no. Nobody joins without a yes.
		</p>
		<div class="field">
			<label class="visually-hidden" for="find-search">Search listed groups</label>
			<input
				id="find-search"
				type="search"
				placeholder="Search by name"
				bind:value={query}
				autocomplete="off"
			/>
		</div>

		{#if error}
			<div class="notice error" role="alert"><p>{error}</p></div>
			<button class="secondary small" type="button" onclick={() => load(false)}>Try again</button>
		{/if}
		{#if actionError}<div class="notice error" role="alert"><p>{actionError}</p></div>{/if}

		{#if entries.length}
			<ul class="rows">
				{#each entries as g (g.id)}
					<li>
						<div class="row-main">
							<div class="info">
								<div class="row-title">
									<strong>{g.name}</strong>
									{#if g.joined}<span class="chip good">You're in</span>{/if}
									{#if g.requested}<span class="chip pending">Requested</span>{/if}
									{#if g.full && !g.joined}<span class="chip off">Full</span>{/if}
									{#if !g.requested && !g.joined && notAccepted.has(g.id)}
										<span class="chip off">Not accepted</span>
									{/if}
								</div>
								{#if g.description}<p class="description">{g.description}</p>{/if}
								<div class="row-meta">
									{#if g.facilitators.length}Facilitated by {joinNames(g.facilitators)}{/if}
									{#if g.meeting}
										· {describeSchedule(g.meeting)}{#if g.place}, {g.place}{/if}
									{/if}
								</div>
							</div>
							<div class="row-actions">
								{#if g.joined}
									<a
										class="button secondary small"
										href="{resolve('/groups/view')}?id={encodeURIComponent(g.id)}"
									>
										Open
									</a>
								{:else if g.requested}
									<button
										class="secondary small"
										type="button"
										disabled={busyId === g.id}
										onclick={() => takeBack(g)}
									>
										Take back my request
									</button>
								{:else if !g.full && !notAccepted.has(g.id) && !deleting}
									<button
										class="primary small"
										type="button"
										disabled={busyId === g.id}
										onclick={() => startAsk(g)}
									>
										Ask to join
									</button>
								{/if}
							</div>
						</div>
					</li>
				{/each}
			</ul>
		{:else if !loading && !error}
			<div class="empty"><p>No listed group matches that search.</p></div>
		{/if}

		{#if loading}
			<p class="muted" role="status">Loading…</p>
		{:else if next}
			<div class="actions">
				<button class="secondary" type="button" onclick={() => load(true)}>Show more groups</button>
			</div>
		{/if}
		{#if notAccepted.size}
			<p class="muted small">
				"Not accepted" means the group didn't take your request. It doesn't say why, and you can ask
				again after a few weeks.
			</p>
		{/if}
	</section>
{/if}

{#if asking && session.user}
	<Modal title="Ask to join {asking.name}" onclose={() => (asking = null)}>
		<p>
			The facilitators{#if asking.facilitators.length}
				({joinNames(asking.facilitators)}){/if} see your name and your note, and say yes or no. Nobody
			else in the group sees your request.
		</p>
		<NoteField
			user={session.user}
			bind:text={note}
			canSign={session.hasMemberKeys}
			label="A note to the facilitators (optional)"
			placeholder="I'm new to the church and was told to ask about this group."
		/>
		{#if askError}<div class="notice error" role="alert"><p>{askError}</p></div>{/if}
		<div class="actions">
			<button
				class="primary"
				type="button"
				disabled={busyId === asking.id || noteTooLong}
				onclick={ask}
			>
				{busyId === asking.id ? 'Sending…' : 'Ask to join'}
			</button>
			<button class="secondary" type="button" onclick={() => (asking = null)}>Cancel</button>
		</div>
	</Modal>
{/if}

<style>
	.description {
		white-space: pre-wrap;
		margin: 0.25rem 0;
	}

	.row-actions {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
		align-items: flex-start;
	}
</style>
