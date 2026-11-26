<script lang="ts">
	// One group: /groups/view?id=… (docs/GROUPS.md §8.1, §9, §17).
	//
	// The id is read from the address in the browser (pages are prerendered,
	// so there is no server-side route per group). Someone who isn't in the
	// group gets a 404 from the API and sees "not found", as if it didn't
	// exist.
	//
	// Spots other work fills in, each a component marked with its issue:
	//   * WaitingForYou, MeetingCard  (#122): above the roster
	//   * RosterPersonActions         (#122): in each roster row
	//   * SharingSettings             (#124): "What this group can see about me"

	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { api, ApiError, seg } from '#lib/api.ts';
	import { date } from '#lib/format.ts';
	import { leaveConfirmation, relationshipOf, type Links } from '#lib/groups.ts';
	import { groupError, loadLinks } from '#lib/groups-api.ts';
	import { session } from '#lib/session.svelte.ts';
	import type { GroupView, Page, RosterEntry } from '#lib/types.ts';
	import Gate from '#lib/ui/Gate.svelte';
	import GroupHistory from '#lib/ui/groups/GroupHistory.svelte';
	import InvitePeople from '#lib/ui/groups/InvitePeople.svelte';
	import ManageGroup from '#lib/ui/groups/ManageGroup.svelte';
	import MeetingCard from '#lib/ui/groups/MeetingCard.svelte';
	import Roster from '#lib/ui/groups/Roster.svelte';
	import RosterPersonActions from '#lib/ui/groups/RosterPersonActions.svelte';
	import SharingSettings from '#lib/ui/groups/SharingSettings.svelte';
	import WaitingForYou from '#lib/ui/groups/WaitingForYou.svelte';

	let groupId = $state('');
	let group = $state<GroupView | null>(null);
	let view = $state<'loading' | 'ok' | 'missing' | 'error'>('loading');
	let error = $state('');
	let tab = $state<'group' | 'manage'>('group');
	let links = $state<Links>({ myAllies: [], supporting: [] });
	let historyVersion = $state(0);
	let loadedFor = '';

	onMount(() => {
		groupId = new URLSearchParams(location.search).get('id') ?? '';
	});

	async function load() {
		view = 'loading';
		try {
			group = await api.get<GroupView>(`/v1/groups/${seg(groupId)}`);
			view = 'ok';
		} catch (e) {
			if (e instanceof ApiError && e.status === 404) {
				view = 'missing';
			} else {
				error = groupError(e);
				view = 'error';
			}
		}
	}

	$effect(() => {
		const u = session.user;
		const k = `${u?.id}:${groupId}`;
		if (u && groupId && k !== loadedFor) {
			loadedFor = k;
			void load();
			void loadLinks(u.roles).then((l) => (links = l));
		}
	});

	/** The group changed: keep the new copy (or fetch one) and the history. */
	async function changed(next?: GroupView) {
		historyVersion++;
		if (next) {
			group = next;
			return;
		}
		try {
			group = await api.get<GroupView>(`/v1/groups/${seg(groupId)}`);
		} catch {
			// The page keeps what it has; reloading shows the current state.
		}
	}

	let isFacilitator = $derived(group?.my_role === 'facilitator');
	let archived = $derived(!!group?.archived_at_ms);
	/** Closed, or switched off for the whole instance: read-only either way. */
	let readOnly = $derived(archived || !!group?.groups_disabled);
	let offer = $derived(
		!!group?.facilitator_offer_until_ms && group.facilitator_offer_until_ms > Date.now()
	);
	let myAlliesInvitable = $derived(
		links.myAllies.filter((a) => a.state === 'active').map((a) => a.id)
	);
	let people = $state<{ id: string; name: string }[]>([]);

	$effect(() => {
		// Names for the "pick from your allies" list come from the allies page's data.
		const ids = myAlliesInvitable;
		if (!ids.length) {
			people = [];
			return;
		}
		void api
			.get<{ allies: { ally_id: string; display_name: string; state: string }[] }>('/v1/me/allies')
			.then(
				(r) =>
					(people = r.allies
						.filter((a) => a.state === 'active')
						.map((a) => ({ id: a.ally_id, name: a.display_name }))
						.sort((a, b) => a.name.localeCompare(b.name)))
			)
			.catch(() => (people = []));
	});

	// Facilitator offer (the last facilitator's account was deleted).
	let offerBusy = $state(false);
	let offerError = $state('');

	async function answerOffer(accept: boolean) {
		offerBusy = true;
		offerError = '';
		try {
			const path = `/v1/groups/${seg(groupId)}/facilitator-offer/${accept ? 'accept' : 'decline'}`;
			if (accept) {
				await changed(await api.post<GroupView>(path));
			} else {
				await api.post<void>(path);
				await changed();
			}
		} catch (e) {
			offerError = groupError(e);
		} finally {
			offerBusy = false;
		}
	}

	// Leaving: always possible, one step, and alliances stay (§9). The
	// confirmation names the allies who are in this group, found by reading
	// the whole roster (a group can be large, so it is read only now).
	let leaveDialog = $state<HTMLDialogElement | null>(null);
	let leaveBusy = $state(false);
	let leaveError = $state('');
	let leaveText = $state('');
	let leaveReady = $state(false);

	async function openLeave() {
		leaveError = '';
		leaveReady = false;
		leaveText = '';
		leaveDialog?.showModal();
		try {
			const names: string[] = [];
			let cursor: string | null = null;
			for (let pages = 0; pages < 50; pages++) {
				const qs: string = cursor ? `?cursor=${encodeURIComponent(cursor)}` : '';
				const page: Page<RosterEntry> = await api.get(
					`/v1/groups/${seg(groupId)}/participants${qs}`
				);
				for (const p of page.items) {
					if (p.user_id !== session.user?.id && relationshipOf(p.user_id, links)) {
						names.push(p.display_name);
					}
				}
				cursor = page.next_cursor;
				if (!cursor) break;
			}
			leaveText = leaveConfirmation(names);
		} catch {
			leaveText = leaveConfirmation([]);
		}
		leaveReady = true;
	}

	async function leave() {
		leaveBusy = true;
		leaveError = '';
		try {
			await api.delete(`/v1/groups/${seg(groupId)}/me`);
			leaveDialog?.close();
			await goto(resolve('/groups'));
		} catch (e) {
			leaveError = groupError(e);
		} finally {
			leaveBusy = false;
		}
	}
</script>

<svelte:head>
	<title>{group ? `${group.name} · Groups` : 'Group'} · Faro</title>
</svelte:head>

<Gate>
	{#snippet children(user)}
		<p class="back"><a href={resolve('/groups')}>← Groups</a></p>

		{#if view === 'loading'}
			<p class="muted" role="status">Loading…</p>
		{:else if view === 'missing'}
			<section class="card">
				<h1>Group not found</h1>
				<p>
					This group doesn't exist, or you're not in it. If someone invited you, open the invitation
					from your email or from <a href={resolve('/groups')}>your groups</a>.
				</p>
			</section>
		{:else if view === 'error'}
			<div class="notice error" role="alert"><p>{error}</p></div>
			<button class="secondary" type="button" onclick={load}>Try again</button>
		{:else if group}
			<div class="page-head">
				<h1>
					{group.name}
					{#if archived}<span class="chip off">Closed</span>{/if}
				</h1>
				{#if group.description}<p class="description">{group.description}</p>{/if}
				<p class="muted small">
					{group.participant_count}
					{group.participant_count === 1 ? 'person' : 'people'}
					{#if group.facilitators.length}
						· Facilitated by {group.facilitators.map((f) => f.display_name).join(', ')}
					{/if}
				</p>
			</div>

			{#if archived}
				<div class="notice warn" role="status">
					<p>
						This group was closed. You can still read it
						{#if group.delete_after_ms}until {date(group.delete_after_ms)}, when it is deleted{/if}.
					</p>
				</div>
			{:else if group.groups_disabled}
				<div class="notice warn" role="status">
					<p>Groups are switched off on this instance, so this group can only be read for now.</p>
				</div>
			{/if}

			{#if offer && !archived}
				<div class="notice info" role="status">
					<p>
						This group has no facilitator. You've been asked to take the role, so someone can invite
						people and look after the group.
					</p>
					<div class="actions">
						<button
							class="primary small"
							type="button"
							disabled={offerBusy}
							onclick={() => answerOffer(true)}
						>
							Become a facilitator
						</button>
						<button
							class="secondary small"
							type="button"
							disabled={offerBusy}
							onclick={() => answerOffer(false)}
						>
							Not now
						</button>
					</div>
					{#if offerError}<p class="field-error" role="alert">{offerError}</p>{/if}
				</div>
			{:else if group.no_facilitator}
				<div class="notice info" role="status">
					<p>
						This group has no facilitator at the moment. Nobody can invite people or change it until
						one is chosen.
					</p>
				</div>
			{/if}

			{#if isFacilitator && !readOnly}
				<nav class="tabs" aria-label="Group">
					<button
						type="button"
						aria-current={tab === 'group' ? 'page' : undefined}
						onclick={() => (tab = 'group')}
					>
						Group
					</button>
					<button
						type="button"
						aria-current={tab === 'manage' ? 'page' : undefined}
						onclick={() => (tab = 'manage')}
					>
						Manage
					</button>
				</nav>
			{/if}

			{#if tab === 'manage' && isFacilitator && !readOnly}
				<ManageGroup
					{group}
					myId={user.id}
					{links}
					{people}
					onchanged={changed}
					onarchived={() => goto(resolve('/groups'))}
				/>
			{:else}
				<WaitingForYou groupId={group.id} />
				<MeetingCard {group} />

				<section class="section" aria-labelledby="roster-h">
					<h2 id="roster-h">People</h2>
					<Roster groupId={group.id} myId={user.id} {links}>
						{#snippet actions(person)}
							<RosterPersonActions {groupId} {person} />
						{/snippet}
					</Roster>
				</section>

				{#if group.can_invite && !isFacilitator}
					<InvitePeople {group} {people} oninvited={() => changed()} />
				{/if}

				<section class="section" aria-labelledby="history-h">
					<h2 id="history-h">History</h2>
					<p class="muted">
						Everyone in the group can see who joined, left or was removed, so nobody is added
						unseen.
					</p>
					<GroupHistory groupId={group.id} version={historyVersion} />
				</section>

				<SharingSettings groupId={group.id} />

				{#if !user.roles.member}
					<p class="muted small">
						Want to use Faro on your own computer too? Joining a group doesn't require it. Ask the
						person who runs this instance how to get started.
					</p>
				{/if}

				{#if !archived && !group.groups_disabled}
					<section class="section" aria-labelledby="leave-h">
						<h2 id="leave-h">Leave this group</h2>
						<p class="muted">You can leave at any time. Your alliances stay as they are.</p>
						<div class="actions">
							<button class="secondary" type="button" onclick={openLeave}>Leave group…</button>
						</div>
					</section>
				{/if}
			{/if}
		{/if}
	{/snippet}
</Gate>

<dialog bind:this={leaveDialog} aria-labelledby="leave-title">
	<h2 id="leave-title">Leave {group?.name ?? 'this group'}?</h2>
	{#if leaveReady}
		<p>{leaveText}</p>
		<p class="muted">The group's facilitators are told that you left.</p>
	{:else}
		<p class="muted" role="status">One moment…</p>
	{/if}
	{#if leaveError}<div class="notice error" role="alert"><p>{leaveError}</p></div>{/if}
	<div class="actions">
		<button class="danger" type="button" onclick={leave} disabled={leaveBusy || !leaveReady}>
			{leaveBusy ? 'Leaving…' : 'Leave group'}
		</button>
		<button class="secondary" type="button" onclick={() => leaveDialog?.close()}>Cancel</button>
	</div>
	<p class="muted small"><a href={resolve('/allies')}>Allies</a></p>
</dialog>

<style>
	.back {
		margin: 0 0 1rem;
	}

	.description {
		white-space: pre-wrap;
	}

	.tabs {
		display: flex;
		gap: 0.25rem;
		margin-bottom: 1.5rem;
		border-bottom: 1px solid var(--border);
	}

	.tabs button {
		background: none;
		border: none;
		border-bottom: 2px solid transparent;
		margin-bottom: -1px;
		padding: 0.55rem 0.8rem;
		color: var(--muted);
		font: inherit;
		font-weight: 600;
		cursor: pointer;
	}

	.tabs button[aria-current='page'] {
		color: var(--text);
		border-bottom-color: var(--accent);
	}
</style>
