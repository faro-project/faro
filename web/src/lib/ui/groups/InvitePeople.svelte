<script lang="ts">
	// Invite people to a group (GROUPS.md §8.7): paste email addresses, or
	// pick people you already know on this instance, or (facilitators) look
	// people up on the instance by name. They get an email (or a notice) and a
	// 7-day invitation; nobody is added until they accept. Facilitators always
	// see this; participants only when the group lets them invite
	// (`group.can_invite`). The name search shows only a name, never an
	// address, and doesn't match addresses at all.
	import { api, seg } from '#lib/api.ts';
	import { date } from '#lib/format.ts';
	import { describeInvited, GROUP_LIMITS, parseEmails } from '#lib/groups.ts';
	import { groupError } from '#lib/groups-api.ts';
	import type {
		GroupInvitesCreated,
		GroupInviteStatus,
		GroupPerson,
		GroupView
	} from '#lib/types.ts';

	let {
		group,
		people = [],
		oninvited
	}: {
		group: GroupView;
		/** Existing users to pick from (your allies). */
		people?: { id: string; name: string }[];
		oninvited?: () => void;
	} = $props();

	let text = $state('');
	let picked = $state(new Set<string>());
	/** Names of people picked from a search, so they stay ticked after a new search. */
	let pickedFromSearch = $state(new Map<string, string>());

	// Search the instance's people by name (facilitators).
	let search = $state('');
	let found = $state<GroupPerson[]>([]);
	let searching = $state(false);
	let searchError = $state('');
	let canSearch = $derived(group.my_role === 'facilitator' && !group.archived_at_ms);
	let searched = '';

	$effect(() => {
		const q = search.trim();
		if (!canSearch || q === searched) return;
		if (q.length < 2) {
			searched = q;
			found = [];
			searchError = '';
			return;
		}
		const t = setTimeout(async () => {
			searched = q;
			searching = true;
			searchError = '';
			try {
				const r = await api.get<GroupPerson[]>(
					`/v1/groups/${seg(group.id)}/user-search?q=${encodeURIComponent(q)}`
				);
				if (q === search.trim()) found = r;
			} catch (e) {
				searchError = groupError(e);
			} finally {
				searching = false;
			}
		}, 300);
		return () => clearTimeout(t);
	});

	function togglePerson(p: GroupPerson) {
		const s = new Set(picked);
		const names = new Map(pickedFromSearch);
		if (s.has(p.user_id)) {
			s.delete(p.user_id);
			names.delete(p.user_id);
		} else {
			s.add(p.user_id);
			names.set(p.user_id, p.display_name);
		}
		picked = s;
		pickedFromSearch = names;
	}
	let busy = $state(false);
	let error = $state('');
	let done = $state('');
	let sent = $state<GroupInvitesCreated['invites']>([]);

	let invites = $state<GroupInviteStatus[] | null>(null);
	let invitesError = $state('');
	let loadedFor = '';

	async function loadInvites() {
		invitesError = '';
		try {
			invites = await api.get<GroupInviteStatus[]>(`/v1/groups/${seg(group.id)}/invites`);
		} catch (e) {
			invitesError = groupError(e);
		}
	}

	$effect(() => {
		if (group.id !== loadedFor) {
			loadedFor = group.id;
			void loadInvites();
		}
	});

	function toggle(id: string) {
		const s = new Set(picked);
		if (s.has(id)) s.delete(id);
		else s.add(id);
		picked = s;
	}

	async function send(e: SubmitEvent) {
		e.preventDefault();
		error = '';
		done = '';
		const { emails, invalid } = parseEmails(text);
		if (invalid.length) {
			error = `These don't look like email addresses: ${invalid.slice(0, 3).join(', ')}${invalid.length > 3 ? '…' : ''}`;
			return;
		}
		const userIds = [...picked];
		const total = emails.length + userIds.length;
		if (total === 0) {
			error = 'Paste at least one email address, or pick someone.';
			return;
		}
		if (total > GROUP_LIMITS.invitesPerRequest) {
			error = `Invite at most ${GROUP_LIMITS.invitesPerRequest} people at a time.`;
			return;
		}
		busy = true;
		try {
			const res = await api.post<GroupInvitesCreated>(`/v1/groups/${seg(group.id)}/invites`, {
				emails,
				user_ids: userIds
			});
			sent = res.invites;
			done = describeInvited(res.invites.length, res.skipped);
			text = '';
			picked = new Set();
			pickedFromSearch = new Map();
			void loadInvites();
			oninvited?.();
		} catch (err) {
			error = groupError(err);
		} finally {
			busy = false;
		}
	}

	const STATE_LABEL = {
		pending: 'Waiting',
		accepted: 'Joined',
		not_accepted: 'Not accepted'
	} as const;
</script>

<form class="card section" onsubmit={send} novalidate>
	<h2>Invite people</h2>
	<p class="muted">
		Everyone you invite gets an email, or a notice if they already use this instance, with an
		invitation that works for 7 days. Nobody joins until they accept. Joining shares nothing about
		their computer.
	</p>

	<div class="field">
		<label for="invite-emails">
			Email addresses
			<span class="hint">Paste one or many, separated by commas, spaces or new lines.</span>
		</label>
		<textarea
			id="invite-emails"
			rows="3"
			bind:value={text}
			autocomplete="off"
			spellcheck="false"
			placeholder="jo@example.org, alex@example.org"></textarea>
	</div>

	{#if people.length}
		<fieldset class="pick">
			<legend>Or pick from your allies</legend>
			{#each people as p (p.id)}
				<label class="check">
					<input type="checkbox" checked={picked.has(p.id)} onchange={() => toggle(p.id)} />
					{p.name}
				</label>
			{/each}
		</fieldset>
	{/if}

	{#if canSearch}
		<div class="field">
			<label for="invite-search">
				Find people on this instance
				<span class="hint">
					Search by name. You can't search by email address; paste addresses above instead.
				</span>
			</label>
			<input
				id="invite-search"
				type="search"
				bind:value={search}
				autocomplete="off"
				placeholder="Start typing a name"
			/>
			{#if searchError}<span class="field-error">{searchError}</span>{/if}
			{#if searching}<p class="muted small" role="status">Searching…</p>{/if}
			{#if found.length || pickedFromSearch.size}
				<ul class="results">
					{#each pickedFromSearch as [id, name] (id)}
						{#if !found.some((f) => f.user_id === id)}
							<li>
								<label class="check">
									<input
										type="checkbox"
										checked
										onchange={() => togglePerson({ user_id: id, display_name: name })}
									/>
									{name}
								</label>
							</li>
						{/if}
					{/each}
					{#each found as f (f.user_id)}
						<li>
							<label class="check">
								<input
									type="checkbox"
									checked={picked.has(f.user_id)}
									onchange={() => togglePerson(f)}
								/>
								{f.display_name}
							</label>
						</li>
					{/each}
				</ul>
			{:else if search.trim().length >= 2 && !searching && !searchError}
				<p class="muted small">Nobody matches that name, or they are already in the group.</p>
			{/if}
		</div>
	{/if}

	{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
	{#if done}<div class="notice ok" role="status"><p>{done}</p></div>{/if}

	<div class="actions">
		<button class="primary" type="submit" disabled={busy}>
			{busy ? 'Sending…' : 'Send invitations'}
		</button>
	</div>

	{#if sent.length}
		<ul class="sent">
			{#each sent as s (s.invite_url)}
				<li>
					<strong>{s.invited}</strong>
					<span class="muted small">until {date(s.expires_at_ms)}</span>
				</li>
			{/each}
		</ul>
	{/if}
</form>

<section class="section" aria-labelledby="invites-h">
	<h3 id="invites-h">Invitations</h3>
	{#if invitesError}
		<div class="notice error" role="alert"><p>{invitesError}</p></div>
	{:else if !invites}
		<p class="muted" role="status">Loading…</p>
	{:else if invites.length === 0}
		<div class="empty"><p>No invitations yet.</p></div>
	{:else}
		<ul class="rows">
			{#each invites as i, n (n)}
				<li>
					<div class="row-main">
						<div>
							<div class="row-title"><strong>{i.invited}</strong></div>
							<div class="row-meta">
								{#if i.inviter}Invited by {i.inviter.display_name} ·
								{/if}{date(i.created_at_ms)}
							</div>
						</div>
						<span class="chip {i.state === 'accepted' ? 'good' : 'pending'}">
							{STATE_LABEL[i.state]}
						</span>
					</div>
				</li>
			{/each}
		</ul>
		<p class="muted small">
			"Not accepted" means the person said no or the invitation ran out. You are not told which.
		</p>
	{/if}
</section>

<style>
	.pick {
		border: none;
		padding: 0;
		margin: 0 0 1rem;
	}

	.pick legend {
		font-weight: 600;
		margin-bottom: 0.4rem;
		padding: 0;
	}

	.results {
		list-style: none;
		padding: 0;
		margin: 0.5rem 0 0;
	}

	.sent {
		list-style: none;
		padding: 0;
		margin: 0.5rem 0 0;
	}

	.sent li {
		display: flex;
		flex-wrap: wrap;
		gap: 0.25rem 0.75rem;
		align-items: baseline;
	}
</style>
