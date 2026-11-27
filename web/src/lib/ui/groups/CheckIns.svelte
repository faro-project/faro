<script lang="ts">
	// Check-ins (GROUPS.md §8.6): a short update you write for your allies in
	// the group, the facilitators, people you choose or the whole group.
	// Encrypted in this browser, signed with your member key, and shown only
	// in this feed: a check-in never sends a notification. Others can reply
	// to you privately.
	//
	// Whole-group check-ins are sealed with the group's current epoch key
	// (one envelope, whatever the group's size), which this browser opens
	// against the roster it verified (`roster`, from GroupKeys). They wait
	// while a facilitator has roster work to do (`postingPaused`).
	import { untrack } from 'svelte';
	import { api, seg } from '../../api.ts';
	import { createPost, epochKeyFor, checkInError, listPosts } from '../../check-in-api.ts';
	import {
		composeCheckIn,
		composeGroupCheckIn,
		composeReply,
		checkInPromptDue,
		loadPromptSetting,
		MAX_NAMED,
		MAX_NOTE_CHARS,
		noteLength,
		readPost,
		savePromptSetting,
		scaleLabel,
		WAITING_LINE,
		type CheckInAudience,
		type CheckInText,
		type PostView
	} from '../../check-in.ts';
	import { ago, dateTime } from '../../format.ts';
	import { instance } from '../../instance.svelte.ts';
	import { keyring } from '../../keys/keyring.svelte.ts';
	import { loadRecipients } from '../../reach-out-api.ts';
	import type { RosterState } from '../../crypto/roster.ts';
	import type { GroupView, Page, RosterEntry, User } from '../../types.ts';
	import UnlockKeys from '../UnlockKeys.svelte';

	let {
		group,
		user,
		roster = null,
		postingPaused = false,
		readOnly = false
	}: {
		group: GroupView;
		user: User;
		roster?: RosterState | null;
		postingPaused?: boolean;
		readOnly?: boolean;
	} = $props();

	let posts = $state.raw<PostView[]>([]);
	let cursor = $state<string | null>(null);
	let loaded = $state(false);
	let loadError = $state('');
	let epochKeys = $state.raw<Record<number, Uint8Array>>({});
	let epochTried = new Set<number>();

	async function load(more = false) {
		try {
			const page = await listPosts(group.id, more ? cursor : null);
			posts = more ? [...posts, ...page.items] : page.items;
			cursor = page.next_cursor;
			loadError = '';
			void instance.load().catch(() => {});
		} catch (e) {
			loadError = checkInError(e);
		} finally {
			loaded = true;
		}
	}

	$effect(() => {
		if (group.id) untrack(() => void load());
	});

	let memberKeys = $derived(keyring.memberFor(user.id));
	let unlocked = $derived(!!memberKeys || !!keyring.allyFor(user.id));

	// Open the keys of the epochs the feed uses, once something is unlocked.
	$effect(() => {
		const r = roster;
		if (!r || !unlocked) return;
		for (const e of new Set(posts.map((p) => p.epoch).filter((e): e is number => e != null))) {
			if (e in epochKeys || epochTried.has(e)) continue;
			epochTried.add(e);
			void epochKeyFor(group.id, user.id, r, e)
				.then((k) => {
					if (k) epochKeys = { ...epochKeys, [e]: k.key };
					else epochTried.delete(e);
				})
				.catch(() => epochTried.delete(e));
		}
	});

	let reads = $derived(
		new Map(
			posts.map((p) => [
				p.id,
				readPost(
					p,
					user.id,
					{
						member: keyring.member,
						ally: keyring.ally,
						epochKey: p.epoch != null ? (epochKeys[p.epoch] ?? null) : null
					},
					instance.info?.instance_id,
					group.id
				)
			])
		)
	);
	let checkIns = $derived(posts.filter((p) => p.kind === 'check_in'));
	let repliesOf = $derived((id: string) => posts.filter((p) => p.parent_id === id));
	let orphans = $derived(
		posts.filter((p) => p.kind === 'check_in_reply' && !posts.some((c) => c.id === p.parent_id))
	);

	// ---- The prompt a day before a meeting -----------------------------------
	let promptOn = $state(false);
	let dismissedFor = $state<number | null>(null);
	let now = Date.now();

	$effect(() => {
		const s = loadPromptSetting(user.id, group.id);
		promptOn = s.enabled;
		dismissedFor = s.dismissedFor;
	});

	function savePrompt() {
		savePromptSetting(user.id, group.id, { enabled: promptOn, dismissedFor });
	}

	let promptDue = $derived(checkInPromptDue(group.next_meeting_at_ms, now, promptOn, dismissedFor));

	// ---- Writing ------------------------------------------------------------------
	let writing = $state(false);
	let scale = $state<number | null>(null);
	let wentWell = $state('');
	let wasHard = $state('');
	let ask = $state('');
	let audience = $state<CheckInAudience>('allies');
	let people = $state<RosterEntry[] | null>(null);
	let chosen = $state<string[]>([]);
	let busy = $state(false);
	let error = $state('');
	let sent = $state(false);

	let canWrite = $derived(!readOnly && user.roles.member);
	let wholeGroupBlocked = $derived(postingPaused || !roster || roster.epoch === 0);

	function start() {
		writing = true;
		sent = false;
		error = '';
		if (promptDue) dismiss();
	}

	function dismiss() {
		dismissedFor = group.next_meeting_at_ms;
		savePrompt();
	}

	async function loadPeople() {
		if (people) return;
		try {
			const page = await api.get<Page<RosterEntry>>(`/v1/groups/${seg(group.id)}/participants`);
			people = page.items.filter((p) => p.user_id !== user.id && !p.unavailable);
		} catch (e) {
			error = checkInError(e);
		}
	}

	$effect(() => {
		if (audience === 'people') untrack(() => void loadPeople());
	});

	$effect(() => {
		if (audience === 'group' && wholeGroupBlocked) audience = 'allies';
	});

	function toggle(id: string) {
		chosen = chosen.includes(id) ? chosen.filter((c) => c !== id) : [...chosen, id];
	}

	let tooLong = $derived([wentWell, wasHard, ask].some((t) => noteLength(t) > MAX_NOTE_CHARS));

	function answers(): CheckInText {
		const c: CheckInText = { scale: scale as CheckInText['scale'] };
		if (wentWell.trim()) c.went_well = wentWell;
		if (wasHard.trim()) c.was_hard = wasHard;
		if (ask.trim()) c.ask = ask;
		return c;
	}

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		const keys = keyring.memberFor(user.id);
		if (!keys || scale === null) return;
		busy = true;
		error = '';
		try {
			let message;
			if (audience === 'group') {
				if (!roster) throw new Error('The group is still loading. Try again.');
				const k = await epochKeyFor(group.id, user.id, roster);
				if (!k || k.epoch !== roster.epoch) {
					throw new Error("You don't have this group's key yet. Try again in a moment.");
				}
				const inst = await instance.load();
				message = composeGroupCheckIn(keys, inst.instance_id, group.id, k.epoch, k.key, answers());
			} else {
				const recipients = await loadRecipients('check_in', {
					audience,
					groupId: group.id,
					userIds: audience === 'people' ? chosen : undefined
				});
				message = composeCheckIn(keys, recipients, group.id, answers());
			}
			await createPost(group.id, {
				audience,
				...(audience === 'people' ? { user_ids: chosen } : {}),
				message
			});
			sent = true;
			writing = false;
			scale = null;
			wentWell = wasHard = ask = '';
			await load();
		} catch (err) {
			error = err instanceof Error && !('status' in err) ? err.message : checkInError(err);
		} finally {
			busy = false;
		}
	}

	// ---- Replying -----------------------------------------------------------------
	let replyTo = $state('');
	let replyText = $state('');
	let replyBusy = $state(false);
	let replyError = $state('');

	async function reply(p: PostView) {
		const keys = keyring.memberFor(user.id);
		if (!keys) return;
		replyBusy = true;
		replyError = '';
		try {
			const recipients = await loadRecipients('check_in_reply', {
				groupId: group.id,
				userIds: [p.author.user_id]
			});
			await createPost(group.id, {
				message: composeReply(keys, recipients, group.id, p.id, replyText)
			});
			replyTo = '';
			replyText = '';
			await load();
		} catch (err) {
			replyError = err instanceof Error && !('status' in err) ? err.message : checkInError(err);
		} finally {
			replyBusy = false;
		}
	}

	const WHO: Record<CheckInAudience, string> = {
		allies: 'my allies in this group',
		facilitators: 'the facilitators',
		people: 'people I choose',
		group: 'the whole group'
	};
</script>

<section class="section" aria-labelledby="checkins-h">
	<h2 id="checkins-h">Check-ins</h2>
	<p class="muted small">
		A short update you write for the group, usually before a meeting. Check-ins are encrypted in
		your browser and signed by you. They show up here and never send anyone a notification.
	</p>

	{#if promptDue && canWrite && !writing}
		<div class="notice info" role="status">
			<p>
				Your group meets {dateTime(group.next_meeting_at_ms!)}. Want to write a check-in first?
			</p>
			<div class="actions">
				<button class="primary small" type="button" onclick={start}>Write a check-in</button>
				<button class="link small" type="button" onclick={dismiss}>Not now</button>
			</div>
		</div>
	{/if}

	{#if sent}
		<div class="notice ok" role="status"><p>✓ Posted. Nobody was notified.</p></div>
	{/if}

	{#if canWrite}
		{#if !writing}
			<div class="actions">
				<button class="primary" type="button" onclick={start}>Write a check-in</button>
			</div>
		{:else}
			<form class="card" onsubmit={submit} novalidate>
				<h3>How's it going?</h3>
				<fieldset class="scale">
					<legend class="visually-hidden">How's it going, from 1 to 5</legend>
					{#each [1, 2, 3, 4, 5] as n (n)}
						<label>
							<input type="radio" bind:group={scale} value={n} />
							<span class="n">{n}</span>
							<span class="muted small">{scaleLabel(n)}</span>
						</label>
					{/each}
				</fieldset>
				<div class="field">
					<label for="ci-well">What went well (optional)</label>
					<textarea id="ci-well" rows="2" bind:value={wentWell}></textarea>
				</div>
				<div class="field">
					<label for="ci-hard">What was hard (optional)</label>
					<textarea id="ci-hard" rows="2" bind:value={wasHard}></textarea>
				</div>
				<div class="field">
					<label for="ci-ask">What I'd like from the group (optional)</label>
					<textarea id="ci-ask" rows="2" bind:value={ask}></textarea>
					<span class="hint" class:over={tooLong}>
						Up to {MAX_NOTE_CHARS} characters each. Encrypted to the people below and signed by you: the
						server can't read it.
					</span>
				</div>

				<fieldset class="choices">
					<legend>Who can read it</legend>
					{#each ['allies', 'facilitators', 'people', 'group'] as const as a (a)}
						<label>
							<input
								type="radio"
								bind:group={audience}
								value={a}
								disabled={a === 'group' && wholeGroupBlocked}
							/>
							{a === 'allies'
								? 'My allies in this group (default)'
								: a === 'facilitators'
									? 'The facilitators'
									: a === 'people'
										? 'People I choose'
										: `The whole group (${group.participant_count} ${group.participant_count === 1 ? 'person' : 'people'})`}
						</label>
					{/each}
				</fieldset>
				{#if postingPaused}
					<p class="muted small" role="status">{WAITING_LINE}</p>
				{:else if wholeGroupBlocked}
					<p class="muted small">
						The whole group is available once a facilitator has set up the group's encryption.
					</p>
				{/if}
				{#if audience === 'people'}
					{#if !people}
						<p class="muted" role="status">Loading the group…</p>
					{:else if people.length === 0}
						<p class="muted">There's nobody else in this group yet.</p>
					{:else}
						<ul class="pick">
							{#each people as p (p.user_id)}
								<li>
									<label>
										<input
											type="checkbox"
											checked={chosen.includes(p.user_id)}
											disabled={!chosen.includes(p.user_id) && chosen.length >= MAX_NAMED}
											onchange={() => toggle(p.user_id)}
										/>
										{p.display_name}
									</label>
								</li>
							{/each}
						</ul>
						<p class="muted small">Up to {MAX_NAMED} people.</p>
					{/if}
				{/if}

				{#if !unlocked || !memberKeys}
					<UnlockKeys kind="member" {user}>
						{#snippet intro()}
							<h3>Unlock to sign</h3>
							<p class="muted small">Your keys sign the check-in, so it needs your passphrase.</p>
						{/snippet}
					</UnlockKeys>
				{/if}
				{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
				<div class="actions">
					<button
						class="primary"
						type="submit"
						disabled={busy ||
							!memberKeys ||
							scale === null ||
							tooLong ||
							(audience === 'people' && chosen.length === 0)}
					>
						{busy ? 'Posting…' : `Post to ${WHO[audience]}`}
					</button>
					<button class="secondary" type="button" onclick={() => (writing = false)}>Cancel</button>
				</div>
			</form>
		{/if}
	{:else if !readOnly && !user.roles.member}
		<p class="muted small">
			Writing a check-in needs your member keys (they sign it). You can still read the ones sent to
			you.
		</p>
	{/if}

	<label class="check small">
		<input
			type="checkbox"
			bind:checked={promptOn}
			onchange={() => {
				dismissedFor = null;
				savePrompt();
			}}
		/>
		Remind me here, the day before a meeting, to write a check-in (in this browser only)
	</label>

	{#if loadError}<div class="notice error" role="alert"><p>{loadError}</p></div>{/if}
	{#if loaded && !loadError && posts.length === 0}
		<p class="muted">No check-ins yet.</p>
	{/if}

	{#if posts.length}
		<ul class="rows">
			{#each checkIns as p (p.id)}
				{@const r = reads.get(p.id)}
				<li>
					<div class="row-title">
						<strong>{p.author.user_id === user.id ? 'You' : p.author.display_name}</strong>
						<span class="muted small">
							· {ago(p.created_at_ms)} ·
							{p.epoch != null ? 'to the whole group' : 'to some people'}
						</span>
					</div>
					{#if !r || r.status === 'invalid'}
						<div class="notice warn small" role="alert">
							<p>This check-in's signature doesn't check out, so it isn't shown.</p>
						</div>
					{:else if r.status === 'locked'}
						<p class="small">
							{#if unlocked}Opening it…{:else}Unlock your keys above to read it.{/if}
						</p>
					{:else if r.status === 'unreadable'}
						<p class="muted small">None of your keys opens this check-in.</p>
					{:else if r.checkIn}
						<p>
							<strong>{r.checkIn.scale} / 5</strong>
							<span class="muted">{scaleLabel(r.checkIn.scale)}</span>
						</p>
						{#if r.checkIn.went_well}
							<p class="ans"><em>What went well.</em> {r.checkIn.went_well}</p>
						{/if}
						{#if r.checkIn.was_hard}
							<p class="ans"><em>What was hard.</em> {r.checkIn.was_hard}</p>
						{/if}
						{#if r.checkIn.ask}
							<p class="ans"><em>What I'd like from the group.</em> {r.checkIn.ask}</p>
						{/if}
						<p class="muted small">
							{#if p.author.user_id === user.id}
								Signed by you.
							{:else if r.verified === 'verified'}
								✓ Signed by {p.author.display_name}, whose key you checked with a safety code.
							{:else if r.verified === 'changed'}
								Signed with a key that isn't the one you checked with {p.author.display_name}.
								Compare safety codes again to be sure.
							{:else}
								Signed with {p.author.display_name}'s key. Not yet verified.
							{/if}
						</p>
					{/if}

					{#each repliesOf(p.id) as rp (rp.id)}
						{@const rr = reads.get(rp.id)}
						<blockquote class="reply">
							{#if rr?.status === 'ok'}
								<strong>{rp.author.user_id === user.id ? 'You' : rp.author.display_name}:</strong>
								{rr.text}
							{:else if rr?.status === 'locked'}
								A private reply. Unlock your keys to read it.
							{:else}
								A reply that isn't shown.
							{/if}
						</blockquote>
					{/each}

					{#if canWrite && p.author.user_id !== user.id && r?.status === 'ok'}
						{#if replyTo === p.id}
							<div class="field">
								<label for="reply-{p.id}">Reply privately to {p.author.display_name}</label>
								<textarea id="reply-{p.id}" rows="2" bind:value={replyText}></textarea>
								<span class="hint" class:over={noteLength(replyText) > MAX_NOTE_CHARS}>
									{noteLength(replyText)} / {MAX_NOTE_CHARS}. Only {p.author.display_name} sees it.
								</span>
							</div>
							{#if !memberKeys}
								<UnlockKeys kind="member" {user}>
									{#snippet intro()}
										<p class="muted small">Unlock your keys to sign the reply.</p>
									{/snippet}
								</UnlockKeys>
							{/if}
							{#if replyError}<div class="notice error" role="alert"><p>{replyError}</p></div>{/if}
							<div class="actions">
								<button
									class="primary small"
									type="button"
									disabled={replyBusy ||
										!memberKeys ||
										!replyText.trim() ||
										noteLength(replyText) > MAX_NOTE_CHARS}
									onclick={() => reply(p)}
								>
									{replyBusy ? 'Sending…' : 'Send reply'}
								</button>
								<button class="link small" type="button" onclick={() => (replyTo = '')}>
									Cancel
								</button>
							</div>
						{:else if !repliesOf(p.id).some((x) => x.author.user_id === user.id)}
							<button
								class="link small"
								type="button"
								onclick={() => {
									replyTo = p.id;
									replyText = '';
									replyError = '';
								}}
							>
								Reply privately
							</button>
						{/if}
					{/if}
				</li>
			{/each}
			{#each orphans as rp (rp.id)}
				{@const rr = reads.get(rp.id)}
				<li>
					<div class="row-title">
						<strong>{rp.author.user_id === user.id ? 'You' : rp.author.display_name}</strong>
						<span class="muted small">· a private reply · {ago(rp.created_at_ms)}</span>
					</div>
					{#if rr?.status === 'ok'}
						<blockquote class="reply">{rr.text}</blockquote>
					{:else}
						<p class="muted small">Unlock your keys to read it.</p>
					{/if}
				</li>
			{/each}
		</ul>
		{#if cursor}
			<div class="actions">
				<button class="secondary" type="button" onclick={() => load(true)}>Show older</button>
			</div>
		{/if}
	{/if}
</section>

<style>
	.scale {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem 1rem;
		border: none;
		padding: 0;
		margin: 0 0 0.75rem;
	}

	.scale label {
		display: flex;
		align-items: center;
		gap: 0.35rem;
	}

	.n {
		font-weight: 600;
	}

	.choices {
		border: none;
		padding: 0;
		margin: 0 0 0.75rem;
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}

	.pick {
		list-style: none;
		padding: 0;
		margin: 0;
		max-height: 16rem;
		overflow-y: auto;
	}

	.ans {
		margin: 0.25rem 0;
		white-space: pre-wrap;
		overflow-wrap: anywhere;
	}

	.reply {
		margin: 0.4rem 0;
		padding: 0.4rem 0.75rem;
		border-left: 3px solid var(--border-strong);
		white-space: pre-wrap;
		overflow-wrap: anywhere;
	}

	.over {
		color: var(--danger, inherit);
	}
</style>
