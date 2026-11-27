<script lang="ts">
	// "Reach out" (GROUPS.md §8.3): tell your allies, a group's facilitators
	// or people you choose that you're struggling. They get an urgent note
	// with no details ("Sam is reaching out. Open Faro to see."), and can
	// answer "I'll call" or "I'm here". An optional message is encrypted to
	// them and signed with your member key, so the server can neither read
	// nor fake it. Without member keys a reach out carries no message and
	// is marked "Sent through the server. Can't be verified."
	import { api, seg } from '../api.ts';
	import { epochKeyFor } from '../check-in-api.ts';
	import type { RosterState } from '../crypto/roster.ts';
	import { instance } from '../instance.svelte.ts';
	import { keyring } from '../keys/keyring.svelte.ts';
	import { loadRecipients, reachOutError, sendReachOut } from '../reach-out-api.ts';
	import {
		composeGroupReachOut,
		composeMessage,
		MAX_NAMED,
		MAX_NOTE_CHARS,
		noteLength,
		sealable,
		type Audience,
		type Recipients
	} from '../reach-out.ts';
	import type { Page, RosterEntry, User } from '../types.ts';
	import Modal from './Modal.svelte';
	import NoteField from './NoteField.svelte';

	/** Whole-group reach outs are for groups of this many people or fewer (decision 10). */
	const WHOLE_GROUP_MAX = 32;

	let {
		user,
		groupId = null,
		participants = null,
		roster = null,
		postingPaused = false,
		onsent
	}: {
		user: User;
		groupId?: string | null;
		/** The group's size: "the whole group" is offered only up to 32. */
		participants?: number | null;
		/** The roster this browser verified (for the epoch whole-group messages are sealed with). */
		roster?: RosterState | null;
		/** A facilitator has roster work to do: whole-group posting waits. */
		postingPaused?: boolean;
		onsent?: () => void;
	} = $props();

	let wholeGroupOffered = $derived(
		!!groupId && participants !== null && participants <= WHOLE_GROUP_MAX
	);
	let wholeGroupBlocked = $derived(postingPaused || !roster || roster.epoch === 0);

	let open = $state(false);
	let step = $state<'who' | 'write' | 'sent'>('who');
	let audience = $state<Audience>('allies');
	let people = $state<RosterEntry[] | null>(null);
	let chosen = $state<string[]>([]);
	let recipients = $state<Recipients | null>(null);
	let text = $state('');
	let busy = $state(false);
	let error = $state('');
	let sentTo = $state(0);

	function start() {
		open = true;
		step = 'who';
		audience = 'allies';
		chosen = [];
		recipients = null;
		text = '';
		error = '';
	}

	async function loadRoster() {
		if (people || !groupId) return;
		try {
			const page = await api.get<Page<RosterEntry>>(`/v1/groups/${seg(groupId)}/participants`);
			people = page.items.filter((p) => p.user_id !== user.id && !p.unavailable);
		} catch (e) {
			error = reachOutError(e);
		}
	}

	$effect(() => {
		if (audience === 'people') void loadRoster();
	});

	function toggle(id: string) {
		chosen = chosen.includes(id) ? chosen.filter((c) => c !== id) : [...chosen, id];
	}

	async function next() {
		busy = true;
		error = '';
		try {
			if (audience === 'group') {
				recipients = null;
				step = 'write';
				return;
			}
			recipients = await loadRecipients('reach_out', {
				audience,
				groupId: audience === 'allies' ? null : groupId,
				userIds: audience === 'people' ? chosen : undefined
			});
			step = 'write';
		} catch (e) {
			error = reachOutError(e);
		} finally {
			busy = false;
		}
	}

	let canSign = $derived(audience === 'group' ? user.roles.member : !!recipients?.can_sign);
	let memberKeys = $derived(keyring.memberFor(user.id));
	let readers = $derived(
		audience === 'group' ? [{ user_id: '' }] : recipients ? sealable(recipients) : []
	);
	let noKey = $derived(recipients?.recipients.filter((r) => !r.enc_pubkey) ?? []);
	let unverified = $derived(
		audience === 'group' || !recipients ? [] : sealable(recipients).filter((r) => !r.sender_ally)
	);
	let tooLong = $derived(noteLength(text) > MAX_NOTE_CHARS);

	/** `signed`: with your signature (and the message, if any). */
	async function send(signed: boolean) {
		if (!recipients && audience !== 'group') return;
		busy = true;
		error = '';
		try {
			const gid = audience === 'allies' ? null : groupId;
			const keys = keyring.memberFor(user.id);
			let message;
			if (audience === 'group') {
				if (signed && keys && groupId && roster) {
					const k = await epochKeyFor(groupId, user.id, roster);
					if (!k || k.epoch !== roster.epoch) {
						throw new Error("You don't have this group's key yet. Try again in a moment.");
					}
					const inst = await instance.load();
					message = composeGroupReachOut(
						keys,
						inst.instance_id,
						groupId,
						k.epoch,
						k.key,
						text.trim() ? text : null
					);
				}
			} else if (signed && keys && readers.length && recipients) {
				message = composeMessage(keys, recipients, 'reach_out', gid, text.trim() ? text : null);
			}
			const r = await sendReachOut({
				audience,
				group_id: gid,
				...(audience === 'people' ? { user_ids: chosen } : {}),
				...(message ? { message } : {})
			});
			sentTo = r.recipients.length;
			step = 'sent';
			onsent?.();
		} catch (e) {
			error = e instanceof Error && !('status' in e) ? e.message : reachOutError(e);
		} finally {
			busy = false;
		}
	}
</script>

<button class="primary" type="button" onclick={start}>Reach out</button>

{#if open}
	<Modal title="Reach out" onclose={() => (open = false)}>
		{#if step === 'sent'}
			<div class="notice ok" role="status">
				<p>
					✓ Sent. {sentTo === 1 ? 'One person was' : `${sentTo} people were`} told you're reaching out.
					You'll see here when someone answers.
				</p>
			</div>
			<div class="actions">
				<button class="secondary" type="button" onclick={() => (open = false)}>Close</button>
			</div>
		{:else if step === 'who'}
			<p>
				Who should know? They get an urgent note that you're reaching out, without any details, and
				can answer "I'll call" or "I'm here".
			</p>
			<fieldset class="choices">
				<legend class="visually-hidden">Who</legend>
				<label>
					<input type="radio" bind:group={audience} value="allies" />
					My allies
				</label>
				{#if groupId}
					<label>
						<input type="radio" bind:group={audience} value="facilitators" />
						The facilitators
					</label>
					<label>
						<input type="radio" bind:group={audience} value="people" />
						People I choose
					</label>
				{/if}
				{#if wholeGroupOffered}
					<label>
						<input type="radio" bind:group={audience} value="group" disabled={wholeGroupBlocked} />
						The whole group ({participants} people)
					</label>
				{/if}
			</fieldset>
			{#if postingPaused && wholeGroupOffered}
				<p class="muted small" role="status">
					Waiting for a facilitator to update the group. The whole group is paused until then; you
					can still reach out to people by name.
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
			{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
			<div class="actions">
				<button
					class="primary"
					type="button"
					disabled={busy || (audience === 'people' && chosen.length === 0)}
					onclick={next}
				>
					{busy ? 'One moment…' : 'Next'}
				</button>
				<button class="secondary" type="button" onclick={() => (open = false)}>Cancel</button>
			</div>
		{:else if recipients || audience === 'group'}
			<p>
				To {audience === 'group'
					? 'everyone in the group'
					: (recipients?.recipients ?? []).map((r) => r.display_name).join(', ')}.
			</p>
			{#if noKey.length}
				<p class="muted small">
					{noKey.map((r) => r.display_name).join(', ')}
					{noKey.length === 1 ? "is told, but can't" : "are told, but can't"} read your message: they
					have no keys yet.
				</p>
			{/if}
			{#if canSign && readers.length}
				<NoteField
					{user}
					bind:text
					canSign
					alwaysSign
					label="A message (optional)"
					placeholder="Rough night. Can someone call me?"
				/>
				{#if unverified.length}
					<p class="muted small">
						The keys of {unverified.map((r) => r.display_name).join(', ')} aren't from your own ally list,
						so they're not yet verified.
					</p>
				{/if}
			{:else}
				<p class="muted small">
					Your reach out is sent through the server. It can't be verified, so it carries no message.
				</p>
			{/if}
			{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}
			<div class="actions">
				{#if canSign && readers.length}
					<button
						class="primary"
						type="button"
						disabled={busy || !memberKeys || tooLong}
						onclick={() => send(true)}
					>
						{busy ? 'Sending…' : 'Send'}
					</button>
					{#if !memberKeys}
						<button class="secondary" type="button" disabled={busy} onclick={() => send(false)}>
							Send without a message
						</button>
					{/if}
				{:else}
					<button class="primary" type="button" disabled={busy} onclick={() => send(false)}>
						{busy ? 'Sending…' : 'Send'}
					</button>
				{/if}
				<button class="link" type="button" onclick={() => (step = 'who')}>Back</button>
			</div>
			{#if canSign && readers.length && !memberKeys}
				<p class="muted small">
					Unlock your keys to sign it and add a message. Sent without, it can't be verified.
				</p>
			{/if}
		{/if}
	</Modal>
{/if}

<style>
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

	.pick li {
		padding: 0.2rem 0;
	}
</style>
