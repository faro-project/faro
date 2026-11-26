<script lang="ts">
	// "Reach out" (GROUPS.md §8.3): tell your allies, a group's facilitators
	// or people you choose that you're struggling. They get an urgent note
	// with no details ("Sam is reaching out. Open Faro to see."), and can
	// answer "I'll call" or "I'm here". An optional message is encrypted to
	// them and signed with your member key, so the server can neither read
	// nor fake it. Without member keys a reach out carries no message and
	// is marked "Sent through the server. Can't be verified."
	import { api, seg } from '../api.ts';
	import { keyring } from '../keys/keyring.svelte.ts';
	import { loadRecipients, reachOutError, sendReachOut } from '../reach-out-api.ts';
	import {
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

	let {
		user,
		groupId = null,
		onsent
	}: { user: User; groupId?: string | null; onsent?: () => void } = $props();

	let open = $state(false);
	let step = $state<'who' | 'write' | 'sent'>('who');
	let audience = $state<Audience>('allies');
	let roster = $state<RosterEntry[] | null>(null);
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
		if (roster || !groupId) return;
		try {
			const page = await api.get<Page<RosterEntry>>(`/v1/groups/${seg(groupId)}/participants`);
			roster = page.items.filter((p) => p.user_id !== user.id && !p.unavailable);
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

	let canSign = $derived(!!recipients?.can_sign);
	let memberKeys = $derived(keyring.memberFor(user.id));
	let readers = $derived(recipients ? sealable(recipients) : []);
	let noKey = $derived(recipients?.recipients.filter((r) => !r.enc_pubkey) ?? []);
	let unverified = $derived(readers.filter((r) => !r.sender_ally));
	let tooLong = $derived(noteLength(text) > MAX_NOTE_CHARS);

	/** `signed`: with your signature (and the message, if any). */
	async function send(signed: boolean) {
		if (!recipients) return;
		busy = true;
		error = '';
		try {
			const gid = audience === 'allies' ? null : groupId;
			const keys = keyring.memberFor(user.id);
			const message =
				signed && keys && readers.length
					? composeMessage(keys, recipients, 'reach_out', gid, text.trim() ? text : null)
					: undefined;
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
			</fieldset>
			{#if audience === 'people'}
				{#if !roster}
					<p class="muted" role="status">Loading the group…</p>
				{:else if roster.length === 0}
					<p class="muted">There's nobody else in this group yet.</p>
				{:else}
					<ul class="pick">
						{#each roster as p (p.user_id)}
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
		{:else if recipients}
			<p>
				To {recipients.recipients.map((r) => r.display_name).join(', ')}.
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
