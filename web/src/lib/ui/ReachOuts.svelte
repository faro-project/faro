<script lang="ts">
	// Reach outs to you and from you (GROUPS.md §8.3), on the home page.
	// To you: who is reaching out, their message (opened and checked here),
	// and "I'll call" / "I'm here". You see that others answered (so five
	// people don't all call at once), not who. From you: who answered.
	import { ago } from '../format.ts';
	import {
		answerReachOut,
		listReachOuts,
		reachOutError,
		setQuietBypass
	} from '../reach-out-api.ts';
	import {
		answerLabel,
		othersLine,
		UNVERIFIED_LINE,
		type Answer,
		type IncomingReachOut,
		type MyReachOuts
	} from '../reach-out.ts';
	import type { User } from '../types.ts';
	import Icon from './Icon.svelte';
	import SignedNote from './SignedNote.svelte';

	let { user, version = 0 }: { user: User; version?: number } = $props();

	let data = $state<MyReachOuts | null>(null);
	let error = $state('');
	let busyId = $state('');

	async function load() {
		try {
			data = await listReachOuts();
			error = '';
		} catch (e) {
			error = reachOutError(e);
		}
	}

	$effect(() => {
		void version;
		void user.id;
		void load();
	});

	function replace(next: IncomingReachOut) {
		if (!data) return;
		data = { ...data, incoming: data.incoming.map((r) => (r.id === next.id ? next : r)) };
	}

	async function answer(r: IncomingReachOut, a: Answer) {
		busyId = r.id;
		error = '';
		try {
			replace(await answerReachOut(r.id, a));
		} catch (e) {
			error = reachOutError(e);
		} finally {
			busyId = '';
		}
	}

	async function letThrough(r: IncomingReachOut) {
		busyId = r.id;
		error = '';
		try {
			await setQuietBypass(r.from.user_id, true);
			if (data) {
				data = {
					...data,
					incoming: data.incoming.map((x) =>
						x.from.user_id === r.from.user_id ? { ...x, quiet_hours_bypass: true } : x
					)
				};
			}
		} catch (e) {
			error = reachOutError(e);
		} finally {
			busyId = '';
		}
	}

	const WHO: Record<string, string> = {
		allies: 'your allies',
		facilitators: 'the facilitators',
		people: 'people you chose'
	};
</script>

{#if error}<div class="notice error" role="alert"><p>{error}</p></div>{/if}

{#if data && data.incoming.length}
	<h3>Reaching out to you</h3>
	<ul class="rows">
		{#each data.incoming as r (r.id)}
			{@const others = othersLine(r.others_answered)}
			<li>
				<div class="row-title">
					<strong>{r.from.display_name} is reaching out</strong>
				</div>
				<div class="row-meta">
					{ago(r.created_at_ms)}{#if r.group_name}
						· {r.group_name}{/if}
				</div>
				{#if r.signed && r.message_id}
					<SignedNote messageId={r.message_id} {user} author={r.from.user_id} />
				{:else}
					<p class="muted small">{UNVERIFIED_LINE}</p>
				{/if}
				{#if others}<p class="small">{others}</p>{/if}
				<div class="actions">
					{#each ['call', 'here'] as const as a (a)}
						<button
							class={r.my_answer === a ? 'primary small' : 'secondary small'}
							type="button"
							aria-pressed={r.my_answer === a}
							disabled={busyId === r.id}
							onclick={() => answer(r, a)}
						>
							{answerLabel(a)}
						</button>
					{/each}
				</div>
				{#if r.my_answer}
					<p class="muted small">
						You answered "{answerLabel(r.my_answer)}". {r.from.display_name} can see that.
					</p>
				{/if}
				{#if !r.quiet_hours_bypass}
					<button
						class="link small"
						type="button"
						disabled={busyId === r.id}
						onclick={() => letThrough(r)}
					>
						Let {r.from.display_name}'s reach outs through quiet hours
					</button>
				{/if}
			</li>
		{/each}
	</ul>
{/if}

{#if data && data.outgoing.length}
	<h3>You reached out</h3>
	<ul class="rows">
		{#each data.outgoing as r (r.id)}
			{@const answered = r.recipients.filter((p) => p.answer)}
			<li>
				<div class="row-title to">
					To {WHO[r.audience] ?? 'people'}{#if r.group_name}
						in {r.group_name}{/if}
				</div>
				<div class="row-meta">
					{ago(r.created_at_ms)} · {r.recipients.map((p) => p.display_name).join(', ')}
				</div>
				{#if r.signed && r.message_id}
					<SignedNote messageId={r.message_id} {user} author={user.id} />
				{:else}
					<p class="muted small">Sent without a message.</p>
				{/if}
				{#if answered.length}
					<ul class="answers">
						{#each answered as p (p.user_id)}
							<li><Icon name="check" /> {p.display_name}: "{answerLabel(p.answer!)}"</li>
						{/each}
					</ul>
				{:else}
					<p class="muted small">Nobody has answered yet.</p>
				{/if}
			</li>
		{/each}
	</ul>
{/if}

<style>
	h3 {
		margin: 1.1rem 0 0.5rem;
	}

	.rows li {
		display: block;
	}

	.to {
		font-family: var(--mono);
		font-size: 0.92rem;
		font-weight: 600;
		letter-spacing: -0.01em;
	}

	/* When and where: metadata, in the code face. */
	.row-meta {
		font-family: var(--mono);
		font-size: 0.78rem;
		margin-bottom: 0.4rem;
	}

	.answers {
		list-style: none;
		padding: 0;
		margin: 0.3rem 0 0;
		font-size: 0.92rem;
	}

	.answers li {
		display: flex;
		align-items: baseline;
		gap: 0.4rem;
	}

	.answers :global(.icon) {
		color: var(--ok);
		align-self: center;
	}

	.rows .actions {
		margin-top: 0.6rem;
	}
</style>
