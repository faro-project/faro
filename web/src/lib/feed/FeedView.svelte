<script lang="ts">
	// One member's feed: alerts, flagged moments, tamper signals and daily
	// reports, newest first. The list is metadata from the server; with the
	// viewer's key unlocked, each item's details are fetched and decrypted
	// here. A member sees exactly what their allies see (§6, §12).
	import { onDestroy, untrack } from 'svelte';
	import { describeError } from '../api.ts';
	import { dateTime } from '../format.ts';
	import { instance } from '../instance.svelte.ts';
	import { keyring } from '../keys/keyring.svelte.ts';
	import type { FeedEntry, Platform, User } from '../types.ts';
	import UnlockKeys from '../ui/UnlockKeys.svelte';
	import {
		bodyTitle,
		describeBody,
		describeEntry,
		isIosBody,
		platformOf,
		reportSummary,
		type NameOf
	} from './describe.ts';
	import {
		entryKey,
		FAILURE_TEXT,
		hasContent,
		loadFeed,
		openEntry,
		thumbnailUrl,
		type OpenFailure,
		type Opened
	} from './feed.ts';
	import ReportView from './ReportView.svelte';

	let {
		memberId,
		viewer,
		keyKind,
		nameOf = () => undefined,
		deviceNames = {},
		devicePlatforms = {}
	}: {
		memberId: string;
		viewer: User;
		keyKind: 'member' | 'ally';
		nameOf?: NameOf;
		deviceNames?: Record<string, string>;
		/** What each device is, where the page knows (the member's own device list). */
		devicePlatforms?: Record<string, Platform>;
	} = $props();

	const WINDOWS = [
		{ days: 1, label: 'Last day' },
		{ days: 7, label: 'Last 7 days' },
		{ days: 30, label: 'Last 30 days' },
		{ days: 90, label: 'Last 90 days' }
	];

	let days = $state(7);
	let only = $state<'all' | 'urgent' | 'reports'>('all');
	let items = $state<FeedEntry[] | null>(null);
	let truncated = $state(false);
	let error = $state('');
	let loading = $state(false);
	let opened = $state<Record<string, Opened | OpenFailure | 'loading'>>({});
	let expanded = $state<Record<string, boolean>>({});
	let learnedNames = $state<Record<string, string>>({});
	let serverPlatforms = $state<Record<string, Platform>>({});
	let learnedIos = $state<Record<string, true>>({});
	let loadedKey = '';

	async function load() {
		loading = true;
		error = '';
		try {
			const r = await loadFeed(memberId, Date.now() - days * 86400_000);
			items = r.items;
			truncated = r.truncated;
			serverPlatforms = r.platforms;
		} catch (e) {
			error = describeError(e);
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		const k = `${memberId}:${days}`;
		if (k !== loadedKey) {
			loadedKey = k;
			void load();
		}
	});

	const refresh = setInterval(() => {
		if (document.visibilityState === 'visible' && !loading) void load();
	}, 120_000);
	onDestroy(() => clearInterval(refresh));

	let secret = $derived(
		keyKind === 'member'
			? keyring.member?.userId === viewer.id
				? keyring.member.encSecret
				: null
			: keyring.ally?.userId === viewer.id
				? keyring.ally.encSecret
				: null
	);

	// Lock clears what was decrypted.
	$effect(() => {
		if (!secret) opened = {};
	});

	// Decrypt everything shown, a few at a time.
	$effect(() => {
		const s = secret;
		const inst = instance.info;
		const list = items;
		if (!s || !inst || !list) return;
		const todo = untrack(() => list.filter((e) => hasContent(e) && !(entryKey(e) in opened)));
		if (!todo.length) return;
		untrack(() => {
			for (const e of todo) opened[entryKey(e)] = 'loading';
		});
		let i = 0;
		const worker = async () => {
			while (i < todo.length) {
				const e = todo[i++];
				const k = entryKey(e);
				try {
					const o = await openEntry(e, inst.instance_id, viewer.id, s);
					opened[k] = o;
					if (o.kind === 'report' && e.type === 'report') {
						learnedNames[e.device_id] = o.report.device_name;
						if (o.report.ios) learnedIos[e.device_id] = true;
					}
					if (o.kind === 'event' && e.device_id && isIosBody(o.body))
						learnedIos[e.device_id] = true;
				} catch (err) {
					opened[k] = typeof err === 'string' ? (err as OpenFailure) : 'broken';
				}
			}
		};
		void Promise.all([worker(), worker(), worker(), worker()]);
	});

	/**
	 * What a device is, if the page knows: from the member's device list, from
	 * the feed (which tells an ally too), or from what an iPhone sent.
	 */
	function platform(id: string | null): Platform | undefined {
		return (
			platformOf(id, devicePlatforms, serverPlatforms) ??
			(id && learnedIos[id] ? ('ios' as const) : undefined)
		);
	}

	function device(id: string | null): string {
		if (!id) return 'A computer';
		return deviceNames[id] ?? learnedNames[id] ?? 'A computer';
	}

	let shown = $derived.by(() => {
		if (!items) return [];
		if (only === 'urgent')
			return items.filter((e) => e.type !== 'report' && e.urgency === 'urgent');
		if (only === 'reports') return items.filter((e) => e.type === 'report');
		return items;
	});

	let urgentCount = $derived(
		items?.filter((e) => e.type !== 'report' && e.urgency === 'urgent').length ?? 0
	);
	let reportCount = $derived(items?.filter((e) => e.type === 'report').length ?? 0);

	function dayLabel(ms: number): string {
		const d = new Date(ms);
		const today = new Date();
		const y = new Date();
		y.setDate(today.getDate() - 1);
		if (d.toDateString() === today.toDateString()) return 'Today';
		if (d.toDateString() === y.toDateString()) return 'Yesterday';
		return d.toLocaleDateString(undefined, { weekday: 'long', day: 'numeric', month: 'long' });
	}

	let groups = $derived.by(() => {
		const out: { label: string; entries: FeedEntry[] }[] = [];
		for (const e of shown) {
			const label = dayLabel(e.received_at_ms);
			if (out.at(-1)?.label === label) out.at(-1)!.entries.push(e);
			else out.push({ label, entries: [e] });
		}
		return out;
	});

	function time(ms: number) {
		return new Date(ms).toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
	}
</script>

{#if !secret}
	<div class="unlock-wrap">
		<UnlockKeys kind={keyKind} user={viewer}>
			{#snippet intro()}
				<h2>Unlock to see the details</h2>
				<p class="muted">
					Below is what the server knows: what kind of thing happened, and when. The details are
					encrypted; your {keyKind === 'member' ? 'keys open' : 'ally key opens'} them in this browser.
				</p>
			{/snippet}
		</UnlockKeys>
	</div>
{/if}

<div class="toolbar">
	<div class="filters">
		<label class="visually-hidden" for="feed-window">Time range</label>
		<select id="feed-window" bind:value={days}>
			{#each WINDOWS as w (w.days)}<option value={w.days}>{w.label}</option>{/each}
		</select>
		<div class="seg" role="group" aria-label="Show">
			<button
				type="button"
				class:on={only === 'all'}
				aria-pressed={only === 'all'}
				onclick={() => (only = 'all')}
			>
				Everything
			</button>
			<button
				type="button"
				class:on={only === 'urgent'}
				aria-pressed={only === 'urgent'}
				onclick={() => (only = 'urgent')}
			>
				Urgent{urgentCount ? ` (${urgentCount})` : ''}
			</button>
			<button
				type="button"
				class:on={only === 'reports'}
				aria-pressed={only === 'reports'}
				onclick={() => (only = 'reports')}
			>
				Reports{reportCount ? ` (${reportCount})` : ''}
			</button>
		</div>
	</div>
	<button class="secondary small" type="button" onclick={load} disabled={loading}>
		{loading ? 'Refreshing…' : 'Refresh'}
	</button>
</div>

{#if error}
	<div class="notice error" role="alert"><p>{error}</p></div>
{:else if !items}
	<p class="muted" role="status">Loading…</p>
{:else if shown.length === 0}
	<div class="empty">
		<p>
			{only === 'urgent'
				? 'Nothing urgent in this time range.'
				: only === 'reports'
					? 'No daily reports in this time range.'
					: 'Nothing in this time range.'}
		</p>
		<p class="small">
			Everyday screen checks that found nothing don't show up here; they are counted in daily
			reports.
		</p>
	</div>
{:else}
	{#if truncated}
		<div class="notice warn">
			<p>Showing the most recent 5,000 items. Choose a shorter range to see all of it.</p>
		</div>
	{/if}
	{#each groups as g (g.label)}
		<h3 class="day">{g.label}</h3>
		<ul class="rows feed">
			{#each g.entries as e (entryKey(e))}
				{@const k = entryKey(e)}
				{@const d = describeEntry(e, nameOf, device(e.device_id), platform(e.device_id))}
				{@const o = opened[k]}
				{@const title =
					(typeof o === 'object' &&
						o.kind === 'event' &&
						bodyTitle(o.body, device(e.device_id), platform(e.device_id))) ||
					d.title}
				<li class="tone-{d.tone}">
					<div class="entry">
						<span class="dot" aria-hidden="true"></span>
						<div class="body">
							<div class="row-title">
								<strong>{title}</strong>
								{#if e.type !== 'report' && e.urgency === 'urgent'}<span class="chip urgent">
										Urgent
									</span>{/if}
								{#if e.type === 'alert'}<span
										class="chip"
										title="Raised by the server from what it can see"
									>
										Server
									</span>{/if}
							</div>
							<div class="row-meta">
								<span title={dateTime(e.received_at_ms)}>{time(e.received_at_ms)}</span>
								{#if e.type === 'event' || e.type === 'report'}
									· {device(e.device_id)}{/if}
								{#if d.text && e.type === 'alert'}
									· {d.text}{/if}
							</div>

							<!-- Content comes from a device: if it doesn't render, only this item fails. -->
							<svelte:boundary>
								{#if hasContent(e)}
									{#if !secret}
										<p class="locked small">🔒 Details encrypted</p>
									{:else if o === 'loading' || o === undefined}
										<p class="muted small">Decrypting…</p>
									{:else if typeof o === 'string'}
										<p class="muted small">{FAILURE_TEXT[o]}</p>
									{:else if o.kind === 'event'}
										<ul class="details small">
											{#each describeBody(o.body, device(e.device_id), Date.now(), platform(e.device_id)) as line, i (i)}<li>
													{line}
												</li>{/each}
										</ul>
										{#if o.body.type === 'flag' && o.body.thumbnail}
											{@const url = thumbnailUrl(o.body.thumbnail)}
											{#if url}
												<img
													class="thumb"
													src={url}
													alt="Blurred screenshot"
													width={o.body.thumbnail.width}
													height={o.body.thumbnail.height}
												/>
											{/if}
										{/if}
									{:else}
										<p class="small">{reportSummary(o.report)}</p>
										<button
											class="link small"
											type="button"
											onclick={() => (expanded[k] = !expanded[k])}
											aria-expanded={!!expanded[k]}
										>
											{expanded[k] ? 'Hide the report' : 'Show the report'}
										</button>
										{#if expanded[k]}<ReportView report={o.report} />{/if}
									{/if}
								{/if}
								{#snippet failed()}
									<p class="muted small">{FAILURE_TEXT.unreadable}</p>
								{/snippet}
							</svelte:boundary>
						</div>
					</div>
				</li>
			{/each}
		</ul>
	{/each}
{/if}

<style>
	.unlock-wrap {
		margin-bottom: 1.5rem;
	}

	.toolbar {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: 0.75rem;
		margin-bottom: 1rem;
	}

	.filters {
		display: flex;
		flex-wrap: wrap;
		gap: 0.6rem;
		align-items: center;
	}

	.seg {
		display: inline-flex;
		border: 1px solid var(--border-strong);
		border-radius: var(--radius-sm);
		overflow: hidden;
	}

	.seg button {
		background: var(--surface);
		color: var(--muted);
		border: none;
		border-radius: 0;
		min-height: 2.4rem;
		padding: 0.4rem 0.8rem;
		font-size: 0.9rem;
	}

	.seg button + button {
		border-left: 1px solid var(--border-strong);
	}

	.seg button.on {
		background: var(--accent-soft);
		color: var(--text);
	}

	.day {
		font-size: 0.85rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--muted);
		margin: 1.5rem 0 0.5rem;
	}

	.entry {
		display: flex;
		gap: 0.8rem;
	}

	.dot {
		width: 0.7rem;
		height: 0.7rem;
		border-radius: 50%;
		margin-top: 0.45rem;
		flex: none;
		background: var(--border-strong);
	}

	.tone-urgent .dot {
		background: var(--danger);
	}

	.tone-normal .dot {
		background: var(--brand);
	}

	.tone-good .dot {
		background: var(--ok);
	}

	.tone-info .dot {
		background: var(--seq-3);
	}

	.body {
		min-width: 0;
		flex: 1;
	}

	.details {
		margin: 0.4rem 0 0;
		padding-left: 1.1rem;
		overflow-wrap: anywhere;
	}

	.locked {
		color: var(--muted);
		margin: 0.35rem 0 0;
	}

	.body > p.small {
		margin: 0.35rem 0 0.2rem;
	}

	.thumb {
		display: block;
		margin-top: 0.6rem;
		width: 160px;
		max-width: 100%;
		height: auto;
		border-radius: 6px;
		border: 1px solid var(--border);
	}
</style>
