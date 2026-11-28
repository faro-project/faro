<script lang="ts">
	// One member's feed: alerts, flagged moments, tamper signals and daily
	// reports, newest first. The list is metadata from the server; with the
	// viewer's key unlocked, each item's details are fetched and decrypted
	// here. A member sees exactly what their allies see (§6, §12).
	//
	// Nothing the server says is taken on trust: each item is checked
	// against the member's key (the member's own, or the one an ally
	// compared by safety code) and its device's signature and hash chain
	// (`verify.ts`). Items that fail are marked and their details not shown;
	// gaps in a computer's history are listed above the feed.
	import { onDestroy, untrack } from 'svelte';
	import { describeError } from '../api.ts';
	import type { DeviceEndorsement, Signed } from '../crypto/proto.ts';
	import { dateTime } from '../format.ts';
	import { instance } from '../instance.svelte.ts';
	import { keyring } from '../keys/keyring.svelte.ts';
	import { verifiedKey } from '../keys/verified.ts';
	import type { ChainLink, FeedEntry, Platform, User } from '../types.ts';
	import Icon from '../ui/Icon.svelte';
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
		loadChain,
		loadFeed,
		openEntry,
		thumbnailUrl,
		type OpenFailure,
		type Opened
	} from './feed.ts';
	import ReportView from './ReportView.svelte';
	import {
		allyMemberKey,
		chainRange,
		checkChain,
		checkEntry,
		deviceKeys,
		passed,
		type ChainCheck,
		type Gap,
		type ItemCheck,
		type MemberKey
	} from './verify.ts';

	let {
		memberId,
		viewer,
		keyKind,
		memberSignPk = null,
		nameOf = () => undefined,
		deviceNames = {},
		devicePlatforms = {}
	}: {
		memberId: string;
		viewer: User;
		keyKind: 'member' | 'ally';
		/**
		 * For an ally: the member's signing key as the server reports it.
		 * Trusted only once the ally compared it by safety code.
		 */
		memberSignPk?: string | null;
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
	let endorsements = $state<Record<string, Signed<DeviceEndorsement>>>({});
	let loadedSince = $state(0);
	type Chain =
		| { range: string; status: 'loading' | 'error' }
		| { range: string; status: 'ok'; links: ChainLink[]; complete: boolean };
	let chains = $state<Record<string, Chain>>({});
	let loadedKey = '';

	async function load() {
		loading = true;
		error = '';
		try {
			const since = Date.now() - days * 86400_000;
			const r = await loadFeed(memberId, since);
			items = r.items;
			truncated = r.truncated;
			serverPlatforms = r.platforms;
			endorsements = r.endorsements;
			loadedSince = since;
			// A history that failed to load is fetched again.
			for (const [d, c] of Object.entries(chains)) if (c.status === 'error') delete chains[d];
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
			chains = {};
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
					// Only what a computer signed names it.
					if (!passed(untrack(() => checks[k]))) continue;
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

	// ---- Checking (verify.ts) ----------------------------------------------

	/** The member key to check against, and where it came from. */
	let memberKey = $derived.by((): MemberKey | null => {
		if (keyKind === 'member') {
			const k = keyring.member;
			return k && k.userId === viewer.id ? { pk: k.signPk, trust: 'own' } : null;
		}
		return allyMemberKey(memberSignPk, verifiedKey(viewer.id, memberId));
	});

	let keys = $derived(
		memberKey && instance.info
			? deviceKeys(memberKey, instance.info.instance_id, memberId, endorsements)
			: new Map<string, Uint8Array | string>()
	);

	let checks = $derived.by(() => {
		const out: Record<string, ItemCheck> = {};
		const inst = instance.info?.instance_id;
		for (const e of items ?? []) {
			out[entryKey(e)] = inst
				? checkEntry(e, memberKey, keys, inst, memberId)
				: { status: 'unchecked' as const };
		}
		return out;
	});

	const ok = (e: FeedEntry) => passed(checks[entryKey(e)]);

	// Fetch each checked device's chain over the range the feed covers.
	$effect(() => {
		const list = items;
		const ks = keys;
		void checks;
		if (!list || !memberKey) return;
		untrack(() => {
			for (const [dev, pk] of ks) {
				if (typeof pk === 'string') continue;
				const r = chainRange(list, dev, ok);
				if (!r) continue;
				const range = `${r.lo}-${r.hi}`;
				if (chains[dev]?.range === range) continue;
				chains[dev] = { range, status: 'loading' };
				loadChain(memberId, dev, r.lo, r.hi)
					.then((c) => {
						if (chains[dev]?.range === range) chains[dev] = { range, status: 'ok', ...c };
					})
					.catch(() => {
						if (chains[dev]?.range === range) chains[dev] = { range, status: 'error' };
					});
			}
		});
	});

	/** Every stored event above urgency `none` received after this must be listed. */
	let listedAfter = $derived(
		truncated && items?.length ? items[items.length - 1].received_at_ms : loadedSince
	);

	let chainChecks = $derived.by(() => {
		const out: Record<string, ChainCheck> = {};
		const inst = instance.info?.instance_id;
		if (!items || !inst) return out;
		for (const [dev, c] of Object.entries(chains)) {
			const pk = keys.get(dev);
			const r = chainRange(items, dev, ok);
			if (c.status !== 'ok' || !(pk instanceof Uint8Array) || !r || c.range !== `${r.lo}-${r.hi}`)
				continue;
			out[dev] = checkChain({
				instanceId: inst,
				deviceId: dev,
				devicePk: pk,
				range: r,
				links: c.links,
				complete: c.complete,
				entries: items,
				listedAfterMs: listedAfter,
				ok
			});
		}
		return out;
	});

	let chainsPending = $derived(Object.values(chains).some((c) => c.status === 'loading'));
	let chainErrors = $derived(
		Object.entries(chains)
			.filter(([, c]) => c.status === 'error')
			.map(([d]) => d)
	);
	let chainCapped = $derived(
		Object.entries(chains)
			.filter(([, c]) => c.status === 'ok' && !c.complete)
			.map(([d]) => d)
	);

	/** An item's check, with what the chain and its content add. */
	function verdict(e: FeedEntry): ItemCheck {
		const k = entryKey(e);
		const c = checks[k] ?? { status: 'unchecked' };
		if (!passed(c)) return c;
		if (e.type === 'event' && chainChecks[e.device_id]?.notInChain.has(e.seq)) {
			return { status: 'failed', reason: 'it isn’t part of this computer’s history' };
		}
		if (opened[k] === 'tampered') return { status: 'failed', reason: 'its details were replaced' };
		return c;
	}

	let failedCount = $derived((items ?? []).filter((e) => verdict(e).status === 'failed').length);
	let gaps = $derived(Object.values(chainChecks).flatMap((c) => c.gaps));
	let broken = $derived(
		Object.entries(chainChecks)
			.filter(([, c]) => c.broken)
			.map(([d, c]) => ({ device: d, reason: c.broken! }))
	);

	function gapText(g: Gap): string {
		const name = device(g.deviceId);
		if (g.kind === 'withheld') {
			const what = (g.eventKind ?? 'event').replaceAll('_', ' ');
			return `The server holds a “${what}” event from ${name} (number ${g.from}) that it left out of this list.`;
		}
		const n = g.to - g.from + 1;
		const which = n === 1 ? `number ${g.from}` : `numbers ${g.from} to ${g.to}`;
		return `${n === 1 ? 'An event' : `${n} events`} from ${name} ${n === 1 ? 'is' : 'are'} missing (${which})${g.inReport ? ', which its daily report counts' : ''}.`;
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

{#if items && !error}
	{#if keyKind === 'ally' && !memberKey}
		<div class="notice warn">
			<p>
				Nothing here can be checked yet: this person hasn't set up their keys, so their computers'
				signatures can't be confirmed.
			</p>
		</div>
	{:else if memberKey?.trust === 'unchecked'}
		<div class="notice warn">
			<p>
				<strong>Not confirmed yet.</strong> These items are signed by computers approved with the
				key the server reports for this person, but you haven't compared safety codes, so the server
				could have made them up. Compare safety codes (the <em>Safety code</em> tab) to confirm them.
			</p>
		</div>
	{:else if memberKey?.trust === 'changed'}
		<div class="notice error" role="alert">
			<p>
				<strong>This person's key has changed</strong> since you compared safety codes. Items are checked
				against the key you compared, so anything signed with the new one shows as not verified until
				you compare the new code.
			</p>
		</div>
	{/if}
	{#if failedCount || gaps.length || broken.length || chainErrors.length}
		<div class="notice error" role="alert">
			{#if failedCount}
				<p>
					<strong>
						{failedCount === 1 ? 'One item' : `${failedCount} items`} failed {failedCount === 1
							? 'its'
							: 'their'} checks.
					</strong>
					{failedCount === 1 ? "It isn't" : "They aren't"} what this person's computers signed, so the
					server may have made {failedCount === 1 ? 'it' : 'them'} up or changed {failedCount === 1
						? 'it'
						: 'them'}. {failedCount === 1 ? 'It is' : 'They are'} marked below, without details.
				</p>
			{/if}
			{#if gaps.length || broken.length}
				<p><strong>The history the server provided has gaps:</strong></p>
				<ul class="gaps">
					{#each broken as b (b.device)}<li>
							{device(b.device)}'s history doesn't add up: {b.reason}.
						</li>{/each}
					{#each gaps as g (`${g.deviceId}:${g.kind}:${g.from}`)}<li>{gapText(g)}</li>{/each}
				</ul>
				<p class="small">
					A computer can lose events it couldn't send (the server then also raises a “chain gap”
					alert), or the server may be holding something back. Talk with {keyKind === 'member'
						? 'your allies'
						: 'this person'} about it.
				</p>
			{/if}
			{#if chainErrors.length}
				<p class="small">
					The history of {chainErrors.map((d) => device(d)).join(', ')} couldn't be loaded, so gaps there
					aren't checked. Refresh to try again.
				</p>
			{/if}
		</div>
	{:else if chainsPending}
		<p class="muted small" role="status">Checking each computer's history…</p>
	{:else if memberKey && (memberKey.trust === 'own' || memberKey.trust === 'checked') && items.length}
		<p class="muted small checked">
			<Icon name="check" /> Every event and report below is signed by one of {keyKind === 'member'
				? 'your'
				: 'their'} computers, and their history has no gaps.
		</p>
	{/if}
	{#if chainCapped.length}
		<p class="muted small">
			Only part of the history of {chainCapped.map((d) => device(d)).join(', ')} was checked. Choose a
			shorter range to check all of it.
		</p>
	{/if}
{/if}

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
				{@const v = verdict(e)}
				{@const title =
					(typeof o === 'object' &&
						v.status !== 'failed' &&
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
								{#if v.status === 'failed'}<span class="chip off">Not verified</span>
								{:else if v.status === 'unconfirmed'}<span
										class="chip pending"
										title="Signed by a computer approved with a key you haven't compared by safety code"
									>
										Unconfirmed
									</span>{/if}
							</div>
							<div class="row-meta">
								<span class="time" title={dateTime(e.received_at_ms)}>
									{time(e.received_at_ms)}
								</span>
								{#if e.type === 'event' || e.type === 'report'}
									· {device(e.device_id)}{/if}
								{#if d.text && e.type === 'alert'}
									· {d.text}{/if}
							</div>
							{#if v.status === 'failed'}
								<p class="small unverified">
									<Icon name="alert" /> Not verified: {v.reason}. It may not have come from {device(
										e.device_id
									)} at all.
								</p>
							{/if}

							<!-- Content comes from a device: if it doesn't render, only this item fails. -->
							<svelte:boundary>
								{#if hasContent(e)}
									{#if v.status === 'failed'}
										<p class="muted small">
											Details not shown, because this item failed its checks.
										</p>
									{:else if !secret}
										<p class="locked small"><Icon name="lock" /> Details encrypted</p>
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
		min-height: 2.2rem;
		padding: 0.35rem 0.75rem;
		font-size: 0.78rem;
		font-variant-numeric: tabular-nums;
	}

	.seg button + button {
		border-left: 1px solid var(--border-strong);
	}

	.seg button:hover:not(.on) {
		background: var(--surface-2);
		color: var(--text);
	}

	.seg button.on {
		background: var(--accent-soft);
		color: var(--accent);
	}

	.day {
		font-size: 0.7rem;
		font-weight: 500;
		text-transform: uppercase;
		letter-spacing: 0.09em;
		color: var(--muted);
		margin: 1.5rem 0 0.5rem;
	}

	.entry {
		display: flex;
		gap: 0.75rem;
	}

	.dot {
		width: 0.5rem;
		height: 0.5rem;
		border-radius: 50%;
		margin-top: 0.55rem;
		flex: none;
		background: var(--border-strong);
	}

	.time {
		font-family: var(--mono);
		font-size: 0.78rem;
		font-variant-numeric: tabular-nums;
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
		display: flex;
		align-items: center;
		gap: 0.4rem;
		color: var(--muted);
		font-family: var(--mono);
		font-size: 0.78rem;
		margin: 0.35rem 0 0;
	}

	.unverified {
		color: var(--danger);
		margin: 0.35rem 0 0;
	}

	.gaps {
		margin: 0.3rem 0 0.5rem;
		padding-left: 1.1rem;
	}

	.checked {
		margin: 0 0 1rem;
	}

	.checked :global(.icon) {
		color: var(--ok);
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
		border-radius: var(--radius-sm);
		border: 1px solid var(--border);
	}
</style>
