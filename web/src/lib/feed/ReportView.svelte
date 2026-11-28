<script lang="ts">
	// A decrypted daily report (ARCHITECTURE.md §6): activity timeline,
	// counts by rating, flagged moments with their blurred thumbnails, and a
	// health summary. Built on the device; the server never saw any of it.
	import type { ActivityState, DailyReport } from '../types.ts';
	import { dateTime, date } from '../format.ts';
	import {
		categoryCounts,
		categoryName,
		describeReason,
		describeTamper,
		hostsByCategory,
		IOS_LIMITS_NOTICE,
		RATING_LABEL
	} from './describe.ts';
	import { thumbnailUrl } from './feed.ts';
	import Icon from '../ui/Icon.svelte';

	let { report }: { report: DailyReport } = $props();

	const STATE: Record<ActivityState, string> = {
		active: 'In use',
		idle: 'Idle (screen on, no input)',
		locked: 'Locked',
		asleep: 'Asleep',
		paused: 'Paused',
		off: 'Off',
		unmonitored: 'Not monitored'
	};

	let span = $derived(Math.max(1, report.period_end_ms - report.period_start_ms));
	let total = $derived(
		report.counts.clean + report.counts.low + report.counts.medium + report.counts.high
	);
	let shownStates = $derived([...new Set(report.timeline.map((t) => t.state))]);

	function time(ms: number) {
		return new Date(ms).toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
	}

	function momentText(f: DailyReport['flagged'][number]): string {
		const parts = [f.reasons.map(describeReason).join('; ')];
		if (f.app) parts.push(`in ${f.app.name ?? f.app.id}`);
		if (f.account) parts.push(`account “${f.account}”`);
		return parts.filter(Boolean).join(' · ');
	}

	/** The account a tamper record concerns, unless its text already says. */
	function accountNote(t: { signal: { signal: string }; account?: string }): string {
		return t.account && t.signal.signal !== 'unmonitored_user_session'
			? ` (account “${t.account}”)`
			: '';
	}

	function protectionWord(on: boolean | null): string {
		return on === null ? 'unknown' : on ? 'on' : 'off';
	}

	function minutes(secs: number) {
		const m = Math.round(secs / 60);
		return m < 60 ? `${m} min` : `${Math.round((m / 60) * 10) / 10} h`;
	}
</script>

<div class="report">
	<p class="muted meta">
		{report.device_name} · {dateTime(report.period_start_ms)} to {dateTime(report.period_end_ms)}
	</p>

	{#if report.ios}
		<!-- An iPhone blocks; it has no activity timeline of its own. -->
	{:else}
		<h4>Activity</h4>
		{#if report.timeline.length === 0}
			<p class="muted small">No activity recorded.</p>
		{:else}
			<div class="timeline" role="img" aria-label="Activity through the day; listed below">
				{#each report.timeline as t, i (i)}
					<span
						class="span st-{t.state}"
						style:left="{((t.start_ms - report.period_start_ms) / span) * 100}%"
						style:width="{Math.max(0.3, ((t.end_ms - t.start_ms) / span) * 100)}%"
						title="{STATE[t.state]}: {time(t.start_ms)}–{time(t.end_ms)}{t.account
							? ` (${t.account})`
							: ''}"
					></span>
				{/each}
			</div>
			<div class="axis muted" aria-hidden="true">
				<span>{time(report.period_start_ms)}</span><span>{time(report.period_end_ms)}</span>
			</div>
			<ul class="legend small">
				{#each shownStates as s (s)}
					<li><span class="swatch st-{s}" aria-hidden="true"></span>{STATE[s]}</li>
				{/each}
			</ul>
		{/if}
	{/if}

	{#if report.ios}
		{@const ios = report.ios}
		<div class="notice info"><p>{IOS_LIMITS_NOTICE}</p></div>

		<h4>Protection</h4>
		{#if ios.protection.length === 0}
			<p class="muted small">No protection changes recorded.</p>
		{:else}
			<ul class="small plain">
				{#each ios.protection as p, i (i)}
					<li>
						<span class="t">{time(p.start_ms)} to {time(p.end_ms)}</span>: Screen Time {protectionWord(
							p.screen_time
						)}, web filter {protectionWord(p.filter)}
					</li>
				{/each}
			</ul>
		{/if}
		{#if ios.loosenings?.length}
			<ul class="small plain">
				{#each ios.loosenings as l, i (i)}<li>
						<span class="t">{time(l.ts_ms)}</span>: {l.text}
					</li>{/each}
			</ul>
		{/if}

		<h4>Blocked lookups</h4>
		{#if ios.blocked.length === 0}
			<p class="muted small">Nothing was blocked, or this report doesn't include it yet.</p>
		{:else}
			{#each ios.blocked as day, i (i)}
				<p class="small">
					<strong class="t">{date(day.day_start_ms)}</strong>: {categoryCounts(day.by_category) ||
						'nothing blocked'}
				</p>
				{#each hostsByCategory(day.hosts) as g (g.category)}
					<p class="small hosts">
						{categoryName(g.category)}:
						{g.hosts.map((h) => `${h.host} (${h.count})`).join(', ')}
					</p>
				{/each}
				{#if day.other_hosts}
					<p class="small hosts muted">
						{day.other_hosts} more lookups of other sites, not listed.
					</p>
				{/if}
			{/each}
		{/if}

		<h4>Blocked apps opened</h4>
		{#if ios.shields.length === 0}
			<p class="muted small">None, or this report doesn't include it yet.</p>
		{:else}
			<ul class="small plain">
				{#each ios.shields as s, i (i)}
					<li>
						<span class="t">{date(s.day_start_ms)}</span>: {s.shown} time{s.shown === 1 ? '' : 's'},
						closed {s.closed}.
					</li>
				{/each}
			</ul>
			<p class="muted small">Faro counts these but never records which apps.</p>
		{/if}
	{:else}
		<h4>Screen checks</h4>
		<ul class="counts">
			<li><span class="n">{total}</span> total</li>
			<li><span class="n">{report.counts.clean}</span> clean</li>
			<li><span class="n">{report.counts.low}</span> low</li>
			<li class:flag={report.counts.medium > 0}>
				<span class="n">{report.counts.medium}</span> medium
			</li>
			<li class:flag={report.counts.high > 0}><span class="n">{report.counts.high}</span> high</li>
		</ul>
	{/if}

	{#if report.flagged.length}
		<h4>{report.ios ? 'Flagged bursts' : 'Flagged moments'}</h4>
		<ul class="flagged">
			{#each report.flagged as f, i (i)}
				{@const url = f.thumbnail ? thumbnailUrl(f.thumbnail) : null}
				<li>
					{#if url && f.thumbnail}
						<img
							src={url}
							alt="Blurred screenshot"
							width={f.thumbnail.width}
							height={f.thumbnail.height}
							class="thumb"
						/>
					{/if}
					<div>
						<div class="row-title">
							<span class="chip {f.rating === 'high' ? 'urgent' : 'normal'}">
								{RATING_LABEL[f.rating]}
							</span>
							<span class="t">{time(f.ts_ms)}</span>
						</div>
						<p class="small">
							{momentText(f)}
						</p>
						{#if f.member_note}<p class="note small">Note from the member: {f.member_note}</p>{/if}
					</div>
				</li>
			{/each}
		</ul>
	{/if}

	{#if report.top_domains?.length || report.top_apps?.length}
		<div class="tops">
			{#if report.top_apps?.length}
				<div>
					<h4>Most used apps</h4>
					<ol class="small">
						{#each report.top_apps as a, i (i)}<li>
								{a.name} <span class="count">({a.count})</span>
							</li>{/each}
					</ol>
				</div>
			{/if}
			{#if report.top_domains?.length}
				<div>
					<h4>Most visited sites</h4>
					<ol class="small">
						{#each report.top_domains as d, i (i)}<li>
								{d.name} <span class="count">({d.count})</span>
							</li>{/each}
					</ol>
				</div>
			{/if}
		</div>
	{/if}

	<h4>Health</h4>
	{#if !report.health.tamper.length && !report.health.context.length && !report.health.agent_restarts && !report.health.capture_failures && !report.health.unmonitored_secs}
		<p class="small"><span class="chip good"><Icon name="check" /> No problems</span></p>
	{:else}
		<ul class="health small">
			{#each report.health.tamper as t, i (i)}
				<li class="bad">
					<Icon name="alert" /> <span class="t">{time(t.ts_ms)}</span>: {describeTamper(
						t.signal
					)}{accountNote(t)}
				</li>
			{/each}
			{#each report.health.context as t, i (i)}
				<li><span class="t">{time(t.ts_ms)}</span>: {describeTamper(t.signal)}</li>
			{/each}
			{#if report.health.agent_restarts}<li>
					Faro restarted {report.health.agent_restarts === 1
						? 'once'
						: `${report.health.agent_restarts} times`}.
				</li>{/if}
			{#if report.health.capture_failures}<li>
					{report.health.capture_failures} screen checks failed.
				</li>{/if}
			{#if report.health.unmonitored_secs}<li>
					Not monitored for {minutes(report.health.unmonitored_secs)}.
				</li>{/if}
		</ul>
	{/if}
</div>

<style>
	.report {
		margin-top: 0.5rem;
	}

	.meta {
		font-family: var(--mono);
		font-size: 0.76rem;
		margin: 0;
	}

	/* Section labels inside a report: small, letter-spaced, like .eyebrow. */
	.report h4 {
		font-size: 0.68rem;
		font-weight: 500;
		text-transform: uppercase;
		letter-spacing: 0.09em;
		color: var(--muted);
		margin: 1.1rem 0 0.45rem;
	}

	/* Times, dates and counts in the code face. */
	.t,
	.count {
		font-family: var(--mono);
		font-size: 0.92em;
		font-weight: 500;
		font-variant-numeric: tabular-nums;
	}

	.count {
		color: var(--muted);
		font-weight: 400;
	}

	.plain {
		list-style: none;
		padding: 0;
		margin: 0;
	}

	.hosts {
		margin: 0.1rem 0 0.1rem 1rem;
	}

	.timeline {
		position: relative;
		height: 10px;
		background: var(--surface-2);
		border: 1px solid var(--border);
		border-radius: 3px;
		overflow: hidden;
	}

	.span {
		position: absolute;
		top: 0;
		bottom: 0;
	}

	.st-active {
		background: var(--seq-2);
	}
	.st-idle {
		background: var(--seq-3);
	}
	.st-locked,
	.st-asleep,
	.st-off {
		background: var(--seq-none);
	}
	.st-paused {
		background: repeating-linear-gradient(
			45deg,
			var(--warn) 0 3px,
			color-mix(in srgb, var(--warn) 35%, transparent) 3px 6px
		);
	}
	.st-unmonitored {
		background: var(--danger);
	}

	.axis {
		display: flex;
		justify-content: space-between;
		margin-top: 0.25rem;
		font-family: var(--mono);
		font-size: 0.72rem;
		font-variant-numeric: tabular-nums;
	}

	.legend {
		list-style: none;
		display: flex;
		flex-wrap: wrap;
		gap: 0.3rem 1rem;
		padding: 0;
		margin: 0.3rem 0 0;
	}

	.legend li {
		display: inline-flex;
		align-items: center;
		gap: 0.35rem;
	}

	.swatch {
		width: 0.65rem;
		height: 0.65rem;
		border-radius: 2px;
		display: inline-block;
	}

	.counts {
		list-style: none;
		display: flex;
		flex-wrap: wrap;
		gap: 0.4rem 1.5rem;
		padding: 0;
		margin: 0;
		font-family: var(--mono);
		font-size: 0.76rem;
		color: var(--muted);
	}

	.counts .n {
		color: var(--text);
		font-size: 1.15rem;
		font-weight: 500;
		letter-spacing: -0.03em;
		font-variant-numeric: tabular-nums;
		margin-right: 0.2rem;
	}

	.counts .flag,
	.counts .flag .n {
		color: var(--danger);
	}

	.flagged {
		list-style: none;
		padding: 0;
		margin: 0;
	}

	.flagged li {
		display: flex;
		gap: 0.9rem;
		align-items: flex-start;
		padding: 0.6rem 0;
		border-top: 1px solid var(--border);
	}

	.flagged li:first-child {
		border-top: none;
	}

	.flagged .t {
		color: var(--muted);
		font-size: 0.78rem;
	}

	.flagged p {
		margin: 0.25rem 0 0;
	}

	.thumb {
		width: 112px;
		height: auto;
		border-radius: var(--radius-sm);
		border: 1px solid var(--border);
		flex: none;
	}

	.note {
		font-style: italic;
	}

	.tops {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
		gap: 0 1.5rem;
	}

	.tops ol {
		margin: 0;
		padding-left: 1.2rem;
	}

	.health {
		margin: 0;
		padding-left: 1.1rem;
	}

	.health .bad {
		color: var(--danger);
	}
</style>
