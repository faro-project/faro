<script lang="ts">
	import { onMount } from 'svelte';
	import { resolve } from '$app/paths';
	import { api, describeError } from '#lib/api.ts';
	import { bytes, count, plural } from '#lib/format.ts';
	import type { Overview, PrivacyNotice } from '#lib/types.ts';

	let overview = $state<Overview | null>(null);
	let notice = $state<PrivacyNotice | null>(null);
	let error = $state('');

	async function load() {
		error = '';
		try {
			overview = await api.get<Overview>('/admin/api/overview');
		} catch (e) {
			error = describeError(e);
		}
		api
			.get<PrivacyNotice>('/v1/privacy-notice')
			.then((n) => (notice = n))
			.catch(() => {});
	}

	onMount(load);

	const MODE_LABEL = {
		'invite-only': 'Invite only',
		open: 'Open to listed domains',
		closed: 'Closed'
	} as const;

	// Most recent first; the ramp goes dark → light with age.
	let recency = $derived.by(() => {
		if (!overview) return [];
		const l = overview.last_seen;
		return [
			{ key: 'within_1h', label: 'In the last hour', n: l.within_1h, tone: 'seq-1' },
			{ key: 'within_24h', label: 'In the last day', n: l.within_24h, tone: 'seq-2' },
			{ key: 'within_7d', label: 'In the last week', n: l.within_7d, tone: 'seq-3' },
			{ key: 'older', label: 'More than a week ago', n: l.older, tone: 'seq-4' },
			{ key: 'never', label: 'Never', n: l.never, tone: 'seq-none' }
		];
	});
	let recencyTotal = $derived(recency.reduce((a, r) => a + r.n, 0));

	function pct(n: number, of: number) {
		return of ? Math.round((n / of) * 100) : 0;
	}

	function graceText(secs: number) {
		const h = secs / 3600;
		return h >= 1 ? `${Math.round(h * 100) / 100} hours` : `${Math.round(secs / 60)} minutes`;
	}
</script>

<svelte:head>
	<title>Admin · Faro</title>
</svelte:head>

{#if error}
	<div class="notice error" role="alert">{error}</div>
	<button class="secondary" type="button" onclick={load}>Try again</button>
{:else if !overview}
	<p class="muted" role="status">Loading…</p>
{:else}
	<h1>{overview.instance_name}</h1>
	<p class="muted">faro-server {overview.server_version}</p>

	{#if !overview.smtp_configured}
		<div class="notice warn" role="status">
			<p>
				<span aria-hidden="true">⚠</span> <strong>Email is not set up.</strong> Nobody can sign in
				by email, and alerts can't reach allies.
				<a href={resolve('/admin/email')}>Email settings</a>
			</p>
		</div>
	{/if}
	{#if overview.notifications.failed > 0}
		<div class="notice error" role="status">
			<p>
				<span aria-hidden="true">⚠</span>
				<strong>
					{plural(overview.notifications.failed, 'notification')} could not be delivered
				</strong>
				after repeated attempts. Check the mail settings and the server log.
				<a href={resolve('/admin/email')}>Test email</a>
			</p>
		</div>
	{/if}
	{#if overview.deletions.overdue > 0}
		<div class="notice error" role="status">
			<p>
				<span aria-hidden="true">⚠</span>
				<strong>
					{plural(overview.deletions.overdue, 'account deletion')} waiting more than a week
				</strong>
				past {overview.deletions.overdue === 1 ? 'its' : 'their'} 7-day hold. An account is only deleted
				after everyone has been emailed about it, and those emails aren't getting through.
				<a href={resolve('/admin/email')}>Test email</a>
			</p>
		</div>
	{/if}

	<div class="tiles">
		<section class="tile" aria-labelledby="t-people">
			<h2 id="t-people">People</h2>
			<p class="figure">{count(overview.users.total)}</p>
			<ul class="sub">
				<li>{plural(overview.users.members, 'member')}</li>
				<li>{plural(overview.users.allies, 'ally', 'allies')}</li>
				<li>{plural(overview.users.admins, 'admin')}</li>
				{#if overview.users.disabled}<li>{count(overview.users.disabled)} disabled</li>{/if}
				{#if overview.deletions.pending}
					<li>{count(overview.deletions.pending)} being deleted</li>
				{/if}
			</ul>
			<a class="more" href={resolve('/admin/people')}>People and invitations</a>
		</section>

		<section class="tile" aria-labelledby="t-devices">
			<h2 id="t-devices">Computers</h2>
			<p class="figure">{count(overview.devices.active)}</p>
			<ul class="sub">
				<li>active</li>
				<li>{count(overview.devices.pending_endorsement)} awaiting their member's approval</li>
				<li>{count(overview.devices.removed)} removed</li>
			</ul>
		</section>

		<section class="tile" aria-labelledby="t-storage">
			<h2 id="t-storage">Storage</h2>
			<p class="figure">{bytes(overview.storage.blobs)}</p>
			<ul class="sub">
				<li>{plural(overview.storage.blob_count, 'encrypted item')}</li>
				{#if overview.storage.database !== null}
					<li>database {bytes(overview.storage.database)}</li>
				{/if}
			</ul>
		</section>

		<section class="tile" aria-labelledby="t-mail">
			<h2 id="t-mail">Notifications</h2>
			<p class="figure">{count(overview.notifications.sent)}</p>
			<ul class="sub">
				<li>sent</li>
				<li>{count(overview.notifications.pending)} waiting</li>
				<li>{count(overview.notifications.retrying)} retrying</li>
				<li class:failed={overview.notifications.failed > 0}>
					{#if overview.notifications.failed > 0}<span aria-hidden="true">⚠</span>{/if}
					{count(overview.notifications.failed)} failed
				</li>
			</ul>
		</section>
	</div>

	<section class="card" aria-labelledby="checkins">
		<h2 id="checkins">Last check-in of active computers</h2>
		{#if recencyTotal === 0}
			<p class="muted">No computers are enrolled yet.</p>
		{:else}
			<div
				class="bar"
				role="img"
				aria-label="Share of active computers by last check-in; listed below"
			>
				{#each recency.filter((r) => r.n > 0) as r (r.key)}
					<span
						class="seg {r.tone}"
						style:flex-grow={r.n}
						title="{r.label}: {count(r.n)} ({pct(r.n, recencyTotal)}%)"
					></span>
				{/each}
			</div>
			<ul class="legend">
				{#each recency as r (r.key)}
					<li>
						<span class="swatch {r.tone}" aria-hidden="true"></span>
						<span class="name">{r.label}</span>
						<span class="n">{count(r.n)}</span>
					</li>
				{/each}
			</ul>
			<p class="hint">
				Allies are alerted when a computer is silent for longer than the grace period ({graceText(
					overview.settings.liveness.grace_secs
				)}).
			</p>
		{/if}
	</section>

	<section class="card" aria-labelledby="settings">
		<h2 id="settings">Settings</h2>
		<dl class="facts">
			<dt>Registration</dt>
			<dd>
				{MODE_LABEL[overview.settings.registration.mode]}
				{#if overview.settings.registration.mode === 'open'}
					({overview.settings.registration.allowed_email_domains.join(', ')})
				{/if}
			</dd>
			<dt>Retention</dt>
			<dd>
				activity log {overview.settings.retention.event_header_days} days, reports and details {overview
					.settings.retention.blob_days} days, alerts {overview.settings.retention.alert_days} days
			</dd>
			<dt>Missed check-in alert after</dt>
			<dd>{graceText(overview.settings.liveness.grace_secs)}</dd>
			<dt>Email</dt>
			<dd>{overview.smtp_configured ? 'Mail server configured' : 'Not configured'}</dd>
		</dl>
		<a href={resolve('/admin/settings')}>Change settings</a>
	</section>

	{#if notice}
		<details class="card notice-card">
			<summary><h2>What you can and cannot see as the operator</h2></summary>
			<p class="muted">
				Members are shown this notice before they sign up. It is generated from this instance's
				settings.
			</p>
			<h3>You can see</h3>
			<ul>
				{#each notice.operator_can_see as item, i (i)}<li>{item}</li>{/each}
			</ul>
			<h3>You cannot see</h3>
			<ul>
				{#each notice.operator_cannot_see as item, i (i)}<li>{item}</li>{/each}
			</ul>
			{#if notice.caveats.length}
				<h3>Limits</h3>
				<ul>
					{#each notice.caveats as item, i (i)}<li>{item}</li>{/each}
				</ul>
			{/if}
		</details>
	{/if}
{/if}

<style>
	.tiles {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(9.5rem, 1fr));
		gap: 0.75rem;
		margin: 1.25rem 0 1rem;
	}

	.tile {
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 1rem;
		display: flex;
		flex-direction: column;
	}

	.tile h2 {
		font-size: 0.85rem;
		font-weight: 600;
		color: var(--muted);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		margin: 0;
	}

	.figure {
		font-size: 2rem;
		font-weight: 700;
		line-height: 1.15;
		margin: 0.3rem 0 0.4rem;
		font-variant-numeric: tabular-nums;
	}

	.sub {
		list-style: none;
		padding: 0;
		margin: 0 0 0.5rem;
		color: var(--muted);
		font-size: 0.88rem;
		line-height: 1.45;
	}

	.sub .failed {
		color: var(--danger);
		font-weight: 600;
	}

	.more {
		margin-top: auto;
		font-size: 0.9rem;
	}

	.card {
		margin-bottom: 1rem;
	}

	.bar {
		display: flex;
		gap: 2px;
		height: 12px;
		margin: 0.75rem 0 1rem;
	}

	.seg {
		flex-basis: 0;
		min-width: 4px;
		border-radius: 3px;
	}

	.seq-1 {
		background: var(--seq-1);
	}
	.seq-2 {
		background: var(--seq-2);
	}
	.seq-3 {
		background: var(--seq-3);
	}
	.seq-4 {
		background: var(--seq-4);
	}
	.seq-none {
		background: var(--seq-none);
	}

	.legend {
		list-style: none;
		padding: 0;
		margin: 0 0 0.75rem;
	}

	.legend li {
		display: flex;
		align-items: center;
		gap: 0.6rem;
		padding: 0.3rem 0;
		border-bottom: 1px solid var(--border);
	}

	.legend li:last-child {
		border-bottom: none;
	}

	.swatch {
		width: 0.8rem;
		height: 0.8rem;
		border-radius: 3px;
		flex: none;
	}

	.legend .name {
		flex: 1;
	}

	.legend .n {
		font-variant-numeric: tabular-nums;
		font-weight: 600;
	}

	.facts {
		display: grid;
		grid-template-columns: max-content 1fr;
		gap: 0.4rem 1.25rem;
		margin: 0 0 1rem;
	}

	.facts dt {
		color: var(--muted);
	}

	.facts dd {
		margin: 0;
	}

	@media (max-width: 480px) {
		.facts {
			grid-template-columns: 1fr;
			gap: 0.1rem;
		}

		.facts dd {
			margin-bottom: 0.5rem;
		}
	}

	.notice-card summary {
		cursor: pointer;
		list-style-position: outside;
	}

	.notice-card summary h2 {
		display: inline;
		font-size: 1.1rem;
	}

	.notice-card h3 {
		font-size: 1rem;
		margin-top: 1rem;
	}

	.notice-card ul {
		padding-left: 1.2rem;
	}
</style>
