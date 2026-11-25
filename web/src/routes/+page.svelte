<script lang="ts">
	import { onMount } from 'svelte';
	import { resolve } from '$app/paths';
	import { api } from '#lib/api.ts';
	import { ago } from '#lib/format.ts';
	import { instance } from '#lib/instance.svelte.ts';
	import { pendingInvite } from '#lib/keys/pending-invite.ts';
	import { session } from '#lib/session.svelte.ts';
	import type { DeviceSummary, MyAllies, SetupStatus, SupportedMember } from '#lib/types.ts';
	import Logo from '#lib/ui/Logo.svelte';

	let needsSetup = $state<boolean | null>(null);
	let devices = $state<DeviceSummary[] | null>(null);
	let allies = $state<MyAllies | null>(null);
	let supporting = $state<SupportedMember[] | null>(null);
	let hasInvite = $state(false);
	let loadedFor = '';

	onMount(async () => {
		hasInvite = !!pendingInvite();
		try {
			needsSetup = (await api.get<SetupStatus>('/v1/setup')).needs_setup;
		} catch {
			needsSetup = null;
		}
	});

	$effect(() => {
		const u = session.user;
		if (!u || u.id === loadedFor) return;
		loadedFor = u.id;
		if (u.roles.member) {
			api
				.get<DeviceSummary[]>('/v1/me/devices')
				.then((d) => (devices = d))
				.catch(() => {});
			api
				.get<MyAllies>('/v1/me/allies')
				.then((a) => (allies = a))
				.catch(() => {});
		}
		if (u.roles.ally) {
			api
				.get<SupportedMember[]>('/v1/ally/members')
				.then((m) => (supporting = m))
				.catch(() => {});
		}
	});

	let activeDevices = $derived(devices?.filter((d) => d.status === 'active') ?? []);
	let pendingDevices = $derived(devices?.filter((d) => d.status === 'pending_endorsement') ?? []);
	let activeAllies = $derived(allies?.allies.filter((a) => a.state === 'active') ?? []);
	let pendingAllies = $derived(allies?.allies.filter((a) => a.state === 'pending') ?? []);

	type Step = { done: boolean; title: string; text: string; href: string; cta: string };
	let steps = $derived.by((): Step[] => [
		{
			done: session.hasMemberKeys,
			title: 'Set up your keys',
			text: 'A passphrase protects the keys that approve your computers and allies.',
			href: resolve('/keys'),
			cta: 'Set up keys'
		},
		{
			done: activeDevices.length > 0,
			title: 'Add a computer',
			text: pendingDevices.length
				? `${pendingDevices.length} waiting for your approval.`
				: 'Install Faro and enroll it with a one-time code.',
			href: resolve('/computers'),
			cta: pendingDevices.length ? 'Approve' : 'Add a computer'
		},
		{
			done: activeAllies.length > 0,
			title: 'Invite an ally',
			text: pendingAllies.length
				? `${pendingAllies.length} waiting for your approval.`
				: 'Someone you trust, who sees your reports and alerts.',
			href: resolve('/allies'),
			cta: pendingAllies.length ? 'Approve' : 'Invite'
		}
	]);
	let setupDone = $derived(steps.every((s) => s.done));
</script>

<svelte:head>
	<title>{instance.info?.name ?? 'Faro'}</title>
</svelte:head>

{#if needsSetup}
	<section class="hero">
		<Logo height={64} />
		<h1>This instance needs setting up</h1>
		<p>Create the admin account with the one-time setup token from the server log.</p>
		<a class="button primary" href={resolve('/setup')}>Start setup</a>
	</section>
{:else if session.user}
	{@const u = session.user}
	<div class="page-head">
		<h1>Hello, {u.display_name}</h1>
		<p>{instance.info?.name ?? 'Faro'}</p>
	</div>

	{#if u.display_name === u.email.split('@')[0]}
		<div class="notice info">
			<p>
				People you're connected with see you as “{u.display_name}”.
				<a href={resolve('/settings')}>Set your name</a>
			</p>
		</div>
	{/if}

	{#if hasInvite}
		<div class="notice info">
			<p>You were accepting an invitation. <a href={resolve('/invite')}>Continue</a></p>
		</div>
	{/if}

	<div class="grid">
		{#if u.roles.member}
			<section class="card panel" aria-labelledby="h-member">
				<h2 id="h-member">Your accountability</h2>
				{#if !setupDone}
					<ol class="checklist">
						{#each steps as s (s.title)}
							<li class:done={s.done}>
								<span class="mark" aria-hidden="true">{s.done ? '✓' : ''}</span>
								<div>
									<strong>{s.title}</strong>
									{#if !s.done}<p class="muted small">{s.text}</p>{/if}
								</div>
								{#if !s.done}<a class="button secondary small" href={s.href}>{s.cta}</a>{/if}
							</li>
						{/each}
					</ol>
				{:else}
					<ul class="stats">
						<li>
							<a href={resolve('/computers')}>
								<span class="n">{activeDevices.length}</span>
								{activeDevices.length === 1 ? 'computer' : 'computers'}
							</a>
						</li>
						<li>
							<a href={resolve('/allies')}>
								<span class="n">{activeAllies.length}</span>
								{activeAllies.length === 1 ? 'ally' : 'allies'}
							</a>
						</li>
					</ul>
					{#if pendingDevices.length || pendingAllies.length || allies?.manifest?.needs_update}
						<div class="notice warn small">
							<p>
								{#if pendingDevices.length}<a href={resolve('/computers')}>
										{pendingDevices.length} computer{pendingDevices.length === 1 ? '' : 's'} to approve
									</a>.
								{/if}
								{#if pendingAllies.length}<a href={resolve('/allies')}>
										{pendingAllies.length} ally to approve
									</a>.
								{/if}
								{#if allies?.manifest?.needs_update}<a href={resolve('/allies')}>
										Confirm your updated ally list
									</a>.{/if}
							</p>
						</div>
					{/if}
					<a class="button primary" href={resolve('/activity')}>See your activity</a>
				{/if}
			</section>
		{/if}

		{#if u.roles.ally}
			<section class="card panel" aria-labelledby="h-ally">
				<h2 id="h-ally">People you support</h2>
				{#if !supporting}
					<p class="muted">Loading…</p>
				{:else if supporting.length === 0}
					<p class="muted">Nobody right now.</p>
				{:else}
					<ul class="people">
						{#each supporting as m (m.member_id)}
							<li>
								{#if m.state === 'active'}
									<a href="{resolve('/supporting/member')}?id={encodeURIComponent(m.member_id)}">
										{m.display_name}
									</a>
								{:else}
									<span>{m.display_name}</span>
									<span class="chip pending">waiting for approval</span>
								{/if}
								<span class="muted small">since {ago(m.activated_at_ms ?? m.created_at_ms)}</span>
							</li>
						{/each}
					</ul>
				{/if}
				<a class="button secondary" href={resolve('/supporting')}>Open</a>
			</section>
		{/if}

		{#if u.roles.admin}
			<section class="card panel" aria-labelledby="h-admin">
				<h2 id="h-admin">Instance admin</h2>
				<p class="muted">
					People, invitations, settings and email. Admins never see anyone's reports.
				</p>
				<a class="button secondary" href={resolve('/admin')}>Admin console</a>
			</section>
		{/if}

		{#if !u.roles.member && !u.roles.ally && !u.roles.admin}
			<section class="card panel">
				<h2>Welcome</h2>
				<p>
					Your account has no role here yet. Ask the person who runs this instance for an
					invitation, or open the invitation link you were sent.
				</p>
			</section>
		{/if}
	</div>
{:else}
	<section class="hero">
		<Logo height={72} />
		<p class="tagline">Free, open-source, self-hosted screen accountability.</p>
		<p class="lead">
			{instance.info && instance.info.name !== 'Faro' ? instance.info.name : 'This instance'} runs Faro.
			People choose to install it on their own computers and invite allies they trust. Reports are encrypted
			so only those allies, and the person themself, can read them.
		</p>
		{#if session.loaded}
			<div class="actions center">
				<a class="button primary" href={resolve('/signin')}>Sign in</a>
				<a class="button secondary" href={resolve('/privacy')}>What this instance can see</a>
			</div>
		{/if}
	</section>
{/if}

<style>
	.hero {
		text-align: center;
		max-width: 36rem;
		margin: 2rem auto 0;
		display: flex;
		flex-direction: column;
		align-items: center;
	}

	.hero :global(.logo) {
		margin-bottom: 1.5rem;
		max-width: 100%;
		height: auto;
	}

	.tagline {
		font-size: 1.2rem;
		font-weight: 600;
	}

	.lead {
		color: var(--muted);
	}

	.actions.center {
		justify-content: center;
	}

	.grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(18rem, 1fr));
		gap: 1rem;
		align-items: start;
	}

	.grid .card + .card {
		margin-top: 0;
	}

	.panel h2 {
		font-size: 1.1rem;
	}

	.checklist {
		list-style: none;
		padding: 0;
		margin: 0;
	}

	.checklist li {
		display: flex;
		align-items: flex-start;
		gap: 0.75rem;
		padding: 0.7rem 0;
		border-top: 1px solid var(--border);
	}

	.checklist li:first-child {
		border-top: none;
	}

	.checklist li > div {
		flex: 1;
	}

	.checklist p {
		margin: 0.15rem 0 0;
	}

	.mark {
		width: 1.4rem;
		height: 1.4rem;
		border-radius: 50%;
		border: 1.5px solid var(--border-strong);
		display: grid;
		place-items: center;
		font-size: 0.8rem;
		font-weight: 700;
		flex: none;
		margin-top: 0.1rem;
	}

	.checklist li.done .mark {
		background: var(--ok);
		border-color: var(--ok);
		color: var(--surface);
	}

	.checklist li.done strong {
		color: var(--muted);
		font-weight: 500;
	}

	.stats {
		list-style: none;
		display: flex;
		gap: 1.5rem;
		padding: 0;
		margin: 0 0 1rem;
	}

	.stats a {
		color: var(--text);
		text-decoration: none;
	}

	.stats .n {
		display: block;
		font-size: 2rem;
		font-weight: 700;
		line-height: 1.1;
		font-variant-numeric: tabular-nums;
	}

	.people {
		list-style: none;
		padding: 0;
		margin: 0 0 1rem;
	}

	.people li {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		gap: 0.25rem 0.6rem;
		padding: 0.35rem 0;
	}

	.people a {
		font-weight: 600;
	}
</style>
