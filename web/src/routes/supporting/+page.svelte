<script lang="ts">
	// The members the viewer is an ally for (GET /v1/ally/members).
	import { resolve } from '$app/paths';
	import { api, describeError } from '#lib/api.ts';
	import { ago, date } from '#lib/format.ts';
	import { verification } from '#lib/keys/verified.ts';
	import { session } from '#lib/session.svelte.ts';
	import type { SupportedMember } from '#lib/types.ts';
	import AllySafetyCode from '#lib/ui/AllySafetyCode.svelte';
	import Gate from '#lib/ui/Gate.svelte';

	let members = $state<SupportedMember[] | null>(null);
	let error = $state('');
	let loadedFor = '';

	async function load() {
		error = '';
		try {
			members = await api.get<SupportedMember[]>('/v1/ally/members');
		} catch (e) {
			error = describeError(e);
		}
	}

	$effect(() => {
		const u = session.user;
		if (u?.roles.ally && u.id !== loadedFor) {
			loadedFor = u.id;
			void load();
		}
	});

	let active = $derived(members?.filter((m) => m.state === 'active') ?? []);
	let pending = $derived(members?.filter((m) => m.state === 'pending') ?? []);
</script>

<svelte:head>
	<title>Supporting · Faro</title>
</svelte:head>

<Gate role="ally">
	{#snippet children(user)}
		<div class="page-head">
			<h1>People you support</h1>
			<p>
				You see their alerts and daily reports, decrypted in your browser with your ally key. Faro
				is for honest conversations: when something comes up, talk to them.
			</p>
		</div>

		{#if error}
			<div class="notice error" role="alert"><p>{error}</p></div>
			<button class="secondary" type="button" onclick={load}>Try again</button>
		{:else if !members}
			<p class="muted" role="status">Loading…</p>
		{:else}
			{#if pending.length}
				<section class="section" aria-labelledby="pending">
					<h2 id="pending">Waiting for approval</h2>
					<ul class="rows">
						{#each pending as m (m.member_id)}
							<li>
								<div class="row-title">
									<strong>{m.display_name}</strong>
									<span class="chip pending">Waiting for them to approve you</span>
								</div>
								<div class="row-meta">You accepted {ago(m.created_at_ms)}.</div>
								<div class="code">
									<AllySafetyCode member={m} viewer={user} />
								</div>
							</li>
						{/each}
					</ul>
				</section>
			{/if}

			<section class="section" aria-labelledby="active">
				<h2 id="active">Supporting</h2>
				{#if active.length === 0}
					<div class="empty">
						<p>
							{pending.length
								? 'Once someone approves you, they appear here.'
								: "You aren't anyone's ally right now."}
						</p>
					</div>
				{:else}
					<ul class="rows">
						{#each active as m (m.member_id)}
							{@const v = verification(user.id, m.member_id, m.member_sign_pubkey)}
							<li>
								<div class="row-main">
									<div>
										<div class="row-title">
											<a
												class="name"
												href="{resolve('/supporting/member')}?id={encodeURIComponent(m.member_id)}"
											>
												{m.display_name}
											</a>
											{#if v === 'changed'}<span class="chip urgent">Key changed</span>{/if}
											{#if v === 'verified'}<span class="chip good">✓ Code checked</span>{/if}
										</div>
										<div class="row-meta">
											Ally since {date(m.activated_at_ms ?? m.created_at_ms)}
										</div>
										{#if m.deletion_purge_after_ms}
											<div class="notice warn small deleting">
												<p>
													{m.display_name} is deleting their account. Until {date(
														m.deletion_purge_after_ms
													)} nothing changes: their computers are still monitored and you can open their
													alerts and reports. Then everything about them is removed from this server.
												</p>
											</div>
										{/if}
									</div>
									<a
										class="button secondary small"
										href="{resolve('/supporting/member')}?id={encodeURIComponent(m.member_id)}"
									>
										Open
									</a>
								</div>
							</li>
						{/each}
					</ul>
				{/if}
			</section>
		{/if}
	{/snippet}
</Gate>

<style>
	.code {
		margin-top: 0.9rem;
	}

	.name {
		font-weight: 700;
		font-size: 1.05rem;
	}

	.deleting {
		margin: 0.6rem 0 0;
	}
</style>
