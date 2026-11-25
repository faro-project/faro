<script lang="ts">
	// Renders `children` only for a signed-in user with `role`; otherwise
	// says what is missing. The API checks every request anyway; this is
	// about showing the right page.
	import { onMount, type Snippet } from 'svelte';
	import { resolve } from '$app/paths';
	import { describeError } from '../api.ts';
	import { instance } from '../instance.svelte.ts';
	import { session } from '../session.svelte.ts';
	import type { User, WellKnown } from '../types.ts';

	let {
		role = 'any',
		children
	}: {
		role?: 'member' | 'ally' | 'any';
		children: Snippet<[User, WellKnown]>;
	} = $props();

	let error = $state('');

	onMount(() => {
		Promise.all([session.refresh(), instance.load()]).catch((e) => (error = describeError(e)));
	});

	let allowed = $derived(
		!!session.user &&
			(role === 'any' || (role === 'member' ? session.user.roles.member : session.user.roles.ally))
	);
</script>

{#if error}
	<div class="notice error" role="alert"><p>{error}</p></div>
{:else if !session.loaded || (session.user && !instance.info)}
	<p class="muted" role="status">Loading…</p>
{:else if !session.user}
	<section class="card">
		<h1>Sign in to continue</h1>
		<p>This page is for people with an account on this instance.</p>
		<div class="actions">
			<a class="button primary" href={resolve('/signin')}>Sign in</a>
		</div>
	</section>
{:else if !allowed}
	<section class="card">
		<h1>{role === 'member' ? 'For members' : 'For allies'}</h1>
		<p>
			{#if role === 'member'}
				This page is for members: people who use Faro on their own computers. Your account
				<strong>{session.user.email}</strong> isn't a member here. Ask the instance's admin for an invitation.
			{:else}
				This page is for allies. You become one by accepting someone's invitation to be their ally.
			{/if}
		</p>
		<p><a href={resolve('/')}>Go to the start page</a></p>
	</section>
{:else if instance.info}
	{@render children(session.user, instance.info)}
{/if}
