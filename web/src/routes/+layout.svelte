<script lang="ts">
	import '../app.css';
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import icon from '$brand/faro-icon.svg';
	import { instance } from '#lib/instance.svelte.ts';
	import { keyring } from '#lib/keys/keyring.svelte.ts';
	import { session } from '#lib/session.svelte.ts';
	import Logo from '#lib/ui/Logo.svelte';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();

	let signOutError = $state('');

	// The sign-in pages show their own state; a "Sign in" link there is noise.
	let onSignInPage = $derived(/\/(signin|auth\/verify)$/.test(page.url.pathname));

	// Pages that are a single form or message read better narrow.
	let narrow = $derived(
		/\/(signin|auth\/verify|invite|setup|keys|privacy)$/.test(page.url.pathname)
	);

	type NavItem = {
		path: '/' | '/activity' | '/computers' | '/allies' | '/supporting' | '/admin';
		label: string;
		match: RegExp;
	};
	let nav = $derived.by((): NavItem[] => {
		const r = session.user?.roles;
		if (!r) return [];
		const items: NavItem[] = [{ path: '/', label: 'Home', match: /^\/$/ }];
		if (r.member) {
			items.push(
				{ path: '/activity', label: 'Activity', match: /^\/activity/ },
				{ path: '/computers', label: 'Computers', match: /^\/computers/ },
				{ path: '/allies', label: 'Allies', match: /^\/allies/ }
			);
		}
		if (r.ally) items.push({ path: '/supporting', label: 'Supporting', match: /^\/supporting/ });
		if (r.admin) items.push({ path: '/admin', label: 'Admin', match: /^\/admin/ });
		return items;
	});

	function current(item: NavItem): boolean {
		const base = resolve('/').replace(/\/$/, '');
		return item.match.test(page.url.pathname.slice(base.length) || '/');
	}

	let footerText = $derived.by(() => {
		const i = instance.info;
		if (!i) return 'Powered by Faro';
		const powered = `Powered by Faro ${i.server_version}`;
		return i.name === 'Faro' ? powered : `${i.name} · ${powered}`;
	});

	onMount(() => {
		// Header only: pages that need the session handle errors themselves.
		session.refresh().catch(() => {});
		instance.load().catch(() => {});
	});

	async function signOut() {
		signOutError = '';
		try {
			await session.signOut();
			await goto(resolve('/signin'));
		} catch {
			signOutError = 'Could not sign out. Try again.';
		}
	}
</script>

<svelte:head>
	<link rel="icon" href={icon} type="image/svg+xml" />
</svelte:head>

<a class="skip" href="#main">Skip to content</a>

<header class="site-header">
	<div class="bar">
		<a class="brand" href={resolve('/')} aria-label="Faro home">
			<Logo height={26} alt="Faro" />
			{#if instance.info && instance.info.name !== 'Faro'}
				<span class="instance" title="This instance">{instance.info.name}</span>
			{/if}
		</a>
		<div class="account">
			{#if session.user}
				{#if keyring.unlocked}
					<button
						class="secondary small lock"
						type="button"
						onclick={() => keyring.lock()}
						title="Forget your unlocked keys in this tab"
					>
						<span aria-hidden="true">🔓</span> Lock
					</button>
				{/if}
				<a class="who" href={resolve('/settings')} title="{session.user.email} · settings">
					{session.user.display_name}
				</a>
				<button class="link" type="button" onclick={signOut}>Sign out</button>
			{:else if session.loaded && !onSignInPage}
				<a class="button primary small" href={resolve('/signin')}>Sign in</a>
			{/if}
		</div>
	</div>
	{#if nav.length > 1}
		<nav class="main-nav" aria-label="Main">
			{#each nav as item (item.path)}
				<a href={resolve(item.path)} aria-current={current(item) ? 'page' : undefined}>
					{item.label}
				</a>
			{/each}
		</nav>
	{/if}
</header>

<main id="main" class:narrow>
	{#if signOutError}
		<div class="notice error" role="alert">{signOutError}</div>
	{/if}
	{#if (keyring.memberRecovered || keyring.allyRecovered) && !page.url.pathname.endsWith('/settings')}
		<div class="notice warn" role="status">
			<p>
				You unlocked your {keyring.memberRecovered ? 'keys' : 'ally key'} with your recovery code.
				<a href={resolve('/settings')}>Choose a new passphrase</a> so you don't need it next time.
			</p>
		</div>
	{/if}
	{@render children()}
</main>

<footer class="site-footer">
	<div class="inner">
		<span>{footerText}</span>
		<a href={resolve('/privacy')}>What this instance can see</a>
	</div>
</footer>

<style>
	.skip {
		position: absolute;
		left: -999px;
		top: 0.5rem;
		background: var(--surface);
		padding: 0.5rem 0.75rem;
		border-radius: var(--radius-sm);
		z-index: 10;
	}

	.skip:focus {
		left: 0.5rem;
	}

	.site-header {
		background: var(--surface);
		border-bottom: 1px solid var(--border);
	}

	.bar,
	.main-nav,
	.site-footer .inner {
		max-width: 64rem;
		margin: 0 auto;
		padding-left: 16px;
		padding-right: 16px;
	}

	.bar {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
		padding-top: 0.85rem;
		padding-bottom: 0.85rem;
	}

	.brand {
		display: inline-flex;
		align-items: center;
		gap: 0.75rem;
		text-decoration: none;
		min-width: 0;
	}

	.instance {
		color: var(--muted);
		font-size: 0.9rem;
		font-weight: 600;
		padding-left: 0.75rem;
		border-left: 1px solid var(--border-strong);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.account {
		display: flex;
		align-items: center;
		gap: 0.9rem;
		min-width: 0;
		font-size: 0.95rem;
	}

	.who {
		color: var(--text);
		font-weight: 600;
		text-decoration: none;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		max-width: 12rem;
	}

	.who:hover {
		color: var(--accent);
	}

	.main-nav {
		display: flex;
		gap: 0.25rem;
		overflow-x: auto;
		scrollbar-width: none;
	}

	.main-nav a {
		padding: 0.55rem 0.75rem 0.65rem;
		color: var(--muted);
		text-decoration: none;
		font-weight: 600;
		border-bottom: 2px solid transparent;
		white-space: nowrap;
	}

	.main-nav a:hover {
		color: var(--text);
	}

	.main-nav a[aria-current='page'] {
		color: var(--text);
		border-bottom-color: var(--brand);
	}

	main {
		flex: 1;
		width: 100%;
		max-width: 64rem;
		margin: 0 auto;
		padding: 2rem 16px 4rem;
	}

	main.narrow {
		max-width: 40rem;
	}

	.site-footer {
		border-top: 1px solid var(--border);
		color: var(--muted);
		font-size: 0.88rem;
	}

	.site-footer .inner {
		display: flex;
		flex-wrap: wrap;
		justify-content: space-between;
		gap: 0.5rem 1.5rem;
		padding-top: 1.25rem;
		padding-bottom: 1.5rem;
	}

	@media (max-width: 560px) {
		.instance {
			display: none;
		}

		.lock {
			padding: 0.3rem 0.5rem;
		}
	}
</style>
