<script lang="ts">
	// Change your own display name (PATCH /v1/me): how the people you're
	// connected with, and the emails Faro sends them, name you.
	import { api, ApiError, describeError } from '../api.ts';
	import { session } from '../session.svelte.ts';
	import type { Me } from '../types.ts';
	import Icon from './Icon.svelte';

	let {
		label = 'Your name',
		hint = 'How your allies, the people you support and the instance admin see you.',
		onsaved
	}: { label?: string; hint?: string; onsaved?: () => void } = $props();

	let name = $state(session.user?.display_name ?? '');
	let busy = $state(false);
	let error = $state('');
	let saved = $state(false);

	/** Save; resolves true when the name is stored (or unchanged). */
	export async function save(): Promise<boolean> {
		error = '';
		saved = false;
		const n = name.trim();
		if (!n || [...n].length > 64) {
			error = 'Use 1 to 64 characters.';
			return false;
		}
		if (n === session.user?.display_name) return true;
		busy = true;
		try {
			const me = await api.patch<Me>('/v1/me', { display_name: n });
			if (session.user) session.user = me.user;
			saved = true;
			onsaved?.();
			return true;
		} catch (e) {
			error =
				e instanceof ApiError && e.code === 'invalid_display_name'
					? 'Use 1 to 64 characters, without control characters.'
					: describeError(e);
			return false;
		} finally {
			busy = false;
		}
	}
</script>

<div class="field">
	<label for="display-name">
		{label}
		<span class="hint">{hint}</span>
	</label>
	<div class="name-row">
		<input
			id="display-name"
			type="text"
			bind:value={name}
			maxlength="64"
			autocomplete="name"
			aria-invalid={error ? 'true' : undefined}
			aria-describedby={error ? 'display-name-error' : undefined}
		/>
		{#if !onsaved}
			<button class="secondary" type="button" onclick={save} disabled={busy}>
				{busy ? 'Saving…' : 'Save'}
			</button>
		{/if}
	</div>
	{#if error}<span class="field-error" id="display-name-error">{error}</span>{/if}
	{#if saved && !onsaved}<span class="saved" role="status"><Icon name="check" /> Saved</span>{/if}
</div>

<style>
	.name-row {
		display: flex;
		gap: 0.6rem;
		flex-wrap: wrap;
	}

	.name-row input {
		flex: 1 1 14rem;
		width: auto;
	}

	.saved {
		margin-top: 0.35rem;
	}
</style>
