<script lang="ts">
	// The recipient list the page is about to sign, or to anchor a new
	// computer to, shown before the member confirms (PROTOCOL.md §5.1, "The
	// member's web app"): each person's signed name and key id, who is new
	// and who is dropped. Names the server now shows differently from the
	// last signed list are offered as changes; they are signed only if the
	// member ticks them (`accepted`, by ally id), so the server can't rename
	// or swap anyone's name on its own.
	import { unb64 } from '../crypto/bytes.ts';
	import { formatKeyId, keyId } from '../crypto/keys.ts';
	import { sanitizeAllyName, type RecipientManifest } from '../crypto/proto.ts';
	import type { NameChange } from '../keys/manifest-trust.ts';

	let {
		title,
		list,
		base = null,
		changes = [],
		accepted = $bindable(new Set<string>())
	}: {
		title: string;
		/** The list shown: the next version, or the one a computer is anchored to. */
		list: RecipientManifest;
		/** The list it is built on, to mark who is new and who is dropped. */
		base?: RecipientManifest | null;
		changes?: NameChange[];
		accepted?: Set<string>;
	} = $props();

	function kid(pk: string): string {
		try {
			return formatKeyId(keyId(unb64(pk)));
		} catch {
			return '?';
		}
	}

	let before = $derived(new Set(base?.allies.map((a) => a.ally_id) ?? []));
	let after = $derived(new Set(list.allies.map((a) => a.ally_id)));
	let dropped = $derived(base?.allies.filter((a) => !after.has(a.ally_id)) ?? []);

	function toggle(id: string, on: boolean) {
		const next = new Set(accepted);
		if (on) next.add(id);
		else next.delete(id);
		accepted = next;
	}
</script>

<section class="recipients" aria-label={title}>
	<h4>{title}</h4>
	<ul>
		<li>
			<span class="who">You</span>
			<code class="kid" title="Key id">{kid(list.member_enc_pubkey)}</code>
		</li>
		{#each list.allies as a (a.ally_id)}
			{@const name = sanitizeAllyName(a.name ?? '')}
			<li>
				<span class="who">
					{#if name}{name}{:else}<em>No name</em>{/if}
					{#if base && !before.has(a.ally_id)}<span class="chip good">New</span>{/if}
				</span>
				<code class="kid" title="Key id">{kid(a.enc_pubkey)}</code>
			</li>
		{/each}
		{#each dropped as a (a.ally_id)}
			{@const name = sanitizeAllyName(a.name ?? '')}
			<li class="dropped">
				<span class="who">
					<s>
						{#if name}{name}{:else}No name{/if}
					</s>
					<span class="chip off">Removed</span>
				</span>
				<code class="kid" title="Key id">{kid(a.enc_pubkey)}</code>
			</li>
		{/each}
	</ul>
	<p class="muted small">
		Version {list.version}. Key ids are the first characters of each person's key; your allies see
		theirs in Faro. If someone here shouldn't be, or someone is missing, don't go on.
	</p>
	{#if changes.length}
		<div class="changes">
			<p class="small">
				{changes.length === 1 ? 'This ally now has' : 'These allies now have'} a different name on the
				server than in your last signed list. Your computers show the signed name. Tick a new name to
				sign it:
			</p>
			{#each changes as c (c.ally_id)}
				<label class="check">
					<input
						type="checkbox"
						checked={accepted.has(c.ally_id)}
						onchange={(e) => toggle(c.ally_id, e.currentTarget.checked)}
					/>
					Use “{c.current}” instead of {#if c.signed}“{c.signed}”{:else}no name{/if}
				</label>
			{/each}
		</div>
	{/if}
</section>

<style>
	.recipients {
		margin: 1rem 0;
		padding: 0.75rem 1rem;
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		background: var(--surface-2);
	}

	h4 {
		margin: 0 0 0.5rem;
	}

	ul {
		list-style: none;
		padding: 0;
		margin: 0 0 0.5rem;
	}

	li {
		display: flex;
		flex-wrap: wrap;
		justify-content: space-between;
		gap: 0.25rem 1rem;
		padding: 0.25rem 0;
	}

	.who {
		overflow-wrap: anywhere;
	}

	.dropped {
		color: var(--muted);
	}

	.changes {
		margin-top: 0.75rem;
	}
</style>
