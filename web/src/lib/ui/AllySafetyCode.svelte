<script lang="ts">
	// The ally's side of the safety-code check: the code from the member's
	// signing key and the ally's *own* key (from the unlocked key, not the
	// server's copy), to read to the member, who sees the same code when
	// approving. Once checked, the ally can remember the member's key in this
	// browser and be warned if it ever changes.
	import { b64, unb64 } from '../crypto/bytes.ts';
	import { safetyCode } from '../crypto/keys.ts';
	import { keyring } from '../keys/keyring.svelte.ts';
	import { markVerified, verification } from '../keys/verified.ts';
	import type { SupportedMember, User } from '../types.ts';
	import Icon from './Icon.svelte';
	import UnlockKeys from './UnlockKeys.svelte';

	let { member, viewer }: { member: SupportedMember; viewer: User } = $props();

	let bump = $state(0);
	let status = $derived.by(() => {
		void bump;
		return verification(viewer.id, member.member_id, member.member_sign_pubkey);
	});

	let code = $derived.by(() => {
		const k = keyring.ally;
		if (!k || k.userId !== viewer.id || !member.member_sign_pubkey) return null;
		return safetyCode(unb64(member.member_sign_pubkey), k.encPk);
	});

	// The server's copy of our key should be the one we hold.
	let keyMismatch = $derived(
		!!keyring.ally && !!member.ally_enc_pubkey && member.ally_enc_pubkey !== b64(keyring.ally.encPk)
	);

	function mark() {
		if (!member.member_sign_pubkey) return;
		markVerified(viewer.id, member.member_id, member.member_sign_pubkey);
		bump++;
	}
</script>

{#if status === 'changed'}
	<div class="notice error" role="alert">
		<p>
			<strong>{member.display_name}'s key has changed</strong> since you compared safety codes in this
			browser. Unless they told you they set up Faro again, ask them before trusting anything here, and
			compare the new code.
		</p>
	</div>
{/if}
{#if !member.member_sign_pubkey}
	<p class="muted">
		{member.display_name} hasn't set up their keys yet, so there is no safety code.
	</p>
{:else if !code}
	<UnlockKeys kind="ally" user={viewer}>
		{#snippet intro()}
			<h3>Unlock your ally key to see the safety code</h3>
			<p class="muted">It is computed from your own key, so it proves the key is yours.</p>
		{/snippet}
	</UnlockKeys>
{:else}
	{#if keyMismatch}
		<div class="notice error" role="alert">
			<p>
				The server lists a different key for you than the one you unlocked. Don't approve anything;
				tell {member.display_name} and the instance's admin.
			</p>
		</div>
	{/if}
	<p>
		Read this to <strong>{member.display_name}</strong> in person or on a call. They see the same code
		when they approve you.
	</p>
	<p class="code-display digits" aria-label="Safety code">
		{#each code.split(' ') as g, i (i)}<span>{g}</span>{/each}
	</p>
	{#if status === 'verified'}
		<p class="small">
			<span class="chip good"><Icon name="check" /> Checked</span> You compared this code with {member.display_name}.
		</p>
	{:else}
		<button class="secondary small" type="button" onclick={mark}>
			We compared it and it matches
		</button>
		<p class="muted small">
			This browser then warns you if {member.display_name}'s key ever changes.
		</p>
	{/if}
{/if}
