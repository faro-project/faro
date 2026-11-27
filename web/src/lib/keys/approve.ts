// Approving an ally (ARCHITECTURE.md §5.2 step 4), shared by the Allies page
// and the group page: the member compares a safety code with the ally, then
// signs an endorsement of the ally's key and the next recipient list with
// the ally added; the server stores both in one transaction
// (`POST /v1/me/allies/{ally_id}/approve`). Nothing else makes a link active,
// whether it began as an email invitation or an alliance proposal.

import { api, ApiError, describeError, seg } from '../api.ts';
import { unb64 } from '../crypto/bytes.ts';
import { safetyCode } from '../crypto/keys.ts';
import { allyEndorsementSigningBytes, nextManifest, signWith } from '../crypto/proto.ts';
import type { ApproveAlly } from '../types.ts';
import type { MemberKeys } from './keyring.svelte.ts';
import { ensureManifest, ManifestTrustError, signManifest } from './member.ts';

/** An active ally, as the recipient list names them. */
export interface ActiveAllyEntry {
	ally_id: string;
	enc_pubkey: string;
	/** The ally's current display name, signed into a format 2 list. */
	name?: string;
}

/** The pending ally being approved: who, and the key whose code was compared. */
export interface ApprovalTarget {
	ally_id: string;
	ally_enc_pubkey: string | null;
	/** The ally's display name, signed into the list (PROTOCOL.md §5.1). */
	display_name?: string;
}

/** The safety code from the unlocked member key and the ally's key. */
export function codeForAlly(keys: MemberKeys | null, ally: ApprovalTarget): string | null {
	if (!keys || !ally.ally_enc_pubkey) return null;
	return safetyCode(keys.signPk, unb64(ally.ally_enc_pubkey));
}

/**
 * Endorse the ally's key and sign the recipient list with them added.
 * `activeAllies` lists the member's other active allies, to start a list if
 * there is none yet. `currentNames` maps ally ids to the names the caller
 * shows now, so the signed list names every ally as they are called today (a
 * rename is picked up here and never forces a re-sign); without an entry an
 * ally keeps the name the last list signed. Throws on failure; see
 * [approveErrorMessage].
 */
export async function approveAlly(
	keys: MemberKeys,
	instanceId: string,
	ally: ApprovalTarget,
	activeAllies: () => Promise<ActiveAllyEntry[]>,
	currentNames: ReadonlyMap<string, string> = new Map()
): Promise<void> {
	const encPubkey = ally.ally_enc_pubkey;
	if (!encPubkey) throw new Error('The ally has no key yet.');
	const latest = await ensureManifest(keys, instanceId, activeAllies);
	const endorsement = signWith(
		keys.signSeed,
		{
			instance_id: instanceId,
			member_id: keys.userId,
			ally_id: ally.ally_id,
			ally_enc_pubkey: encPubkey,
			endorsed_at_ms: Date.now()
		},
		allyEndorsementSigningBytes
	);
	const manifest = signManifest(
		keys,
		nextManifest(latest, [
			...latest.allies.map((a) => ({ ...a, name: currentNames.get(a.ally_id) ?? a.name ?? '' })),
			{
				ally_id: ally.ally_id,
				enc_pubkey: encPubkey,
				name: currentNames.get(ally.ally_id) ?? ally.display_name ?? ''
			}
		])
	);
	const body: ApproveAlly = { endorsement, manifest };
	await api.post(`/v1/me/allies/${seg(ally.ally_id)}/approve`, body);
}

/** A sentence for what can go wrong approving. */
export function approveErrorMessage(e: unknown): string {
	if (e instanceof ManifestTrustError) return e.message;
	if (e instanceof ApiError) {
		switch (e.code) {
			case 'ally_not_active':
			case 'ally_already_in_manifest':
				return 'Your recipient list still names an ally who left. Confirm the updated list on the Allies page first.';
			case 'manifest_version_mismatch':
				return 'Your recipient list changed in another tab. Reload this page and try again.';
			case 'not_pending':
			case 'already_active':
				return 'This ally was already approved or removed elsewhere.';
		}
	}
	return describeError(e);
}
