// What the group page knows about your proposals, shared by "Waiting for
// you" and every roster row: one load, one refresh after anything changes.

import { api } from './api.ts';
import type { Links } from './groups.ts';
import { loadLinks } from './groups-api.ts';
import type { IncomingProposal, MyProposals, OutgoingProposal, ProposalBlock } from './types.ts';

class ProposalsState {
	incoming = $state<IncomingProposal[]>([]);
	outgoing = $state<OutgoingProposal[]>([]);
	blocks = $state<ProposalBlock[]>([]);
	/** Your alliances, as user ids (who can still be proposed to). */
	links = $state<Links>({ myAllies: [], supporting: [] });
	loaded = $state(false);
	/** Bumped after any change, so pages with their own copies can reload. */
	version = $state(0);

	private roles = { member: false, ally: false };

	/** Load everything; call again after a change. Failures leave what is there. */
	async refresh(roles = this.roles) {
		this.roles = roles;
		const [mine, blocks, links] = await Promise.all([
			api.get<MyProposals>('/v1/me/proposals').catch(() => null),
			api.get<ProposalBlock[]>('/v1/me/proposal-blocks').catch(() => null),
			loadLinks(roles)
		]);
		if (mine) {
			this.incoming = mine.incoming;
			this.outgoing = mine.outgoing;
		}
		if (blocks) this.blocks = blocks;
		this.links = links;
		this.loaded = true;
		this.version++;
	}

	/** Roles can change when an ally key is made; re-read them with the lists. */
	async refreshWith(roles: { member: boolean; ally: boolean }) {
		await this.refresh({
			member: roles.member || this.roles.member,
			ally: roles.ally || this.roles.ally
		});
	}
}

export const proposals = new ProposalsState();
