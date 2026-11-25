// The instance's branding (`GET /v1/branding`), fetched once per page load.
// Operator content: see branding.ts for the rules.

import { api } from './api.ts';
import type { PublicBranding } from './types.ts';

class Branding {
	info = $state<PublicBranding | null>(null);
	private pending: Promise<PublicBranding> | null = null;

	load(): Promise<PublicBranding> {
		if (this.info) return Promise.resolve(this.info);
		this.pending ??= api
			.get<PublicBranding>('/v1/branding')
			.then((b) => (this.info = b))
			.finally(() => (this.pending = null));
		return this.pending;
	}

	/** Fetch again (after an admin change). */
	async reload(): Promise<void> {
		this.info = null;
		await this.load().catch(() => {});
	}
}

export const branding = new Branding();
