// The instance this page is served by: `GET /.well-known/faro`, fetched once.
//
// Its `instance_id` goes into every structure the browser signs and every
// AAD it decrypts with. The id comes from the same (untrusted) instance as
// everything else; what protects members is that devices check what they
// receive against the instance identity they pinned, and that a signature
// naming the wrong instance is useless to anyone.

import { api } from './api.ts';
import type { WellKnown } from './types.ts';

class Instance {
	info = $state<WellKnown | null>(null);
	private pending: Promise<WellKnown> | null = null;

	load(): Promise<WellKnown> {
		if (this.info) return Promise.resolve(this.info);
		this.pending ??= api
			.get<WellKnown>('/.well-known/faro')
			.then((w) => (this.info = w))
			.finally(() => (this.pending = null));
		return this.pending;
	}
}

export const instance = new Instance();
