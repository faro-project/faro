// Whether this instance lists any groups, for the "Find a group" entry in
// the main navigation (GROUPS.md §17). Asked once per signed-in person; the
// directory is served only to signed-in users.

import { api } from './api.ts';
import type { DirectoryEntry, Page } from './types.ts';

class Directory {
	/** At least one listed group exists (and the directory is switched on). */
	has = $state(false);
	private asked = '';

	/** Look once for `userId`; later calls for the same person do nothing. */
	async check(userId: string) {
		if (this.asked === userId) return;
		this.asked = userId;
		try {
			const page = await api.get<Page<DirectoryEntry>>('/v1/group-directory');
			this.has = page.items.length > 0;
		} catch {
			this.has = false;
		}
	}

	/** Someone signed out. */
	clear() {
		this.asked = '';
		this.has = false;
	}
}

export const directory = new Directory();
