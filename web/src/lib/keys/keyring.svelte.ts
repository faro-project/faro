// Unlocked private keys, held in this tab's memory only.
//
// Nothing here is ever written to storage: reloading the page, signing out,
// "Lock" or 30 idle minutes forget the keys, and the passphrase is needed
// again. The member keys (signing seed and encryption secret) sign
// endorsements and recipient manifests and open the member's own items; the
// ally key opens what members share. Locking also forgets everything
// decrypted with them.

import { wipe, type Bytes } from '../crypto/bytes.ts';
import { clearOpened } from '../feed/feed.ts';

export interface MemberKeys {
	userId: string;
	signSeed: Bytes;
	signPk: Bytes;
	encSecret: Bytes;
	encPk: Bytes;
}

export interface AllyKey {
	userId: string;
	encSecret: Bytes;
	encPk: Bytes;
}

const IDLE_MS = 30 * 60 * 1000;

class Keyring {
	member = $state.raw<MemberKeys | null>(null);
	ally = $state.raw<AllyKey | null>(null);
	/** The member keys were unlocked with the recovery code (time for a new passphrase). */
	memberRecovered = $state(false);

	private timer: ReturnType<typeof setTimeout> | null = null;

	get unlocked(): boolean {
		return this.member !== null || this.ally !== null;
	}

	setMember(k: MemberKeys, recovered = false) {
		this.forgetMember();
		this.member = k;
		this.memberRecovered = recovered;
		this.touch();
	}

	setAlly(k: AllyKey) {
		this.forgetAlly();
		this.ally = k;
		this.touch();
	}

	/** Member keys for `userId`, if unlocked (and restart the idle timer). */
	memberFor(userId: string | undefined): MemberKeys | null {
		const k = this.member;
		if (!k || k.userId !== userId) return null;
		this.touch();
		return k;
	}

	allyFor(userId: string | undefined): AllyKey | null {
		const k = this.ally;
		if (!k || k.userId !== userId) return null;
		this.touch();
		return k;
	}

	/** Restart the idle timer. */
	touch() {
		if (this.timer) clearTimeout(this.timer);
		if (!this.unlocked) return;
		this.timer = setTimeout(() => this.lock(), IDLE_MS);
	}

	private forgetMember() {
		if (this.member) wipe(this.member.signSeed, this.member.encSecret);
		this.member = null;
		this.memberRecovered = false;
	}

	private forgetAlly() {
		if (this.ally) wipe(this.ally.encSecret);
		this.ally = null;
	}

	lock() {
		clearOpened();
		this.forgetMember();
		this.forgetAlly();
		if (this.timer) clearTimeout(this.timer);
		this.timer = null;
	}
}

export const keyring = new Keyring();
