//! The cryptographic half of the group roster log (`faro_proto::roster`,
//! PROTOCOL.md §10): signature and key checks on entries and snapshots,
//! and making, sealing and opening epoch keys.
//!
//! The server runs [`apply_entry`] on uploads to refuse garbage early, but
//! it is never the trust anchor: every client runs the same checks (the
//! web app's port is `web/src/lib/crypto/roster.ts`) against its own
//! persisted checkpoint.

use crate::{random_bytes, seal_to, verify_item, CryptoError, EncryptionKeypair};
use faro_proto::keys::Signed;
use faro_proto::roster::{
    epoch_key_check, EpochRotation, RosterChange, RosterEntry, RosterError, RosterSnapshot,
    RosterState,
};
use faro_proto::{EncPublicKey, InstanceId, SignPublicKey, UserId};
use zeroize::Zeroizing;

/// A roster entry with its signer's signature.
pub type SignedRosterEntry = Signed<RosterEntry>;
/// A roster snapshot with its signer's signature.
pub type SignedRosterSnapshot = Signed<RosterSnapshot>;

fn check_keys(
    user: &UserId,
    enc: &EncPublicKey,
    sign: &Option<SignPublicKey>,
) -> Result<(), RosterError> {
    let bad_sign = sign
        .as_ref()
        .is_some_and(|k| crate::validate_sign_pubkey(k).is_err());
    if crate::validate_enc_pubkey(enc).is_err() || bad_sign {
        return Err(RosterError::WeakKey(user.clone()));
    }
    Ok(())
}

/// Check `e` completely against `state` and apply it: structure first (no
/// keys needed), then chain position, signer and changes, then the keys it
/// introduces, then the signature. On any error `state` is unchanged.
pub fn apply_entry(state: &mut RosterState, e: &SignedRosterEntry) -> Result<(), RosterError> {
    e.body.validate()?;
    let key = state.check(&e.body)?;
    for c in &e.body.changes {
        if let RosterChange::Join {
            user_id,
            enc_pubkey,
            sign_pubkey,
            ..
        }
        | RosterChange::Keys {
            user_id,
            enc_pubkey,
            sign_pubkey,
        } = c
        {
            check_keys(user_id, enc_pubkey, sign_pubkey)?;
        }
    }
    verify_item(&key, &e.body, &e.sig).map_err(|_| RosterError::BadSignature)?;
    state.apply_checked(&e.body);
    Ok(())
}

/// Check a snapshot (structure, keys, its signer's signature) and return the
/// state it describes. Whether to trust it at all is the caller's rule: a
/// client with a checkpoint replays entries instead (PROTOCOL.md §10.4).
pub fn verify_snapshot(s: &SignedRosterSnapshot) -> Result<RosterState, RosterError> {
    s.body.validate()?;
    let key = s.body.signer_key()?;
    for m in &s.body.members {
        check_keys(&m.user_id, &m.enc_pubkey, &m.sign_pubkey)?;
    }
    verify_item(&key, &s.body, &s.sig).map_err(|_| RosterError::BadSignature)?;
    Ok(RosterState::from_snapshot(&s.body))
}

/// A fresh epoch: a random 32-byte key and the rotation that commits to it.
pub fn new_epoch(
    instance: &InstanceId,
    group: &str,
    epoch: u64,
) -> (Zeroizing<[u8; 32]>, EpochRotation) {
    let key = Zeroizing::new(random_bytes::<32>());
    let key_check = epoch_key_check(instance, group, epoch, &key);
    (key, EpochRotation { epoch, key_check })
}

/// Seal an epoch key to one participant (`crypto_box_seal`).
pub fn seal_epoch_key(key: &[u8; 32], to: &EncPublicKey) -> Result<Vec<u8>, CryptoError> {
    crate::validate_enc_pubkey(to)?;
    seal_to(to, key)
}

/// Open a sealed epoch key and check it against the commitment in the
/// accepted roster (`expected`). A key the instance made up fails here.
pub fn open_epoch_key(
    keypair: &EncryptionKeypair,
    sealed: &[u8],
    instance: &InstanceId,
    group: &str,
    epoch: u64,
    expected: &faro_proto::Hash32,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let opened = keypair.unseal(sealed)?;
    let key: [u8; 32] = opened
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Decrypt)?;
    let key = Zeroizing::new(key);
    if epoch_key_check(instance, group, epoch, &key) != *expected {
        return Err(CryptoError::Decrypt);
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SigningKey;
    use faro_proto::roster::{genesis_prev_hash, GroupRole};

    struct P {
        id: UserId,
        sign: SigningKey,
        enc: EncryptionKeypair,
    }

    fn p(id: &str) -> P {
        P {
            id: UserId::new(id),
            sign: SigningKey::generate(),
            enc: EncryptionKeypair::generate(),
        }
    }

    fn inst() -> InstanceId {
        InstanceId::new("inst_a")
    }

    fn join(p: &P, role: GroupRole, with_sign: bool) -> RosterChange {
        RosterChange::Join {
            user_id: p.id.clone(),
            role,
            enc_pubkey: p.enc.public(),
            sign_pubkey: with_sign.then(|| p.sign.public()),
        }
    }

    fn entry(
        state: &RosterState,
        signer: &P,
        changes: Vec<RosterChange>,
        rotate: bool,
    ) -> RosterEntry {
        let epoch = rotate.then(|| new_epoch(&inst(), "g", state.epoch + 1).1);
        RosterEntry {
            instance_id: inst(),
            group_id: "g".into(),
            seq: state.next_seq,
            prev_hash: state.head,
            at_ms: 1,
            signer: signer.id.clone(),
            changes,
            epoch,
        }
    }

    #[test]
    fn signed_log_and_snapshot() {
        let f = p("usr_f");
        let a = p("usr_a");
        let mut s = RosterState::new(inst(), "g".into());
        assert_eq!(s.head, genesis_prev_hash(&inst(), "g"));
        let g = f.sign.endorse(entry(
            &s,
            &f,
            vec![join(&f, GroupRole::Facilitator, true)],
            true,
        ));
        apply_entry(&mut s, &g).unwrap();

        // A forged signature (by someone else's key) is refused, state unchanged.
        let e = entry(&s, &f, vec![join(&a, GroupRole::Participant, false)], true);
        let forged = a.sign.endorse(e.clone());
        let before = s.clone();
        assert_eq!(apply_entry(&mut s, &forged), Err(RosterError::BadSignature));
        assert_eq!(s, before);
        apply_entry(&mut s, &f.sign.endorse(e)).unwrap();

        // A participant can't sign, even with their own valid signature.
        let e = entry(
            &s,
            &a,
            vec![RosterChange::Leave {
                user_id: f.id.clone(),
            }],
            true,
        );
        assert_eq!(
            apply_entry(&mut s, &a.sign.endorse(e)),
            Err(RosterError::NotAFacilitator(a.id.clone()))
        );

        let snap = f.sign.endorse(s.snapshot(2, f.id.clone()).unwrap());
        assert_eq!(verify_snapshot(&snap).unwrap(), s);
        let mut bad = snap.clone();
        bad.body.members.pop();
        assert!(verify_snapshot(&bad).is_err());
    }

    #[test]
    fn weak_keys_are_refused() {
        let f = p("usr_f");
        let mut s = RosterState::new(inst(), "g".into());
        let mut e = entry(&s, &f, vec![join(&f, GroupRole::Facilitator, true)], true);
        if let RosterChange::Join { enc_pubkey, .. } = &mut e.changes[0] {
            *enc_pubkey = EncPublicKey([0; 32]);
        }
        assert_eq!(
            apply_entry(&mut s, &f.sign.endorse(e)),
            Err(RosterError::WeakKey(f.id.clone()))
        );
    }

    #[test]
    fn epoch_keys_open_only_with_the_committed_key() {
        let a = EncryptionKeypair::generate();
        let (key, rot) = new_epoch(&inst(), "g", 3);
        let sealed = seal_epoch_key(&key, &a.public()).unwrap();
        let opened = open_epoch_key(&a, &sealed, &inst(), "g", 3, &rot.key_check).unwrap();
        assert_eq!(*opened, *key);
        // The instance's own key, sealed to the same person, fails the check.
        let (other, _) = new_epoch(&inst(), "g", 3);
        let sealed = seal_epoch_key(&other, &a.public()).unwrap();
        assert!(open_epoch_key(&a, &sealed, &inst(), "g", 3, &rot.key_check).is_err());
        // So does the right key presented as another epoch.
        let sealed = seal_epoch_key(&key, &a.public()).unwrap();
        assert!(open_epoch_key(&a, &sealed, &inst(), "g", 4, &rot.key_check).is_err());
        assert_eq!(sealed.len(), faro_proto::roster::SEALED_EPOCH_KEY_LEN);
    }
}
