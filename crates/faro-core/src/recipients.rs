//! Verified recipient sets (ARCHITECTURE.md §5.2, §5.3).
//!
//! The instance serves the key directory, but it is not trusted to decide who
//! can read a member's data. A device encrypts only to keys carrying a valid
//! signature from the member signing key it pinned at enrollment. A
//! [`RecipientSet`] can only be built by [`RecipientSet::verify`], so holding
//! one is proof that every key in it passed these checks: a curious or
//! compromised instance cannot slip in an eavesdropping key.

use faro_crypto::{verify_signed, Recipient};
use faro_proto::api::MemberKeysResponse;
use faro_proto::keys::AllyEndorsement;
use faro_proto::{EncPublicKey, InstanceId, SignPublicKey, UserId};
use std::collections::BTreeMap;

/// Errors that make the whole key response unusable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecipientError {
    #[error("key response is for member {got}, expected {expected}")]
    MemberIdMismatch { expected: UserId, got: UserId },
    #[error("key response carries a member signing key that differs from the pinned one")]
    MemberKeyMismatch,
    #[error("member encryption key binding is not signed by the pinned member key")]
    MemberBindingBadSignature,
    #[error("member encryption key binding is for a different instance")]
    MemberBindingWrongInstance,
    #[error("member encryption key binding is for a different member")]
    MemberBindingWrongMember,
    #[error("member encryption key is a low-order X25519 point")]
    MemberKeyWeak,
}

/// Why one ally endorsement was ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Not signed by the pinned member key: forged or corrupted.
    BadSignature,
    /// Validly signed, but for another instance (replayed across instances).
    WrongInstance,
    /// Validly signed, but for another member (replayed across members).
    WrongMember,
    /// Names the member as their own ally; the member already gets a copy
    /// through their own binding, and a second member key would be ambiguous.
    AllyIsMember,
    /// The key is a low-order X25519 point: sealing to it would be readable
    /// by anyone.
    WeakKey,
}

/// An ally endorsement that was not used, and why. Callers should surface
/// these (log, tray warning): a stream of bad signatures suggests a
/// misbehaving instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedEndorsement {
    pub ally_id: UserId,
    pub endorsed_at_ms: i64,
    pub reason: RejectReason,
}

/// A verified ally key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAlly {
    pub ally_id: UserId,
    pub enc_pubkey: EncPublicKey,
    pub endorsed_at_ms: i64,
}

/// The member plus their verified allies. Only constructible by verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientSet {
    instance_id: InstanceId,
    member_id: UserId,
    member_key: EncPublicKey,
    allies: Vec<VerifiedAlly>,
    rejected: Vec<RejectedEndorsement>,
}

/// X25519 public keys of small order (libsodium's `has_small_order` list,
/// compared with the top bit cleared). Sealing to any of them yields a shared
/// secret the attacker can compute without a private key.
const SMALL_ORDER: [[u8; 32]; 7] = [
    // 0 (order 4)
    [0; 32],
    // 1 (order 1)
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    // order-8 points
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    // p - 1 (order 2)
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p (= 0)
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p + 1 (= 1)
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// Whether `k` is a low-order X25519 point (ignoring the unused top bit).
pub fn is_weak_x25519(k: &EncPublicKey) -> bool {
    let mut masked = k.0;
    masked[31] &= 0x7f;
    SMALL_ORDER.contains(&masked)
}

impl RecipientSet {
    /// Verify a `GET /v1/members/{id}/keys` response.
    ///
    /// * The response must be for `member_id` and carry exactly the pinned
    ///   member signing key (a swapped key is a hard error, not a warning).
    /// * The member's encryption-key binding must verify under the pinned key
    ///   and name this instance and member; otherwise the whole response is
    ///   rejected, because the member is always a recipient.
    /// * Each ally endorsement must verify under the pinned key and name this
    ///   instance and member. Failures are skipped and returned through
    ///   [`RecipientSet::rejected`]; they never cause an error, so a hostile
    ///   instance cannot use one bad entry to stop all uploads.
    /// * Duplicate endorsements for the same ally keep the newest
    ///   `endorsed_at_ms` (ties: the larger key, for determinism).
    pub fn verify(
        resp: &MemberKeysResponse,
        pinned_member_sign_pubkey: &SignPublicKey,
        instance_id: &InstanceId,
        member_id: &UserId,
    ) -> Result<RecipientSet, RecipientError> {
        if &resp.member_id != member_id {
            return Err(RecipientError::MemberIdMismatch {
                expected: member_id.clone(),
                got: resp.member_id.clone(),
            });
        }
        if &resp.member_sign_pubkey != pinned_member_sign_pubkey {
            return Err(RecipientError::MemberKeyMismatch);
        }
        let binding = &resp.member_enc_key;
        verify_signed(pinned_member_sign_pubkey, binding)
            .map_err(|_| RecipientError::MemberBindingBadSignature)?;
        if &binding.body.instance_id != instance_id {
            return Err(RecipientError::MemberBindingWrongInstance);
        }
        if &binding.body.member_id != member_id {
            return Err(RecipientError::MemberBindingWrongMember);
        }
        if is_weak_x25519(&binding.body.member_enc_pubkey) {
            return Err(RecipientError::MemberKeyWeak);
        }

        let mut rejected = Vec::new();
        let mut best: BTreeMap<UserId, VerifiedAlly> = BTreeMap::new();
        for e in &resp.allies {
            let b: &AllyEndorsement = &e.body;
            let reason = if verify_signed(pinned_member_sign_pubkey, e).is_err() {
                Some(RejectReason::BadSignature)
            } else if &b.instance_id != instance_id {
                Some(RejectReason::WrongInstance)
            } else if &b.member_id != member_id {
                Some(RejectReason::WrongMember)
            } else if &b.ally_id == member_id {
                Some(RejectReason::AllyIsMember)
            } else if is_weak_x25519(&b.ally_enc_pubkey) {
                Some(RejectReason::WeakKey)
            } else {
                None
            };
            if let Some(reason) = reason {
                tracing::warn!(ally = %b.ally_id, ?reason, "ignoring ally endorsement");
                rejected.push(RejectedEndorsement {
                    ally_id: b.ally_id.clone(),
                    endorsed_at_ms: b.endorsed_at_ms,
                    reason,
                });
                continue;
            }
            let cand = VerifiedAlly {
                ally_id: b.ally_id.clone(),
                enc_pubkey: b.ally_enc_pubkey,
                endorsed_at_ms: b.endorsed_at_ms,
            };
            match best.get(&cand.ally_id) {
                Some(cur)
                    if (cur.endorsed_at_ms, cur.enc_pubkey)
                        >= (cand.endorsed_at_ms, cand.enc_pubkey) => {}
                _ => {
                    best.insert(cand.ally_id.clone(), cand);
                }
            }
        }

        Ok(RecipientSet {
            instance_id: instance_id.clone(),
            member_id: member_id.clone(),
            member_key: binding.body.member_enc_pubkey,
            allies: best.into_values().collect(),
            rejected,
        })
    }

    pub fn instance_id(&self) -> &InstanceId {
        &self.instance_id
    }

    pub fn member_id(&self) -> &UserId {
        &self.member_id
    }

    pub fn member_key(&self) -> &EncPublicKey {
        &self.member_key
    }

    /// Verified allies, sorted by id, one per ally.
    pub fn allies(&self) -> &[VerifiedAlly] {
        &self.allies
    }

    /// Endorsements that failed verification.
    pub fn rejected(&self) -> &[RejectedEndorsement] {
        &self.rejected
    }

    /// Everyone to encrypt to: the member first (transparency, §5.1), then
    /// each verified ally. Never empty.
    pub fn recipients(&self) -> Vec<Recipient> {
        std::iter::once(Recipient {
            user_id: self.member_id.clone(),
            pubkey: self.member_key,
        })
        .chain(self.allies.iter().map(|a| Recipient {
            user_id: a.ally_id.clone(),
            pubkey: a.enc_pubkey,
        }))
        .collect()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use faro_crypto::{EncryptionKeypair, SigningKey};
    use faro_proto::keys::{MemberEncKeyBinding, Signed};

    pub(crate) struct Fixture {
        pub member_sign: SigningKey,
        pub member_enc: EncryptionKeypair,
        pub allies: Vec<(UserId, EncryptionKeypair)>,
        pub inst: InstanceId,
        pub member: UserId,
    }

    impl Fixture {
        pub fn new(n_allies: usize) -> Self {
            Fixture {
                member_sign: SigningKey::generate(),
                member_enc: EncryptionKeypair::generate(),
                allies: (0..n_allies)
                    .map(|i| {
                        (
                            UserId::new(format!("usr_ally{i}")),
                            EncryptionKeypair::generate(),
                        )
                    })
                    .collect(),
                inst: InstanceId::new("inst_test"),
                member: UserId::new("usr_member"),
            }
        }

        pub fn endorse(
            &self,
            ally: &UserId,
            key: EncPublicKey,
            at: i64,
        ) -> Signed<AllyEndorsement> {
            self.member_sign.endorse(AllyEndorsement {
                instance_id: self.inst.clone(),
                member_id: self.member.clone(),
                ally_id: ally.clone(),
                ally_enc_pubkey: key,
                endorsed_at_ms: at,
            })
        }

        pub fn response(&self) -> MemberKeysResponse {
            MemberKeysResponse {
                member_id: self.member.clone(),
                member_sign_pubkey: self.member_sign.public(),
                member_enc_key: self.member_sign.endorse(MemberEncKeyBinding {
                    instance_id: self.inst.clone(),
                    member_id: self.member.clone(),
                    member_enc_pubkey: self.member_enc.public(),
                    endorsed_at_ms: 1,
                }),
                allies: self
                    .allies
                    .iter()
                    .map(|(id, k)| self.endorse(id, k.public(), 10))
                    .collect(),
            }
        }

        pub fn verify(&self, resp: &MemberKeysResponse) -> Result<RecipientSet, RecipientError> {
            RecipientSet::verify(resp, &self.member_sign.public(), &self.inst, &self.member)
        }

        pub fn set(&self) -> RecipientSet {
            self.verify(&self.response()).unwrap()
        }
    }

    #[test]
    fn happy_path_includes_member_first() {
        let f = Fixture::new(2);
        let set = f.set();
        let r = set.recipients();
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].user_id, f.member);
        assert_eq!(r[0].pubkey, f.member_enc.public());
        assert!(set.rejected().is_empty());
    }

    #[test]
    fn member_only_when_no_allies() {
        let f = Fixture::new(0);
        assert_eq!(f.set().recipients().len(), 1);
    }

    #[test]
    fn swapped_member_key_is_fatal() {
        // The instance replaces the member's signing key with its own and
        // re-signs everything: devices must refuse.
        let f = Fixture::new(1);
        let attacker = SigningKey::generate();
        let mut resp = f.response();
        resp.member_sign_pubkey = attacker.public();
        resp.member_enc_key = attacker.endorse(resp.member_enc_key.body.clone());
        resp.allies = vec![attacker.endorse(resp.allies[0].body.clone())];
        assert_eq!(f.verify(&resp), Err(RecipientError::MemberKeyMismatch));
    }

    #[test]
    fn forged_member_binding_is_fatal() {
        let f = Fixture::new(1);
        let attacker = SigningKey::generate();
        let eve = EncryptionKeypair::generate();
        let mut resp = f.response();
        let mut b = resp.member_enc_key.body.clone();
        b.member_enc_pubkey = eve.public();
        resp.member_enc_key = attacker.endorse(b.clone());
        assert_eq!(
            f.verify(&resp),
            Err(RecipientError::MemberBindingBadSignature)
        );
        // Valid signature over a modified body also fails.
        resp.member_enc_key = Signed {
            body: b,
            sig: f.response().member_enc_key.sig,
        };
        assert_eq!(
            f.verify(&resp),
            Err(RecipientError::MemberBindingBadSignature)
        );
    }

    #[test]
    fn member_binding_wrong_scope_is_fatal() {
        let f = Fixture::new(0);
        let mut resp = f.response();
        let mut b = resp.member_enc_key.body.clone();
        b.instance_id = InstanceId::new("inst_other");
        resp.member_enc_key = f.member_sign.endorse(b);
        assert_eq!(
            f.verify(&resp),
            Err(RecipientError::MemberBindingWrongInstance)
        );
        let mut b = f.response().member_enc_key.body;
        b.member_id = UserId::new("usr_other");
        resp.member_enc_key = f.member_sign.endorse(b);
        assert_eq!(
            f.verify(&resp),
            Err(RecipientError::MemberBindingWrongMember)
        );
    }

    #[test]
    fn wrong_member_id_in_response_is_fatal() {
        let f = Fixture::new(0);
        let mut resp = f.response();
        resp.member_id = UserId::new("usr_someone_else");
        assert!(matches!(
            f.verify(&resp),
            Err(RecipientError::MemberIdMismatch { .. })
        ));
    }

    #[test]
    fn injected_eavesdropper_is_rejected() {
        let f = Fixture::new(1);
        let attacker = SigningKey::generate();
        let eve = EncryptionKeypair::generate();
        let eve_id = UserId::new("usr_eve");
        let mut resp = f.response();
        // 1. Signed by the attacker.
        resp.allies.push(attacker.endorse(AllyEndorsement {
            instance_id: f.inst.clone(),
            member_id: f.member.clone(),
            ally_id: eve_id.clone(),
            ally_enc_pubkey: eve.public(),
            endorsed_at_ms: 99,
        }));
        // 2. A real endorsement with its key swapped for Eve's.
        let mut swapped = resp.allies[0].clone();
        swapped.body.ally_enc_pubkey = eve.public();
        swapped.body.endorsed_at_ms = 100;
        resp.allies.push(swapped);
        // 3. A genuine endorsement by this member for another instance.
        resp.allies.push(f.member_sign.endorse(AllyEndorsement {
            instance_id: InstanceId::new("inst_evil"),
            member_id: f.member.clone(),
            ally_id: eve_id.clone(),
            ally_enc_pubkey: eve.public(),
            endorsed_at_ms: 5,
        }));
        // 4. A genuine endorsement for a different member.
        resp.allies.push(f.member_sign.endorse(AllyEndorsement {
            instance_id: f.inst.clone(),
            member_id: UserId::new("usr_other_member"),
            ally_id: eve_id.clone(),
            ally_enc_pubkey: eve.public(),
            endorsed_at_ms: 5,
        }));
        let set = f.verify(&resp).unwrap();
        let keys: Vec<_> = set.recipients().into_iter().map(|r| r.pubkey).collect();
        assert!(!keys.contains(&eve.public()));
        assert_eq!(keys.len(), 2);
        let reasons: Vec<_> = set.rejected().iter().map(|r| r.reason).collect();
        assert_eq!(
            reasons,
            vec![
                RejectReason::BadSignature,
                RejectReason::BadSignature,
                RejectReason::WrongInstance,
                RejectReason::WrongMember
            ]
        );
    }

    #[test]
    fn dedupe_keeps_newest() {
        let f = Fixture::new(1);
        let (ally, old_key) = &f.allies[0];
        let new_key = EncryptionKeypair::generate();
        let mut resp = f.response();
        resp.allies.push(f.endorse(ally, new_key.public(), 50));
        resp.allies.push(f.endorse(ally, old_key.public(), 20));
        let set = f.verify(&resp).unwrap();
        assert_eq!(set.allies().len(), 1);
        assert_eq!(set.allies()[0].enc_pubkey, new_key.public());
        assert_eq!(set.allies()[0].endorsed_at_ms, 50);
        // Order of the input does not matter.
        resp.allies.reverse();
        assert_eq!(f.verify(&resp).unwrap().allies(), set.allies());
    }

    #[test]
    fn weak_and_self_endorsements_rejected() {
        let f = Fixture::new(0);
        let mut resp = f.response();
        resp.allies
            .push(f.endorse(&UserId::new("usr_zero"), EncPublicKey([0; 32]), 1));
        let mut one_high_bit = [0u8; 32];
        one_high_bit[0] = 1;
        one_high_bit[31] = 0x80;
        resp.allies
            .push(f.endorse(&UserId::new("usr_one"), EncPublicKey(one_high_bit), 1));
        resp.allies
            .push(f.endorse(&f.member, EncryptionKeypair::generate().public(), 1));
        let set = f.verify(&resp).unwrap();
        assert_eq!(set.recipients().len(), 1);
        let reasons: Vec<_> = set.rejected().iter().map(|r| r.reason).collect();
        assert_eq!(
            reasons,
            vec![
                RejectReason::WeakKey,
                RejectReason::WeakKey,
                RejectReason::AllyIsMember
            ]
        );
        // A weak member key is fatal.
        let mut resp = f.response();
        let mut b = resp.member_enc_key.body.clone();
        b.member_enc_pubkey = EncPublicKey([0; 32]);
        resp.member_enc_key = f.member_sign.endorse(b);
        assert_eq!(f.verify(&resp), Err(RecipientError::MemberKeyWeak));
    }

    #[test]
    fn real_keys_are_not_weak() {
        for _ in 0..64 {
            assert!(!is_weak_x25519(&EncryptionKeypair::generate().public()));
        }
    }
}
