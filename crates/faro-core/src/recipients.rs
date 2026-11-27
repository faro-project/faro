//! Verified recipient sets (ARCHITECTURE.md §5.2, §5.3; PROTOCOL.md §5.1).
//!
//! The instance serves the key directory, but it is not trusted to decide who
//! can read a member's data. A [`RecipientSet`] holds the keys of one
//! member-signed [`RecipientManifest`](faro_proto::keys::RecipientManifest)
//! that passed every device rule, so a curious or compromised instance
//! cannot slip in an eavesdropping key.
//!
//! Outside this crate a set can only be obtained from the outbox
//! ([`Outbox::bootstrap_manifest`](crate::outbox::Outbox::bootstrap_manifest),
//! [`Outbox::accept_manifest`](crate::outbox::Outbox::accept_manifest),
//! [`Outbox::current_recipients`](crate::outbox::Outbox::current_recipients)),
//! which only hands one out once its manifest is the persisted checkpoint.
//! Even so, a set can go stale while it is held (another component accepts a
//! newer manifest that removes an ally). That is why the outbox also refuses
//! to store an event or report sealed to any set other than the current
//! checkpoint: freshness is enforced where ciphertext becomes uploadable, not
//! only where the set is built.
//!
//! ## Why not endorsements
//!
//! Earlier versions picked recipients from the individual
//! `Signed<AllyEndorsement>`s and the `MemberEncKeyBinding` in
//! `MemberKeysResponse`. Those documents can only *add* trust: once the
//! member has signed "ally A has key K", that signature verifies forever. A
//! malicious instance could therefore
//!
//! * keep serving a **removed** ally's old endorsement, so devices keep
//!   encrypting to that ally;
//! * re-serve an ally's (or the member's) **pre-rotation** key, undoing a
//!   rotation done because the old key leaked.
//!
//! The manifest fixes this by making "who may read" one signed document with
//! a version. The device remembers the highest version it accepted (the
//! *checkpoint*, persisted by [`crate::outbox::Outbox`]) and refuses
//! anything older ([`RecipientError::Rollback`]), a different document
//! claiming the same version ([`RecipientError::Equivocation`]), or a
//! format 3 successor that names another predecessor
//! ([`RecipientError::Fork`]). There is
//! deliberately no endorsement-based constructor any more: leaving one
//! around would invite a "fallback" that reintroduces the bug.

use faro_crypto::{verify_signed, Recipient};
use faro_proto::api::SignedRecipientManifest;
use faro_proto::keys::{ManifestAlly, ManifestError, ManifestRef};
use faro_proto::{EncPublicKey, Hash32, InstanceId, SignPublicKey, UserId};

/// Why a fetched manifest was not accepted. On any of these the device keeps
/// using its last accepted manifest and warns the member (PROTOCOL.md §5.1);
/// it never falls back to endorsements.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecipientError {
    /// Not signed by the pinned member key: forged, corrupted, or signed by a
    /// key the instance substituted.
    #[error("recipient manifest is not signed by the pinned member key")]
    BadSignature,
    /// Genuinely signed, but for another instance (replayed across
    /// instances).
    #[error("recipient manifest is for instance {got}, expected {expected}")]
    WrongInstance {
        expected: InstanceId,
        got: InstanceId,
    },
    /// Genuinely signed, but for another member (replayed across members).
    #[error("recipient manifest is for member {got}, expected {expected}")]
    WrongMember { expected: UserId, got: UserId },
    /// Structurally invalid (version 0, too many allies, unsorted or
    /// duplicate ids, member listed as their own ally, malformed id, unknown
    /// format, a name in format 1 (not signed), a missing or oversized name).
    #[error("recipient manifest is malformed: {0}")]
    Invalid(#[from] ManifestError),
    /// The member's own key is a small-order X25519 point.
    #[error("member encryption key in the manifest is a low-order X25519 point")]
    MemberKeyWeak,
    /// An ally key is a small-order X25519 point.
    #[error("encryption key for ally {ally_id} is a low-order X25519 point")]
    AllyKeyWeak { ally_id: UserId },
    /// Older than the checkpoint: the instance is re-serving a superseded
    /// list (e.g. one that still contains a removed ally, or a pre-rotation
    /// key).
    #[error("recipient manifest rollback: have version {}, got version {}", have.version, got.version)]
    Rollback { have: ManifestRef, got: ManifestRef },
    /// Same version as the checkpoint but a different document. Only a
    /// member signing key that signed two documents at one version (bug or
    /// compromise) can produce this, so it deserves loud attention.
    #[error("recipient manifest equivocation at version {version}: have {have}, got {got}")]
    Equivocation {
        version: u64,
        have: Hash32,
        got: Hash32,
    },
    /// The next version after the checkpoint, but built on another
    /// predecessor: its format 3 `prev_hash` isn't the checkpoint's hash. The
    /// member's key signed a second branch, typically because the instance
    /// served their web app an older list to build on, so this document may
    /// list an ally the member removed.
    #[error("recipient manifest fork at version {version}: it follows {got_prev}, but this device has {have}")]
    Fork {
        version: u64,
        have: Hash32,
        got_prev: Hash32,
    },
}

/// What accepting a manifest means for the stored checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestDecision {
    /// Exactly the checkpointed manifest; nothing to persist.
    Unchanged,
    /// A newer manifest (or the first one). The outbox persists it as the
    /// checkpoint, in the same transaction as the check, before the set is
    /// returned: a set newer than the on-disk checkpoint would let a restart
    /// accept a rollback to the older one.
    Advanced(ManifestRef),
}

/// Compare a manifest's ref with the stored checkpoint (§5.1 rule 5).
///
/// This is the rule every manifest accepted by the outbox goes through, also
/// used for the [`ManifestAnchor`](crate::outbox::ManifestAnchor) of a fresh
/// device, so the anchor and the checkpoint obey the same monotonic rule.
pub fn compare_to_checkpoint(
    checkpoint: Option<ManifestRef>,
    got: ManifestRef,
) -> Result<ManifestDecision, RecipientError> {
    let Some(have) = checkpoint else {
        return Ok(ManifestDecision::Advanced(got));
    };
    match got.version.cmp(&have.version) {
        std::cmp::Ordering::Less => Err(RecipientError::Rollback { have, got }),
        std::cmp::Ordering::Equal if got.hash != have.hash => Err(RecipientError::Equivocation {
            version: got.version,
            have: have.hash,
            got: got.hash,
        }),
        std::cmp::Ordering::Equal => Ok(ManifestDecision::Unchanged),
        std::cmp::Ordering::Greater => Ok(ManifestDecision::Advanced(got)),
    }
}

/// Check a format 3 manifest's link to the checkpoint (§5.1 rule 5): the
/// version right after the checkpoint must name the checkpoint as its
/// predecessor, or it is [`RecipientError::Fork`]. A manifest further ahead
/// can't be checked (the versions in between were never seen), nor can one
/// in format 1 or 2, which carry no link.
pub fn check_link(
    checkpoint: Option<ManifestRef>,
    version: u64,
    prev_hash: Option<Hash32>,
) -> Result<(), RecipientError> {
    match (checkpoint, prev_hash) {
        (Some(have), Some(p)) if have.version.checked_add(1) == Some(version) && p != have.hash => {
            Err(RecipientError::Fork {
                version,
                have: have.hash,
                got_prev: p,
            })
        }
        _ => Ok(()),
    }
}

/// The member plus exactly the allies of one accepted manifest. Outside this
/// crate, only the outbox hands these out (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientSet {
    instance_id: InstanceId,
    member_id: UserId,
    member_key: EncPublicKey,
    allies: Vec<ManifestAlly>,
    manifest: ManifestRef,
    issued_at_ms: i64,
}

/// Re-exported from `faro-crypto`, which owns the shared small-order list.
pub use faro_crypto::is_weak_x25519;

/// Longest malformed id echoed back in [`ManifestError::MalformedId`].
const MAX_ECHOED_ID: usize = 80;

/// `validate` echoes a malformed id verbatim. The id came from the instance
/// and is unbounded, and these errors end up in logs and in the warning shown
/// to the member, so keep only a prefix.
fn bounded_manifest_error(e: ManifestError) -> ManifestError {
    match e {
        ManifestError::MalformedId(id) if id.len() > MAX_ECHOED_ID => {
            let mut end = MAX_ECHOED_ID;
            while !id.is_char_boundary(end) {
                end -= 1;
            }
            ManifestError::MalformedId(format!("{}… ({} bytes)", &id[..end], id.len()))
        }
        other => other,
    }
}

impl RecipientSet {
    /// Verify a manifest from `GET /v1/members/{id}/recipient-manifest`
    /// against the enrollment and the persisted checkpoint (PROTOCOL.md
    /// §5.1), in this order:
    ///
    /// 1. [`RecipientManifest::validate`](faro_proto::keys::RecipientManifest::validate)
    ///    (version, ally count, id syntax, order). It needs no keys and is
    ///    linear in the document, so it runs **before** the signature check
    ///    (the spec lists it third): `signing_bytes` encodes every string, and
    ///    a hostile document with a few multi-megabyte ids would otherwise
    ///    make the device encode and hash all of it just to reject it. The
    ///    outcome is a rejection either way; only the reported reason can
    ///    differ for a document that is both forged and malformed.
    /// 2. The signature verifies under `pinned_member_sign_pubkey`, the key
    ///    pinned at enrollment, never a key supplied by the instance.
    /// 3. `instance_id` and `member_id` match the enrollment.
    /// 4. Neither the member key nor any ally key is a small-order point.
    /// 5. The manifest's [`ManifestRef`] does not move backwards from, or
    ///    fork at, `checkpoint` ([`compare_to_checkpoint`]), and the version
    ///    right after it names it as its predecessor ([`check_link`]).
    ///
    /// This function is pure and persists nothing, which is why it is
    /// crate-private: handing out a set whose checkpoint is not yet on disk
    /// (or one checked against the wrong checkpoint) would reopen the
    /// rollback. The outbox wraps it in one `IMMEDIATE` transaction.
    pub(crate) fn from_manifest(
        manifest: &SignedRecipientManifest,
        pinned_member_sign_pubkey: &SignPublicKey,
        instance_id: &InstanceId,
        member_id: &UserId,
        checkpoint: Option<ManifestRef>,
    ) -> Result<(RecipientSet, ManifestDecision), RecipientError> {
        let m = &manifest.body;
        m.validate().map_err(bounded_manifest_error)?;
        verify_signed(pinned_member_sign_pubkey, manifest)
            .map_err(|_| RecipientError::BadSignature)?;
        if &m.instance_id != instance_id {
            return Err(RecipientError::WrongInstance {
                expected: instance_id.clone(),
                got: m.instance_id.clone(),
            });
        }
        if &m.member_id != member_id {
            return Err(RecipientError::WrongMember {
                expected: member_id.clone(),
                got: m.member_id.clone(),
            });
        }
        if is_weak_x25519(&m.member_enc_pubkey) {
            return Err(RecipientError::MemberKeyWeak);
        }
        if let Some(a) = m.allies.iter().find(|a| is_weak_x25519(&a.enc_pubkey)) {
            return Err(RecipientError::AllyKeyWeak {
                ally_id: a.ally_id.clone(),
            });
        }
        let reference = m.reference();
        let decision = compare_to_checkpoint(checkpoint, reference)?;
        check_link(checkpoint, m.version, m.prev_hash)?;
        Ok((
            RecipientSet {
                instance_id: m.instance_id.clone(),
                member_id: m.member_id.clone(),
                member_key: m.member_enc_pubkey,
                allies: m.allies.clone(),
                manifest: reference,
                issued_at_ms: m.issued_at_ms,
            },
            decision,
        ))
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

    /// The allies of the accepted manifest, in manifest order (strictly
    /// ascending `ally_id`).
    pub fn allies(&self) -> &[ManifestAlly] {
        &self.allies
    }

    /// The exact manifest this set came from. Writers and reports cite it so
    /// the ally app can tell a device still encrypting to an outdated list
    /// (the withholding limit in PROTOCOL.md §5.1).
    pub fn manifest_ref(&self) -> ManifestRef {
        self.manifest
    }

    /// The manifest's `issued_at_ms`, for display ("ally list as of …").
    pub fn issued_at_ms(&self) -> i64 {
        self.issued_at_ms
    }

    /// Everyone to encrypt to: the member first (transparency, §5.1), then
    /// exactly the manifest's allies in manifest order. Never empty.
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
    use crate::clock::ManualClock;
    use crate::writer::{open_event_body, EventWriter};
    use faro_crypto::{ChainHead, EncryptionKeypair, SigningKey};
    use faro_proto::body::EventBody;
    use faro_proto::keys::{
        RecipientManifest, Signed, MANIFEST_FORMAT_V1, MANIFEST_FORMAT_V2, MANIFEST_FORMAT_V3,
        MAX_MANIFEST_ALLIES,
    };
    use faro_proto::{DeviceId, Signature, SignedEvent, Urgency};

    pub(crate) struct Fixture {
        pub member_sign: SigningKey,
        pub member_enc: EncryptionKeypair,
        /// Sorted by id, so they can go into a manifest as-is.
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
                            UserId::new(format!("usr_ally{i:02}")),
                            EncryptionKeypair::generate(),
                        )
                    })
                    .collect(),
                inst: InstanceId::new("inst_test"),
                member: UserId::new("usr_member"),
            }
        }

        /// An unsigned manifest listing the fixture's member key and allies.
        pub fn body(&self, version: u64) -> RecipientManifest {
            RecipientManifest {
                format: MANIFEST_FORMAT_V1,
                instance_id: self.inst.clone(),
                member_id: self.member.clone(),
                version,
                prev_hash: None,
                issued_at_ms: 1_000 + version as i64,
                member_enc_pubkey: self.member_enc.public(),
                allies: self
                    .allies
                    .iter()
                    .map(|(id, k)| ManifestAlly {
                        ally_id: id.clone(),
                        enc_pubkey: k.public(),
                        name: None,
                    })
                    .collect(),
            }
        }

        /// `body` in format 2, each ally named "Ally <n>".
        pub fn named_body(&self, version: u64) -> RecipientManifest {
            let mut b = self.body(version);
            b.format = MANIFEST_FORMAT_V2;
            for (i, a) in b.allies.iter_mut().enumerate() {
                a.name = Some(format!("Ally {i}"));
            }
            b
        }

        /// Sign with the genuine member key.
        pub fn sign(&self, body: RecipientManifest) -> SignedRecipientManifest {
            self.member_sign.endorse(body)
        }

        pub fn manifest(&self, version: u64) -> SignedRecipientManifest {
            self.sign(self.body(version))
        }

        pub fn accept(
            &self,
            m: &SignedRecipientManifest,
            checkpoint: Option<ManifestRef>,
        ) -> Result<(RecipientSet, ManifestDecision), RecipientError> {
            RecipientSet::from_manifest(
                m,
                &self.member_sign.public(),
                &self.inst,
                &self.member,
                checkpoint,
            )
        }

        /// The set from a version-1 manifest on a fresh device.
        pub fn set(&self) -> RecipientSet {
            self.accept(&self.manifest(1), None).unwrap().0
        }
    }

    fn ally(id: &str, k: &EncryptionKeypair) -> ManifestAlly {
        ManifestAlly {
            ally_id: UserId::new(id),
            enc_pubkey: k.public(),
            name: None,
        }
    }

    /// Seal one event to `set` through the real writer.
    fn seal_event(f: &Fixture, set: &RecipientSet) -> SignedEvent {
        let dev = DeviceId::new("dev_test");
        let w = EventWriter::new(
            SigningKey::generate(),
            f.inst.clone(),
            dev.clone(),
            ChainHead::genesis(&f.inst, &dev),
            ManualClock::new(1_800_000_000_000, 0),
        );
        w.prepare(&EventBody::Resumed, Urgency::None, set)
            .unwrap()
            .into_event()
    }

    fn envelope_recipients(ev: &SignedEvent) -> Vec<UserId> {
        ev.body
            .as_ref()
            .unwrap()
            .envelopes
            .iter()
            .map(|e| e.recipient.clone())
            .collect()
    }

    #[test]
    fn happy_path_member_first_then_manifest_order() {
        let f = Fixture::new(3);
        let m = f.manifest(1);
        let (set, decision) = f.accept(&m, None).unwrap();
        assert_eq!(decision, ManifestDecision::Advanced(m.body.reference()));
        assert_eq!(set.manifest_ref(), m.body.reference());
        assert_eq!(set.issued_at_ms(), m.body.issued_at_ms);
        let r = set.recipients();
        assert_eq!(r.len(), 4);
        assert_eq!(r[0].user_id, f.member);
        assert_eq!(r[0].pubkey, f.member_enc.public());
        for (got, (id, k)) in r[1..].iter().zip(&f.allies) {
            assert_eq!(&got.user_id, id);
            assert_eq!(got.pubkey, k.public());
        }
        // Re-serving the checkpointed manifest is a no-op.
        assert_eq!(
            f.accept(&m, Some(m.body.reference())).unwrap(),
            (set, ManifestDecision::Unchanged)
        );
    }

    #[test]
    fn format_2_names_are_signed() {
        let f = Fixture::new(2);
        let m = f.sign(f.named_body(1));
        let (set, _) = f.accept(&m, None).unwrap();
        let names: Vec<_> = set.allies().iter().map(|a| a.display_name()).collect();
        assert_eq!(
            names,
            [Some("Ally 0".to_owned()), Some("Ally 1".to_owned())]
        );
        // Same keys, same recipients: names change nothing about who reads.
        assert_eq!(set.recipients(), f.set().recipients());

        // The instance puts a false name next to a real key, swaps two
        // names, or drops one: none of it verifies.
        let mut forged = m.clone();
        forged.body.allies[0].name = Some("Someone trusted".into());
        assert_eq!(f.accept(&forged, None), Err(RecipientError::BadSignature));
        let mut swapped = m.clone();
        swapped.body.allies[0].name = m.body.allies[1].name.clone();
        swapped.body.allies[1].name = m.body.allies[0].name.clone();
        assert_eq!(f.accept(&swapped, None), Err(RecipientError::BadSignature));
        // Relabelled as format 1 with the names dropped: the v1 bytes were
        // never signed.
        let mut downgraded = m.clone();
        downgraded.body.format = MANIFEST_FORMAT_V1;
        for a in &mut downgraded.body.allies {
            a.name = None;
        }
        assert_eq!(
            f.accept(&downgraded, None),
            Err(RecipientError::BadSignature)
        );
        // Names added to a genuine format 1 manifest aren't signed.
        let mut added = f.manifest(1);
        added.body.allies[0].name = Some("Ally 0".into());
        assert!(matches!(
            f.accept(&added, None),
            Err(RecipientError::Invalid(ManifestError::UnsignedName(_)))
        ));
    }

    #[test]
    fn formats_follow_the_checkpoint_rules() {
        let f = Fixture::new(1);
        let v1 = f.manifest(1);
        let (set, _) = f.accept(&v1, None).unwrap();
        assert_eq!(set.allies()[0].display_name(), None);
        // The member's next re-sign moves the device to format 2.
        let v2 = f.sign(f.named_body(2));
        assert_eq!(
            f.accept(&v2, Some(v1.body.reference())).unwrap().1,
            ManifestDecision::Advanced(v2.body.reference())
        );
        // The other format at the same version is a different document.
        let other = f.sign(f.named_body(1));
        assert!(matches!(
            f.accept(&other, Some(v1.body.reference())),
            Err(RecipientError::Equivocation { version: 1, .. })
        ));
        // Back to format 1 at a later version is allowed (it only loses the
        // names).
        let v3 = f.manifest(3);
        assert!(f.accept(&v3, Some(v2.body.reference())).is_ok());
    }

    /// `named_body` in format 3 at `version`, following `prev`.
    fn linked_body(f: &Fixture, version: u64, prev: Option<Hash32>) -> RecipientManifest {
        let mut b = f.named_body(version);
        b.format = MANIFEST_FORMAT_V3;
        b.prev_hash = prev;
        b
    }

    /// #180: ally Eve was removed at version 3. The instance served the
    /// member's page version 2 (which lists her), the page signed a second
    /// version 3 on it, then version 4 on that. A device holding the real
    /// version 3 refuses the first as equivocation (as before) and the
    /// second as a fork, which formats 1 and 2 could not show.
    #[test]
    fn a_successor_built_on_another_branch_is_a_fork() {
        let f = Fixture::new(1);
        let eve = EncryptionKeypair::generate();
        let with_eve = |version: u64, prev: Option<Hash32>| {
            let mut b = linked_body(&f, version, prev);
            b.allies.push(ManifestAlly {
                ally_id: UserId::new("usr_zz_eve"),
                enc_pubkey: eve.public(),
                name: Some("Eve".into()),
            });
            f.sign(b)
        };
        let v1 = f.sign(linked_body(&f, 1, None));
        let v2 = with_eve(2, Some(v1.body.hash()));
        let v3 = f.sign(linked_body(&f, 3, Some(v2.body.hash())));
        let cp3 = v3.body.reference();
        // The genuine chain advances.
        let (_, d) = f.accept(&v2, Some(v1.body.reference())).unwrap();
        assert_eq!(d, ManifestDecision::Advanced(v2.body.reference()));
        assert_eq!(
            f.accept(&v3, Some(v2.body.reference())).unwrap().1,
            ManifestDecision::Advanced(cp3)
        );
        // The branch built on version 2.
        let fork3 = with_eve(3, Some(v2.body.hash()));
        let fork4 = with_eve(4, Some(fork3.body.hash()));
        assert!(matches!(
            f.accept(&fork3, Some(cp3)),
            Err(RecipientError::Equivocation { version: 3, .. })
        ));
        assert_eq!(
            f.accept(&fork4, Some(cp3)),
            Err(RecipientError::Fork {
                version: 4,
                have: cp3.hash,
                got_prev: fork3.body.hash()
            })
        );
        // The genuine successor is accepted.
        let v4 = f.sign(linked_body(&f, 4, Some(cp3.hash)));
        assert!(f.accept(&v4, Some(cp3)).is_ok());
    }

    #[test]
    fn links_are_checked_only_where_they_can_be() {
        let f = Fixture::new(1);
        let v2 = f.sign(f.named_body(2));
        let cp2 = v2.body.reference();
        // Format 2 after format 2: no link to check.
        assert!(f.accept(&f.sign(f.named_body(3)), Some(cp2)).is_ok());
        // The first format 3 version after a format 2 one names it.
        let v3 = f.sign(linked_body(&f, 3, Some(cp2.hash)));
        assert!(f.accept(&v3, Some(cp2)).is_ok());
        // A gap: the versions in between were never seen, so any link is
        // accepted, as any newer version is.
        let v9 = f.sign(linked_body(&f, 9, Some(Hash32([7; 32]))));
        assert!(f.accept(&v9, Some(cp2)).is_ok());
        // No checkpoint (trust on first use): nothing to compare with.
        assert!(f.accept(&v3, None).is_ok());
        // The stored checkpoint re-verified against itself is unchanged.
        assert_eq!(
            f.accept(&v3, Some(v3.body.reference())).unwrap().1,
            ManifestDecision::Unchanged
        );
        assert_eq!(check_link(Some(cp2), 3, None), Ok(()));
        assert_eq!(
            check_link(
                Some(ManifestRef {
                    version: u64::MAX,
                    hash: Hash32::ZERO
                }),
                0,
                Some(Hash32([1; 32]))
            ),
            Ok(())
        );
    }

    #[test]
    fn member_only_when_no_allies() {
        let f = Fixture::new(0);
        assert_eq!(f.set().recipients().len(), 1);
    }

    #[test]
    fn newer_version_advances_even_with_gaps() {
        // The device may miss intermediate versions while offline.
        let f = Fixture::new(1);
        let v1 = f.manifest(1).body.reference();
        let v7 = f.manifest(7);
        assert_eq!(
            f.accept(&v7, Some(v1)).unwrap().1,
            ManifestDecision::Advanced(v7.body.reference())
        );
    }

    /// The headline bug: ally A is removed in v2; the instance re-serves v1.
    #[test]
    fn removed_ally_cannot_be_reinstated_by_rollback() {
        let f = Fixture::new(0);
        let a = EncryptionKeypair::generate();
        let b = EncryptionKeypair::generate();
        let mut v1 = f.body(1);
        v1.allies = vec![ally("usr_a", &a), ally("usr_b", &b)];
        let v1 = f.sign(v1);
        let mut v2 = f.body(2);
        v2.allies = vec![ally("usr_b", &b)];
        let v2 = f.sign(v2);

        let (_, d1) = f.accept(&v1, None).unwrap();
        let ManifestDecision::Advanced(cp1) = d1 else {
            panic!("first manifest must advance")
        };
        let (set2, d2) = f.accept(&v2, Some(cp1)).unwrap();
        let ManifestDecision::Advanced(cp2) = d2 else {
            panic!("v2 must advance")
        };
        assert_eq!(cp2, v2.body.reference());

        // v1 still carries a perfectly valid member signature, which is
        // exactly why endorsements could not express removal.
        assert!(verify_signed(&f.member_sign.public(), &v1).is_ok());
        assert_eq!(
            f.accept(&v1, Some(cp2)),
            Err(RecipientError::Rollback {
                have: cp2,
                got: v1.body.reference()
            })
        );

        // Items sealed to the v2 set never reach A.
        let ev = seal_event(&f, &set2);
        let who = envelope_recipients(&ev);
        assert_eq!(who, vec![f.member.clone(), UserId::new("usr_b")]);
        assert!(open_event_body(&ev, &UserId::new("usr_a"), &a).is_err());
        assert!(open_event_body(&ev, &UserId::new("usr_b"), &b).is_ok());
        assert!(open_event_body(&ev, &f.member, &f.member_enc).is_ok());
        let a_kid = faro_proto::keys::key_id(a.public().as_bytes());
        assert!(ev
            .body
            .as_ref()
            .unwrap()
            .envelopes
            .iter()
            .all(|e| e.key_id != a_kid));
    }

    #[test]
    fn ally_key_rotation_cannot_be_rolled_back() {
        let f = Fixture::new(0);
        let old = EncryptionKeypair::generate();
        let new = EncryptionKeypair::generate();
        let mut v1 = f.body(1);
        v1.allies = vec![ally("usr_a", &old)];
        let v1 = f.sign(v1);
        let mut v2 = f.body(2);
        v2.allies = vec![ally("usr_a", &new)];
        let v2 = f.sign(v2);
        let cp2 = v2.body.reference();

        let (set2, _) = f.accept(&v2, Some(v1.body.reference())).unwrap();
        assert!(matches!(
            f.accept(&v1, Some(cp2)),
            Err(RecipientError::Rollback { .. })
        ));
        let ev = seal_event(&f, &set2);
        assert!(open_event_body(&ev, &UserId::new("usr_a"), &new).is_ok());
        assert!(
            open_event_body(&ev, &UserId::new("usr_a"), &old).is_err(),
            "the leaked pre-rotation key must not open new items"
        );
    }

    #[test]
    fn member_key_rotation_cannot_be_rolled_back() {
        let f = Fixture::new(1);
        let new = EncryptionKeypair::generate();
        let v1 = f.manifest(1);
        let mut v2 = f.body(2);
        v2.member_enc_pubkey = new.public();
        let v2 = f.sign(v2);
        let cp2 = v2.body.reference();

        let (set2, _) = f.accept(&v2, Some(v1.body.reference())).unwrap();
        assert_eq!(set2.member_key(), &new.public());
        assert_eq!(
            f.accept(&v1, Some(cp2)),
            Err(RecipientError::Rollback {
                have: cp2,
                got: v1.body.reference()
            })
        );
        let ev = seal_event(&f, &set2);
        assert!(open_event_body(&ev, &f.member, &new).is_ok());
        assert!(open_event_body(&ev, &f.member, &f.member_enc).is_err());
    }

    #[test]
    fn equivocation_at_same_version_is_rejected() {
        let f = Fixture::new(1);
        let eve = EncryptionKeypair::generate();
        let v2 = f.manifest(2);
        let cp2 = v2.body.reference();
        // A second, genuinely signed document at version 2 adding Eve.
        let mut fork = f.body(2);
        fork.allies.push(ally("usr_zz_eve", &eve));
        let fork = f.sign(fork);
        assert_eq!(
            f.accept(&fork, Some(cp2)),
            Err(RecipientError::Equivocation {
                version: 2,
                have: cp2.hash,
                got: fork.body.hash()
            })
        );
        // Even a change to `issued_at_ms` alone is a different document.
        let mut retimed = f.body(2);
        retimed.issued_at_ms += 1;
        assert!(matches!(
            f.accept(&f.sign(retimed), Some(cp2)),
            Err(RecipientError::Equivocation { version: 2, .. })
        ));
    }

    #[test]
    fn forged_signature_is_rejected() {
        let f = Fixture::new(1);
        let eve = EncryptionKeypair::generate();
        let genuine = f.manifest(3);
        // A genuine signature over a modified body (Eve's key swapped in).
        let mut body = genuine.body.clone();
        body.allies[0].enc_pubkey = eve.public();
        let swapped = Signed {
            body,
            sig: genuine.sig,
        };
        assert_eq!(f.accept(&swapped, None), Err(RecipientError::BadSignature));
        // A higher version carried over with the old signature.
        let mut body = genuine.body.clone();
        body.version = 4;
        let bumped = Signed {
            body,
            sig: genuine.sig,
        };
        assert_eq!(f.accept(&bumped, None), Err(RecipientError::BadSignature));
        // Garbage signature bytes.
        let garbage = Signed {
            body: genuine.body.clone(),
            sig: Signature([0x5a; 64]),
        };
        assert_eq!(f.accept(&garbage, None), Err(RecipientError::BadSignature));
    }

    #[test]
    fn manifest_signed_by_non_pinned_key_is_rejected() {
        // The instance substitutes its own signing key and signs a newer
        // version that adds Eve. Only the pinned key counts.
        let f = Fixture::new(1);
        let attacker = SigningKey::generate();
        let eve = EncryptionKeypair::generate();
        let mut body = f.body(99);
        body.allies.push(ally("usr_zz_eve", &eve));
        let m = attacker.endorse(body);
        assert!(verify_signed(&attacker.public(), &m).is_ok());
        assert_eq!(
            f.accept(&m, Some(f.manifest(1).body.reference())),
            Err(RecipientError::BadSignature)
        );
        assert_eq!(f.accept(&m, None), Err(RecipientError::BadSignature));
    }

    #[test]
    fn manifest_for_other_member_or_instance_is_rejected() {
        let f = Fixture::new(1);
        let mut other_member = f.body(5);
        other_member.member_id = UserId::new("usr_other");
        assert_eq!(
            f.accept(&f.sign(other_member), None),
            Err(RecipientError::WrongMember {
                expected: f.member.clone(),
                got: UserId::new("usr_other"),
            })
        );
        let mut other_inst = f.body(5);
        other_inst.instance_id = InstanceId::new("inst_evil");
        assert_eq!(
            f.accept(&f.sign(other_inst), None),
            Err(RecipientError::WrongInstance {
                expected: f.inst.clone(),
                got: InstanceId::new("inst_evil"),
            })
        );
    }

    #[test]
    fn structurally_invalid_manifests_are_rejected() {
        let f = Fixture::new(0);
        let k = EncryptionKeypair::generate();
        let signed_with = |allies: Vec<ManifestAlly>| {
            let mut b = f.body(1);
            b.allies = allies;
            f.sign(b)
        };
        assert!(matches!(
            f.accept(
                &signed_with(vec![ally("usr_b", &k), ally("usr_a", &k)]),
                None
            ),
            Err(RecipientError::Invalid(ManifestError::NotSorted(_)))
        ));
        // A duplicate entry could otherwise smuggle in a second key for one ally.
        let k2 = EncryptionKeypair::generate();
        assert!(matches!(
            f.accept(
                &signed_with(vec![ally("usr_a", &k), ally("usr_a", &k2)]),
                None
            ),
            Err(RecipientError::Invalid(ManifestError::NotSorted(_)))
        ));
        assert_eq!(
            f.accept(&signed_with(vec![ally("usr_member", &k)]), None),
            Err(RecipientError::Invalid(ManifestError::MemberIsAlly))
        );
        assert!(matches!(
            f.accept(&signed_with(vec![ally("dev_not_a_user", &k)]), None),
            Err(RecipientError::Invalid(ManifestError::MalformedId(_)))
        ));
        let mut zero = f.body(0);
        zero.allies.clear();
        assert_eq!(
            f.accept(&f.sign(zero), None),
            Err(RecipientError::Invalid(ManifestError::ZeroVersion))
        );

        let many: Vec<ManifestAlly> = (0..=MAX_MANIFEST_ALLIES)
            .map(|i| ally(&format!("usr_{i:03}"), &k))
            .collect();
        let too_many = signed_with(many.clone());
        assert_eq!(
            f.accept(&too_many, None),
            Err(RecipientError::Invalid(ManifestError::TooManyAllies(
                MAX_MANIFEST_ALLIES + 1
            )))
        );
        // `validate` runs before any hashing, so even an unsigned oversized
        // document is refused for its size.
        let unsigned = Signed {
            body: too_many.body,
            sig: Signature([0; 64]),
        };
        assert!(matches!(
            f.accept(&unsigned, None),
            Err(RecipientError::Invalid(ManifestError::TooManyAllies(_)))
        ));
        // Exactly the maximum is fine.
        let max = signed_with(many[..MAX_MANIFEST_ALLIES].to_vec());
        assert_eq!(
            f.accept(&max, None).unwrap().0.recipients().len(),
            MAX_MANIFEST_ALLIES + 1
        );
    }

    /// Regression: only the ally count was bounded before the signature
    /// check, so multi-megabyte ids were encoded and hashed in full before
    /// `validate` rejected them.
    #[test]
    fn oversized_ids_are_refused_before_hashing() {
        let f = Fixture::new(0);
        let k = EncryptionKeypair::generate();
        let huge = format!("usr_{}", "a".repeat(1 << 20));
        let unsigned = |body: RecipientManifest| Signed {
            body,
            sig: Signature([0; 64]),
        };
        let mut b = f.body(1);
        b.allies = vec![ally(&huge, &k)];
        let mut by_member = f.body(1);
        by_member.member_id = UserId::new(huge.clone());
        let mut by_instance = f.body(1);
        by_instance.instance_id = InstanceId::new(format!("inst_{}", "b".repeat(1 << 20)));
        for doc in [b, by_member, by_instance] {
            // An unsigned document reports the malformed id, not a bad
            // signature: the structural check ran first.
            match f.accept(&unsigned(doc), None) {
                Err(RecipientError::Invalid(ManifestError::MalformedId(echo))) => {
                    assert!(echo.len() < 200, "echoed {} bytes", echo.len());
                    assert!(echo.ends_with("bytes)"), "{echo}");
                }
                other => panic!("expected MalformedId, got {other:?}"),
            }
        }
        // Short malformed ids are echoed unchanged.
        assert_eq!(
            bounded_manifest_error(ManifestError::MalformedId("dev_x".into())),
            ManifestError::MalformedId("dev_x".into())
        );
        // Truncation respects UTF-8 boundaries.
        let wide = "é".repeat(100);
        assert!(matches!(
            bounded_manifest_error(ManifestError::MalformedId(wide)),
            ManifestError::MalformedId(s) if s.starts_with("éé")
        ));
    }

    #[test]
    fn weak_keys_are_rejected() {
        let f = Fixture::new(0);
        let mut b = f.body(1);
        b.member_enc_pubkey = EncPublicKey([0; 32]);
        assert_eq!(
            f.accept(&f.sign(b), None),
            Err(RecipientError::MemberKeyWeak)
        );

        // `1` with the ignored top bit set is still the identity point.
        let mut one_high_bit = [0u8; 32];
        one_high_bit[0] = 1;
        one_high_bit[31] = 0x80;
        let good = EncryptionKeypair::generate();
        let mut b = f.body(1);
        b.allies = vec![
            ally("usr_a", &good),
            ManifestAlly {
                ally_id: UserId::new("usr_b"),
                enc_pubkey: EncPublicKey(one_high_bit),
                name: None,
            },
        ];
        assert_eq!(
            f.accept(&f.sign(b), None),
            Err(RecipientError::AllyKeyWeak {
                ally_id: UserId::new("usr_b")
            })
        );
    }

    #[test]
    fn checkpoint_comparison_rules() {
        let r = |v: u64, h: &[u8]| ManifestRef {
            version: v,
            hash: Hash32::of(h),
        };
        assert_eq!(
            compare_to_checkpoint(None, r(1, b"a")),
            Ok(ManifestDecision::Advanced(r(1, b"a")))
        );
        assert_eq!(
            compare_to_checkpoint(Some(r(3, b"a")), r(3, b"a")),
            Ok(ManifestDecision::Unchanged)
        );
        assert_eq!(
            compare_to_checkpoint(Some(r(3, b"a")), r(4, b"b")),
            Ok(ManifestDecision::Advanced(r(4, b"b")))
        );
        assert_eq!(
            compare_to_checkpoint(Some(r(3, b"a")), r(2, b"a")),
            Err(RecipientError::Rollback {
                have: r(3, b"a"),
                got: r(2, b"a")
            })
        );
        assert!(matches!(
            compare_to_checkpoint(Some(r(3, b"a")), r(3, b"b")),
            Err(RecipientError::Equivocation { version: 3, .. })
        ));
    }

    #[test]
    fn real_keys_are_not_weak() {
        for _ in 0..64 {
            assert!(!is_weak_x25519(&EncryptionKeypair::generate().public()));
        }
    }
}
