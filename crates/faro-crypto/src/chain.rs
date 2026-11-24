//! Hash-chain + signature verification of device events (§3.6), shared by
//! `faro-server` (which verifies on ingest) and `faro-core` (which verifies
//! its own outbox and anything it re-reads).

use crate::sign::verify_item;
use faro_proto::event::EventShapeError;
use faro_proto::{
    genesis_hash, DeviceId, EventHeader, Hash32, InstanceId, SignPublicKey, SignedEvent,
};

/// Where a device's chain currently ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainHead {
    /// The `seq` the next event must carry.
    pub next_seq: u64,
    /// The `prev_hash` the next event must carry.
    pub prev_hash: Hash32,
}

impl ChainHead {
    pub fn genesis(instance_id: &InstanceId, device_id: &DeviceId) -> Self {
        ChainHead {
            next_seq: 0,
            prev_hash: genesis_hash(instance_id, device_id),
        }
    }

    /// Move the head past `header` (call only after a successful verify).
    pub fn advance(&mut self, header: &EventHeader) {
        self.next_seq = header.seq + 1;
        self.prev_hash = header.chain_hash();
    }
}

/// How a verified event links to the current head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    /// `seq == next_seq` and `prev_hash` matches: the normal case.
    Contiguous,
    /// `seq > next_seq`: events `missing_from..=missing_to` never arrived.
    /// The event itself is authentic but its `prev_hash` cannot be checked.
    /// The instance must raise an urgent `chain_gap` alert.
    Gap { missing_from: u64, missing_to: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("malformed event: {0}")]
    Shape(#[from] EventShapeError),
    #[error("event is for a different instance")]
    WrongInstance,
    #[error("event is for a different device")]
    WrongDevice,
    #[error("invalid device signature")]
    BadSignature,
    /// `seq < next_seq`. The caller should compare with the stored header to
    /// decide between an idempotent re-upload and a conflicting rewrite.
    #[error("seq {seq} is behind the chain head")]
    Behind { seq: u64 },
    /// `seq == next_seq` but `prev_hash` does not match: the device's history
    /// was rewritten (events deleted/reordered locally). Urgent.
    #[error("prev_hash mismatch at seq {seq}")]
    Fork { seq: u64 },
}

/// Verify the device signature on an event header.
pub fn verify_event_signature(pk: &SignPublicKey, ev: &SignedEvent) -> Result<(), ChainError> {
    verify_item(pk, &ev.header, &ev.sig).map_err(|_| ChainError::BadSignature)
}

/// Verify `ev` as the next event of `(instance_id, device_id)` after `head`.
///
/// Checks, in order: ids, shape (body commitments), signature, then linkage.
/// Does **not** mutate `head`; on `Ok` the caller calls [`ChainHead::advance`].
pub fn verify_next(
    head: &ChainHead,
    instance_id: &InstanceId,
    device_id: &DeviceId,
    pk: &SignPublicKey,
    ev: &SignedEvent,
    body_expected: bool,
) -> Result<Link, ChainError> {
    let h = &ev.header;
    if &h.instance_id != instance_id {
        return Err(ChainError::WrongInstance);
    }
    if &h.device_id != device_id {
        return Err(ChainError::WrongDevice);
    }
    ev.check_shape(body_expected)?;
    verify_event_signature(pk, ev)?;
    if h.seq < head.next_seq {
        return Err(ChainError::Behind { seq: h.seq });
    }
    if h.seq > head.next_seq {
        return Ok(Link::Gap {
            missing_from: head.next_seq,
            missing_to: h.seq - 1,
        });
    }
    if h.prev_hash != head.prev_hash {
        return Err(ChainError::Fork { seq: h.seq });
    }
    Ok(Link::Contiguous)
}

/// Verify a whole sequence from genesis; returns the final head and every gap.
pub fn verify_chain(
    instance_id: &InstanceId,
    device_id: &DeviceId,
    pk: &SignPublicKey,
    events: &[SignedEvent],
    body_expected: bool,
) -> Result<(ChainHead, Vec<Link>), ChainError> {
    let mut head = ChainHead::genesis(instance_id, device_id);
    let mut gaps = Vec::new();
    for ev in events {
        let link = verify_next(&head, instance_id, device_id, pk, ev, body_expected)?;
        if link != Link::Contiguous {
            gaps.push(link);
        }
        head.advance(&ev.header);
    }
    Ok((head, gaps))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{seal_item, EncryptionKeypair, Recipient, SigningKey};
    use faro_proto::{EventKind, Urgency, UserId, EVENT_HEADER_VERSION};

    struct Dev {
        key: SigningKey,
        inst: InstanceId,
        dev: DeviceId,
        head: ChainHead,
        ally: EncryptionKeypair,
    }

    impl Dev {
        fn new() -> Self {
            let inst = InstanceId::new("inst_t");
            let dev = DeviceId::new("dev_t");
            Dev {
                key: SigningKey::generate(),
                head: ChainHead::genesis(&inst, &dev),
                inst,
                dev,
                ally: EncryptionKeypair::generate(),
            }
        }

        fn next(&mut self, kind: EventKind) -> SignedEvent {
            let mut header = EventHeader {
                v: EVENT_HEADER_VERSION,
                instance_id: self.inst.clone(),
                device_id: self.dev.clone(),
                seq: self.head.next_seq,
                prev_hash: self.head.prev_hash,
                ts_ms: 1_000 + self.head.next_seq as i64,
                mono_ms: self.head.next_seq,
                boot_id: "b".into(),
                kind,
                urgency: Urgency::None,
                body_hash: Hash32::ZERO,
                body_len: 0,
            };
            let body = seal_item(
                b"{}",
                &header.body_aad(),
                &[Recipient {
                    user_id: UserId::new("usr_a"),
                    pubkey: self.ally.public(),
                }],
            )
            .unwrap();
            header.body_hash = body.body_hash();
            header.body_len = body.ciphertext.len() as u64;
            let sig = self.key.sign(&header);
            self.head.advance(&header);
            SignedEvent {
                header,
                sig,
                body: Some(body),
            }
        }
    }

    #[test]
    fn contiguous_chain_verifies() {
        let mut d = Dev::new();
        let evs: Vec<_> = (0..5).map(|_| d.next(EventKind::Flag)).collect();
        let (head, gaps) = verify_chain(&d.inst, &d.dev, &d.key.public(), &evs, true).unwrap();
        assert_eq!(head, d.head);
        assert!(gaps.is_empty());
    }

    #[test]
    fn deleted_event_is_a_gap() {
        let mut d = Dev::new();
        let mut evs: Vec<_> = (0..5).map(|_| d.next(EventKind::Flag)).collect();
        evs.remove(2);
        let (_, gaps) = verify_chain(&d.inst, &d.dev, &d.key.public(), &evs, true).unwrap();
        assert_eq!(
            gaps,
            vec![Link::Gap {
                missing_from: 2,
                missing_to: 2
            }]
        );
    }

    #[test]
    fn rewritten_history_is_a_fork() {
        let mut d = Dev::new();
        let e0 = d.next(EventKind::Boot);
        let _e1 = d.next(EventKind::Flag); // the member deletes this one...
                                           // ...and re-signs a replacement at seq 1 chained from a different prev.
        d.head = ChainHead {
            next_seq: 1,
            prev_hash: Hash32::of(b"forged"),
        };
        let e1b = d.next(EventKind::Capture);
        let err = verify_chain(&d.inst, &d.dev, &d.key.public(), &[e0, e1b], true).unwrap_err();
        assert_eq!(err, ChainError::Fork { seq: 1 });
    }

    #[test]
    fn tampered_urgency_breaks_signature() {
        let mut d = Dev::new();
        let mut e = d.next(EventKind::Tamper);
        e.header.urgency = Urgency::Urgent;
        let head = ChainHead::genesis(&d.inst, &d.dev);
        assert_eq!(
            verify_next(&head, &d.inst, &d.dev, &d.key.public(), &e, true),
            Err(ChainError::BadSignature)
        );
    }

    #[test]
    fn swapped_body_is_rejected() {
        let mut d = Dev::new();
        let mut a = d.next(EventKind::Flag);
        let b = d.next(EventKind::Flag);
        a.body = b.body.clone();
        let head = ChainHead::genesis(&d.inst, &d.dev);
        assert!(matches!(
            verify_next(&head, &d.inst, &d.dev, &d.key.public(), &a, true),
            Err(ChainError::Shape(_))
        ));
    }

    #[test]
    fn replay_is_behind() {
        let mut d = Dev::new();
        let e0 = d.next(EventKind::Boot);
        let mut head = ChainHead::genesis(&d.inst, &d.dev);
        head.advance(&e0.header);
        assert_eq!(
            verify_next(&head, &d.inst, &d.dev, &d.key.public(), &e0, true),
            Err(ChainError::Behind { seq: 0 })
        );
    }

    #[test]
    fn wrong_device_key_rejected() {
        let mut d = Dev::new();
        let e = d.next(EventKind::Boot);
        let other = SigningKey::generate();
        let head = ChainHead::genesis(&d.inst, &d.dev);
        assert_eq!(
            verify_next(&head, &d.inst, &d.dev, &other.public(), &e, true),
            Err(ChainError::BadSignature)
        );
    }
}
