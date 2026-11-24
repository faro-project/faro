//! Building signed, encrypted, hash-chained events (ARCHITECTURE.md §3.6, §5).
//!
//! The order of operations matters and is fixed here so callers cannot get
//! it wrong:
//!
//! 1. Fill the header (ids, next `seq`, `prev_hash`, clocks, kind, floored
//!    urgency) with an all-zero `body_hash`.
//! 2. Serialize the body to JSON (in a zeroizing buffer) and seal it to the
//!    verified recipients with the header's `body_aad`, binding the
//!    ciphertext to this device and `seq`.
//! 3. Commit to the ciphertext in `body_hash` / `body_len`.
//! 4. Sign the header.
//!
//! [`EventWriter::prepare`] does not move the chain head. The head advances
//! only after the outbox has durably stored the event
//! ([`EventWriter::write`] / [`EventWriter::adopt_committed`]), so a crash
//! between signing and storing can never cause the same `seq` to be signed
//! twice with different content (which the instance would see as a fork).
//!
//! A [`PreparedEvent`] also remembers which recipient manifest its body was
//! sealed to, so the outbox can refuse it if that manifest is no longer the
//! device's checkpoint (an ally was removed while the set was held).

use crate::clock::Clock;
use crate::outbox::{Outbox, OutboxError};
use crate::recipients::RecipientSet;
use faro_crypto::Zeroizing;
use faro_crypto::{open_item, seal_item, ChainHead, CryptoError, EncryptionKeypair, SigningKey};
use faro_proto::body::EventBody;
use faro_proto::keys::ManifestRef;
use faro_proto::{
    DeviceId, EventHeader, Hash32, InstanceId, SignedEvent, Urgency, UserId, EVENT_HEADER_VERSION,
};

#[derive(Debug, thiserror::Error)]
pub enum WriterError {
    #[error("recipient set is for instance {got}, writer is for {expected}")]
    RecipientInstanceMismatch {
        expected: InstanceId,
        got: InstanceId,
    },
    #[error("body serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("encryption failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("sequence number space exhausted")]
    SeqOverflow,
    #[error("prepared event does not extend the writer's head (stale prepare?)")]
    StaleHead,
    #[error(transparent)]
    Outbox(#[from] OutboxError),
}

/// A signed event and the chain head that results once it is committed.
///
/// Fields are private: the only way to obtain one is [`EventWriter::prepare`],
/// so a `PreparedEvent` always holds an encrypted body and a consistent head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedEvent {
    event: SignedEvent,
    prev_head: ChainHead,
    new_head: ChainHead,
    manifest: ManifestRef,
}

impl PreparedEvent {
    pub fn event(&self) -> &SignedEvent {
        &self.event
    }
    /// The head this event was built on.
    pub fn prev_head(&self) -> ChainHead {
        self.prev_head
    }
    /// The head after this event.
    pub fn new_head(&self) -> ChainHead {
        self.new_head
    }
    pub fn into_event(self) -> SignedEvent {
        self.event
    }
    /// The recipient manifest the body was sealed to.
    /// [`Outbox::commit`] refuses the event unless this is still the stored
    /// checkpoint.
    pub fn manifest_ref(&self) -> ManifestRef {
        self.manifest
    }

    /// Test-only escape hatch to construct inconsistent values.
    #[cfg(test)]
    pub(crate) fn with_new_head(mut self, h: ChainHead) -> Self {
        self.new_head = h;
        self
    }
}

/// Produces the device's events. Owns the device signing key.
pub struct EventWriter<C: Clock> {
    key: SigningKey,
    instance_id: InstanceId,
    device_id: DeviceId,
    head: ChainHead,
    clock: C,
}

impl<C: Clock> std::fmt::Debug for EventWriter<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventWriter")
            .field("device_pubkey", &self.key.public())
            .field("instance_id", &self.instance_id)
            .field("device_id", &self.device_id)
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}

impl<C: Clock> EventWriter<C> {
    /// `head` must come from durable storage ([`Outbox::head`]).
    pub fn new(
        key: SigningKey,
        instance_id: InstanceId,
        device_id: DeviceId,
        head: ChainHead,
        clock: C,
    ) -> Self {
        EventWriter {
            key,
            instance_id,
            device_id,
            head,
            clock,
        }
    }

    pub fn head(&self) -> ChainHead {
        self.head
    }
    pub fn instance_id(&self) -> &InstanceId {
        &self.instance_id
    }
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }
    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }
    pub fn clock(&self) -> &C {
        &self.clock
    }

    /// Re-sync with storage (e.g. after another component committed).
    pub fn set_head(&mut self, head: ChainHead) {
        self.head = head;
    }

    /// Build and sign the next event without advancing the head.
    ///
    /// The header's urgency is `max(urgency, kind floor)`.
    pub fn prepare(
        &self,
        body: &EventBody,
        urgency: Urgency,
        recipients: &RecipientSet,
    ) -> Result<PreparedEvent, WriterError> {
        if recipients.instance_id() != &self.instance_id {
            return Err(WriterError::RecipientInstanceMismatch {
                expected: self.instance_id.clone(),
                got: recipients.instance_id().clone(),
            });
        }
        if self.head.next_seq == u64::MAX {
            return Err(WriterError::SeqOverflow);
        }
        let kind = body.kind();
        let boot_id = self.clock.boot_id();
        let mono_ms = self.clock.mono_ms();
        let ts_ms = self.clock.wall_ms();
        let mut header = EventHeader {
            v: EVENT_HEADER_VERSION,
            instance_id: self.instance_id.clone(),
            device_id: self.device_id.clone(),
            seq: self.head.next_seq,
            prev_hash: self.head.prev_hash,
            ts_ms,
            mono_ms,
            boot_id,
            kind,
            urgency: urgency.max(kind.min_urgency()),
            body_hash: Hash32::ZERO,
            body_len: 0,
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(body)?);
        let item = seal_item(&plaintext, &header.body_aad(), &recipients.recipients())?;
        header.body_hash = item.body_hash();
        header.body_len = item.ciphertext.len() as u64;
        let sig = self.key.sign(&header);
        let mut new_head = self.head;
        new_head.advance(&header);
        Ok(PreparedEvent {
            event: SignedEvent {
                header,
                sig,
                body: Some(item),
            },
            prev_head: self.head,
            new_head,
            manifest: recipients.manifest_ref(),
        })
    }

    /// Advance the in-memory head after the outbox committed `prepared`.
    pub fn adopt_committed(&mut self, prepared: &PreparedEvent) -> Result<(), WriterError> {
        if prepared.prev_head != self.head {
            return Err(WriterError::StaleHead);
        }
        self.head = prepared.new_head;
        Ok(())
    }

    /// Prepare, durably commit and adopt in one step. Returns the stored event.
    pub fn write(
        &mut self,
        outbox: &mut Outbox,
        body: &EventBody,
        urgency: Urgency,
        recipients: &RecipientSet,
    ) -> Result<SignedEvent, WriterError> {
        let prepared = self.prepare(body, urgency, recipients)?;
        outbox.commit(&prepared)?;
        self.adopt_committed(&prepared)?;
        Ok(prepared.into_event())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("event has no body")]
    NoBody,
    #[error("decryption failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("body is not valid JSON for an event body: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("body kind {body} does not match header kind {header}")]
    KindMismatch {
        header: faro_proto::EventKind,
        body: faro_proto::EventKind,
    },
}

/// Decrypt and parse an event body as recipient `me` (member tray view, ally
/// app, tests). Does **not** verify the signature or chain; do that first
/// with `faro_crypto::verify_next`.
pub fn open_event_body(
    ev: &SignedEvent,
    me: &UserId,
    keypair: &EncryptionKeypair,
) -> Result<EventBody, OpenError> {
    let item = ev.body.as_ref().ok_or(OpenError::NoBody)?;
    let pt = open_item(item, &ev.header.body_aad(), me, keypair)?;
    let body: EventBody = serde_json::from_slice(&pt)?;
    if body.kind() != ev.header.kind {
        return Err(OpenError::KindMismatch {
            header: ev.header.kind,
            body: body.kind(),
        });
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use crate::recipients::tests::Fixture;
    use faro_crypto::verify_chain;
    use faro_proto::body::{FlagBody, Rating, Reason, ReasonSource, TamperSignal};
    use faro_proto::EventKind;

    pub(crate) fn writer(f: &Fixture, clock: ManualClock) -> EventWriter<ManualClock> {
        let dev = DeviceId::new("dev_test");
        EventWriter::new(
            SigningKey::generate(),
            f.inst.clone(),
            dev.clone(),
            ChainHead::genesis(&f.inst, &dev),
            clock,
        )
    }

    fn flag() -> EventBody {
        EventBody::Flag(FlagBody {
            rating: Rating::High,
            reasons: vec![Reason {
                source: ReasonSource::Image,
                label: "explicit".into(),
                score: Some(0.97),
            }],
            app: None,
            window_title: Some("title".into()),
            browser: None,
            thumbnail: None,
            burst: true,
            account: None,
        })
    }

    #[test]
    fn chain_verifies_and_everyone_can_open() {
        let f = Fixture::new(2);
        let set = f.set();
        let clock = ManualClock::new(1_800_000_000_000, 100);
        let mut w = writer(&f, clock.clone());
        let bodies = vec![
            EventBody::Boot {
                os: "macos".into(),
                client_version: "0.1.0".into(),
            },
            flag(),
            EventBody::Tamper {
                signal: TamperSignal::WaylandTokenLost,
                account: None,
            },
            EventBody::Resumed,
        ];
        let mut events = Vec::new();
        for b in &bodies {
            let p = w.prepare(b, Urgency::None, &set).unwrap();
            w.adopt_committed(&p).unwrap();
            events.push(p.into_event());
            clock.advance(1_000);
        }
        let (head, gaps) = verify_chain(
            &f.inst,
            w.device_id(),
            &w.signing_key().public(),
            &events,
            true,
        )
        .unwrap();
        assert!(gaps.is_empty());
        assert_eq!(head, w.head());
        assert_eq!(head.next_seq, 4);

        for (ev, b) in events.iter().zip(&bodies) {
            assert_eq!(&open_event_body(ev, &f.member, &f.member_enc).unwrap(), b);
            for (id, k) in &f.allies {
                assert_eq!(&open_event_body(ev, id, k).unwrap(), b);
            }
            let stranger = EncryptionKeypair::generate();
            assert!(open_event_body(ev, &UserId::new("usr_eve"), &stranger).is_err());
            assert_eq!(ev.body.as_ref().unwrap().envelopes.len(), 3);
        }
        // Clocks are recorded.
        assert_eq!(events[1].header.ts_ms, 1_800_000_001_000);
        assert_eq!(events[1].header.mono_ms, 1_100);
        assert_eq!(events[1].header.boot_id, "manual-boot-0");
    }

    #[test]
    fn urgency_is_floored_and_signed() {
        let f = Fixture::new(1);
        let set = f.set();
        let w = writer(&f, ManualClock::new(0, 0));
        let p = w
            .prepare(
                &EventBody::Tamper {
                    signal: TamperSignal::WaylandTokenLost,
                    account: None,
                },
                Urgency::None,
                &set,
            )
            .unwrap();
        assert_eq!(p.event().header.urgency, Urgency::Urgent);
        let p = w
            .prepare(
                &EventBody::SettingsChange { changes: vec![] },
                Urgency::None,
                &set,
            )
            .unwrap();
        assert_eq!(p.event().header.urgency, Urgency::Normal);
        // Caller may raise above the floor.
        let p = w
            .prepare(&EventBody::Shutdown, Urgency::Urgent, &set)
            .unwrap();
        assert_eq!(p.event().header.urgency, Urgency::Urgent);
        assert_eq!(p.event().header.kind, EventKind::Shutdown);
    }

    #[test]
    fn prepare_does_not_advance_head() {
        let f = Fixture::new(0);
        let set = f.set();
        let mut w = writer(&f, ManualClock::new(0, 0));
        let h0 = w.head();
        let a = w
            .prepare(&EventBody::Shutdown, Urgency::None, &set)
            .unwrap();
        let b = w
            .prepare(&EventBody::Shutdown, Urgency::None, &set)
            .unwrap();
        assert_eq!(w.head(), h0);
        assert_eq!(a.event().header.seq, b.event().header.seq);
        w.adopt_committed(&a).unwrap();
        assert_eq!(w.head(), a.new_head());
        // b was built on the old head; adopting it now must fail.
        assert!(matches!(w.adopt_committed(&b), Err(WriterError::StaleHead)));
    }

    #[test]
    fn body_bound_to_seq() {
        // Moving one event's body onto another header must not decrypt.
        let f = Fixture::new(0);
        let set = f.set();
        let mut w = writer(&f, ManualClock::new(0, 0));
        let a = w.prepare(&flag(), Urgency::None, &set).unwrap();
        w.adopt_committed(&a).unwrap();
        let b = w.prepare(&flag(), Urgency::None, &set).unwrap();
        let mut moved = b.into_event();
        moved.body = a.event().body.clone();
        assert!(matches!(
            open_event_body(&moved, &f.member, &f.member_enc),
            Err(OpenError::Crypto(_))
        ));
    }

    #[test]
    fn rejects_recipients_from_other_instance() {
        let f = Fixture::new(0);
        let mut other = Fixture::new(0);
        other.inst = InstanceId::new("inst_other");
        let w = writer(&f, ManualClock::new(0, 0));
        assert!(matches!(
            w.prepare(&EventBody::Shutdown, Urgency::None, &other.set()),
            Err(WriterError::RecipientInstanceMismatch { .. })
        ));
    }

    #[test]
    fn seq_overflow_is_an_error() {
        let f = Fixture::new(0);
        let mut w = writer(&f, ManualClock::new(0, 0));
        w.set_head(ChainHead {
            next_seq: u64::MAX,
            prev_hash: Hash32::ZERO,
        });
        assert!(matches!(
            w.prepare(&EventBody::Shutdown, Urgency::None, &f.set()),
            Err(WriterError::SeqOverflow)
        ));
    }
}
