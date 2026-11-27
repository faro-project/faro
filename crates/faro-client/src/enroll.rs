//! Enrollment and activation, the parts every platform shares
//! (ARCHITECTURE.md §3.8, §5.2 step 3, §7; PROTOCOL.md §5.1 "Bootstrapping").
//!
//! ```text
//! enroll:   GET /.well-known/faro ─▶ member confirms instance name ─▶ pin identity
//!           ─▶ new device key ─▶ POST /v1/devices/enroll ─▶ pin member sign key
//! activate: poll GET /v1/devices/self until active
//!           ─▶ verify DeviceEndorsement against the PINNED member key
//!           ─▶ GET recipient manifest (≤ 64 KiB)
//!           ─▶ Outbox::bootstrap_manifest(.., AtLeast(endorsement.min_manifest))
//! ```
//!
//! Where the device key and the enrollment record are kept is the
//! platform's business (a 0600 state directory on desktop, the Keychain and
//! the app group container on iOS). Everything that decides what to trust
//! is here, so every platform checks the same things:
//!
//! * [`discover`] checks the discovery document before the member is shown
//!   the instance name.
//! * [`register`] checks the enrollment response: same instance as
//!   discovered, well-formed ids, a usable member key, the member key named
//!   by the link's `m` if there is one, and a sane token.
//! * [`verify_endorsement`] accepts only an endorsement signed by the
//!   member key pinned at enrollment, for exactly this device and key.
//! * [`bootstrap_from_endorsement`] seeds the recipient manifest no lower
//!   than the anchor the member signed into the endorsement.
//!
//! The device seals nothing until activation completes: it has no recipient
//! set before the outbox is bootstrapped.

use crate::client::{ClientError, DeviceCredentials, InstanceClient};
use crate::link::EnrollCode;
use faro_core::{ManifestAnchor, Outbox, OutboxError, RecipientSet};
use faro_crypto::verify_signed;
use faro_proto::api::{
    EnrollRequest, Platform, SignedRecipientManifest, WellKnown, PROTOCOL_VERSION,
};
use faro_proto::keys::{key_id, DeviceEndorsement, Signed};
use faro_proto::{DeviceId, InstanceId, SignPublicKey, UserId};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
use url::Url;

/// Longest instance name shown to the member.
pub const MAX_INSTANCE_NAME: usize = 100;

#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Outbox(#[from] OutboxError),
    #[error("the instance's discovery document is not acceptable: {0}")]
    InvalidInstance(String),
    #[error("the instance's enrollment response is not acceptable: {0}")]
    InvalidResponse(String),
    #[error("endorsement rejected: {0}")]
    Endorsement(#[from] EndorsementError),
    #[error("the member removed this device on the instance")]
    DeviceRemoved,
    #[error("the instance returned member key {got}, but the enrollment link names {expected}; refusing to enroll (the instance may be trying to substitute its own key)")]
    MemberKeyMismatch { expected: String, got: String },
}

/// Why a `DeviceEndorsement` from the instance was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndorsementError {
    #[error("not signed by the member key pinned at enrollment")]
    BadSignature,
    #[error("endorsement is for instance {0}, not this enrollment's")]
    WrongInstance(String),
    #[error("endorsement is for member {0}, not this enrollment's")]
    WrongMember(String),
    #[error("endorsement is for device {0}, not this device")]
    WrongDevice(String),
    #[error("endorsement names a different device key")]
    WrongKey,
    #[error("endorsement's min_manifest version is 0")]
    NoAnchor,
}

/// What enrollment established. The desktop service keeps it in
/// `enrollment.json`; other platforms keep the token with the device key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrollment {
    /// Normalized instance base URL (ends in `/`).
    pub instance_url: String,
    pub instance_id: InstanceId,
    /// The instance name the member confirmed.
    pub instance_name: String,
    /// Pinned from `/.well-known/faro`; re-checked by the runtime.
    pub instance_identity_pubkey: SignPublicKey,
    pub device_id: DeviceId,
    /// Bearer token. Secret; redacted from `Debug`.
    pub device_token: String,
    pub member_id: UserId,
    /// Pinned at enrollment: the root of trust for the endorsement and every
    /// recipient manifest.
    pub member_sign_pubkey: SignPublicKey,
    pub device_name: String,
    pub enrolled_at_ms: i64,
}

impl fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Enrollment")
            .field("instance_url", &self.instance_url)
            .field("instance_id", &self.instance_id)
            .field("instance_name", &self.instance_name)
            .field("device_id", &self.device_id)
            .field("device_token", &"<redacted>")
            .field("member_id", &self.member_id)
            .field("member_sign_pubkey", &self.member_sign_pubkey)
            .field("device_name", &self.device_name)
            .finish_non_exhaustive()
    }
}

impl Drop for Enrollment {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.device_token);
    }
}

/// What the member is asked to confirm before enrolling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceInfo {
    pub url: Url,
    /// Sanitized for display (control characters removed, bounded).
    pub name: String,
    pub well_known: WellKnown,
}

/// Fingerprint of the device key, as the member's web app shows it for the
/// pending device (`key_id`). The member compares the two before endorsing,
/// so the instance cannot slip in its own key.
pub fn device_fingerprint(pubkey: &SignPublicKey) -> String {
    key_id(pubkey.as_bytes())
}

/// Fingerprint (`key_id`) of the member signing key pinned at enrollment:
/// the safety code the member compares with their web app, and the value of
/// an enrollment link's `m` parameter.
pub fn member_fingerprint(pubkey: &SignPublicKey) -> String {
    key_id(pubkey.as_bytes())
}

/// `raw` without control characters and surrounding whitespace, cut to 64
/// characters: the form of device name the instance accepts. Empty if
/// nothing printable is left. A name the member typed is acceptable only
/// if this leaves it unchanged.
pub fn clean_device_name(raw: &str) -> String {
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).collect();
    let cleaned: String = cleaned.trim().chars().take(64).collect();
    cleaned.trim().to_owned()
}

/// Fetch and check the instance's discovery document.
pub async fn discover(client: &InstanceClient) -> Result<InstanceInfo, EnrollError> {
    let wk = client.well_known().await?;
    if wk.protocol != PROTOCOL_VERSION {
        return Err(EnrollError::InvalidInstance(format!(
            "speaks protocol {}, this client speaks {PROTOCOL_VERSION}",
            wk.protocol
        )));
    }
    if !wk.instance_id.is_well_formed() {
        return Err(EnrollError::InvalidInstance("malformed instance id".into()));
    }
    if faro_crypto::validate_sign_pubkey(&wk.identity_pubkey).is_err() {
        return Err(EnrollError::InvalidInstance(
            "identity key is not a usable Ed25519 key".into(),
        ));
    }
    let name: String = wk
        .name
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_INSTANCE_NAME)
        .collect();
    let name = name.trim().to_owned();
    if name.is_empty() {
        return Err(EnrollError::InvalidInstance("instance has no name".into()));
    }
    Ok(InstanceInfo {
        url: client.base_url().clone(),
        name,
        well_known: wk,
    })
}

/// What [`register`] sends about this device.
#[derive(Debug, Clone)]
pub struct Registration<'a> {
    pub code: &'a EnrollCode,
    /// The public half of the new device key.
    pub device_pubkey: SignPublicKey,
    pub platform: Platform,
    pub device_name: &'a str,
    pub client_version: &'a str,
    /// The member key's fingerprint from the enrollment link (`m`, see
    /// [`crate::link::parse_member_key_id`]). When set, an enrollment
    /// response naming any other member key is refused.
    pub member_key: Option<&'a str>,
    /// The device's wall clock, recorded as `enrolled_at_ms`.
    pub now_ms: i64,
}

/// `POST /v1/devices/enroll` for an instance the member confirmed
/// (`info`, from [`discover`]), and check the response. Returns the
/// [`Enrollment`] to persist; the caller has already stored the device key.
pub async fn register(
    client: &InstanceClient,
    info: &InstanceInfo,
    reg: &Registration<'_>,
) -> Result<Enrollment, EnrollError> {
    let req = EnrollRequest {
        enroll_code: reg.code.display_form(),
        sign_pubkey: reg.device_pubkey,
        platform: reg.platform,
        device_name: reg.device_name.to_owned(),
        client_version: reg.client_version.to_owned(),
    };
    let resp = client.enroll(&req).await?;
    if resp.instance_id != info.well_known.instance_id {
        return Err(EnrollError::InvalidResponse(
            "instance id differs from the discovery document".into(),
        ));
    }
    if !resp.device_id.is_well_formed() || !resp.member_id.is_well_formed() {
        return Err(EnrollError::InvalidResponse("malformed id".into()));
    }
    if faro_crypto::validate_sign_pubkey(&resp.member_sign_pubkey).is_err() {
        return Err(EnrollError::InvalidResponse(
            "member signing key is not a usable Ed25519 key".into(),
        ));
    }
    if let Some(expected) = reg.member_key {
        let got = member_fingerprint(&resp.member_sign_pubkey);
        if !got.eq_ignore_ascii_case(expected) {
            return Err(EnrollError::MemberKeyMismatch {
                expected: expected.to_owned(),
                got,
            });
        }
    }
    let token_ok = (16..=512).contains(&resp.device_token.len())
        && resp.device_token.bytes().all(|b| b.is_ascii_graphic());
    if !token_ok {
        return Err(EnrollError::InvalidResponse(
            "malformed device token".into(),
        ));
    }
    Ok(Enrollment {
        instance_url: info.url.to_string(),
        instance_id: resp.instance_id.clone(),
        instance_name: info.name.clone(),
        instance_identity_pubkey: info.well_known.identity_pubkey,
        device_id: resp.device_id.clone(),
        device_token: resp.device_token.clone(),
        member_id: resp.member_id.clone(),
        member_sign_pubkey: resp.member_sign_pubkey,
        device_name: reg.device_name.to_owned(),
        enrolled_at_ms: reg.now_ms,
    })
}

/// Verify a `DeviceEndorsement` served by the instance.
///
/// It must be signed by the member key pinned at enrollment (never a key the
/// instance supplies now) and name exactly this instance, member, device id
/// and device key, with a real manifest anchor.
pub fn verify_endorsement(
    signed: &Signed<DeviceEndorsement>,
    enrollment: &Enrollment,
    device_pubkey: &SignPublicKey,
) -> Result<DeviceEndorsement, EndorsementError> {
    verify_signed(&enrollment.member_sign_pubkey, signed)
        .map_err(|_| EndorsementError::BadSignature)?;
    let e = &signed.body;
    let clip = |s: &str| s.chars().take(80).collect::<String>();
    if e.instance_id != enrollment.instance_id {
        return Err(EndorsementError::WrongInstance(clip(
            e.instance_id.as_str(),
        )));
    }
    if e.member_id != enrollment.member_id {
        return Err(EndorsementError::WrongMember(clip(e.member_id.as_str())));
    }
    if e.device_id != enrollment.device_id {
        return Err(EndorsementError::WrongDevice(clip(e.device_id.as_str())));
    }
    if &e.device_sign_pubkey != device_pubkey {
        return Err(EndorsementError::WrongKey);
    }
    if e.min_manifest.version == 0 {
        return Err(EndorsementError::NoAnchor);
    }
    Ok(e.clone())
}

/// Outcome of one [`poll_endorsement`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndorsementPoll {
    /// Still `pending_endorsement`.
    Pending,
    /// Active, with a verified endorsement.
    Endorsed(Box<Signed<DeviceEndorsement>>),
}

/// Ask the instance once whether the member has endorsed this device.
pub async fn poll_endorsement(
    client: &InstanceClient,
    enrollment: &Enrollment,
    device_pubkey: &SignPublicKey,
) -> Result<EndorsementPoll, EnrollError> {
    let me = client.device_self().await?;
    if me.device_id != enrollment.device_id {
        return Err(EnrollError::InvalidResponse(
            "device status is for another device".into(),
        ));
    }
    match me.status.as_str() {
        "removed" => Err(EnrollError::DeviceRemoved),
        "active" => {
            let signed = me.endorsement.ok_or_else(|| {
                EnrollError::InvalidResponse("active device without an endorsement".into())
            })?;
            verify_endorsement(&signed, enrollment, device_pubkey)?;
            Ok(EndorsementPoll::Endorsed(Box::new(signed)))
        }
        _ => Ok(EndorsementPoll::Pending),
    }
}

/// Poll until the device is endorsed. Transient failures are retried with
/// backoff; a forged endorsement or a removed device ends the wait with an
/// error (the caller decides whether to try again much later).
pub async fn await_endorsement(
    client: &InstanceClient,
    enrollment: &Enrollment,
    device_pubkey: &SignPublicKey,
    poll_every: Duration,
) -> Result<Signed<DeviceEndorsement>, EnrollError> {
    let mut backoff = crate::backoff::Backoff::new(poll_every, Duration::from_secs(300));
    loop {
        match poll_endorsement(client, enrollment, device_pubkey).await {
            Ok(EndorsementPoll::Endorsed(e)) => return Ok(*e),
            Ok(EndorsementPoll::Pending) => {
                backoff.reset();
                tokio::time::sleep(poll_every).await;
            }
            Err(EnrollError::Client(e)) if e.is_transient() => {
                let d = backoff.next_delay();
                tracing::info!(error = %e, retry_in = ?d, "endorsement poll failed; retrying");
                tokio::time::sleep(d).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Seed the outbox's recipient-manifest checkpoint from `manifest`, anchored
/// at the verified endorsement's `min_manifest` (PROTOCOL.md §5.1
/// "Bootstrapping"). A manifest below the anchor is refused as a rollback, a
/// different one at the anchor's version as equivocation; nothing is stored
/// in either case.
pub fn bootstrap_from_endorsement(
    outbox: &mut Outbox,
    manifest: &SignedRecipientManifest,
    enrollment: &Enrollment,
    endorsement: &DeviceEndorsement,
) -> Result<RecipientSet, OutboxError> {
    outbox.bootstrap_manifest(
        manifest,
        &enrollment.member_sign_pubkey,
        &enrollment.member_id,
        ManifestAnchor::AtLeast(endorsement.min_manifest),
    )
}

/// Bootstrap `outbox` from the instance's current manifest unless it
/// already has a checkpoint. `endorsement` must be the verified one.
/// Returns the set when this call bootstrapped it.
pub async fn bootstrap_if_needed(
    client: &InstanceClient,
    outbox: &mut Outbox,
    enrollment: &Enrollment,
    endorsement: &DeviceEndorsement,
) -> Result<Option<RecipientSet>, EnrollError> {
    if let Some(cp) = outbox.manifest_checkpoint()? {
        tracing::debug!(
            version = cp.version,
            "recipient manifest already bootstrapped"
        );
        return Ok(None);
    }
    let manifest = client.recipient_manifest(&enrollment.member_id).await?;
    let set = bootstrap_from_endorsement(outbox, &manifest, enrollment, endorsement)?;
    tracing::info!(
        version = set.manifest_ref().version,
        allies = set.allies().len(),
        "recipient manifest bootstrapped; device is active"
    );
    Ok(Some(set))
}

/// Client for an enrolled device, at its pinned instance URL unless
/// `base_override` names another.
pub fn device_client(
    enrollment: &Enrollment,
    key: std::sync::Arc<faro_crypto::SigningKey>,
    clock: std::sync::Arc<dyn faro_core::Clock>,
    opts: &crate::client::ClientOptions,
    base_override: Option<Url>,
) -> Result<InstanceClient, EnrollError> {
    let base = match base_override {
        Some(u) => u,
        None => crate::link::parse_instance_url(&enrollment.instance_url)
            .map_err(|e| EnrollError::InvalidResponse(e.to_string()))?,
    };
    Ok(InstanceClient::new(base, clock, opts)?
        .with_device(DeviceCredentials::from_enrollment(enrollment, key)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_crypto::{EncryptionKeypair, SigningKey};
    use faro_proto::keys::{ManifestRef, RecipientManifest};

    struct Fixture {
        member: SigningKey,
        device: SigningKey,
        enrollment: Enrollment,
    }

    fn fixture() -> Fixture {
        let member = SigningKey::generate();
        let device = SigningKey::generate();
        let enrollment = Enrollment {
            instance_url: "https://faro.example.org/".into(),
            instance_id: InstanceId::new("inst_a"),
            instance_name: "Example".into(),
            instance_identity_pubkey: SigningKey::generate().public(),
            device_id: DeviceId::new("dev_d"),
            device_token: "t".repeat(32),
            member_id: UserId::new("usr_m"),
            member_sign_pubkey: member.public(),
            device_name: "Laptop".into(),
            enrolled_at_ms: 1,
        };
        Fixture {
            member,
            device,
            enrollment,
        }
    }

    fn manifest(f: &Fixture, version: u64, allies: &[&str]) -> SignedRecipientManifest {
        f.member.endorse(RecipientManifest {
            instance_id: f.enrollment.instance_id.clone(),
            member_id: f.enrollment.member_id.clone(),
            version,
            issued_at_ms: 1000 + version as i64,
            member_enc_pubkey: EncryptionKeypair::generate().public(),
            allies: allies
                .iter()
                .map(|a| faro_proto::keys::ManifestAlly {
                    ally_id: UserId::new(*a),
                    enc_pubkey: EncryptionKeypair::generate().public(),
                })
                .collect(),
        })
    }

    fn endorsement(f: &Fixture, anchor: ManifestRef) -> DeviceEndorsement {
        DeviceEndorsement {
            instance_id: f.enrollment.instance_id.clone(),
            member_id: f.enrollment.member_id.clone(),
            device_id: f.enrollment.device_id.clone(),
            device_sign_pubkey: f.device.public(),
            endorsed_at_ms: 5,
            min_manifest: anchor,
        }
    }

    fn anchor() -> ManifestRef {
        ManifestRef {
            version: 1,
            hash: faro_proto::Hash32([3; 32]),
        }
    }

    #[test]
    fn accepts_genuine_endorsement() {
        let f = fixture();
        let signed = f.member.endorse(endorsement(&f, anchor()));
        let e = verify_endorsement(&signed, &f.enrollment, &f.device.public()).unwrap();
        assert_eq!(e.min_manifest, anchor());
    }

    #[test]
    fn rejects_forged_endorsement() {
        let f = fixture();
        // Signed by a key the instance controls, not the pinned member key.
        let forged = SigningKey::generate().endorse(endorsement(&f, anchor()));
        assert_eq!(
            verify_endorsement(&forged, &f.enrollment, &f.device.public()),
            Err(EndorsementError::BadSignature)
        );
        // A genuine signature over different content (tampered after signing).
        let mut tampered = f.member.endorse(endorsement(&f, anchor()));
        tampered.body.min_manifest.version = 9;
        assert_eq!(
            verify_endorsement(&tampered, &f.enrollment, &f.device.public()),
            Err(EndorsementError::BadSignature)
        );
    }

    #[test]
    fn rejects_endorsement_for_another_device_or_key() {
        let f = fixture();
        let mut e = endorsement(&f, anchor());
        e.device_id = DeviceId::new("dev_other");
        let signed = f.member.endorse(e);
        assert!(matches!(
            verify_endorsement(&signed, &f.enrollment, &f.device.public()),
            Err(EndorsementError::WrongDevice(_))
        ));

        let mut e = endorsement(&f, anchor());
        e.device_sign_pubkey = SigningKey::generate().public();
        let signed = f.member.endorse(e);
        assert_eq!(
            verify_endorsement(&signed, &f.enrollment, &f.device.public()),
            Err(EndorsementError::WrongKey)
        );

        let mut e = endorsement(&f, anchor());
        e.member_id = UserId::new("usr_other");
        assert!(matches!(
            verify_endorsement(&f.member.endorse(e), &f.enrollment, &f.device.public()),
            Err(EndorsementError::WrongMember(_))
        ));

        let mut e = endorsement(&f, anchor());
        e.instance_id = InstanceId::new("inst_other");
        assert!(matches!(
            verify_endorsement(&f.member.endorse(e), &f.enrollment, &f.device.public()),
            Err(EndorsementError::WrongInstance(_))
        ));

        let mut e = endorsement(&f, anchor());
        e.min_manifest.version = 0;
        assert_eq!(
            verify_endorsement(&f.member.endorse(e), &f.enrollment, &f.device.public()),
            Err(EndorsementError::NoAnchor)
        );
    }

    fn outbox(f: &Fixture) -> (tempfile::TempDir, Outbox) {
        let dir = tempfile::tempdir().unwrap();
        let o = Outbox::open(
            dir.path(),
            &f.enrollment.instance_id,
            &f.enrollment.device_id,
        )
        .unwrap();
        (dir, o)
    }

    #[test]
    fn bootstrap_refuses_manifest_below_anchor() {
        let f = fixture();
        let v1 = manifest(&f, 1, &["usr_removed"]);
        let v2 = manifest(&f, 2, &[]);
        // The member approved the device when v2 (without the removed ally)
        // was current; the instance serves the pre-removal v1.
        let e = endorsement(&f, v2.body.reference());
        let (_d, mut o) = outbox(&f);
        let err = bootstrap_from_endorsement(&mut o, &v1, &f.enrollment, &e).unwrap_err();
        assert!(
            matches!(
                err,
                OutboxError::Manifest(faro_core::RecipientError::Rollback { .. })
            ),
            "{err:?}"
        );
        assert_eq!(o.manifest_checkpoint().unwrap(), None, "nothing stored");
        // A different document at the anchor's version is equivocation.
        let other_v2 = manifest(&f, 2, &["usr_x"]);
        let err = bootstrap_from_endorsement(&mut o, &other_v2, &f.enrollment, &e).unwrap_err();
        assert!(matches!(
            err,
            OutboxError::Manifest(faro_core::RecipientError::Equivocation { .. })
        ));
        assert_eq!(o.manifest_checkpoint().unwrap(), None);
        // The anchored manifest itself, or a newer one, is accepted.
        let set = bootstrap_from_endorsement(&mut o, &v2, &f.enrollment, &e).unwrap();
        assert_eq!(set.manifest_ref(), v2.body.reference());
        assert!(set.allies().is_empty());
    }

    #[test]
    fn bootstrap_accepts_newer_than_anchor_but_not_forged() {
        let f = fixture();
        let v1 = manifest(&f, 1, &[]);
        let v3 = manifest(&f, 3, &["usr_a"]);
        let e = endorsement(&f, v1.body.reference());
        let (_d, mut o) = outbox(&f);
        let forged = SigningKey::generate().endorse(v3.body.clone());
        assert!(bootstrap_from_endorsement(&mut o, &forged, &f.enrollment, &e).is_err());
        let set = bootstrap_from_endorsement(&mut o, &v3, &f.enrollment, &e).unwrap();
        assert_eq!(set.manifest_ref().version, 3);
        // Never a second bootstrap.
        assert!(matches!(
            bootstrap_from_endorsement(&mut o, &v3, &f.enrollment, &e),
            Err(OutboxError::AlreadyBootstrapped { .. })
        ));
    }
}
