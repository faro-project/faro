//! Device enrollment and activation (ARCHITECTURE.md §3.8, §5.2 step 3, §7;
//! PROTOCOL.md §5.1 "Bootstrapping").
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
//! The device seals nothing until activation completes: it has no recipient
//! set before the outbox is bootstrapped. The first manifest must be at or
//! above the anchor the member signed into the endorsement, so an instance
//! can't start a new device on a pre-removal ally list.
//!
//! **The member key is the root of trust**, and it arrives in the
//! instance's enrollment response. When the enrollment link carries the
//! member key's fingerprint (`m`, from the member's own browser) the device
//! refuses any other key ([`EnrollError::MemberKeyMismatch`]); otherwise
//! the CLI shows [`member_fingerprint`] as a safety code for the member to
//! compare with their web app, and `faro-service status` keeps showing it.
//! Without either check an instance could substitute its own member key.

use crate::client::{ClientError, ClientOptions, DeviceCredentials, InstanceClient};
use crate::link::EnrollCode;
use crate::state::{self, Enrollment, StateDir, StateError, ENDORSEMENT_FILE, ENROLLMENT_FILE};
use faro_core::clock::Clock;
use faro_core::{ManifestAnchor, Outbox, OutboxError, RecipientSet};
use faro_crypto::{verify_signed, SigningKey};
use faro_proto::api::{EnrollRequest, Platform, WellKnown, PROTOCOL_VERSION};
use faro_proto::keys::{key_id, DeviceEndorsement, Signed};
use faro_proto::SignPublicKey;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// Longest instance name shown to the member.
pub const MAX_INSTANCE_NAME: usize = 100;

#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Outbox(#[from] OutboxError),
    #[error("enrollment cancelled: the instance was not confirmed")]
    Declined,
    #[error("the instance's discovery document is not acceptable: {0}")]
    InvalidInstance(String),
    #[error("the instance's enrollment response is not acceptable: {0}")]
    InvalidResponse(String),
    #[error("invalid device name: {0}")]
    DeviceName(String),
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

/// This build's platform.
pub fn this_platform() -> Platform {
    if cfg!(target_os = "macos") {
        Platform::Macos
    } else if cfg!(windows) {
        Platform::Windows
    } else {
        Platform::Linux
    }
}

/// A device name the instance accepts (1-64 printable characters, no
/// surrounding whitespace), from `name` or the host name.
pub fn device_name(name: Option<&str>) -> Result<String, EnrollError> {
    let raw = match name {
        Some(n) => n.to_owned(),
        None => hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .map(|h| h.trim_end_matches(".local").to_owned())
            .unwrap_or_else(|| "Faro device".to_owned()),
    };
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).collect();
    let cleaned: String = cleaned.trim().chars().take(64).collect();
    let cleaned = cleaned.trim().to_owned();
    if cleaned.is_empty() {
        return Err(EnrollError::DeviceName(
            "must contain at least one printable character".into(),
        ));
    }
    if name.is_some() && cleaned != raw {
        return Err(EnrollError::DeviceName(
            "must be 1-64 printable characters without surrounding spaces".into(),
        ));
    }
    Ok(cleaned)
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

/// Parameters for [`enroll`].
#[derive(Debug, Clone)]
pub struct EnrollParams {
    pub instance: Url,
    pub code: EnrollCode,
    pub device_name: String,
    pub client: ClientOptions,
    /// The member key's fingerprint from the enrollment link (`m`, see
    /// [`crate::link::parse_member_key_id`]). When set, an enrollment
    /// response naming any other member key is refused.
    pub member_key: Option<String>,
}

/// Enroll this device: discover and confirm the instance, generate the
/// device key, register it and persist the pinned keys.
///
/// `confirm` is shown the instance name and must return `true` to proceed
/// (the CLI prompts, `--yes` answers for it). Refuses if the state directory
/// already holds an enrollment.
pub async fn enroll(
    dir: &StateDir,
    clock: Arc<dyn Clock>,
    params: &EnrollParams,
    confirm: impl FnOnce(&InstanceInfo) -> bool,
) -> Result<Enrollment, EnrollError> {
    if let Some(existing) = dir.read_json::<Enrollment>(ENROLLMENT_FILE)? {
        return Err(StateError::AlreadyEnrolled {
            instance: existing.instance_url.clone(),
            device: existing.device_id.clone(),
        }
        .into());
    }
    let client = InstanceClient::new(params.instance.clone(), clock.clone(), &params.client)?;
    let info = discover(&client).await?;
    if !confirm(&info) {
        return Err(EnrollError::Declined);
    }
    let key = state::store_device_key(dir)?;
    let req = EnrollRequest {
        enroll_code: params.code.display_form(),
        sign_pubkey: key.public(),
        platform: this_platform(),
        device_name: params.device_name.clone(),
        client_version: env!("CARGO_PKG_VERSION").to_owned(),
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
    if let Some(expected) = &params.member_key {
        let got = member_fingerprint(&resp.member_sign_pubkey);
        if !got.eq_ignore_ascii_case(expected) {
            return Err(EnrollError::MemberKeyMismatch {
                expected: expected.clone(),
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
    let enrollment = Enrollment {
        instance_url: info.url.to_string(),
        instance_id: resp.instance_id.clone(),
        instance_name: info.name.clone(),
        instance_identity_pubkey: info.well_known.identity_pubkey,
        device_id: resp.device_id.clone(),
        device_token: resp.device_token.clone(),
        member_id: resp.member_id.clone(),
        member_sign_pubkey: resp.member_sign_pubkey,
        device_name: params.device_name.clone(),
        enrolled_at_ms: clock.wall_ms(),
    };
    dir.write_json(ENROLLMENT_FILE, &enrollment)?;
    tracing::info!(device = %enrollment.device_id, instance = %enrollment.instance_id,
        "enrolled; waiting for the member to endorse this device");
    Ok(enrollment)
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
    manifest: &faro_proto::api::SignedRecipientManifest,
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

/// Finish activation once endorsed: persist the verified endorsement and,
/// unless the outbox already has a checkpoint, bootstrap it from the
/// instance's current manifest.
pub async fn activate(
    dir: &StateDir,
    client: &InstanceClient,
    enrollment: &Enrollment,
    key: &SigningKey,
    signed: &Signed<DeviceEndorsement>,
) -> Result<(), EnrollError> {
    let endorsement = verify_endorsement(signed, enrollment, &key.public())?;
    dir.write_json(ENDORSEMENT_FILE, signed)?;
    let mut outbox = Outbox::open(dir.path(), &enrollment.instance_id, &enrollment.device_id)?;
    if let Some(cp) = outbox.manifest_checkpoint()? {
        tracing::debug!(
            version = cp.version,
            "recipient manifest already bootstrapped"
        );
        return Ok(());
    }
    let manifest = client.recipient_manifest(&enrollment.member_id).await?;
    let set = bootstrap_from_endorsement(&mut outbox, &manifest, enrollment, &endorsement)?;
    tracing::info!(
        version = set.manifest_ref().version,
        allies = set.allies().len(),
        "recipient manifest bootstrapped; device is active"
    );
    Ok(())
}

/// Client for an enrolled device.
pub fn device_client(
    enrollment: &Enrollment,
    key: Arc<SigningKey>,
    clock: Arc<dyn Clock>,
    opts: &ClientOptions,
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
    use faro_crypto::EncryptionKeypair;
    use faro_proto::keys::{ManifestRef, RecipientManifest};
    use faro_proto::{DeviceId, InstanceId, UserId};

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

    fn manifest(
        f: &Fixture,
        version: u64,
        allies: &[&str],
    ) -> faro_proto::api::SignedRecipientManifest {
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

    #[test]
    fn device_names() {
        assert_eq!(device_name(Some("Sam's MacBook")).unwrap(), "Sam's MacBook");
        assert!(device_name(Some(" padded ")).is_err());
        assert!(device_name(Some("")).is_err());
        assert!(device_name(Some(&"x".repeat(65))).is_err());
        let host = device_name(None).unwrap();
        assert!((1..=64).contains(&host.chars().count()));
    }
}
