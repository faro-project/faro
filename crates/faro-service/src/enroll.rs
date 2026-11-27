//! Device enrollment and activation into the state directory
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
//! Every check on what the instance returns is `faro_client::enroll`'s,
//! shared with the iOS core; this module keeps the key and the records in
//! the state directory.
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

use crate::client::{ClientError, ClientOptions, InstanceClient};
use crate::link::EnrollCode;
use crate::state::{self, Enrollment, StateDir, StateError, ENDORSEMENT_FILE, ENROLLMENT_FILE};
use faro_client::enroll as shared;
use faro_core::clock::Clock;
use faro_core::{Outbox, OutboxError};
use faro_crypto::SigningKey;
use faro_proto::api::Platform;
use faro_proto::keys::{DeviceEndorsement, Signed};
use faro_proto::SignPublicKey;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

pub use faro_client::enroll::{
    bootstrap_from_endorsement, device_fingerprint, member_fingerprint, verify_endorsement,
    EndorsementError, EndorsementPoll, InstanceInfo, MAX_INSTANCE_NAME,
};

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

impl From<shared::EnrollError> for EnrollError {
    fn from(e: shared::EnrollError) -> Self {
        match e {
            shared::EnrollError::Client(e) => EnrollError::Client(e),
            shared::EnrollError::Outbox(e) => EnrollError::Outbox(e),
            shared::EnrollError::InvalidInstance(m) => EnrollError::InvalidInstance(m),
            shared::EnrollError::InvalidResponse(m) => EnrollError::InvalidResponse(m),
            shared::EnrollError::Endorsement(e) => EnrollError::Endorsement(e),
            shared::EnrollError::DeviceRemoved => EnrollError::DeviceRemoved,
            shared::EnrollError::MemberKeyMismatch { expected, got } => {
                EnrollError::MemberKeyMismatch { expected, got }
            }
        }
    }
}

/// This build's platform.
pub fn this_platform() -> Platform {
    if cfg!(target_os = "macos") {
        Platform::Macos
    } else if cfg!(windows) {
        Platform::Windows
    } else if cfg!(target_os = "android") {
        Platform::Android
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
    let cleaned = shared::clean_device_name(&raw);
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
    Ok(shared::discover(client).await?)
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
    let enrollment = shared::register(
        &client,
        &info,
        &shared::Registration {
            code: &params.code,
            device_pubkey: key.public(),
            platform: this_platform(),
            device_name: &params.device_name,
            client_version: env!("CARGO_PKG_VERSION"),
            member_key: params.member_key.as_deref(),
            now_ms: clock.wall_ms(),
        },
    )
    .await?;
    dir.write_json(ENROLLMENT_FILE, &enrollment)?;
    tracing::info!(device = %enrollment.device_id, instance = %enrollment.instance_id,
        "enrolled; waiting for the member to endorse this device");
    Ok(enrollment)
}

/// Ask the instance once whether the member has endorsed this device.
pub async fn poll_endorsement(
    client: &InstanceClient,
    enrollment: &Enrollment,
    device_pubkey: &SignPublicKey,
) -> Result<EndorsementPoll, EnrollError> {
    Ok(shared::poll_endorsement(client, enrollment, device_pubkey).await?)
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
    Ok(shared::await_endorsement(client, enrollment, device_pubkey, poll_every).await?)
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
    shared::bootstrap_if_needed(client, &mut outbox, enrollment, &endorsement).await?;
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
    Ok(shared::device_client(
        enrollment,
        key,
        clock,
        opts,
        base_override,
    )?)
}

// The endorsement and bootstrap tests are faro-client's (`faro_client::enroll`).
#[cfg(test)]
mod tests {
    use super::*;

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
