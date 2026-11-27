//! The one error type Swift sees.

use crate::keys::KeyStoreError;
use faro_client::enroll::EnrollError;
use faro_client::fetch::FetchError;
use faro_client::link::LinkError;
use faro_client::uplink::UplinkError;
use faro_client::ClientError;
use faro_core::{OutboxError, WriterError};

/// Why a call failed. Every variant carries a message for logs; the variant
/// is what the app acts on.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FaroError {
    /// The enrollment link (or a code typed by hand) is malformed.
    #[error("invalid enrollment link: {message}")]
    InvalidLink { message: String },
    /// This device is not enrolled yet.
    #[error("this device is not enrolled")]
    NotEnrolled,
    /// This device is already enrolled; leave Faro first to enroll again.
    #[error("this device is already enrolled with {instance}")]
    AlreadyEnrolled { instance: String },
    /// Enrolled, but the member hasn't approved this device yet: nothing
    /// can be recorded before the recipients are known.
    #[error("the member hasn't approved this device yet")]
    NotApproved,
    /// The member removed this device, or the account was deleted. Final.
    #[error("the instance no longer accepts this device: {message}")]
    Retired { message: String },
    /// The instance refused something, or isn't a Faro instance this
    /// client can use.
    #[error("{message}")]
    Instance { message: String },
    /// Couldn't reach the instance, or it failed; try again later.
    #[error("{message}")]
    Network { message: String },
    /// Something the instance sent doesn't check out (an identity that
    /// changed, a member key that doesn't match the link, a forged
    /// endorsement or manifest). Nothing was trusted or stored.
    #[error("{message}")]
    Integrity { message: String },
    /// The key store is locked (on iOS, before the first unlock after a
    /// reboot). Try again later; nothing is wrong.
    #[error("{message}")]
    KeysLocked { message: String },
    /// The key store failed.
    #[error("{message}")]
    KeyStore { message: String },
    /// Local storage (the database or the data directory) failed.
    #[error("{message}")]
    Storage { message: String },
    /// A data bundle from the update channel was refused, or the update
    /// metadata didn't verify against the root.
    #[error("{message}")]
    Update { message: String },
    /// The caller passed something this API doesn't accept.
    #[error("{message}")]
    InvalidArgument { message: String },
}

impl FaroError {
    pub(crate) fn storage(e: impl std::fmt::Display) -> Self {
        FaroError::Storage {
            message: e.to_string(),
        }
    }
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        FaroError::InvalidArgument {
            message: message.into(),
        }
    }
}

impl From<KeyStoreError> for FaroError {
    fn from(e: KeyStoreError) -> Self {
        let message = e.to_string();
        match e {
            KeyStoreError::Locked { .. } => FaroError::KeysLocked { message },
            KeyStoreError::Failed { .. } => FaroError::KeyStore { message },
        }
    }
}

impl From<LinkError> for FaroError {
    fn from(e: LinkError) -> Self {
        FaroError::InvalidLink {
            message: e.to_string(),
        }
    }
}

impl From<ClientError> for FaroError {
    fn from(e: ClientError) -> Self {
        let message = e.to_string();
        if e.retired().is_some() {
            FaroError::Retired { message }
        } else if e.is_pending_endorsement() {
            FaroError::NotApproved
        } else if matches!(e, ClientError::IdentityChanged { .. }) {
            FaroError::Integrity { message }
        } else if e.is_transient() || matches!(e, ClientError::Transport(_)) {
            FaroError::Network { message }
        } else {
            FaroError::Instance { message }
        }
    }
}

impl From<OutboxError> for FaroError {
    fn from(e: OutboxError) -> Self {
        match e {
            OutboxError::NotBootstrapped => FaroError::NotApproved,
            OutboxError::Manifest(e) => FaroError::Integrity {
                message: e.to_string(),
            },
            e => FaroError::storage(e),
        }
    }
}

impl From<WriterError> for FaroError {
    fn from(e: WriterError) -> Self {
        match e {
            WriterError::Outbox(e) => e.into(),
            e => FaroError::storage(e),
        }
    }
}

impl From<rusqlite::Error> for FaroError {
    fn from(e: rusqlite::Error) -> Self {
        FaroError::storage(e)
    }
}

impl From<UplinkError> for FaroError {
    fn from(e: UplinkError) -> Self {
        match e {
            UplinkError::Client(e) => e.into(),
            UplinkError::Outbox(e) => e.into(),
        }
    }
}

impl From<FetchError> for FaroError {
    fn from(e: FetchError) -> Self {
        match e {
            FetchError::Client(e) => e.into(),
            FetchError::Io { .. } => FaroError::storage(e),
            e => FaroError::Update {
                message: e.to_string(),
            },
        }
    }
}

impl From<EnrollError> for FaroError {
    fn from(e: EnrollError) -> Self {
        match e {
            EnrollError::Client(e) => e.into(),
            EnrollError::Outbox(e) => e.into(),
            EnrollError::DeviceRemoved => FaroError::Retired {
                message: e.to_string(),
            },
            EnrollError::InvalidInstance(_) => FaroError::Instance {
                message: e.to_string(),
            },
            EnrollError::InvalidResponse(_)
            | EnrollError::Endorsement(_)
            | EnrollError::MemberKeyMismatch { .. } => FaroError::Integrity {
                message: e.to_string(),
            },
        }
    }
}
