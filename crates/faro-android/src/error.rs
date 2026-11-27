//! From the errors of faro-service and faro-client to [`FaroAndroidError`].

use crate::types::FaroAndroidError;
use faro_core::OutboxError;
use faro_service::client::ClientError;
use faro_service::enroll::EnrollError;
use faro_service::state::StateError;
use faro_service::ServiceError;

pub(crate) fn client_err(e: ClientError) -> FaroAndroidError {
    let m = e.to_string();
    if e.retired().is_some() {
        FaroAndroidError::State(m)
    } else if e.is_pending_endorsement() {
        FaroAndroidError::State("the member hasn't approved this phone yet".into())
    } else if matches!(e, ClientError::IdentityChanged { .. }) {
        FaroAndroidError::Integrity(m)
    } else if e.is_transient() || matches!(e, ClientError::Transport(_)) {
        FaroAndroidError::Network(m)
    } else {
        FaroAndroidError::Instance(m)
    }
}

pub(crate) fn state_err(e: StateError) -> FaroAndroidError {
    let m = e.to_string();
    match e {
        StateError::NotEnrolled => FaroAndroidError::State("this phone is not enrolled".into()),
        StateError::AlreadyEnrolled { instance, .. } => {
            FaroAndroidError::State(format!("this phone is already enrolled with {instance}"))
        }
        StateError::Busy { .. } => FaroAndroidError::State(
            "Faro is busy with this phone's data; try again in a moment".into(),
        ),
        StateError::Io { .. } | StateError::Unsafe { .. } | StateError::Corrupt { .. } => {
            FaroAndroidError::Storage(m)
        }
    }
}

fn outbox_err(e: OutboxError) -> FaroAndroidError {
    match e {
        OutboxError::Manifest(e) => FaroAndroidError::Integrity(e.to_string()),
        e => FaroAndroidError::Storage(e.to_string()),
    }
}

pub(crate) fn enroll_err(e: EnrollError) -> FaroAndroidError {
    let m = e.to_string();
    match e {
        EnrollError::Client(e) => client_err(e),
        EnrollError::State(e) => state_err(e),
        EnrollError::Outbox(e) => outbox_err(e),
        EnrollError::DeviceName(_) => FaroAndroidError::Invalid(m),
        EnrollError::InvalidInstance(_) => FaroAndroidError::Instance(m),
        EnrollError::DeviceRemoved => FaroAndroidError::State(m),
        EnrollError::Declined
        | EnrollError::InvalidResponse(_)
        | EnrollError::Endorsement(_)
        | EnrollError::MemberKeyMismatch { .. } => FaroAndroidError::Integrity(m),
    }
}

pub(crate) fn service_err(e: ServiceError) -> FaroAndroidError {
    let m = e.to_string();
    match e {
        ServiceError::State(e) => state_err(e),
        ServiceError::Outbox(e) => outbox_err(e),
        ServiceError::Client(e) => client_err(e),
        ServiceError::Enroll(e) => enroll_err(e),
        ServiceError::DeviceRemoved => FaroAndroidError::State(m),
        _ => FaroAndroidError::Storage(m),
    }
}
