//! `GET /.well-known/faro`: instance discovery (§3.8).
//!
//! Clients fetch this at enrollment, show the instance name for confirmation
//! and pin `identity_pubkey`.

use crate::state::AppState;
use axum::extract::State;
use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use faro_proto::api::{WellKnown, PROTOCOL_VERSION};

/// Oldest client release this server still accepts.
pub const MIN_CLIENT_VERSION: &str = "0.1.0";

pub async fn get(State(state): State<AppState>) -> Response {
    let body = WellKnown {
        instance_id: state.instance_id().clone(),
        name: state.config().instance.name.clone(),
        identity_pubkey: state.identity().public(),
        server_version: env!("CARGO_PKG_VERSION").to_owned(),
        min_client_version: MIN_CLIENT_VERSION.to_owned(),
        protocol: PROTOCOL_VERSION,
    };
    let mut resp = Json(body).into_response();
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    resp
}
