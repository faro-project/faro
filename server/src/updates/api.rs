//! `GET /v1/updates/…`: the mirror's public, read-only routes (PROTOCOL.md
//! §8).
//!
//! No authentication: everything here is a project-signed public release,
//! and clients verify it themselves. An enrolled device is not needed to
//! read it, which also lets a new member's browser download the installer
//! from their own instance.

use crate::error::AppError;
use crate::state::AppState;
use crate::updates::upstream::FetchError;
use crate::updates::MirrorError;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use faro_proto::api::UpdatesInfo;
use faro_update::metadata::MAX_ROOT_BYTES;
use tower::ServiceExt;
use tower_http::services::ServeFile;

/// `GET /v1/updates`
pub async fn info(State(state): State<AppState>) -> Json<UpdatesInfo> {
    Json(UpdatesInfo {
        available: state.updates().and_then(|m| m.served()).is_some(),
        channel: state.settings().updates.channel,
    })
}

/// `GET /v1/updates/timestamp.json`
pub async fn timestamp(State(state): State<AppState>) -> Result<Response, AppError> {
    let served = served(&state)?;
    Ok(json_bytes(served.timestamp.clone()))
}

/// `GET /v1/updates/targets.json`
pub async fn targets(State(state): State<AppState>) -> Result<Response, AppError> {
    let served = served(&state)?;
    Ok(json_bytes(served.targets.clone()))
}

/// `GET /v1/updates/roots/{n}.json`
///
/// Rotations newer than the project's first root are held by the mirror.
/// A client with an older root than the mirror's own may ask for one the
/// mirror never needed (it started from a newer root file); that one is
/// passed through from upstream unverified and uncached, since the mirror
/// cannot verify a root older than the one it trusts. The client verifies
/// every root itself.
pub async fn root(
    State(state): State<AppState>,
    Path(file): Path<String>,
) -> Result<Response, AppError> {
    let n: u64 = file
        .strip_suffix(".json")
        .and_then(|s| s.parse().ok())
        .filter(|n| *n >= 1)
        .ok_or(AppError::NotFound)?;
    let mirror = state.updates().ok_or(AppError::NotFound)?;
    let served = served(&state)?;
    if let Some(b) = served.roots.get(&n) {
        return Ok(json_bytes(b.clone()));
    }
    if n > served.root_version {
        return Err(AppError::NotFound);
    }
    let up = mirror.upstream().ok_or(AppError::NotFound)?;
    match up
        .get_meta(&format!("roots/{n}.json"), MAX_ROOT_BYTES)
        .await
    {
        Ok(Some(b)) => Ok(json_bytes(Bytes::from(b))),
        Ok(None) => Err(AppError::NotFound),
        Err(e) => Err(upstream_failed(&e)),
    }
}

/// `GET /v1/updates/targets/{*name}`: one artifact, with range support.
pub async fn artifact(
    State(state): State<AppState>,
    Path(name): Path<String>,
    req: Request,
) -> Result<Response, AppError> {
    let mirror = state.updates().ok_or(AppError::NotFound)?;
    let path = match mirror.artifact(&name).await {
        Ok(Some(p)) => p,
        Ok(None) => return Err(AppError::NotFound),
        Err(MirrorError::Fetch(e)) => return Err(upstream_failed(&e)),
        Err(e) => return Err(AppError::internal(e.to_string())),
    };
    let resp = match ServeFile::new(path).oneshot(req).await {
        Ok(r) => r,
        Err(never) => match never {},
    };
    let (mut parts, body) = resp.into_parts();
    if parts.status == StatusCode::NOT_FOUND {
        // Removed by a concurrent refresh between lookup and open.
        return Err(AppError::NotFound);
    }
    parts.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok(Response::from_parts(parts, Body::new(body)))
}

fn served(state: &AppState) -> Result<std::sync::Arc<crate::updates::Served>, AppError> {
    state
        .updates()
        .and_then(|m| m.served())
        .ok_or(AppError::NotFound)
}

fn json_bytes(b: Bytes) -> Response {
    let mut resp = Body::from(b).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

fn upstream_failed(e: &FetchError) -> AppError {
    tracing::warn!(error = %e, "update mirror could not fetch from upstream");
    AppError::Unavailable("upstream_unavailable")
}
