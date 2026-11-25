//! Instance branding (see [`crate::branding`]).
//!
//! * `GET /v1/branding`: public, because pages show it before sign-in. It
//!   carries only what is switched on.
//! * `GET /v1/branding/logo/{id}.png`: public. The re-encoded PNG, from this
//!   origin, cached for a year: a new logo gets a new id, so a new URL.
//! * `GET` and `PATCH /admin/api/branding`, `PUT` and
//!   `DELETE /admin/api/branding/logo`: admins only.
//!
//! The logo upload is the raw image, with `Content-Type` `image/png`,
//! `image/jpeg` or `image/webp`. Like the JSON requirement elsewhere, this
//! is also a CSRF defence: a cross-site form can't send those types, and a
//! cross-site `fetch` with them needs a CORS preflight this server never
//! approves.
//!
//! None of this is in `/.well-known/faro`, emails or any alert, and changing
//! it notifies nobody.

use crate::auth::session::SessionUser;
use crate::branding::{
    self, BrandingPatch, BrandingSettings, LogoError, SupportContact, LOGO_MAX_UPLOAD_BYTES,
};
use crate::db::repo::branding as repo;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use super::ApiJson;

/// The CSP of the logo itself, should anyone open it as a page: nothing
/// runs, nothing loads.
pub const LOGO_CSP: &str = "default-src 'none'; frame-ancestors 'none'; sandbox";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoJson {
    /// The logo is at `/v1/branding/logo/{id}.png`.
    pub id: String,
    pub width: u32,
    pub height: u32,
}

impl From<repo::LogoInfo> for LogoJson {
    fn from(l: repo::LogoInfo) -> Self {
        LogoJson {
            id: l.id,
            width: l.width,
            height: l.height,
        }
    }
}

/// `GET /v1/branding`: what pages show. Only what is switched on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicBranding {
    /// From `faro.toml`; the logo's alt text.
    pub instance_name: String,
    /// Show the instance name in the header.
    pub show_name: bool,
    pub logo: Option<LogoJson>,
    pub welcome: Option<String>,
    pub support: Option<SupportContact>,
}

pub async fn get_public(State(state): State<AppState>) -> AppResult<Json<PublicBranding>> {
    let row = repo::get(state.db().pool()).await?;
    let s = &row.settings;
    Ok(Json(PublicBranding {
        instance_name: state.config().instance.name.clone(),
        show_name: s.show_name,
        logo: row.logo.filter(|_| s.show_logo).map(LogoJson::from),
        welcome: (s.welcome_enabled && !s.welcome.is_empty()).then(|| s.welcome.clone()),
        support: s
            .support_enabled
            .then(|| SupportContact::parse(&s.support).ok())
            .flatten(),
    }))
}

/// `GET /v1/branding/logo/{id}.png`
pub async fn get_logo(
    State(state): State<AppState>,
    Path(file): Path<String>,
) -> AppResult<Response> {
    let id = file
        .strip_suffix(".png")
        .filter(|id| branding::is_logo_id(id))
        .ok_or(AppError::NotFound)?;
    let png = repo::logo_png(state.db().pool(), id)
        .await?
        .ok_or(AppError::NotFound)?;
    let mut resp = Body::from(png).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(LOGO_CSP),
    );
    h.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("inline; filename=\"logo.png\""),
    );
    Ok(resp)
}

/// `GET /admin/api/branding`: everything, including text that is switched
/// off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminBranding {
    pub instance_name: String,
    pub settings: BrandingSettings,
    pub logo: Option<LogoJson>,
}

async fn admin_view(state: &AppState) -> AppResult<AdminBranding> {
    let row = repo::get(state.db().pool()).await?;
    Ok(AdminBranding {
        instance_name: state.config().instance.name.clone(),
        settings: row.settings,
        logo: row.logo.map(LogoJson::from),
    })
}

pub async fn admin_get(
    State(state): State<AppState>,
    s: SessionUser,
) -> AppResult<Json<AdminBranding>> {
    s.require_admin()?;
    Ok(Json(admin_view(&state).await?))
}

/// `PATCH /admin/api/branding`: any subset of the settings, checked, stored
/// and in effect on the next page load.
pub async fn admin_patch(
    State(state): State<AppState>,
    s: SessionUser,
    ApiJson(patch): ApiJson<BrandingPatch>,
) -> AppResult<Json<AdminBranding>> {
    s.require_admin()?;
    let mut tx = state.db().begin_write().await?;
    let current = repo::get(&mut *tx).await?.settings;
    let next = current
        .apply(&patch)
        .map_err(|e| AppError::bad_request(e.code(), e.to_string()))?;
    repo::set_settings(&mut *tx, &next, state.now_ms()).await?;
    tx.commit().await?;
    tracing::info!(admin = %s.user.id, "instance branding changed");
    Ok(Json(admin_view(&state).await?))
}

fn logo_error(e: LogoError) -> AppError {
    AppError::bad_request(e.code(), e.to_string())
}

/// `PUT /admin/api/branding/logo`: the raw image. Decoded and re-encoded
/// before anything is stored.
pub async fn admin_put_logo(
    State(state): State<AppState>,
    s: SessionUser,
    headers: HeaderMap,
    body: Body,
) -> AppResult<Json<AdminBranding>> {
    s.require_admin()?;
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if branding::upload_format(content_type).is_none() {
        return Err(logo_error(LogoError::UnsupportedFormat));
    }
    let bytes = axum::body::to_bytes(body, LOGO_MAX_UPLOAD_BYTES)
        .await
        .map_err(|_| logo_error(LogoError::TooLarge))?;
    let logo = tokio::task::spawn_blocking(move || branding::reencode_logo(&bytes))
        .await
        .map_err(|e| AppError::internal(format!("logo task failed: {e}")))?
        .map_err(logo_error)?;
    repo::set_logo(state.db().pool(), &logo, state.now_ms()).await?;
    tracing::info!(admin = %s.user.id, "instance logo changed");
    Ok(Json(admin_view(&state).await?))
}

/// `DELETE /admin/api/branding/logo`
pub async fn admin_delete_logo(
    State(state): State<AppState>,
    s: SessionUser,
) -> AppResult<Json<AdminBranding>> {
    s.require_admin()?;
    if repo::remove_logo(state.db().pool(), state.now_ms()).await? {
        tracing::info!(admin = %s.user.id, "instance logo removed");
    }
    Ok(Json(admin_view(&state).await?))
}
