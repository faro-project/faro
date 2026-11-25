//! First-run setup (§7 "Instance admin"): create the first admin account.
//!
//! `faro-server init` (or the first `serve`) prints a one-time setup token.
//! `POST /v1/setup` exchanges it for the admin account and a session. It only
//! works while no admin exists, the token is single-use and stored hashed, and
//! the endpoint is rate-limited, so an instance exposed to the internet
//! before its admin finishes setup cannot be claimed by a stranger.

use super::ApiJson;
use crate::auth::{normalize_display_name, normalize_email, session};
use crate::db::repo::{auth_tokens, users};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::tokens::{is_token_shaped, TokenPurpose};
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use faro_crypto::random_bytes;
use faro_proto::UserId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SetupStatus {
    /// True until the first admin account exists.
    pub needs_setup: bool,
}

/// `GET /v1/setup`: lets the web wizard decide what to show.
pub async fn status(State(state): State<AppState>) -> AppResult<Json<SetupStatus>> {
    let needs_setup = users::count_admins(state.db().pool()).await? == 0;
    Ok(Json(SetupStatus { needs_setup }))
}

#[derive(Deserialize)]
pub struct SetupRequest {
    pub setup_token: String,
    pub email: String,
    pub display_name: String,
}

impl std::fmt::Debug for SetupRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupRequest").finish_non_exhaustive()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetupResponse {
    pub user: users::User,
}

/// `POST /v1/setup`
pub async fn create_admin(
    State(state): State<AppState>,
    ApiJson(req): ApiJson<SetupRequest>,
) -> AppResult<Response> {
    // Validate input before touching the token so a typo does not burn it.
    let email = normalize_email(&req.email)
        .ok_or_else(|| AppError::bad_request("invalid_email", "invalid email address"))?;
    let display_name = normalize_display_name(&req.display_name).ok_or_else(|| {
        AppError::bad_request(
            "invalid_display_name",
            "display name must be 1-64 characters",
        )
    })?;
    if !is_token_shaped(req.setup_token.trim()) {
        return Err(AppError::AuthFailed("invalid_setup_token"));
    }
    let token_hash = state
        .hasher()
        .hash(TokenPurpose::Setup, req.setup_token.trim());
    let now = state.now_ms();

    let mut tx = state.db().begin_write().await?;
    if users::count_admins(&mut *tx).await? > 0 {
        return Err(AppError::conflict(
            "already_set_up",
            "this instance already has an admin",
        ));
    }
    if !auth_tokens::consume_setup_token(&mut *tx, &token_hash, now).await? {
        return Err(AppError::AuthFailed("invalid_setup_token"));
    }
    if users::by_email(&mut *tx, &email).await?.is_some() {
        return Err(AppError::conflict(
            "email_in_use",
            "an account with this email already exists",
        ));
    }
    let user = users::User {
        id: UserId::from_random(&random_bytes::<16>()),
        email,
        display_name,
        // The first admin is usually also someone who wants accountability
        // (an individual self-hoster). Being a member only lets them manage
        // their *own* keys and devices; it grants nothing over anyone else.
        roles: users::Roles {
            admin: true,
            member: true,
            ally: false,
        },
        disabled: false,
        created_at_ms: now,
        deletion: None,
    };
    users::insert(&mut *tx, &user).await?;
    users::touch_login(&mut *tx, &user.id, now).await?;
    tx.commit().await?;
    tracing::info!(user = %user.id, "first admin account created");

    let cookie = session::create(&state, &user).await?;
    Ok((
        StatusCode::CREATED,
        [(header::SET_COOKIE, cookie)],
        Json(SetupResponse { user }),
    )
        .into_response())
}
