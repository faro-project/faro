//! Email magic-link sign-in, logout and `GET /v1/me`.
//!
//! The magic-link request endpoint returns the **same response whether or not
//! an account exists**, and the email is sent from a background task, so
//! neither the body nor (to first order) the timing reveals who has an
//! account. The link puts the token in the URL *fragment*
//! (`/auth/verify#token=…`): fragments are never sent to servers, so the
//! token cannot leak via access logs or `Referer` when the web app loads; the
//! app then POSTs it to `/v1/auth/magic-link/verify`.

use super::ApiJson;
use crate::auth::{normalize_display_name, normalize_email, session};
use crate::config::RegistrationMode;
use crate::db::repo::invites::{self, InviteKind};
use crate::db::repo::{auth_tokens, member_keys, sessions, users};
use crate::error::{AppError, AppResult};
use crate::mailer::Email;
use crate::ratelimit::Limit;
use crate::state::AppState;
use crate::tokens::{is_token_shaped, new_token, TokenPurpose};
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use faro_crypto::random_bytes;
use faro_proto::UserId;
use serde::{Deserialize, Serialize};

/// Magic links expire after 15 minutes.
pub const MAGIC_LINK_TTL_MS: i64 = 15 * 60 * 1000;

#[derive(Debug, Deserialize)]
pub struct MagicLinkRequest {
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MagicLinkResponse {
    pub status: String,
}

fn accepted() -> (StatusCode, Json<MagicLinkResponse>) {
    (
        StatusCode::ACCEPTED,
        Json(MagicLinkResponse {
            status: "if_account_exists_email_sent".to_owned(),
        }),
    )
}

/// `POST /v1/auth/magic-link`
pub async fn request_link(
    State(state): State<AppState>,
    ApiJson(req): ApiJson<MagicLinkRequest>,
) -> AppResult<(StatusCode, Json<MagicLinkResponse>)> {
    // A syntactically invalid address reveals nothing about accounts.
    let email = normalize_email(&req.email)
        .ok_or_else(|| AppError::bad_request("invalid_email", "invalid email address"))?;
    let now = state.now_ms();

    // Per-address limit so the instance cannot be used to flood one inbox.
    // Applied whether or not the account exists, and answered with the same
    // response, so it is not an existence oracle either.
    let email_key = format!(
        "email:{}",
        state.hasher().hash(TokenPurpose::RateLimitEmail, &email)
    );
    let per_email = Limit::per_hour(state.config().rate_limit.magic_links_per_email_per_hour);
    if state
        .rate_limiter()
        .check_account(&email_key, per_email, now)
        .is_err()
    {
        tracing::info!("magic link suppressed by per-address rate limit");
        return Ok(accepted());
    }

    let existing = users::by_email(state.db().pool(), &email).await?;
    let link_user: Option<Option<UserId>> = match &existing {
        Some(u) if !u.disabled => Some(Some(u.id.clone())),
        Some(_) => None,
        None if may_register(&state, &email, now).await? => Some(None),
        None => None,
    };
    let Some(user_id) = link_user else {
        return Ok(accepted());
    };

    let token = new_token();
    auth_tokens::insert_magic_link(
        state.db().pool(),
        &state.hasher().hash(TokenPurpose::MagicLink, &token),
        &email,
        user_id.as_ref(),
        now,
        now + MAGIC_LINK_TTL_MS,
    )
    .await?;

    let cfg = state.config();
    let mail = Email {
        to: email,
        subject: format!("Sign in to {}", cfg.instance.name),
        text: format!(
            "Use this link to sign in to {name}:\n\n{url}/auth/verify#token={token}\n\n\
             The link works once and expires in 15 minutes.\n\
             If you did not ask to sign in, you can ignore this email.\n",
            name = cfg.instance.name,
            url = cfg.public_url,
            token = token.as_str(),
        ),
    };
    let mailer = state.mailer();
    tokio::spawn(async move {
        if let Err(e) = mailer.send(mail).await {
            tracing::warn!(error = %e, "could not send sign-in email");
        }
    });
    Ok(accepted())
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub token: String,
}

impl std::fmt::Debug for VerifyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifyRequest { .. }")
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub user: users::User,
    /// True if this sign-in created the account (open registration).
    pub created: bool,
}

/// Whether an address without an account may create one by signing in:
/// never in `closed` mode; in `open` mode if its domain is allowed; and in
/// `invite-only` or `open` mode if it holds a live invite (an ally may be
/// anywhere, not only on the college's domain).
async fn may_register(state: &AppState, email: &str, now: i64) -> AppResult<bool> {
    let reg = state.settings().registration;
    if reg.mode == RegistrationMode::Closed {
        return Ok(false);
    }
    if reg.mode == RegistrationMode::Open && reg.domain_allowed(email) {
        return Ok(true);
    }
    Ok(
        !invites::live_kinds_for_email(state.db().pool(), email, now)
            .await?
            .is_empty(),
    )
}

/// Local part of an email, as a starting display name for self-registered users.
fn default_display_name(email: &str) -> String {
    let local = email.split('@').next().unwrap_or("member");
    let name: String = local.chars().take(64).collect();
    if name.is_empty() {
        "member".to_owned()
    } else {
        name
    }
}

/// `POST /v1/auth/magic-link/verify`
pub async fn verify_link(
    State(state): State<AppState>,
    ApiJson(req): ApiJson<VerifyRequest>,
) -> AppResult<Response> {
    let token = req.token.trim();
    if !is_token_shaped(token) {
        return Err(AppError::AuthFailed("invalid_or_expired_link"));
    }
    let hash = state.hasher().hash(TokenPurpose::MagicLink, token);
    let now = state.now_ms();

    let mut tx = state.db().begin_write().await?;
    let link = auth_tokens::consume_magic_link(&mut tx, &hash, now)
        .await?
        .ok_or(AppError::AuthFailed("invalid_or_expired_link"))?;

    let (user, created) = match link.user_id {
        Some(id) => {
            let u = users::by_id(&mut *tx, &id)
                .await?
                .filter(|u| !u.disabled)
                .ok_or(AppError::AuthFailed("invalid_or_expired_link"))?;
            (u, false)
        }
        None => match users::by_email(&mut *tx, &link.email).await? {
            // Someone created the account between request and verify.
            Some(u) if !u.disabled => (u, false),
            Some(_) => return Err(AppError::AuthFailed("invalid_or_expired_link")),
            None => {
                // Re-check policy at verify time: the admin may have closed
                // registration (or the invite may have expired) since the
                // link was sent.
                let reg = state.settings().registration;
                let kinds = invites::live_kinds_for_email(&mut *tx, &link.email, now).await?;
                let open_ok = reg.mode == RegistrationMode::Open && reg.domain_allowed(&link.email);
                if reg.mode == RegistrationMode::Closed || (!open_ok && kinds.is_empty()) {
                    return Err(AppError::Forbidden("registration_closed"));
                }
                let u = users::User {
                    id: UserId::from_random(&random_bytes::<16>()),
                    display_name: default_display_name(&link.email),
                    email: link.email.clone(),
                    roles: users::Roles {
                        admin: false,
                        // Self-registered accounts are members (they came to
                        // be held accountable); an ally invite alone makes
                        // an ally-only account.
                        member: open_ok || kinds.contains(&InviteKind::Member),
                        ally: kinds.contains(&InviteKind::Ally),
                    },
                    disabled: false,
                    created_at_ms: now,
                };
                users::insert(&mut *tx, &u).await?;
                (u, true)
            }
        },
    };
    // An admin's member invite is redeemed by signing in.
    let mut user = user;
    if invites::consume_member_invites(&mut tx, &user.email, &user.id, now).await? > 0 {
        users::grant_member(&mut *tx, &user.id).await?;
        user.roles.member = true;
    }
    users::touch_login(&mut *tx, &user.id, now).await?;
    tx.commit().await?;

    let cookie = session::create(&state, &user).await?;
    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(VerifyResponse { user, created }),
    )
        .into_response())
}

/// `POST /v1/auth/logout`: always succeeds and always clears the cookie.
pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    if let Some(s) = session::from_headers(&state, &headers).await? {
        sessions::delete(state.db().pool(), &s.session_hash).await?;
    }
    Ok((
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, session::clear_cookie(&state))],
    )
        .into_response())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MeResponse {
    pub user: users::User,
    pub has_member_keys: bool,
}

/// `PATCH /v1/me` body: the fields a person may change about themself.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateMe {
    pub display_name: Option<String>,
}

/// `PATCH /v1/me`: change your own display name (1–64 printable
/// characters), as members, allies and admins see it, and as emails name
/// you. Accounts made by signing in start with the address's local part.
pub async fn update_me(
    State(state): State<AppState>,
    s: session::SessionUser,
    ApiJson(req): ApiJson<UpdateMe>,
) -> AppResult<Json<MeResponse>> {
    if let Some(name) = &req.display_name {
        let name = normalize_display_name(name).ok_or_else(|| {
            AppError::bad_request(
                "invalid_display_name",
                "display_name must be 1-64 printable characters",
            )
        })?;
        users::set_display_name(state.db().pool(), &s.user.id, &name).await?;
    }
    let user = users::by_id(state.db().pool(), &s.user.id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let has_member_keys = member_keys::sign_pubkey(state.db().pool(), &user.id)
        .await?
        .is_some();
    Ok(Json(MeResponse {
        user,
        has_member_keys,
    }))
}

/// `GET /v1/me`
pub async fn me(
    State(state): State<AppState>,
    s: session::SessionUser,
) -> AppResult<Json<MeResponse>> {
    let has_member_keys = member_keys::sign_pubkey(state.db().pool(), &s.user.id)
        .await?
        .is_some();
    Ok(Json(MeResponse {
        user: s.user,
        has_member_keys,
    }))
}
