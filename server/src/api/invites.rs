//! Ally invitations (§4.3, §5.2 step 1, §7 "Member" step 4).
//!
//! 1. A member invites an address: `POST /v1/me/invites {email}`. The
//!    invite token (256-bit, stored hashed, 7 days) is emailed as
//!    `<public_url>/invite#token=…` (a URL fragment, so it never reaches
//!    access logs or `Referer`).
//! 2. The invitee opens the link: `GET /v1/invites/{token}` shows who
//!    invited them and on which instance.
//! 3. They sign in with the invited address (an outstanding invite lets that
//!    address create an account even under `invite-only` registration; see
//!    [`crate::api::auth`]). Their browser generates an X25519 keypair,
//!    wraps the private key with their passphrase, and
//!    `POST /v1/invites/{token}/accept` uploads it ([`AllyKeyUpload`]). The
//!    link is now `pending`.
//! 4. The member compares safety codes with the ally and signs an
//!    endorsement of that key (see [`crate::api::allies`]).
//!
//! Only the invited address can accept: possession of the link alone is not
//! enough, so an intercepted or forwarded invite cannot be used by someone
//! else. Nobody, including an instance admin, can create a link for a
//! member: invites are created from the member's own session and approval
//! needs the member's signing key.

use super::keys::{parse_wrapped, RewrapResponse};
use super::ApiJson;
use crate::auth::normalize_email;
use crate::auth::session::SessionUser;
use crate::db::repo::invites::{self, InviteKind, InviteRow};
use crate::db::repo::{allies, is_unique_violation, users};
use crate::error::{AppError, AppResult};
use crate::mailer::Email;
use crate::state::AppState;
use crate::tokens::{is_token_shaped, new_token, TokenPurpose};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use faro_proto::api::{AllyKeyUpload, REQUEST_MAX_SKEW_MS};
use faro_proto::encoding::b64_encode;
use faro_proto::keys::{key_id, ProvenAllyKeyRewrap};
use faro_proto::{EncPublicKey, UserId};
use serde::{Deserialize, Serialize};

/// Invites expire after 7 days.
pub const INVITE_TTL_MS: i64 = 7 * 24 * 3600 * 1000;
/// Unused, unexpired invites one account may have out at once.
pub const MAX_LIVE_INVITES: i64 = 20;
/// Live (pending + active) allies per member: as many as one recipient
/// manifest can list (every item is wrapped to each ally, and the ingest
/// limit is 64 envelopes per item).
pub const MAX_ALLIES: i64 = faro_proto::keys::MAX_MANIFEST_ALLIES as i64;
/// Size cap for the opaque wrapped private key.
const MAX_WRAPPED_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInvite {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteCreated {
    pub email: String,
    pub expires_at_ms: i64,
    /// Also emailed. Returned so the member can share it another way if
    /// email is slow; only the invited address can accept it.
    pub invite_url: String,
}

fn invite_url(state: &AppState, token: &str) -> String {
    format!("{}/invite#token={token}", state.config().public_url)
}

/// Create, store and email an invite. Shared by the member (ally invites)
/// and admin (member invites) endpoints.
pub(crate) async fn create(
    state: &AppState,
    inviter: &users::User,
    kind: InviteKind,
    email: &str,
) -> AppResult<InviteCreated> {
    // Nobody new joins through someone whose account is being deleted.
    if inviter.deletion.is_some() {
        return Err(crate::auth::session::account_being_deleted());
    }
    let now = state.now_ms();
    if invites::count_live_by_inviter(state.db().pool(), &inviter.id, now).await?
        >= MAX_LIVE_INVITES
    {
        return Err(AppError::conflict(
            "too_many_invites",
            "too many open invitations; wait for some to be accepted or expire",
        ));
    }
    let token = new_token();
    let expires_at_ms = now + INVITE_TTL_MS;
    invites::insert(
        state.db().pool(),
        &InviteRow {
            token_hash: state.hasher().hash(TokenPurpose::Invite, &token),
            kind,
            inviter_id: inviter.id.clone(),
            email: email.to_owned(),
            created_at_ms: now,
            expires_at_ms,
        },
    )
    .await?;

    let url = invite_url(state, &token);
    let instance = &state.config().instance.name;
    let inviter_name = &inviter.display_name;
    let (subject, text) = match kind {
        InviteKind::Ally => (
            format!("{inviter_name} invited you to be their ally on {instance}"),
            format!(
                "{inviter_name} has invited you to be an accountability ally on {instance}.\n\n\
                 As an ally you are told when something needs attention, and you can read \
                 what {inviter_name} shares with you after unlocking Faro with your own \
                 passphrase. The people who run this server cannot read it.\n\n\
                 Accept the invitation (sign in with this email address):\n{url}\n\n\
                 The invitation expires in 7 days. If you did not expect it, you can ignore \
                 this email.\n"
            ),
        ),
        InviteKind::Member => (
            format!("You are invited to {instance}"),
            format!(
                "{inviter_name} has invited you to join {instance}, a Faro accountability \
                 instance.\n\nSign in with this email address to create your account:\n\
                 {url}\n\nThe invitation expires in 7 days. If you did not expect it, you can \
                 ignore this email.\n"
            ),
        ),
    };
    let mail = Email {
        to: email.to_owned(),
        subject,
        text,
    };
    let mailer = state.mailer();
    tokio::spawn(async move {
        if let Err(e) = mailer.send(mail).await {
            tracing::warn!(code = e.code(), "could not send invitation email");
        }
    });
    Ok(InviteCreated {
        email: email.to_owned(),
        expires_at_ms,
        invite_url: url,
    })
}

/// `POST /v1/me/invites`: a member invites an ally.
pub async fn create_ally_invite(
    State(state): State<AppState>,
    s: SessionUser,
    ApiJson(req): ApiJson<CreateInvite>,
) -> AppResult<(StatusCode, Json<InviteCreated>)> {
    s.require_member()?;
    let email = normalize_email(&req.email)
        .ok_or_else(|| AppError::bad_request("invalid_email", "invalid email address"))?;
    if email == s.user.email {
        return Err(AppError::bad_request(
            "cannot_invite_self",
            "you cannot be your own ally",
        ));
    }
    let pool = state.db().pool();
    if allies::count_live(pool, &s.user.id).await? >= MAX_ALLIES {
        return Err(AppError::conflict(
            "too_many_allies",
            format!("a member can have at most {MAX_ALLIES} allies"),
        ));
    }
    if let Some(existing) = users::by_email(pool, &email).await? {
        if allies::live_state(pool, &s.user.id, &existing.id)
            .await?
            .is_some()
        {
            return Err(AppError::conflict(
                "already_linked",
                "this person is already your ally (or has a pending invitation accepted)",
            ));
        }
    }
    let created = create(&state, &s.user, InviteKind::Ally, &email).await?;
    tracing::info!(member = %s.user.id, "ally invitation created");
    Ok((StatusCode::CREATED, Json(created)))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteInfo {
    pub kind: String,
    pub inviter_display_name: String,
    pub instance_name: String,
    /// The address that must sign in to accept.
    pub email: String,
    pub expires_at_ms: i64,
}

async fn live_invite(state: &AppState, token: &str) -> AppResult<InviteRow> {
    if !is_token_shaped(token) {
        return Err(AppError::NotFound);
    }
    invites::find_live(
        state.db().pool(),
        &state.hasher().hash(TokenPurpose::Invite, token),
        state.now_ms(),
    )
    .await?
    .ok_or(AppError::NotFound)
}

/// `GET /v1/invites/{token}` (unauthenticated; rate-limited). Unknown, used
/// and expired tokens are indistinguishable (404), and so are invitations
/// from an account that is disabled or being deleted (usable again if the
/// deletion is cancelled).
pub async fn get_invite(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> AppResult<Json<InviteInfo>> {
    let inv = live_invite(&state, &token).await?;
    let inviter = users::by_id(state.db().pool(), &inv.inviter_id)
        .await?
        .filter(|u| !u.disabled && u.deletion.is_none())
        .ok_or(AppError::NotFound)?;
    Ok(Json(InviteInfo {
        kind: inv.kind.as_str().to_owned(),
        inviter_display_name: inviter.display_name,
        instance_name: state.config().instance.name.clone(),
        email: inv.email,
        expires_at_ms: inv.expires_at_ms,
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteAccepted {
    pub member_id: UserId,
    pub state: String,
    pub ally_key_id: String,
}

/// `POST /v1/invites/{token}/accept`: the invited person (signed in with
/// the invited address) uploads their encryption key.
pub async fn accept(
    State(state): State<AppState>,
    Path(token): Path<String>,
    s: SessionUser,
    ApiJson(up): ApiJson<AllyKeyUpload>,
) -> AppResult<(StatusCode, Json<InviteAccepted>)> {
    s.require_not_being_deleted()?;
    if faro_crypto::validate_enc_pubkey(&up.enc_pubkey).is_err() {
        return Err(AppError::bad_request(
            "invalid_enc_pubkey",
            "enc_pubkey is not a usable X25519 key",
        ));
    }
    if !up.wrapped_privkey.is_object() || up.wrapped_privkey.to_string().len() > MAX_WRAPPED_BYTES {
        return Err(AppError::bad_request(
            "invalid_wrapped_key",
            "wrapped_privkey must be a JSON object of at most 8 KiB",
        ));
    }
    let inv = live_invite(&state, &token).await?;
    // Member invites are redeemed by signing in, not here.
    if inv.kind != InviteKind::Ally {
        return Err(AppError::NotFound);
    }
    if s.user.email != inv.email {
        return Err(AppError::Forbidden("invite_email_mismatch"));
    }
    let member = inv.inviter_id.clone();
    if member == s.user.id {
        return Err(AppError::bad_request(
            "cannot_invite_self",
            "you cannot be your own ally",
        ));
    }
    let now = state.now_ms();

    let mut tx = state.db().begin_write().await?;
    // Validate everything before consuming the invite, so a mistake (a
    // freshly generated key on a second device) does not burn it. Neither
    // side may be on the way out: the member was not told about a new ally
    // in their deletion notice, nor the ally about a new member.
    if users::is_being_deleted(&mut *tx, &member).await? {
        return Err(AppError::NotFound);
    }
    super::account::refuse_if_being_deleted(&mut *tx, &s.user.id).await?;
    if allies::live_state(&mut *tx, &member, &s.user.id)
        .await?
        .is_some()
    {
        return Err(AppError::conflict(
            "already_linked",
            "you are already linked to this member",
        ));
    }
    match allies::live_key(&mut *tx, &s.user.id).await? {
        Some(k) if k.enc_pubkey != up.enc_pubkey => {
            // One key per ally: replacing it would silently cut them off
            // from every other member who endorsed the old one.
            return Err(AppError::conflict(
                "ally_key_mismatch",
                "you already have an ally key; unlock it (GET /v1/me/ally-key) and use it",
            ));
        }
        Some(_) => {}
        None => {
            allies::insert_key(
                &mut *tx,
                &s.user.id,
                &up.enc_pubkey,
                &up.wrapped_privkey,
                now,
            )
            .await?;
        }
    }
    if !invites::consume(&mut *tx, &inv.token_hash, &s.user.id, now).await? {
        return Err(AppError::NotFound);
    }
    match allies::insert_pending(&mut *tx, &member, &s.user.id, now).await {
        Ok(_) => {}
        Err(e) if is_unique_violation(&e) => {
            return Err(AppError::conflict(
                "already_linked",
                "you are already linked to this member",
            ))
        }
        Err(e) => return Err(e.into()),
    }
    users::grant_ally(&mut *tx, &s.user.id).await?;
    tx.commit().await?;
    tracing::info!(member = %member, ally = %s.user.id, "ally invitation accepted");

    crate::notify::send_notice(
        &state,
        &member,
        format!("{} accepted your invitation", s.user.display_name),
        format!(
            "{} accepted your invitation to be your ally on {}. Open Faro, compare safety \
             codes with them, and approve them to start sharing.",
            s.user.display_name,
            state.config().instance.name
        ),
    );
    Ok((
        StatusCode::CREATED,
        Json(InviteAccepted {
            member_id: member,
            state: allies::LinkState::Pending.as_str().to_owned(),
            ally_key_id: key_id(up.enc_pubkey.as_bytes()),
        }),
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllyKeyBlob {
    pub enc_pubkey: EncPublicKey,
    pub key_id: String,
    /// Passphrase-wrapped private key, opened in the browser.
    pub wrapped_privkey: serde_json::Value,
    pub created_at_ms: i64,
}

/// `GET /v1/me/ally-key`: the caller's own wrapped ally key, so they can
/// unlock it on another browser.
pub async fn get_my_ally_key(
    State(state): State<AppState>,
    s: SessionUser,
) -> AppResult<Json<AllyKeyBlob>> {
    let k = allies::live_key(state.db().pool(), &s.user.id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(AllyKeyBlob {
        enc_pubkey: k.enc_pubkey,
        key_id: k.key_id,
        wrapped_privkey: k.wrapped_privkey,
        created_at_ms: k.created_at_ms,
    }))
}

// ---- Re-wrapping the ally key ---------------------------------------------
//
// An ally changes their passphrase, or gets a new recovery code, by
// replacing `wrapped_privkey`. The key itself never changes, so no member
// has to approve anything again and safety codes stay the same.
//
// The instance can't tell a good wrapping from garbage, so a stolen session
// alone must not be able to overwrite it: that would lock the ally out of
// every member they support. Members prove possession by signing
// (`PUT /v1/me/keys/wrapped`). An X25519 key can't sign, so the instance
// seals a challenge to the ally's public key instead, and only the holder of
// the private key can open it. The browser answers with a MAC keyed by the
// challenge (`AllyKeyRewrap::proof`), never the challenge itself, so this
// can't be used to make the browser open other sealed boxes for the
// instance. The challenge is a keyed hash over the ally, their key, the time
// and the wrapping it replaces, so it needs no storage, expires after
// `REQUEST_MAX_SKEW_MS`, and is good for one change only.

/// `POST /v1/me/ally-key/challenge` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllyKeyChallenge {
    pub enc_pubkey: EncPublicKey,
    /// The instance's clock, for the [`faro_proto::keys::AllyKeyRewrap`].
    pub issued_at_ms: i64,
    /// A 32-byte challenge sealed to `enc_pubkey` (`crypto_box_seal`),
    /// base64url.
    pub sealed_challenge: String,
}

fn challenge_for(
    state: &AppState,
    ally: &UserId,
    key: &allies::AllyKeyRow,
    issued_at_ms: i64,
) -> blake3::Hash {
    // Only the last field can contain a newline.
    let input = format!(
        "{}\n{}\n{issued_at_ms}\n{}",
        ally.as_str(),
        key.enc_pubkey.to_b64(),
        key.wrapped_privkey
    );
    state.hasher().mac(TokenPurpose::AllyKeyChallenge, &input)
}

/// `POST /v1/me/ally-key/challenge`: a challenge only the caller's ally key
/// can open, for [`put_my_wrapped_ally_key`].
pub async fn ally_key_challenge(
    State(state): State<AppState>,
    s: SessionUser,
) -> AppResult<Json<AllyKeyChallenge>> {
    let k = allies::live_key(state.db().pool(), &s.user.id)
        .await?
        .ok_or(AppError::NotFound)?;
    let issued_at_ms = state.now_ms();
    let challenge = challenge_for(&state, &s.user.id, &k, issued_at_ms);
    let sealed = faro_crypto::seal_to(&k.enc_pubkey, challenge.as_bytes())
        .map_err(|_| AppError::internal("could not seal the challenge"))?;
    Ok(Json(AllyKeyChallenge {
        enc_pubkey: k.enc_pubkey,
        issued_at_ms,
        sealed_challenge: b64_encode(&sealed),
    }))
}

/// `PUT /v1/me/ally-key/wrapped`: replace the wrapped copy of the caller's
/// ally key (a new passphrase, or a new recovery code), proven with a
/// challenge from [`ally_key_challenge`]. The public key can't change.
/// Like the member's re-wrap, this notifies nobody: nothing anyone else
/// sees has changed.
pub async fn put_my_wrapped_ally_key(
    State(state): State<AppState>,
    s: SessionUser,
    ApiJson(proven): ApiJson<ProvenAllyKeyRewrap>,
) -> AppResult<Json<RewrapResponse>> {
    let req = &proven.body;
    if &req.instance_id != state.instance_id() || req.ally_id != s.user.id {
        return Err(AppError::bad_request(
            "rewrap_mismatch",
            "the request must name this instance and your account",
        ));
    }
    let wrapped_privkey = parse_wrapped("wrapped_privkey", &req.wrapped_privkey)?;
    let pool = state.db().pool();
    let k = allies::live_key(pool, &s.user.id).await?.ok_or_else(|| {
        AppError::conflict(
            "ally_key_required",
            "you have no ally key; accept an invitation first",
        )
    })?;
    if req.enc_pubkey != k.enc_pubkey {
        return Err(AppError::conflict(
            "ally_key_mismatch",
            "your ally key can't be replaced, only wrapped under a new passphrase",
        ));
    }
    let now = state.now_ms();
    if req.issued_at_ms > now || now - req.issued_at_ms > REQUEST_MAX_SKEW_MS {
        return Err(AppError::bad_request(
            "stale_request",
            "the challenge has expired; ask for a new one",
        ));
    }
    let challenge = challenge_for(&state, &s.user.id, &k, req.issued_at_ms);
    let expected = req.proof(challenge.as_bytes());
    // `blake3::Hash` compares in constant time.
    if blake3::Hash::from_bytes(proven.proof.0) != blake3::Hash::from_bytes(expected.0) {
        return Err(AppError::bad_request(
            "bad_rewrap_proof",
            "the proof is wrong, or its challenge was already used",
        ));
    }
    if !allies::replace_wrapped(pool, &k.id, &k.wrapped_privkey, &wrapped_privkey).await? {
        return Err(AppError::conflict(
            "stale_request",
            "your key was changed while this request was being made",
        ));
    }
    tracing::info!(ally = %s.user.id, "ally re-wrapped their key");
    Ok(Json(RewrapResponse { updated_at_ms: now }))
}
