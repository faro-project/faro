//! Member keys and the key directory devices encrypt to (§5.2).
//!
//! The member's signing key is the root of trust for their accountability
//! setup: it endorses their devices and their allies' encryption keys, and
//! signs the recipient manifest ([`crate::api::manifests`]) that devices
//! actually pick recipients from. The directory below is kept for the
//! safety-code flow and older clients; devices must not choose recipients
//! from it (endorsements cannot express removal).
//! The server stores the public halves and the passphrase/recovery-wrapped
//! private halves, which it cannot open.
//!
//! The server verifies every signature it stores, even though devices and
//! browsers re-verify everything themselves: catching a bad binding at upload
//! gives the member a clear error instead of a silently broken setup.

use super::ApiJson;
use crate::auth::session::SessionUser;
use crate::db::repo::{allies, is_unique_violation, member_keys};
use crate::device_auth::DeviceOrSession;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use faro_proto::api::MemberKeysResponse;
use faro_proto::keys::{key_id, MemberEncKeyBinding, Signed};
use faro_proto::{EncPublicKey, SignPublicKey, UserId};
use serde::{Deserialize, Serialize};

/// Maximum serialized size of each opaque wrapped-key blob. A `WrappedSecret`
/// is a few hundred bytes; this leaves room for future formats.
const MAX_WRAPPED_BYTES: usize = 8 * 1024;

/// `PUT /v1/me/keys` body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutMemberKeys {
    pub sign_pubkey: SignPublicKey,
    /// The member's encryption key, signed by `sign_pubkey`.
    pub enc_binding: Signed<MemberEncKeyBinding>,
    /// Passphrase-wrapped Ed25519 seed (opaque to the server).
    pub wrapped_sign_key: serde_json::Value,
    /// Passphrase-wrapped X25519 secret (opaque to the server).
    pub wrapped_enc_key: serde_json::Value,
    /// Both secrets wrapped under the recovery code (opaque to the server).
    pub recovery_wrapped: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutMemberKeysResponse {
    pub sign_pubkey: SignPublicKey,
    pub sign_key_id: String,
    pub enc_pubkey: EncPublicKey,
    pub enc_key_id: String,
}

/// `GET /v1/me/keys` response: everything the member's browser needs to
/// unlock their keys on a new device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberKeysBlob {
    pub sign_pubkey: SignPublicKey,
    pub enc_binding: Signed<MemberEncKeyBinding>,
    pub wrapped_sign_key: serde_json::Value,
    pub wrapped_enc_key: serde_json::Value,
    pub recovery_wrapped: serde_json::Value,
    pub created_at_ms: i64,
}

fn check_wrapped(name: &'static str, v: &serde_json::Value) -> Result<(), AppError> {
    if !v.is_object() {
        return Err(AppError::bad_request(
            "invalid_wrapped_key",
            format!("{name} must be a JSON object"),
        ));
    }
    if v.to_string().len() > MAX_WRAPPED_BYTES {
        return Err(AppError::bad_request(
            "invalid_wrapped_key",
            format!("{name} is too large"),
        ));
    }
    Ok(())
}

/// `PUT /v1/me/keys`: set the member's keys, once.
///
/// Rotation is deliberately not supported yet: replacing the root key would
/// silently invalidate every device and ally endorsement, so it needs its own
/// flow (re-endorsement, ally notification) rather than an overwrite.
pub async fn put_my_keys(
    State(state): State<AppState>,
    s: SessionUser,
    ApiJson(req): ApiJson<PutMemberKeys>,
) -> AppResult<(StatusCode, Json<PutMemberKeysResponse>)> {
    s.require_member()?;
    check_wrapped("wrapped_sign_key", &req.wrapped_sign_key)?;
    check_wrapped("wrapped_enc_key", &req.wrapped_enc_key)?;
    check_wrapped("recovery_wrapped", &req.recovery_wrapped)?;

    let b = &req.enc_binding.body;
    if faro_crypto::validate_sign_pubkey(&req.sign_pubkey).is_err() {
        return Err(AppError::bad_request(
            "invalid_sign_pubkey",
            "sign_pubkey is not a usable Ed25519 key",
        ));
    }
    if faro_crypto::validate_enc_pubkey(&b.member_enc_pubkey).is_err() {
        return Err(AppError::bad_request(
            "invalid_enc_pubkey",
            "member_enc_pubkey is not a usable X25519 key",
        ));
    }
    if &b.instance_id != state.instance_id() || b.member_id != s.user.id {
        return Err(AppError::bad_request(
            "binding_mismatch",
            "the binding must name this instance and your account",
        ));
    }
    faro_crypto::verify_signed(&req.sign_pubkey, &req.enc_binding).map_err(|_| {
        AppError::bad_request(
            "bad_binding_signature",
            "enc_binding is not signed by sign_pubkey",
        )
    })?;

    let now = state.now_ms();
    let row = member_keys::MemberKeysRow {
        user_id: s.user.id.clone(),
        sign_pubkey: req.sign_pubkey,
        enc_pubkey: b.member_enc_pubkey,
        enc_binding: req.enc_binding.clone(),
        wrapped_sign_key: req.wrapped_sign_key,
        wrapped_enc_key: req.wrapped_enc_key,
        recovery_wrapped: req.recovery_wrapped,
        created_at_ms: now,
    };
    match member_keys::insert_new(state.db().pool(), &row).await {
        Ok(true) => {}
        Ok(false) => {
            return Err(AppError::conflict(
                "keys_already_set",
                "member keys are already set; rotation is not supported yet",
            ))
        }
        Err(e) if is_unique_violation(&e) => {
            return Err(AppError::conflict(
                "key_in_use",
                "this signing key is already registered",
            ))
        }
        Err(e) => return Err(e.into()),
    }
    Ok((
        StatusCode::CREATED,
        Json(PutMemberKeysResponse {
            sign_pubkey: row.sign_pubkey,
            sign_key_id: key_id(row.sign_pubkey.as_bytes()),
            enc_pubkey: row.enc_pubkey,
            enc_key_id: key_id(row.enc_pubkey.as_bytes()),
        }),
    ))
}

/// `GET /v1/me/keys`
pub async fn get_my_keys(
    State(state): State<AppState>,
    s: SessionUser,
) -> AppResult<Json<MemberKeysBlob>> {
    let row = member_keys::get(state.db().pool(), &s.user.id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(MemberKeysBlob {
        sign_pubkey: row.sign_pubkey,
        enc_binding: row.enc_binding,
        wrapped_sign_key: row.wrapped_sign_key,
        wrapped_enc_key: row.wrapped_enc_key,
        recovery_wrapped: row.recovery_wrapped,
        created_at_ms: row.created_at_ms,
    }))
}

/// `GET /v1/members/{id}/keys`: the public key directory for one member.
///
/// Callable by the member themself or by one of the member's own devices
/// (including a pending one, which needs the keys to finish setting up).
/// Anyone else, **including instance admins**, gets 404: admins must not be
/// able to map out whom a member trusts beyond the metadata they already see.
pub async fn member_keys_directory(
    State(state): State<AppState>,
    Path(member): Path<String>,
    caller: DeviceOrSession,
) -> AppResult<Json<MemberKeysResponse>> {
    let member = UserId::new(member);
    let allowed = match &caller {
        DeviceOrSession::Device(d) => d.row().owner_user_id == member,
        DeviceOrSession::Session(s) => s.user.id == member,
    };
    if !allowed || !member.is_well_formed() {
        return Err(AppError::NotFound);
    }
    let keys = member_keys::get(state.db().pool(), &member)
        .await?
        .ok_or(AppError::NotFound)?;

    // Only hand out ally keys that (a) carry a valid endorsement by this
    // member for this instance and (b) are still live in `ally_keys`. Devices
    // re-check (a) against their pinned member key; (b) lets a revocation
    // take effect even before the member re-endorses.
    let mut out = Vec::new();
    for a in allies::active_endorsed(state.db().pool(), &member).await? {
        let e = &a.endorsement;
        let consistent = &e.body.instance_id == state.instance_id()
            && e.body.member_id == member
            && e.body.ally_id == a.ally_id
            && faro_crypto::verify_signed(&keys.sign_pubkey, e).is_ok();
        if !consistent {
            tracing::warn!(ally = %a.ally_id, "skipping ally endorsement that does not verify");
            continue;
        }
        let live = allies::live_enc_keys(state.db().pool(), &a.ally_id).await?;
        if live.contains(&e.body.ally_enc_pubkey) {
            out.push(a.endorsement);
        }
    }

    Ok(Json(MemberKeysResponse {
        member_id: member,
        member_sign_pubkey: keys.sign_pubkey,
        member_enc_key: keys.enc_binding,
        allies: out,
    }))
}
