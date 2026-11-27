//! Recipient manifests (PROTOCOL.md §5.1): the member-signed, versioned list
//! of everyone a device may encrypt to.
//!
//! * `PUT /v1/me/recipient-manifest` (member session): upload the next
//!   version for an *unchanged or shrunken* ally set ([`Change::Refresh`]).
//! * `GET /v1/members/{id}/recipient-manifest` (that member's own device,
//!   pending ones included because they bootstrap from it, or the member):
//!   the latest version, 404 if there is none.
//! * Approving an ally ([`Change::Add`]) and removing one ([`Change::Remove`])
//!   carry their manifest in the request and are checked here too, inside
//!   the same transaction that changes the link (see [`crate::api::allies`]).
//!
//! ## What the instance enforces
//!
//! Devices verify every manifest themselves against the member key they
//! pinned, so none of this is needed for confidentiality. The instance
//! checks anyway, for two reasons: a bad document is caught at upload with a
//! clear error instead of leaving devices stuck on an older version; and the
//! rules below tie the encryption recipients to the **links**, which are the
//! instance's authority for feed and blob access, so the two cannot drift
//! apart unannounced:
//!
//! 1. structure first ([`RecipientManifest::validate`](faro_proto::keys::RecipientManifest::validate)), before any key
//!    work, as on devices;
//! 2. signed by the member's stored signing key, naming this instance and
//!    the caller;
//! 3. no small-order keys ([`faro_crypto::validate_enc_pubkey`]);
//! 4. `member_enc_pubkey` is the member's registered encryption key (from
//!    their key binding);
//! 5. `version` is exactly the latest stored version + 1 (1 for the first),
//!    so rollback, replay of the current version and skipped versions are all
//!    refused;
//! 6. the ally set changes only as the operation allows (below), and every
//!    listed ally has an **active** link whose stored key is the listed key.
//!
//! Both formats are accepted. The ally names a format 2 manifest carries
//! are signed by the member and checked only for length (by `validate`).
//! The instance stores and serves them as signed, and never compares them
//! with its own display names: a member re-signs when they choose, so an
//! ally who renames themselves never forces an upload, and any upload picks
//! the new name up.
//!
//! | Operation | Ally set must be |
//! |---|---|
//! | `PUT` ([`Change::Refresh`]) | the previous set, minus only allies whose link has already ended (an ally who left); every still-active ally stays listed |
//! | approve ([`Change::Add`]) | the previous set plus exactly the approved ally with their stored key |
//! | remove ([`Change::Remove`]) | the previous set minus exactly the removed ally |
//!
//! A `PUT` can therefore never add an ally (only approval, which needs the
//! member's endorsement of the ally's key, can) and never silently drop an
//! active ally (removal goes through `DELETE /v1/me/allies/{id}`, which
//! ends the link and raises the `ally_removed` alert).
//!
//! **The previous set.** Normally the allies of the latest stored manifest.
//! For a member who has no manifest yet it is their currently active links
//! (each approved earlier with a signed endorsement), so a member whose
//! allies predate manifests can sign their first one; for everyone else that
//! set is empty.
//!
//! **An ally who leaves** cannot sign anything, so their link ends at once
//! and the stored manifest still lists them until the member uploads the
//! next version. `GET /v1/me/allies` reports that state
//! ([`ManifestStatus::needs_update`]), and approving or removing another
//! ally is refused with `ally_not_active` until the member has done so.

use super::ApiJson;
use crate::auth::session::SessionUser;
use crate::db::repo::allies::{self, LinkState, LinkView};
use crate::db::repo::{is_unique_violation, manifests, member_keys};
use crate::device_auth::DeviceOrSession;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use faro_proto::api::SignedRecipientManifest;
use faro_proto::keys::{ManifestAlly, ManifestRef};
use faro_proto::{EncPublicKey, UserId};
use serde::{Deserialize, Serialize};
use sqlx::AnyConnection;

/// How an upload may change the ally set (module docs).
#[derive(Debug, Clone, Copy)]
pub enum Change<'a> {
    /// `PUT /v1/me/recipient-manifest`.
    Refresh,
    /// Approving `ally`, whose stored encryption key is `key`.
    Add { ally: &'a UserId, key: EncPublicKey },
    /// Removing `ally`.
    Remove { ally: &'a UserId },
}

/// Longest part of a structural error echoed back (it can contain an id the
/// client sent).
const MAX_ERROR_DETAIL: usize = 120;

fn bounded(s: String) -> String {
    if s.len() <= MAX_ERROR_DETAIL {
        return s;
    }
    let mut end = MAX_ERROR_DETAIL;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// The ally set the upload is compared against (module docs, "The previous
/// set"), sorted by `ally_id` like a manifest.
async fn previous_set(
    conn: &mut AnyConnection,
    member: &UserId,
    latest: Option<&manifests::StoredManifest>,
) -> AppResult<Vec<ManifestAlly>> {
    if let Some(l) = latest {
        return Ok(l.manifest.body.allies.clone());
    }
    let mut out = Vec::new();
    for ally_id in allies::active_ally_ids(&mut *conn, member).await? {
        if let Some(k) = allies::live_key(&mut *conn, &ally_id).await? {
            out.push(ManifestAlly {
                ally_id,
                enc_pubkey: k.enc_pubkey,
                name: None,
            });
        }
    }
    out.sort_by(|a, b| a.ally_id.cmp(&b.ally_id));
    Ok(out)
}

/// The same allies with the same keys, in the same order. Names (format 2)
/// are not compared: they are the member's to sign, the instance doesn't
/// read them, and a renamed ally shows up at the next upload whatever it is.
fn same_recipients(a: &[ManifestAlly], b: &[ManifestAlly]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| x.ally_id == y.ally_id && x.enc_pubkey == y.enc_pubkey)
}

fn set_mismatch(msg: &str) -> AppError {
    AppError::bad_request("manifest_set_mismatch", msg)
}

/// Check every rule for storing `m` as `member`'s next manifest. Must run
/// inside the caller's write transaction, which then stores it with
/// [`store`] (and applies the link change, if any) before committing.
pub async fn check_upload(
    conn: &mut AnyConnection,
    state: &AppState,
    member: &UserId,
    m: &SignedRecipientManifest,
    change: Change<'_>,
) -> AppResult<()> {
    let body = &m.body;
    // 1. Structure, before any key or database work.
    body.validate()
        .map_err(|e| AppError::bad_request("invalid_manifest", bounded(e.to_string())))?;

    // 2. Signature and identity.
    let keys = member_keys::get(&mut *conn, member).await?.ok_or_else(|| {
        AppError::conflict("member_keys_required", "set up your member keys first")
    })?;
    faro_crypto::verify_signed(&keys.sign_pubkey, m).map_err(|_| {
        AppError::bad_request(
            "bad_manifest_signature",
            "the recipient manifest is not signed by your member key",
        )
    })?;
    if &body.instance_id != state.instance_id() || &body.member_id != member {
        return Err(AppError::bad_request(
            "manifest_mismatch",
            "the recipient manifest must name this instance and your account",
        ));
    }

    // 3. Keys anyone could open.
    let weak = std::iter::once(&body.member_enc_pubkey)
        .chain(body.allies.iter().map(|a| &a.enc_pubkey))
        .any(|k| faro_crypto::validate_enc_pubkey(k).is_err());
    if weak {
        return Err(AppError::bad_request(
            "weak_manifest_key",
            "the recipient manifest contains an unusable (small-order) key",
        ));
    }

    // 4. The member's own key is the registered one.
    if body.member_enc_pubkey != keys.enc_pubkey {
        return Err(AppError::bad_request(
            "manifest_member_key_mismatch",
            "member_enc_pubkey must be your registered encryption key",
        ));
    }

    // 5. Exactly the next version.
    let latest = manifests::latest(&mut *conn, member).await?;
    let expected = match &latest {
        Some(l) => l.reference.version.checked_add(1).ok_or_else(|| {
            AppError::conflict("manifest_version_exhausted", "no further versions")
        })?,
        None => 1,
    };
    if body.version != expected {
        return Err(AppError::conflict(
            "manifest_version_mismatch",
            format!(
                "the next recipient manifest must be version {expected}, not {}",
                body.version
            ),
        ));
    }

    // 6a. The set changes only as the operation allows.
    let prev = previous_set(&mut *conn, member, latest.as_ref()).await?;
    let listed = |id: &UserId| body.allies.iter().any(|a| &a.ally_id == id);
    let mut added: Option<&UserId> = None;
    match change {
        Change::Refresh => {
            if let Some(a) = body
                .allies
                .iter()
                .find(|a| !prev.iter().any(|p| p.ally_id == a.ally_id))
            {
                return Err(AppError::bad_request(
                    "manifest_adds_ally",
                    format!(
                        "{} is not in your current recipient manifest; allies are only added \
                         by approving them",
                        a.ally_id
                    ),
                ));
            }
            for p in &prev {
                if !listed(&p.ally_id) && allies::is_active(&mut *conn, member, &p.ally_id).await? {
                    return Err(AppError::conflict(
                        "use_ally_removal",
                        format!(
                            "{} is still your ally; remove them with DELETE /v1/me/allies/{}",
                            p.ally_id, p.ally_id
                        ),
                    ));
                }
            }
        }
        Change::Add { ally, key } => {
            if prev.iter().any(|p| &p.ally_id == ally) {
                return Err(AppError::conflict(
                    "ally_already_in_manifest",
                    "this ally is still listed in your recipient manifest; upload an updated \
                     manifest first",
                ));
            }
            let mut want = prev.clone();
            want.push(ManifestAlly {
                ally_id: ally.clone(),
                enc_pubkey: key,
                name: None,
            });
            want.sort_by(|a, b| a.ally_id.cmp(&b.ally_id));
            if !same_recipients(&body.allies, &want) {
                return Err(set_mismatch(
                    "the recipient manifest must list exactly your current allies plus this \
                     ally with their key",
                ));
            }
            added = Some(ally);
        }
        Change::Remove { ally } => {
            if !prev.iter().any(|p| &p.ally_id == ally) {
                return Err(set_mismatch(
                    "this ally is not in your current recipient manifest",
                ));
            }
            let want: Vec<ManifestAlly> = prev
                .iter()
                .filter(|p| &p.ally_id != ally)
                .cloned()
                .collect();
            if !same_recipients(&body.allies, &want) {
                return Err(set_mismatch(
                    "the recipient manifest must list exactly your current allies minus this \
                     ally",
                ));
            }
        }
    }

    // 6b. Every listed ally (other than the one being approved, whose link
    // becomes active in this transaction) holds an active link with exactly
    // the listed key.
    for a in &body.allies {
        if Some(&a.ally_id) == added {
            continue;
        }
        if !allies::is_active(&mut *conn, member, &a.ally_id).await? {
            return Err(AppError::conflict(
                "ally_not_active",
                format!(
                    "{} is no longer your ally (they may have left); upload a recipient \
                     manifest without them first",
                    a.ally_id
                ),
            ));
        }
        let stored = allies::live_key(&mut *conn, &a.ally_id).await?;
        if stored.map(|k| k.enc_pubkey) != Some(a.enc_pubkey) {
            return Err(AppError::bad_request(
                "manifest_key_mismatch",
                format!("the key listed for {} is not their stored key", a.ally_id),
            ));
        }
    }
    Ok(())
}

/// Store a checked manifest in the caller's transaction. A concurrent upload
/// of the same version loses with `manifest_version_mismatch`.
pub async fn store(
    conn: &mut AnyConnection,
    m: &SignedRecipientManifest,
    now_ms: i64,
) -> AppResult<ManifestRef> {
    match manifests::insert(&mut *conn, m, now_ms).await {
        Ok(r) => Ok(r),
        Err(e) if is_unique_violation(&e) => Err(AppError::conflict(
            "manifest_version_mismatch",
            "another recipient manifest with this version was stored meanwhile",
        )),
        Err(e) => Err(e.into()),
    }
}

/// `PUT /v1/me/recipient-manifest`
pub async fn put_my_manifest(
    State(state): State<AppState>,
    s: SessionUser,
    ApiJson(m): ApiJson<SignedRecipientManifest>,
) -> AppResult<(StatusCode, Json<ManifestRef>)> {
    s.require_member()?;
    let mut tx = state.db().begin_write().await?;
    check_upload(&mut tx, &state, &s.user.id, &m, Change::Refresh).await?;
    let r = store(&mut tx, &m, state.now_ms()).await?;
    tx.commit().await?;
    tracing::info!(member = %s.user.id, version = r.version, "recipient manifest stored");
    Ok((StatusCode::CREATED, Json(r)))
}

/// `GET /v1/members/{id}/recipient-manifest`
///
/// Only the member and the member's own devices (pending ones included: a
/// fresh device needs it to bootstrap, PROTOCOL.md §5.1) may read it.
/// Everyone else, **instance admins included**, gets the same 404 as for a
/// member without a manifest.
pub async fn get_member_manifest(
    State(state): State<AppState>,
    Path(member): Path<String>,
    caller: DeviceOrSession,
) -> AppResult<Json<SignedRecipientManifest>> {
    let member = UserId::new(member);
    let allowed = match &caller {
        DeviceOrSession::Device(d) => d.row().owner_user_id == member,
        DeviceOrSession::Session(s) => s.user.id == member,
    };
    if !allowed || !member.is_well_formed() {
        return Err(AppError::NotFound);
    }
    let latest = manifests::latest(state.db().pool(), &member)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(latest.manifest))
}

/// How the member's latest manifest relates to their links, shown on
/// `GET /v1/me/allies`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestStatus {
    /// The latest stored manifest.
    pub current: ManifestRef,
    /// Devices are still encrypting to someone who should not be listed: an
    /// ally who left (see `departed`) or an ally whose stored key differs
    /// from the listed one. The member should sign and `PUT` the next
    /// version.
    pub needs_update: bool,
    /// Listed in the manifest, but their link has ended (they left). Their
    /// feed and blob access already ended with the link; devices keep
    /// sealing new items to them until the member uploads a manifest without
    /// them.
    pub departed: Vec<UserId>,
}

/// Compare the latest manifest with the member's live links.
pub async fn status(
    state: &AppState,
    member: &UserId,
    links: &[LinkView],
) -> AppResult<Option<ManifestStatus>> {
    let Some(latest) = manifests::latest(state.db().pool(), member).await? else {
        return Ok(None);
    };
    let mut departed = Vec::new();
    let mut stale_key = false;
    for a in &latest.manifest.body.allies {
        match links
            .iter()
            .find(|l| l.ally_id == a.ally_id && l.state == LinkState::Active)
        {
            None => departed.push(a.ally_id.clone()),
            Some(l) => stale_key |= l.ally_enc_pubkey != Some(a.enc_pubkey),
        }
    }
    Ok(Some(ManifestStatus {
        current: latest.reference,
        needs_update: stale_key || !departed.is_empty(),
        departed,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_details_are_bounded() {
        assert_eq!(bounded("short".into()), "short");
        let long = "é".repeat(200);
        let b = bounded(long);
        assert!(b.len() <= MAX_ERROR_DETAIL + "…".len());
        assert!(b.ends_with('…'));
    }
}
