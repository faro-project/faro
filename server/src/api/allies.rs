//! Member ↔ ally links (§4.3, §5.2 steps 2 and 4, §3.7 "ally removed").
//!
//! Member side (`/v1/me/allies…`, member role required):
//!
//! * `GET` lists live links, with each ally's encryption key and the
//!   member's signing key: the browser computes the **safety code** from
//!   these (`faro_proto::keys::safety_code`) so member and ally can compare
//!   it in person. The server deliberately does not compute it: a code
//!   computed by the party it is meant to check proves nothing.
//! * `POST …/{ally_id}/approve` takes `{endorsement, manifest}`
//!   ([`ApproveAlly`]): a [`Signed<AllyEndorsement>`] made with the member's
//!   key, which must name this instance, the caller, that ally and the
//!   ally's stored key, and the next [`SignedRecipientManifest`], which must
//!   be the previous ally set plus exactly this ally with that key
//!   ([`manifests::Change::Add`]). The link becomes `active` and the
//!   manifest is stored in **one** transaction, so devices can never be
//!   handed a manifest listing an ally whose link is not active (or the
//!   reverse). A normal-urgency `ally_added` alert tells the member and the
//!   existing allies; the new ally gets a content-free notice instead.
//! * `DELETE …/{ally_id}` with `{manifest}` ([`RemoveAlly`]) removes the
//!   link. For an **active** ally the manifest is required and must be the
//!   previous set minus exactly this ally ([`manifests::Change::Remove`]); it
//!   is stored in the same transaction as the removal. Removing an active
//!   ally raises a normal-urgency `ally_removed` alert that goes to the
//!   removed ally (as the alert's extra recipient), the member, and the
//!   remaining allies: an ally can never be dropped silently. A pending
//!   link (never in any manifest) is removed without one.
//!
//! Ally side (`/v1/ally/members…`): list the members one supports, and
//! leave (`DELETE`), which tells the member and the remaining allies.
//!
//! **Leaving cannot update the manifest.** Only the member can sign one, so
//! when an ally leaves the link ends at once (feed and blob access stop with
//! it, because active links are the only authority for those) while the
//! stored manifest still lists them. The member's devices keep sealing new
//! items to the departed ally until the member signs and uploads the next
//! manifest without them; the ally can no longer fetch any of that
//! ciphertext from this instance. The member is told so by a notice, and
//! `GET /v1/me/allies` reports `manifest.needs_update` with the departed
//! ally listed until it is done.
//!
//! Admins have no route here that acts on anyone else's links: every
//! endpoint works on the caller's own relationships only.

use super::manifests::{self, Change, ManifestStatus};
use super::{ApiJson, OptionalApiJson};
use crate::auth::session::SessionUser;
use crate::db::repo::alerts::{self, AlertSource, NewAlert};
use crate::db::repo::allies::{self, LinkState, LinkView};
use crate::db::repo::{member_keys, notifications, users};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use faro_proto::api::{ServerAlertKind, SignedRecipientManifest};
use faro_proto::keys::{key_id, AllyEndorsement, ManifestRef, Signed};
use faro_proto::{EncPublicKey, SignPublicKey, UserId};
use serde::{Deserialize, Serialize};

/// One of the member's allies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllyLink {
    pub ally_id: UserId,
    pub display_name: String,
    pub email: String,
    pub state: LinkState,
    pub created_at_ms: i64,
    pub activated_at_ms: Option<i64>,
    /// Safety-code inputs: the ally's encryption key …
    pub ally_enc_pubkey: Option<EncPublicKey>,
    pub ally_key_id: Option<String>,
    /// … and the member's signing key.
    pub member_sign_pubkey: Option<SignPublicKey>,
    /// When the ally's account will be deleted, if they asked for that
    /// (§12): they stop being an ally then.
    pub deletion_purge_after_ms: Option<i64>,
}

/// `GET /v1/me/allies` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MyAllies {
    /// Live (pending and active) links.
    pub allies: Vec<AllyLink>,
    /// The latest recipient manifest and whether it needs re-signing (an
    /// ally left); `None` before the member's first manifest.
    pub manifest: Option<ManifestStatus>,
}

impl From<LinkView> for AllyLink {
    fn from(v: LinkView) -> Self {
        AllyLink {
            ally_key_id: v.ally_enc_pubkey.map(|k| key_id(k.as_bytes())),
            ally_id: v.ally_id,
            display_name: v.other_display_name,
            email: v.other_email,
            state: v.state,
            created_at_ms: v.created_at_ms,
            activated_at_ms: v.activated_at_ms,
            ally_enc_pubkey: v.ally_enc_pubkey,
            member_sign_pubkey: v.member_sign_pubkey,
            deletion_purge_after_ms: v.other_deletion_purge_after_ms,
        }
    }
}

/// `GET /v1/me/allies`
pub async fn list_my_allies(
    State(state): State<AppState>,
    s: SessionUser,
) -> AppResult<Json<MyAllies>> {
    s.require_member()?;
    let rows = allies::list_for_member(state.db().pool(), &s.user.id).await?;
    let manifest = manifests::status(&state, &s.user.id, &rows).await?;
    Ok(Json(MyAllies {
        allies: rows.into_iter().map(AllyLink::from).collect(),
        manifest,
    }))
}

fn parse_user(id: String) -> AppResult<UserId> {
    let id = UserId::new(id);
    if id.is_well_formed() {
        Ok(id)
    } else {
        Err(AppError::NotFound)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkStatus {
    pub ally_id: UserId,
    pub state: LinkState,
    /// The recipient manifest stored with the change.
    pub manifest: ManifestRef,
}

/// `POST /v1/me/allies/{ally_id}/approve` body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveAlly {
    pub endorsement: Signed<AllyEndorsement>,
    /// The previous ally set plus exactly this ally.
    pub manifest: SignedRecipientManifest,
}

/// `DELETE /v1/me/allies/{ally_id}` body (required for an active ally).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoveAlly {
    /// The previous ally set minus exactly this ally.
    pub manifest: SignedRecipientManifest,
}

/// `POST /v1/me/allies/{ally_id}/approve`
pub async fn approve(
    State(state): State<AppState>,
    Path(ally): Path<String>,
    s: SessionUser,
    ApiJson(req): ApiJson<ApproveAlly>,
) -> AppResult<Json<LinkStatus>> {
    s.require_member()?;
    s.require_not_being_deleted()?;
    let ally = parse_user(ally)?;
    let member = &s.user.id;
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    super::account::refuse_if_being_deleted(&mut *tx, member).await?;
    // The ally's deletion notice went to the members they already
    // supported: a new one would not have been told.
    if users::is_being_deleted(&mut *tx, &ally).await? {
        return Err(AppError::conflict(
            "ally_deleting",
            "this person's account is being deleted",
        ));
    }
    match allies::live_state(&mut *tx, member, &ally).await? {
        Some(LinkState::Pending) => {}
        Some(LinkState::Active) => {
            return Err(AppError::conflict(
                "already_active",
                "this ally is already approved",
            ))
        }
        Some(LinkState::Removed) | None => return Err(AppError::NotFound),
    }
    let key = allies::live_key(&mut *tx, &ally)
        .await?
        .ok_or_else(|| AppError::conflict("ally_has_no_key", "the ally has no key"))?;
    let endorsement = &req.endorsement;
    let e = &endorsement.body;
    if &e.instance_id != state.instance_id()
        || &e.member_id != member
        || e.ally_id != ally
        || e.ally_enc_pubkey != key.enc_pubkey
    {
        return Err(AppError::bad_request(
            "endorsement_mismatch",
            "the endorsement must name this instance, your account, this ally and their key",
        ));
    }
    let member_key = member_keys::sign_pubkey(&mut *tx, member)
        .await?
        .ok_or_else(|| {
            AppError::conflict("member_keys_required", "set up your member keys first")
        })?;
    faro_crypto::verify_signed(&member_key, endorsement).map_err(|_| {
        AppError::bad_request(
            "bad_endorsement_signature",
            "endorsement is not signed by your member key",
        )
    })?;
    manifests::check_upload(
        &mut tx,
        &state,
        member,
        &req.manifest,
        Change::Add {
            ally: &ally,
            key: key.enc_pubkey,
        },
    )
    .await?;
    let json = serde_json::to_string(endorsement)
        .map_err(|_| AppError::internal("cannot serialize endorsement"))?;
    if !allies::activate(&mut *tx, member, &ally, &json, now).await? {
        return Err(AppError::conflict(
            "not_pending",
            "the link is no longer pending",
        ));
    }
    let manifest = manifests::store(&mut tx, &req.manifest, now).await?;
    let kind = ServerAlertKind::AllyAdded;
    alerts::insert_routed(
        &mut *tx,
        &NewAlert {
            member_id: member,
            device_id: None,
            source: AlertSource::Server,
            kind: kind.as_str(),
            urgency: kind.urgency(),
            event_seq: None,
            detail: Some(format!("added:{ally}")),
            dedupe_key: Some(format!("ally_added:{member}:{ally}:{}", manifest.version)),
            now_ms: now,
        },
        None,
        // The new ally hears about it from the notice below, not as an
        // "alert" about themself.
        Some(&ally),
        None,
    )
    .await?;
    tx.commit().await?;
    tracing::info!(member = %member, ally = %ally, version = manifest.version, "ally approved");
    crate::notify::send_notice(
        &state,
        &ally,
        format!("{} approved you as their ally", s.user.display_name),
        format!(
            "{} approved you as their ally on {}. You will now be notified when something \
             needs attention.",
            s.user.display_name,
            state.config().instance.name
        ),
    );
    Ok(Json(LinkStatus {
        ally_id: ally,
        state: LinkState::Active,
        manifest,
    }))
}

/// Why a link ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndReason {
    /// The member removed the ally.
    RemovedByMember,
    /// The ally left.
    Left,
    /// The purge of one side's account (§12). Nobody is alerted again: the
    /// deletion notices told everyone, with the date, when it was asked.
    AccountDeleted,
}

/// Inside `tx`: end the live link and, if it was active and the reason
/// calls for it, raise the `ally_removed` alert. Removed by the member: the
/// ally is the extra recipient, because they are no longer an ally but must
/// be told. Left: the member is told anyway.
pub(crate) async fn end_link(
    tx: &mut sqlx::AnyConnection,
    member: &UserId,
    ally: &UserId,
    reason: EndReason,
    now: i64,
) -> AppResult<LinkState> {
    let prev = allies::remove(&mut *tx, member, ally, now)
        .await?
        .ok_or(AppError::NotFound)?;
    let by_member = reason == EndReason::RemovedByMember;
    if prev == LinkState::Active && reason != EndReason::AccountDeleted {
        let kind = ServerAlertKind::AllyRemoved;
        let verb = if by_member { "removed" } else { "left" };
        alerts::insert_with_extra_recipient(
            &mut *tx,
            &NewAlert {
                member_id: member,
                device_id: None,
                source: AlertSource::Server,
                kind: kind.as_str(),
                urgency: kind.urgency(),
                event_seq: None,
                detail: Some(format!("{verb}:{ally}")),
                dedupe_key: Some(format!("ally_removed:{member}:{ally}:{now}")),
                now_ms: now,
            },
            by_member.then_some(ally),
        )
        .await?;
    }
    notifications::suppress_pending_about_member(&mut *tx, ally, member).await?;
    Ok(prev)
}

/// `DELETE /v1/me/allies/{ally_id}`
pub async fn remove(
    State(state): State<AppState>,
    Path(ally): Path<String>,
    s: SessionUser,
    OptionalApiJson(req): OptionalApiJson<RemoveAlly>,
) -> AppResult<StatusCode> {
    s.require_member()?;
    let ally = parse_user(ally)?;
    let member = &s.user.id;
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let version = match (allies::live_state(&mut *tx, member, &ally).await?, req) {
        (Some(LinkState::Active), Some(req)) => {
            manifests::check_upload(
                &mut tx,
                &state,
                member,
                &req.manifest,
                Change::Remove { ally: &ally },
            )
            .await?;
            Some(manifests::store(&mut tx, &req.manifest, now).await?.version)
        }
        (Some(LinkState::Active), None) => {
            return Err(AppError::bad_request(
                "manifest_required",
                "removing an approved ally needs the next recipient manifest without them",
            ))
        }
        // Never in a manifest: nothing for devices to change.
        (Some(LinkState::Pending), None) => None,
        (Some(LinkState::Pending), Some(_)) => {
            return Err(AppError::bad_request(
                "manifest_not_needed",
                "this ally was never approved, so the recipient manifest does not change",
            ))
        }
        (Some(LinkState::Removed) | None, _) => return Err(AppError::NotFound),
    };
    end_link(&mut tx, member, &ally, EndReason::RemovedByMember, now).await?;
    tx.commit().await?;
    tracing::info!(member = %member, ally = %ally, ?version, "ally removed by member");
    Ok(StatusCode::NO_CONTENT)
}

/// A member the caller supports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedMember {
    pub member_id: UserId,
    pub display_name: String,
    pub state: LinkState,
    pub created_at_ms: i64,
    pub activated_at_ms: Option<i64>,
    /// Safety-code inputs, as on the member side.
    pub member_sign_pubkey: Option<SignPublicKey>,
    pub ally_enc_pubkey: Option<EncPublicKey>,
    /// When the member's account will be deleted, if they asked for that
    /// (§12). Their items can be opened until then.
    pub deletion_purge_after_ms: Option<i64>,
}

/// `GET /v1/ally/members`
pub async fn list_my_members(
    State(state): State<AppState>,
    s: SessionUser,
) -> AppResult<Json<Vec<SupportedMember>>> {
    let rows = allies::list_for_ally(state.db().pool(), &s.user.id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|v| SupportedMember {
                member_id: v.member_id,
                display_name: v.other_display_name,
                state: v.state,
                created_at_ms: v.created_at_ms,
                activated_at_ms: v.activated_at_ms,
                member_sign_pubkey: v.member_sign_pubkey,
                ally_enc_pubkey: v.ally_enc_pubkey,
                deletion_purge_after_ms: v.other_deletion_purge_after_ms,
            })
            .collect(),
    ))
}

/// `DELETE /v1/ally/members/{member_id}`: the caller stops being an ally.
///
/// The ally cannot sign the member's manifest, so this ends the link alone
/// (module docs, "Leaving cannot update the manifest"): access stops now,
/// and the member is asked to sign a manifest without the ally.
pub async fn leave(
    State(state): State<AppState>,
    Path(member): Path<String>,
    s: SessionUser,
) -> AppResult<StatusCode> {
    let member = parse_user(member)?;
    let ally = &s.user.id;
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let prev = end_link(&mut tx, &member, ally, EndReason::Left, now).await?;
    tx.commit().await?;
    tracing::info!(member = %member, ally = %ally, "ally left");
    if prev == LinkState::Active {
        crate::notify::send_notice(
            &state,
            &member,
            format!("{} is no longer your ally", s.user.display_name),
            format!(
                "{} stopped being your ally on {}. They can no longer see anything on this \
                 server, but your devices keep encrypting new items to them until you open \
                 Faro and confirm your updated ally list.",
                s.user.display_name,
                state.config().instance.name
            ),
        );
    }
    Ok(StatusCode::NO_CONTENT)
}
