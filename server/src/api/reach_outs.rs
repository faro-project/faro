//! Reach out, signed messages and the reach-out settings (GROUPS.md §8.3,
//! §10.2, §16). The rules are in [`crate::messages`].
//!
//! * `GET /v1/me/message-recipients?for=&audience=&group_id=&user_ids=`:
//!   who a message would go to, with the key to seal to for each.
//! * `POST /v1/me/reach-outs` `{audience, group_id?, user_ids?, message?}`:
//!   reach out. `message` is a [`SealedGroupMessage`] signed with the
//!   sender's member key; without it the reach out is content-free and
//!   can't be verified (the only kind an ally-only sender can send).
//! * `GET /v1/me/reach-outs`: reach outs to and from the caller, with
//!   answers. A recipient sees how many others answered, not who; the
//!   sender sees who answered.
//! * `POST /v1/reach-outs/{id}/answer` `{answer: "call" | "here"}`.
//! * `GET /v1/group-messages/{id}`: a message, for its author and its
//!   recipients only (a join-request note: while they facilitate the
//!   group; a whole-group reach out: anyone in the group now who was in it
//!   when it was sent), with the author's signing key for the browser to
//!   check it against.
//! * `GET /v1/me/reach-out-settings`, `PUT|DELETE
//!   /v1/me/quiet-hours-bypass/{user_id}` ("let *Sam*'s reach outs through
//!   quiet hours") and `PUT /v1/me/reach-out-prefs/{user_id}` `{mode}`
//!   (move someone's reach outs to the digest, or switch them off).
//!
//! Everything someone can't see is `404`.

use super::ApiJson;
use crate::auth::session::SessionUser;
use crate::db::repo::group_messages::{self, Answer, Audience, ReachOut, SenderSetting};
use crate::db::repo::group_roster;
use crate::db::repo::groups::{self, Role};
use crate::db::repo::{member_keys, users};
use crate::error::{AppError, AppResult};
use crate::messages::{self, RecipientKey};
use crate::notify::policy::Mode;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use faro_proto::group::{GroupMessageKind, SealedGroupMessage};
use faro_proto::{InstanceId, SignPublicKey, UserId};
use serde::{Deserialize, Serialize};

fn parse_user(id: &str) -> AppResult<UserId> {
    let id = UserId::new(id);
    if id.is_well_formed() {
        Ok(id)
    } else {
        Err(AppError::NotFound)
    }
}

// ---- Recipients ------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RecipientsQuery {
    /// `reach_out` (default), `proposal_note`, `join_request_note`,
    /// `check_in` or `check_in_reply`.
    #[serde(rename = "for")]
    pub for_kind: Option<String>,
    /// Reach outs and check-ins: `allies` (default), `facilitators`,
    /// `people` or `group`.
    pub audience: Option<String>,
    pub group_id: Option<String>,
    /// Comma-separated user ids (`people`, and a proposal note's recipient).
    pub user_ids: Option<String>,
}

/// `GET /v1/me/message-recipients` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipients {
    pub instance_id: InstanceId,
    pub recipients: Vec<RecipientKey>,
    /// The caller has member keys, so can sign a message.
    pub can_sign: bool,
}

fn split_ids(s: &Option<String>) -> Vec<UserId> {
    s.as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(UserId::new)
        .collect()
}

fn parse_audience(s: Option<&str>) -> AppResult<Audience> {
    match s {
        None => Ok(Audience::Allies),
        Some(a) => Audience::parse(a).ok_or_else(|| {
            AppError::bad_request(
                "invalid_audience",
                "audience is allies, facilitators, people or group",
            )
        }),
    }
}

/// `GET /v1/me/message-recipients`
pub async fn recipients(
    State(state): State<AppState>,
    s: SessionUser,
    Query(q): Query<RecipientsQuery>,
) -> AppResult<Json<Recipients>> {
    let me = &s.user.id;
    let kind = match q.for_kind.as_deref() {
        None => GroupMessageKind::ReachOut,
        Some(k) => GroupMessageKind::parse(k).ok_or_else(|| {
            AppError::bad_request(
                "invalid_kind",
                "for is reach_out, proposal_note, join_request_note, check_in or check_in_reply",
            )
        })?,
    };
    let named = split_ids(&q.user_ids);
    let gid = q.group_id.as_deref();
    let mut tx = state.db().begin_write().await?;
    let people = match kind {
        GroupMessageKind::ReachOut => {
            let audience = parse_audience(q.audience.as_deref())?;
            messages::resolve_audience(&mut tx, &state, me, audience, gid, &named).await?
        }
        GroupMessageKind::ProposalNote => {
            if named.len() != 1 || gid.is_none() {
                return Err(AppError::bad_request(
                    "invalid_recipients",
                    "a proposal note names its group and one person",
                ));
            }
            messages::resolve_audience(&mut tx, &state, me, Audience::People, gid, &named).await?
        }
        GroupMessageKind::JoinRequestNote => {
            let gid = gid.ok_or(AppError::NotFound)?;
            super::group_listing::note_recipients(&state, &mut tx, gid).await?
        }
        GroupMessageKind::CheckIn => {
            let gid = gid.ok_or(AppError::NotFound)?;
            let audience = parse_audience(q.audience.as_deref())?;
            messages::resolve_check_in_audience(&mut tx, &state, me, audience, gid, &named).await?
        }
        GroupMessageKind::CheckInReply => {
            if named.len() != 1 || gid.is_none() {
                return Err(AppError::bad_request(
                    "invalid_recipients",
                    "a reply names its group and the check-in's author",
                ));
            }
            messages::resolve_audience(&mut tx, &state, me, Audience::People, gid, &named).await?
        }
    };
    let recipients = messages::recipient_keys(&mut tx, me, &people).await?;
    let can_sign = member_keys::sign_pubkey(&mut *tx, me).await?.is_some();
    tx.commit().await?;
    Ok(Json(Recipients {
        instance_id: state.instance_id().clone(),
        recipients,
        can_sign,
    }))
}

// ---- Reach outs ------------------------------------------------------------------

/// `POST /v1/me/reach-outs` body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateReachOut {
    #[serde(default)]
    pub audience: Option<Audience>,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub user_ids: Vec<UserId>,
    /// Signed with the sender's member key. Left out: content-free and
    /// unverifiable.
    #[serde(default)]
    pub message: Option<SealedGroupMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersonRef {
    pub user_id: UserId,
    pub display_name: String,
}

/// How many recipients other than the caller gave each answer.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnswerCounts {
    pub call: u32,
    pub here: u32,
}

/// A reach out to the caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingReachOut {
    pub id: String,
    pub from: PersonRef,
    pub group_id: Option<String>,
    /// While the caller is in the group.
    pub group_name: Option<String>,
    pub audience: Audience,
    pub created_at_ms: i64,
    /// It carries a signed message (`message_id`). `false`: "Sent through
    /// the server. Can't be verified."
    pub signed: bool,
    pub message_id: Option<String>,
    pub my_answer: Option<Answer>,
    pub my_answered_at_ms: Option<i64>,
    /// So five people don't all call at once.
    pub others_answered: AnswerCounts,
    /// The caller lets this person's reach outs through quiet hours.
    pub quiet_hours_bypass: bool,
}

/// Someone a reach out went to, as its sender sees them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachOutRecipient {
    pub user_id: UserId,
    pub display_name: String,
    pub answer: Option<Answer>,
    pub answered_at_ms: Option<i64>,
}

/// A reach out the caller sent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutgoingReachOut {
    pub id: String,
    pub group_id: Option<String>,
    pub group_name: Option<String>,
    pub audience: Audience,
    pub created_at_ms: i64,
    pub signed: bool,
    pub message_id: Option<String>,
    pub recipients: Vec<ReachOutRecipient>,
}

/// `GET /v1/me/reach-outs` response, newest first on each side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MyReachOuts {
    pub incoming: Vec<IncomingReachOut>,
    pub outgoing: Vec<OutgoingReachOut>,
}

async fn incoming_view(
    conn: &mut sqlx::AnyConnection,
    me: &UserId,
    o: ReachOut,
) -> AppResult<IncomingReachOut> {
    let rs = group_messages::recipients_of(&mut *conn, &o.id).await?;
    let mine = rs.iter().find(|r| &r.user_id == me);
    let mut others = AnswerCounts::default();
    for r in rs.iter().filter(|r| &r.user_id != me) {
        match r.answer {
            Some(Answer::Call) => others.call += 1,
            Some(Answer::Here) => others.here += 1,
            None => {}
        }
    }
    let quiet_hours_bypass = group_messages::has_bypass(&mut *conn, me, &o.sender_id).await?;
    Ok(IncomingReachOut {
        my_answer: mine.and_then(|r| r.answer),
        my_answered_at_ms: mine.and_then(|r| r.answered_at_ms),
        others_answered: others,
        quiet_hours_bypass,
        id: o.id,
        from: PersonRef {
            user_id: o.sender_id,
            display_name: o.sender_name,
        },
        group_id: o.group_id,
        group_name: o.group_name,
        audience: o.audience,
        created_at_ms: o.created_at_ms,
        signed: o.signed,
        message_id: o.message_id,
    })
}

async fn outgoing_view(conn: &mut sqlx::AnyConnection, o: ReachOut) -> AppResult<OutgoingReachOut> {
    let recipients = group_messages::recipients_of(&mut *conn, &o.id)
        .await?
        .into_iter()
        .map(|r| ReachOutRecipient {
            user_id: r.user_id,
            display_name: r.display_name,
            answer: r.answer,
            answered_at_ms: r.answered_at_ms,
        })
        .collect();
    Ok(OutgoingReachOut {
        id: o.id,
        group_id: o.group_id,
        group_name: o.group_name,
        audience: o.audience,
        created_at_ms: o.created_at_ms,
        signed: o.signed,
        message_id: o.message_id,
        recipients,
    })
}

/// `POST /v1/me/reach-outs`
pub async fn create(
    State(state): State<AppState>,
    s: SessionUser,
    ApiJson(req): ApiJson<CreateReachOut>,
) -> AppResult<(StatusCode, Json<OutgoingReachOut>)> {
    s.require_not_being_deleted()?;
    let me = &s.user.id;
    let audience = req.audience.unwrap_or(Audience::Allies);
    let gid = req.group_id.as_deref();
    let mut tx = state.db().begin_write().await?;
    super::account::refuse_if_being_deleted(&mut *tx, me).await?;
    let people =
        messages::resolve_audience(&mut tx, &state, me, audience, gid, &req.user_ids).await?;
    let id = messages::send_reach_out(
        &mut tx,
        &state,
        me,
        audience,
        gid,
        &people,
        req.message.as_ref(),
    )
    .await?;
    let row = group_messages::reach_out_by_id(&mut *tx, &id, me)
        .await?
        .ok_or_else(|| AppError::internal("reach out vanished"))?;
    let view = outgoing_view(&mut tx, row).await?;
    tx.commit().await?;
    tracing::info!(
        audience = audience.as_str(),
        recipients = people.len(),
        signed = view.signed,
        "reach out sent"
    );
    Ok((StatusCode::CREATED, Json(view)))
}

/// `GET /v1/me/reach-outs`
pub async fn list_mine(
    State(state): State<AppState>,
    s: SessionUser,
) -> AppResult<Json<MyReachOuts>> {
    let me = &s.user.id;
    let mut conn = state.db().pool().acquire().await?;
    let mut incoming = Vec::new();
    for o in group_messages::incoming(&mut *conn, me).await? {
        incoming.push(incoming_view(&mut conn, me, o).await?);
    }
    let mut outgoing = Vec::new();
    for o in group_messages::outgoing(&mut *conn, me).await? {
        outgoing.push(outgoing_view(&mut conn, o).await?);
    }
    Ok(Json(MyReachOuts { incoming, outgoing }))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerReachOut {
    pub answer: Answer,
}

/// `POST /v1/reach-outs/{id}/answer`: "I'll call" or "I'm here". The
/// sender is told who answered, once; answering again changes the answer
/// quietly.
pub async fn answer(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<AnswerReachOut>,
) -> AppResult<Json<IncomingReachOut>> {
    let me = &s.user.id;
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let row = group_messages::reach_out_by_id(&mut *tx, &id, me)
        .await?
        .ok_or(AppError::NotFound)?;
    let first = group_messages::answer(&mut tx, &id, me, req.answer, now)
        .await?
        .ok_or(AppError::NotFound)?;
    if first {
        crate::groups::tell_reach_out_answered(&mut tx, &id, &row.sender_id, me, now).await?;
    }
    let view = incoming_view(&mut tx, me, row).await?;
    tx.commit().await?;
    Ok(Json(view))
}

// ---- Messages ----------------------------------------------------------------------

/// The author of a message, with the key to check it against.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageAuthor {
    pub user_id: UserId,
    pub display_name: String,
    /// Their member signing key, as the instance holds it. The browser
    /// trusts it only as far as it can check it (an ally compared it in
    /// person through the safety code); otherwise it is "not yet verified".
    pub sign_pubkey: Option<SignPublicKey>,
}

/// `GET /v1/group-messages/{id}` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageView {
    pub id: String,
    pub kind: GroupMessageKind,
    pub author: MessageAuthor,
    pub created_at_ms: i64,
    #[serde(flatten)]
    pub sealed: SealedGroupMessage,
}

/// `GET /v1/group-messages/{id}`: for its author and signed recipients
/// only. A note on a proposal hidden from its recipient is the author's
/// alone (decline privacy, principle 5).
pub async fn get_message(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
) -> AppResult<Json<MessageView>> {
    let me = &s.user.id;
    let mut conn = state.db().pool().acquire().await?;
    let m = group_messages::message_by_id(&mut *conn, &id)
        .await?
        .ok_or(AppError::NotFound)?;
    if &m.author_id != me {
        let allowed = match (m.sealed.message.body.epoch, m.group_id.as_deref()) {
            // Sealed with a group's epoch key: whoever is in the group now
            // and was when it was sent.
            (Some(_), Some(g)) => {
                group_roster::may_read_item(&mut *conn, g, me, m.created_at_ms).await?
            }
            (Some(_), None) => false,
            (None, _) => group_messages::is_recipient(&mut *conn, &id, me).await?,
        };
        if !allowed {
            return Err(AppError::NotFound);
        }
        if m.kind == GroupMessageKind::ProposalNote
            && group_messages::is_on_hidden_proposal(&mut *conn, &id).await?
        {
            return Err(AppError::NotFound);
        } // A join-request note is for the group's facilitators: someone who
          // has stopped being one can't read it any more.
        if m.kind == GroupMessageKind::JoinRequestNote {
            let facilitator = match m.group_id.as_deref() {
                Some(g) => groups::active_participant(&mut *conn, g, me)
                    .await?
                    .is_some_and(|p| p.role == Role::Facilitator),
                None => false,
            };
            if !facilitator {
                return Err(AppError::NotFound);
            }
        }
    }
    let author = users::by_id(&mut *conn, &m.author_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let sign_pubkey = member_keys::sign_pubkey(&mut *conn, &m.author_id).await?;
    Ok(Json(MessageView {
        id: m.id,
        kind: m.kind,
        author: MessageAuthor {
            user_id: m.author_id,
            display_name: author.display_name,
            sign_pubkey,
        },
        created_at_ms: m.created_at_ms,
        sealed: m.sealed,
    }))
}

// ---- Settings ----------------------------------------------------------------------

/// `GET /v1/me/reach-out-settings`: everyone the caller changed a
/// reach-out setting for.
pub async fn settings(
    State(state): State<AppState>,
    s: SessionUser,
) -> AppResult<Json<Vec<SenderSetting>>> {
    Ok(Json(
        group_messages::settings_of(state.db().pool(), &s.user.id).await?,
    ))
}

async fn other_user(state: &AppState, me: &UserId, id: &str) -> AppResult<UserId> {
    let other = parse_user(id)?;
    if &other == me {
        return Err(AppError::bad_request(
            "cannot_set_for_self",
            "this setting is about other people",
        ));
    }
    if users::by_id(state.db().pool(), &other).await?.is_none() {
        return Err(AppError::NotFound);
    }
    Ok(other)
}

/// `PUT /v1/me/quiet-hours-bypass/{user_id}`: let this person's reach outs
/// through the caller's quiet hours. Idempotent.
pub async fn put_bypass(
    State(state): State<AppState>,
    s: SessionUser,
    Path(user): Path<String>,
) -> AppResult<StatusCode> {
    let other = other_user(&state, &s.user.id, &user).await?;
    group_messages::set_bypass(state.db().pool(), &s.user.id, &other, true, state.now_ms()).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/me/quiet-hours-bypass/{user_id}`. Idempotent.
pub async fn delete_bypass(
    State(state): State<AppState>,
    s: SessionUser,
    Path(user): Path<String>,
) -> AppResult<StatusCode> {
    let other = parse_user(&user)?;
    group_messages::set_bypass(state.db().pool(), &s.user.id, &other, false, state.now_ms())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutReachOutPrefs {
    /// `immediate` (the default), `digest` or `off`.
    pub mode: Mode,
}

/// `PUT /v1/me/reach-out-prefs/{user_id}`: how the caller hears about this
/// person's reach outs. Reach outs aren't tamper-class, so `off` holds
/// (they still show in Faro).
pub async fn put_prefs(
    State(state): State<AppState>,
    s: SessionUser,
    Path(user): Path<String>,
    ApiJson(req): ApiJson<PutReachOutPrefs>,
) -> AppResult<StatusCode> {
    let other = other_user(&state, &s.user.id, &user).await?;
    let mode = (req.mode != Mode::Immediate).then_some(req.mode);
    group_messages::set_mode(state.db().pool(), &s.user.id, &other, mode).await?;
    Ok(StatusCode::NO_CONTENT)
}
