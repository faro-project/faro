//! Check-ins and replies: a group's feed (GROUPS.md §8.6, §16 "Phase C";
//! PROTOCOL.md §11).
//!
//! * `POST /v1/groups/{id}/posts` `{audience?, user_ids?, message}`: a
//!   check-in, or (when `message.kind` is `check_in_reply`) a private reply
//!   to one. `message` is a [`SealedGroupMessage`] signed with the author's
//!   member key. The audience is `allies` (the author's allies who are in
//!   this group, the default), `facilitators`, `people` (up to 32 named
//!   participants) or `group` (sealed with the group's current epoch key:
//!   one envelope, whatever the size). A whole-group post waits while a
//!   facilitator has roster work to do (`posting_paused`).
//! * `GET /v1/groups/{id}/posts?before=`: the feed the caller may read,
//!   newest first, 50 a page. Each post comes with its author's signing key
//!   for the browser to check it against.
//!
//! **A check-in never notifies anyone.** Nothing here touches the alert
//! pipeline: people see check-ins by opening the group (GROUPS.md §14).
//! Everyone who isn't an active participant gets `404`, as everywhere in
//! groups; someone who left or was removed gets nothing from the moment
//! they go, whatever a facilitator has signed (§10.5).

use super::reach_outs::MessageAuthor;
use super::ApiJson;
use crate::api::groups::{load, load_in_tx, require_writable};
use crate::auth::session::SessionUser;
use crate::db::repo::group_messages::Audience;
use crate::db::repo::group_posts::{
    self, NewPost, Post, PostKind, FEED_PAGE, MAX_CHECK_INS_PER_DAY, MAX_REPLIES_PER_DAY,
};
use crate::db::repo::{groups, is_unique_violation, member_keys};
use crate::error::{AppError, AppResult};
use crate::messages::{self, Expect};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use faro_proto::group::{GroupMessageKind, SealedGroupMessage};
use faro_proto::UserId;
use serde::{Deserialize, Serialize};

const DAY_MS: i64 = 24 * 3600 * 1000;

/// `POST /v1/groups/{id}/posts` body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePost {
    /// A check-in's audience (default `allies`). Ignored for a reply, which
    /// goes to the check-in's author alone.
    #[serde(default)]
    pub audience: Option<Audience>,
    #[serde(default)]
    pub user_ids: Vec<UserId>,
    pub message: SealedGroupMessage,
}

/// A post as served: the signed message and its encrypted body, for the
/// browser to verify and open.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostView {
    pub id: String,
    pub kind: GroupMessageKind,
    pub author: MessageAuthor,
    pub parent_id: Option<String>,
    /// Set for a whole-group post: the epoch whose key opens it.
    pub epoch: Option<u64>,
    pub created_at_ms: i64,
    #[serde(flatten)]
    pub sealed: SealedGroupMessage,
}

/// `GET /v1/groups/{id}/posts` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostPage {
    pub items: Vec<PostView>,
    /// Pass as `before` for the next page.
    pub next_cursor: Option<String>,
}

async fn view(conn: &mut sqlx::AnyConnection, p: Post) -> AppResult<PostView> {
    let sign_pubkey = member_keys::sign_pubkey(&mut *conn, &p.author_id).await?;
    Ok(PostView {
        id: p.id,
        kind: p.sealed.message.body.kind,
        author: MessageAuthor {
            user_id: p.author_id,
            display_name: p.author_name,
            sign_pubkey,
        },
        parent_id: p.parent_id,
        epoch: p.epoch,
        created_at_ms: p.created_at_ms,
        sealed: p.sealed,
    })
}

fn too_many() -> AppError {
    AppError::TooManyRequests {
        retry_after_secs: 3600,
    }
}

/// `POST /v1/groups/{id}/posts`
pub async fn create(
    State(state): State<AppState>,
    s: SessionUser,
    Path(gid): Path<String>,
    ApiJson(req): ApiJson<CreatePost>,
) -> AppResult<(StatusCode, Json<PostView>)> {
    s.require_not_being_deleted()?;
    let me = &s.user.id;
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    super::account::refuse_if_being_deleted(&mut *tx, me).await?;
    let (group, _) = load_in_tx(&mut tx, me, &gid).await?;
    require_writable(&state, &group)?;
    let m = &req.message.message.body;
    if m.group_id.as_deref() != Some(gid.as_str()) {
        return Err(AppError::bad_request(
            "invalid_message",
            "the message names another group",
        ));
    }
    let (kind, expect_kind, whole_group, allowed) = match m.kind {
        GroupMessageKind::CheckIn => {
            if group_posts::count_since(&mut *tx, me, PostKind::CheckIn, now - DAY_MS).await?
                >= MAX_CHECK_INS_PER_DAY
            {
                return Err(too_many());
            }
            let audience = req.audience.unwrap_or(Audience::Allies);
            let people = messages::resolve_check_in_audience(
                &mut tx,
                &state,
                me,
                audience,
                &gid,
                &req.user_ids,
            )
            .await?;
            (
                PostKind::CheckIn,
                GroupMessageKind::CheckIn,
                audience == Audience::Group,
                people,
            )
        }
        GroupMessageKind::CheckInReply => {
            let parent_id = m.parent_id.clone().ok_or_else(|| {
                AppError::bad_request("invalid_message", "a reply names its check-in")
            })?;
            let parent = group_posts::visible_by_id(&mut *tx, &gid, me, &parent_id)
                .await?
                .filter(|p| p.kind == PostKind::CheckIn)
                .ok_or(AppError::NotFound)?;
            if &parent.author_id == me {
                return Err(AppError::bad_request(
                    "cannot_reply_to_self",
                    "you can't reply to your own check-in",
                ));
            }
            // The author must still be in the group to be written to.
            if groups::active_participant(&mut *tx, &gid, &parent.author_id)
                .await?
                .is_none()
            {
                return Err(AppError::NotFound);
            }
            if group_posts::has_reply(&mut *tx, me, &parent_id).await? {
                return Err(AppError::conflict(
                    "already_replied",
                    "you already replied to this check-in",
                ));
            }
            if group_posts::count_since(&mut *tx, me, PostKind::Reply, now - DAY_MS).await?
                >= MAX_REPLIES_PER_DAY
            {
                return Err(too_many());
            }
            (
                PostKind::Reply,
                GroupMessageKind::CheckInReply,
                false,
                vec![parent.author_id],
            )
        }
        _ => {
            return Err(AppError::bad_request(
                "invalid_message",
                "expected a check-in or a reply",
            ))
        }
    };
    messages::check_message(
        &mut tx,
        &state,
        me,
        &req.message,
        &Expect {
            kind: expect_kind,
            group_id: Some(&gid),
            allowed: &allowed,
            whole_group,
        },
    )
    .await?;
    let post = NewPost {
        group_id: &gid,
        kind,
        sealed: &req.message,
        now_ms: now,
    };
    match group_posts::insert(&mut tx, &post).await {
        Ok(()) => {}
        Err(e) if is_unique_violation(&e) => {
            return Err(AppError::conflict(
                "message_exists",
                "a post with this id already exists",
            ))
        }
        Err(e) => return Err(e.into()),
    }
    let stored = group_posts::visible_by_id(&mut *tx, &gid, me, &req.message.message.body.item_id)
        .await?
        .ok_or_else(|| AppError::internal("post vanished"))?;
    let out = view(&mut tx, stored).await?;
    tx.commit().await?;
    tracing::info!(kind = kind.as_str(), whole_group, "post created");
    Ok((StatusCode::CREATED, Json(out)))
}

#[derive(Debug, Deserialize)]
pub struct FeedQuery {
    /// `<created_at_ms>:<id>` of the last post of the previous page.
    pub before: Option<String>,
}

fn parse_cursor(s: &str) -> AppResult<(i64, String)> {
    s.split_once(':')
        .and_then(|(at, id)| Some((at.parse::<i64>().ok()?, id.to_owned())))
        .filter(|(_, id)| faro_proto::group::is_hex_id(id))
        .ok_or_else(|| AppError::bad_request("invalid_cursor", "that page marker isn't valid"))
}

/// `GET /v1/groups/{id}/posts`
pub async fn feed(
    State(state): State<AppState>,
    s: SessionUser,
    Path(gid): Path<String>,
    Query(q): Query<FeedQuery>,
) -> AppResult<Json<PostPage>> {
    load(&state, &s, &gid).await?;
    let me = &s.user.id;
    let before = q.before.as_deref().map(parse_cursor).transpose()?;
    let mut conn = state.db().pool().acquire().await?;
    let rows = group_posts::feed(
        &mut *conn,
        &gid,
        me,
        before.as_ref().map(|(at, id)| (*at, id.as_str())),
        FEED_PAGE + 1,
    )
    .await?;
    let more = rows.len() as i64 > FEED_PAGE;
    let mut items = Vec::new();
    for p in rows.into_iter().take(FEED_PAGE as usize) {
        items.push(view(&mut conn, p).await?);
    }
    let next_cursor = more
        .then(|| {
            items
                .last()
                .map(|p| format!("{}:{}", p.created_at_ms, p.id))
        })
        .flatten();
    Ok(Json(PostPage { items, next_cursor }))
}
