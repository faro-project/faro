//! Opt-in sharing with a group and pairing suggestions (docs/GROUPS.md
//! §8.2, §8.5).
//!
//! * `PUT /v1/groups/{id}/me/sharing` `{share_status, share_allies}`: what
//!   the caller shows the group. Off by default. Turning one off hides it
//!   at once and **tells nobody**; the dot reads *not shared*, as if it had
//!   never been on (decision 5).
//! * The roster's `status` (see [`fill_statuses`]) and
//!   `GET /v1/groups/{id}/participants/{user_id}/allies` show only what a
//!   person chose to share, and only about that one person.
//! * `POST /v1/groups/{id}/suggestions`, `GET .../suggestions` and
//!   `DELETE .../suggestions/{id}`: facilitators post, see and withdraw
//!   pairing suggestions. `GET /v1/groups/{id}/me/suggestions` and
//!   `POST /v1/groups/{id}/me/suggestions/{id}/dismiss`: each person's own
//!   cards.
//!
//! **No aggregates.** Nothing here (and no admin route) reports how many
//! participants share, or have not shared, anything: a facilitator sees a
//! person's dot or allies only if that person chose to show them to the
//! whole group, and a person who didn't looks exactly like one who never
//! did (no "12 of 30 shared" anywhere).
//!
//! **A suggestion is not a proposal** (principle 3). Posting one writes only
//! to `pairing_suggestions`: no proposal, no link, no notification. A
//! person sends a proposal (or doesn't) through the ordinary proposal
//! route, and which of the two did is nobody else's business: no facilitator
//! route returns dismissals or outcomes, and reposting an existing pair
//! looks the same whatever happened to it.

use super::groups::{load, load_in_tx, require_facilitator, require_writable};
use super::ApiJson;
use crate::auth::session::SessionUser;
use crate::db::repo::group_sharing::{self, Card, PostedSuggestion, SharedAlly, StatusDot};
use crate::db::repo::groups::{self, RosterEntry};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use faro_proto::UserId;
use serde::{Deserialize, Serialize};

/// Pairs in one request ("a pasted list for large groups").
pub const MAX_PAIRS_PER_REQUEST: usize = 200;

// ---- Sharing -------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharingChoice {
    pub share_status: bool,
    pub share_allies: bool,
}

#[derive(Debug, Serialize)]
pub struct SharingView {
    pub share_status: bool,
    pub share_allies: bool,
    /// People in the group, so the choice shows who would see it.
    pub audience: i64,
}

/// `PUT /v1/groups/{id}/me/sharing`. Nobody is told, whichever way it goes.
pub async fn set_sharing(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<SharingChoice>,
) -> AppResult<Json<SharingView>> {
    let (group, _) = load(&state, &s, &id).await?;
    require_writable(&state, &group)?;
    let pool = state.db().pool();
    if !group_sharing::set_sharing(pool, &id, &s.user.id, req.share_status, req.share_allies)
        .await?
    {
        return Err(AppError::NotFound);
    }
    Ok(Json(SharingView {
        share_status: req.share_status,
        share_allies: req.share_allies,
        audience: groups::count_active(pool, &id).await?,
    }))
}

/// Add each roster entry's dot: the real one for people who chose to show
/// it, `not_shared` for everyone else.
pub(crate) async fn fill_statuses(
    state: &AppState,
    group: &str,
    items: &mut [RosterEntry],
) -> AppResult<()> {
    let grace_ms = i64::try_from(state.settings().liveness.grace_secs)
        .unwrap_or(i64::MAX / 1000)
        .saturating_mul(1000);
    let ids: Vec<UserId> = items.iter().map(|e| e.user_id.clone()).collect();
    let mut dots =
        group_sharing::statuses(state.db().pool(), group, &ids, state.now_ms(), grace_ms).await?;
    for e in items {
        e.status = Some(dots.remove(&e.user_id).unwrap_or(StatusDot::NotShared));
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct SharedAllies {
    /// False when the person doesn't show their allies to the group.
    pub shared: bool,
    pub allies: Vec<SharedAlly>,
}

/// `GET /v1/groups/{id}/participants/{user_id}/allies`: the person's allies
/// in this group, if they chose to show them. Only links where both people
/// are active participants.
pub async fn shared_allies(
    State(state): State<AppState>,
    s: SessionUser,
    Path((id, user_id)): Path<(String, String)>,
) -> AppResult<Json<SharedAllies>> {
    load(&state, &s, &id).await?;
    let target = UserId::new(user_id);
    let pool = state.db().pool();
    match group_sharing::shares_allies(pool, &id, &target).await? {
        None => Err(AppError::NotFound),
        Some(false) => Ok(Json(SharedAllies {
            shared: false,
            allies: Vec::new(),
        })),
        Some(true) => Ok(Json(SharedAllies {
            shared: true,
            allies: group_sharing::shared_allies(pool, &id, &target).await?,
        })),
    }
}

// ---- Suggestions ---------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pair {
    pub a: UserId,
    pub b: UserId,
}

#[derive(Debug, Serialize)]
pub struct Suggested {
    pub posted: usize,
}

/// `POST /v1/groups/{id}/suggestions` `[{a, b}]`: a facilitator posts
/// pairings, one or a whole list. Repeats are ignored. Nobody is notified
/// and nothing else is created.
pub async fn suggest(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
    ApiJson(pairs): ApiJson<Vec<Pair>>,
) -> AppResult<(StatusCode, Json<Suggested>)> {
    if pairs.is_empty() || pairs.len() > MAX_PAIRS_PER_REQUEST {
        return Err(AppError::bad_request(
            "invalid_pairs",
            format!("send between 1 and {MAX_PAIRS_PER_REQUEST} pairs at once"),
        ));
    }
    if pairs.iter().any(|p| p.a == p.b) {
        return Err(AppError::bad_request(
            "invalid_pairs",
            "a pairing needs two different people",
        ));
    }
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let (group, me) = load_in_tx(&mut tx, &s.user.id, &id).await?;
    require_facilitator(&me)?;
    require_writable(&state, &group)?;
    let mut wanted: Vec<&UserId> = pairs.iter().flat_map(|p| [&p.a, &p.b]).collect();
    wanted.sort();
    wanted.dedup();
    let active = group_sharing::active_among(&mut *tx, &id, &wanted).await?;
    if active.len() != wanted.len() {
        return Err(AppError::bad_request(
            "not_a_participant",
            "everyone in a pairing must be in this group",
        ));
    }
    let mut posted = 0;
    for p in &pairs {
        if group_sharing::add_suggestion(&mut *tx, &id, &s.user.id, &p.a, &p.b, now).await? {
            posted += 1;
        }
    }
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(Suggested { posted })))
}

/// `GET /v1/groups/{id}/suggestions`: facilitators see what they posted:
/// the pair and when. Never whether anyone dismissed or acted on it.
pub async fn posted(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<PostedSuggestion>>> {
    let (_, me) = load(&state, &s, &id).await?;
    require_facilitator(&me)?;
    Ok(Json(group_sharing::posted(state.db().pool(), &id).await?))
}

/// `DELETE /v1/groups/{id}/suggestions/{suggestion_id}`: withdraw one.
pub async fn withdraw(
    State(state): State<AppState>,
    s: SessionUser,
    Path((id, suggestion_id)): Path<(String, String)>,
) -> AppResult<StatusCode> {
    let (group, me) = load(&state, &s, &id).await?;
    require_facilitator(&me)?;
    require_writable(&state, &group)?;
    if group_sharing::delete_suggestion(state.db().pool(), &id, &suggestion_id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}

/// `GET /v1/groups/{id}/me/suggestions`: the caller's own cards, nobody
/// else's, whatever their role.
pub async fn my_cards(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<Card>>> {
    load(&state, &s, &id).await?;
    Ok(Json(
        group_sharing::my_cards(state.db().pool(), &id, &s.user.id).await?,
    ))
}

/// `POST /v1/groups/{id}/me/suggestions/{suggestion_id}/dismiss`: hide the
/// caller's card (also what the client calls once they have sent a
/// proposal from it). Only their own side changes.
pub async fn dismiss(
    State(state): State<AppState>,
    s: SessionUser,
    Path((id, suggestion_id)): Path<(String, String)>,
) -> AppResult<StatusCode> {
    load(&state, &s, &id).await?;
    if group_sharing::dismiss(state.db().pool(), &id, &suggestion_id, &s.user.id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}
