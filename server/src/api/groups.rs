//! Groups (docs/GROUPS.md): create, roster, history, details, invitations,
//! leaving, removing and the facilitator role.
//!
//! **Authorization** is checked on every route against the caller's *active*
//! row in `group_participants` ([`load`]). Anyone else (an ex-participant, a
//! stranger, an admin who isn't in the group) gets `404`, never `403`, so
//! group ids can't be probed. A participant who lacks the role for an action
//! gets `403 not_a_facilitator`. Admins see groups only as metadata, through
//! `/admin/api/groups` ([`super::admin`]).
//!
//! **Read-only.** An archived group, and every group while the admin has
//! groups switched off, refuses changes with `409` (`group_archived`,
//! `groups_disabled`) but can still be read.
//!
//! **Invitations** work like ally invitations ([`super::invites`]): a
//! 256-bit token stored hashed, 7 days, single use, bound to one address or
//! one user, so a forwarded link is useless to anyone else. The email says
//! "*Sam* invited you to join a group on *instance*" and never names the
//! group; the name is shown after sign-in ([`get_invite`]). Under
//! `invite-only` registration a live group invite lets its address sign up,
//! unless the admin turned that off ([`super::auth`]).
//!
//! **Nothing here touches `ally_links`.** Leaving or being removed never
//! ends an alliance (GROUPS.md principle 4).

use super::group_listing::{
    my_reminders, require_may_list, Listing, ListingInput, MyMeetingReminders,
};
use super::ApiJson;
use crate::auth::normalize_email;
use crate::auth::session::SessionUser;
use crate::db::repo::group_listing;
use crate::db::repo::group_notices::NoticeKind;
use crate::db::repo::groups::{
    self, Ended, Group, GroupUpdate, HistoryEntry, HistoryKind, Invite, InviteForMe, InviteStatus,
    JoinedVia, Page, Participant, Person, Role, RosterEntry, MAX_FACILITATORS,
};
use crate::db::repo::{is_unique_violation, users};
use crate::error::{AppError, AppResult};
use crate::mailer::Email;
use crate::meetings::{self, Meeting, MeetingInput};
use crate::settings::{GroupSettings, WhoCanCreateGroups, WhoCanInvite};
use crate::state::AppState;
use crate::tokens::{is_token_shaped, new_token, TokenPurpose};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use faro_proto::UserId;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashSet;

/// Invitations expire after 7 days (as ally invitations do).
pub const INVITE_TTL_MS: i64 = 7 * 24 * 3600 * 1000;
/// Addresses and users in one invitation request.
pub const MAX_INVITES_PER_REQUEST: usize = 50;
/// Open invitations one group may have out at once.
pub const MAX_LIVE_INVITES_PER_GROUP: i64 = 200;
const MAX_NAME_CHARS: usize = 100;
const MAX_DESCRIPTION_CHARS: usize = 1000;
/// Participant limits facilitators may set.
const MAX_PARTICIPANT_LIMIT: i64 = 100_000;
/// Invitations listed per request.
const INVITE_LIST_LIMIT: i64 = 200;

// ---- Shared helpers ----------------------------------------------------------

pub(crate) fn group_settings(state: &AppState) -> GroupSettings {
    state.settings().groups
}

/// The caller's group, or `404`. See the module docs.
pub(crate) async fn load(
    state: &AppState,
    s: &SessionUser,
    id: &str,
) -> AppResult<(Group, Participant)> {
    load_in(state.db().pool(), &s.user.id, id).await
}

async fn load_in<'e>(
    e: impl sqlx::Executor<'e, Database = sqlx::Any> + Copy,
    user: &UserId,
    id: &str,
) -> AppResult<(Group, Participant)> {
    let me = groups::active_participant(e, id, user)
        .await?
        .ok_or(AppError::NotFound)?;
    let group = groups::by_id(e, id).await?.ok_or(AppError::NotFound)?;
    Ok((group, me))
}

pub(crate) fn require_facilitator(me: &Participant) -> AppResult<()> {
    if me.role == Role::Facilitator {
        Ok(())
    } else {
        Err(AppError::Forbidden("not_a_facilitator"))
    }
}

/// Changes are refused on an archived group and while groups are off.
pub(crate) fn require_writable(state: &AppState, group: &Group) -> AppResult<()> {
    if group.is_archived() {
        return Err(AppError::conflict(
            "group_archived",
            "this group was closed and can only be read",
        ));
    }
    require_enabled(state)
}

pub(crate) fn require_enabled(state: &AppState) -> AppResult<()> {
    if group_settings(state).enabled {
        Ok(())
    } else {
        Err(AppError::conflict(
            "groups_disabled",
            "groups are switched off on this instance",
        ))
    }
}

/// Who may invite into `group`: the instance's setting, narrowed (never
/// widened) by the group's own.
pub fn effective_who_can_invite(settings: &GroupSettings, group: &Group) -> WhoCanInvite {
    settings
        .who_can_invite
        .narrowest(group.who_can_invite.unwrap_or(settings.who_can_invite))
}

fn can_invite(settings: &GroupSettings, group: &Group, me: &Participant) -> bool {
    me.role == Role::Facilitator
        || effective_who_can_invite(settings, group) == WhoCanInvite::Participants
}

pub(crate) fn parse_json_field(raw: &Option<String>) -> Option<serde_json::Value> {
    raw.as_deref().and_then(|s| serde_json::from_str(s).ok())
}

fn validate_name(raw: &str) -> AppResult<String> {
    let n = raw.trim();
    if n.is_empty() || n.chars().count() > MAX_NAME_CHARS || n.chars().any(char::is_control) {
        return Err(AppError::bad_request(
            "invalid_name",
            format!("a group's name is 1 to {MAX_NAME_CHARS} characters"),
        ));
    }
    Ok(n.to_owned())
}

fn validate_description(raw: &str) -> AppResult<String> {
    let d = raw.trim();
    if d.chars().count() > MAX_DESCRIPTION_CHARS
        || d.chars().any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(AppError::bad_request(
            "invalid_description",
            format!("a group's description is at most {MAX_DESCRIPTION_CHARS} characters"),
        ));
    }
    Ok(d.to_owned())
}

fn double_option<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

// ---- Views -------------------------------------------------------------------

/// A group as a participant sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupView {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_at_ms: i64,
    pub my_role: Role,
    pub participant_count: i64,
    pub facilitators: Vec<Person>,
    /// Who may invite, after the instance's setting.
    pub who_can_invite: WhoCanInvite,
    /// What the group's facilitators chose, before the instance's limit;
    /// `null` until they choose (then the instance's setting applies).
    pub group_who_can_invite: Option<WhoCanInvite>,
    /// The instance's setting: `facilitators` means "any participant" can't
    /// be chosen for this group.
    pub instance_who_can_invite: WhoCanInvite,
    /// Whether the caller may invite right now.
    pub can_invite: bool,
    pub max_participants: Option<i64>,
    /// `{cadence, weekday, minute_of_day, tz_offset_min, place?, anchor_ms}`.
    pub meeting: Option<serde_json::Value>,
    /// The start of the next meeting (Unix ms), if there is a schedule.
    pub next_meeting_at_ms: Option<i64>,
    /// The caller's own reminder choices for this group.
    pub my_meeting_reminders: MyMeetingReminders,
    pub listed: bool,
    /// `{show_meeting_time, show_place}`; `null` until first set.
    pub listing: Option<serde_json::Value>,
    pub archived_at_ms: Option<i64>,
    /// When an archived group is deleted.
    pub delete_after_ms: Option<i64>,
    /// No facilitator: nobody can invite, remove or edit.
    pub no_facilitator: bool,
    /// The caller is offered the facilitator role until this time (the last
    /// facilitator's account was deleted).
    pub facilitator_offer_until_ms: Option<i64>,
    /// Groups are switched off on this instance: read-only.
    pub groups_disabled: bool,
    /// What the caller shows this group (§8.2). Only their own choices:
    /// nobody is ever told how many others have shared anything.
    pub my_sharing: MySharing,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MySharing {
    pub share_status: bool,
    pub share_allies: bool,
}

pub(crate) async fn view(
    state: &AppState,
    group: &Group,
    me: &Participant,
) -> AppResult<GroupView> {
    let pool = state.db().pool();
    let settings = group_settings(state);
    let facilitators = groups::facilitators(pool, &group.id).await?;
    let participant_count = groups::count_active(pool, &group.id).await?;
    let offer = (group.facilitator_offer_user.as_ref() == Some(&me.user_id))
        .then_some(group.facilitator_offer_until_ms)
        .flatten()
        .filter(|until| *until > state.now_ms());
    Ok(GroupView {
        id: group.id.clone(),
        name: group.name.clone(),
        description: group.description.clone(),
        created_at_ms: group.created_at_ms,
        my_role: me.role,
        participant_count,
        no_facilitator: facilitators.is_empty() && !group.is_archived(),
        facilitators,
        who_can_invite: effective_who_can_invite(&settings, group),
        group_who_can_invite: group.who_can_invite,
        instance_who_can_invite: settings.who_can_invite,
        can_invite: !group.is_archived() && settings.enabled && can_invite(&settings, group, me),
        max_participants: group.max_participants,
        meeting: parse_json_field(&group.meeting_json),
        next_meeting_at_ms: group
            .meeting_json
            .as_deref()
            .and_then(Meeting::parse)
            .filter(|_| !group.is_archived())
            .map(|m| m.next_start(state.now_ms())),
        my_meeting_reminders: my_reminders(pool, &group.id, &me.user_id, participant_count).await?,
        listed: group.listed && settings.enabled,
        listing: parse_json_field(&group.listing_json),
        archived_at_ms: group.archived_at_ms,
        delete_after_ms: group.delete_after_ms,
        facilitator_offer_until_ms: offer,
        groups_disabled: !settings.enabled,
        my_sharing: MySharing {
            share_status: me.share_status,
            share_allies: me.share_allies,
        },
    })
}

// ---- Create, list, get -------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateGroup {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

/// `POST /v1/groups`: the creator becomes the first facilitator.
pub async fn create(
    State(state): State<AppState>,
    s: SessionUser,
    ApiJson(req): ApiJson<CreateGroup>,
) -> AppResult<(StatusCode, Json<GroupView>)> {
    s.require_not_being_deleted()?;
    let settings = group_settings(&state);
    require_enabled(&state)?;
    if settings.who_can_create == WhoCanCreateGroups::Admins && !s.user.roles.admin {
        return Err(AppError::Forbidden("group_creation_restricted"));
    }
    let name = validate_name(&req.name)?;
    let description = validate_description(&req.description)?;
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    if groups::count_live_groups_of(&mut *tx, &s.user.id).await?
        >= i64::from(settings.max_groups_per_user)
    {
        return Err(too_many_groups(&settings));
    }
    let id = groups::insert_group(&mut *tx, &name, &description, &s.user.id, now).await?;
    groups::add_participant(
        &mut *tx,
        &id,
        &s.user.id,
        Role::Facilitator,
        None,
        JoinedVia::Created,
        now,
    )
    .await?;
    groups::add_history(
        &mut *tx,
        &id,
        HistoryKind::Joined,
        Some(&s.user.id),
        Some(&s.user.id),
        now,
    )
    .await?;
    tx.commit().await?;
    tracing::info!(group = %id, "group created");
    let (group, me) = load(&state, &s, &id).await?;
    Ok((StatusCode::CREATED, Json(view(&state, &group, &me).await?)))
}

pub(crate) fn too_many_groups(settings: &GroupSettings) -> AppError {
    AppError::conflict(
        "too_many_groups",
        format!(
            "a person can be in at most {} groups on this instance",
            settings.max_groups_per_user
        ),
    )
}

/// One line of `GET /v1/groups`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSummary {
    pub id: String,
    pub name: String,
    pub description: String,
    pub my_role: Role,
    pub participant_count: i64,
    pub meeting: Option<serde_json::Value>,
    pub archived_at_ms: Option<i64>,
    pub delete_after_ms: Option<i64>,
    /// The caller is offered the facilitator role.
    pub facilitator_offer: bool,
}

/// `GET /v1/groups`: the groups the caller is in, archived ones too (they
/// stay readable for 30 days).
pub async fn list_mine(
    State(state): State<AppState>,
    s: SessionUser,
) -> AppResult<Json<Vec<GroupSummary>>> {
    let now = state.now_ms();
    let mine = groups::groups_of(state.db().pool(), &s.user.id).await?;
    Ok(Json(
        mine.into_iter()
            .map(|m| GroupSummary {
                facilitator_offer: m.group.facilitator_offer_user.as_ref() == Some(&s.user.id)
                    && m.group.facilitator_offer_until_ms.is_some_and(|u| u > now),
                meeting: parse_json_field(&m.group.meeting_json),
                id: m.group.id,
                name: m.group.name,
                description: m.group.description,
                my_role: m.role,
                participant_count: m.participant_count,
                archived_at_ms: m.group.archived_at_ms,
                delete_after_ms: m.group.delete_after_ms,
            })
            .collect(),
    ))
}

/// `GET /v1/groups/{id}`
pub async fn get(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
) -> AppResult<Json<GroupView>> {
    let (group, me) = load(&state, &s, &id).await?;
    Ok(Json(view(&state, &group, &me).await?))
}

#[derive(Debug, Deserialize)]
pub struct RosterQuery {
    pub q: Option<String>,
    pub cursor: Option<String>,
}

pub(crate) fn cursor_of(raw: &Option<String>) -> AppResult<Option<(i64, String)>> {
    raw.as_deref()
        .filter(|c| !c.is_empty())
        .map(|c| {
            groups::parse_cursor(c)
                .ok_or_else(|| AppError::bad_request("invalid_cursor", "invalid cursor"))
        })
        .transpose()
}

/// `GET /v1/groups/{id}/participants?q=&cursor=`: 100 per page. People the
/// caller has an alliance with come first (each entry says which kind), then
/// everyone else, oldest participant first. Names only, never email
/// addresses.
pub async fn roster(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
    Query(q): Query<RosterQuery>,
) -> AppResult<Json<Page<RosterEntry>>> {
    load(&state, &s, &id).await?;
    let cursor = cursor_of(&q.cursor)?;
    let mut page =
        groups::roster(state.db().pool(), &id, &s.user.id, q.q.as_deref(), cursor).await?;
    super::group_sharing::fill_statuses(&state, &id, &mut page.items).await?;
    Ok(Json(page))
}

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    pub cursor: Option<String>,
}

/// `GET /v1/groups/{id}/history?cursor=`: joins, leaves, removals and other
/// changes, newest first, 100 per page. Visible to every participant, so
/// nobody can be added unseen.
pub async fn history(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
    Query(q): Query<HistoryQuery>,
) -> AppResult<Json<Page<HistoryEntry>>> {
    load(&state, &s, &id).await?;
    let cursor = cursor_of(&q.cursor)?;
    Ok(Json(groups::history(state.db().pool(), &id, cursor).await?))
}

/// `GET /v1/groups/{id}/me/allies`: the people in this group the caller is
/// allied with (either way, waiting links too), for the leave
/// confirmation. A short list, not the roster.
pub async fn my_allies_here(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<groups::GroupAlly>>> {
    load(&state, &s, &id).await?;
    Ok(Json(
        groups::allies_in_group(state.db().pool(), &id, &s.user.id).await?,
    ))
}

#[derive(Debug, Deserialize)]
pub struct UserSearchQuery {
    pub q: Option<String>,
}

/// Shortest search text: one letter would list half the instance.
const USER_SEARCH_MIN_CHARS: usize = 2;

/// `GET /v1/groups/{id}/user-search?q=`: a facilitator looks for people on
/// the instance to invite, by display name. Returns only an id and a name
/// (at most 20), never an email address, and doesn't match addresses at
/// all, so it can't be used to learn whether an address has an account.
/// People already in the group and accounts that can't join are left out.
pub async fn user_search(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
    Query(q): Query<UserSearchQuery>,
) -> AppResult<Json<Vec<Person>>> {
    let (group, me) = load(&state, &s, &id).await?;
    require_facilitator(&me)?;
    require_writable(&state, &group)?;
    let text = q.q.unwrap_or_default();
    if text.trim().chars().count() < USER_SEARCH_MIN_CHARS {
        return Ok(Json(Vec::new()));
    }
    Ok(Json(
        groups::search_users(state.db().pool(), &id, &text).await?,
    ))
}

// ---- Edit and archive --------------------------------------------------------

/// `PATCH /v1/groups/{id}`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchGroup {
    /// List the group in the directory, or take it out (§8.8).
    pub listed: Option<bool>,
    /// What a listing shows; fields left out stay as they are.
    pub listing: Option<ListingInput>,
    /// Replaces the schedule; `null` removes it (§8.4).
    #[serde(default, deserialize_with = "double_option")]
    pub meeting: Option<Option<MeetingInput>>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub who_can_invite: Option<WhoCanInvite>,
    /// `null` removes the limit.
    #[serde(default, deserialize_with = "double_option")]
    pub max_participants: Option<Option<i64>>,
}

/// `PATCH /v1/groups/{id}`: facilitators only.
pub async fn patch(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<PatchGroup>,
) -> AppResult<Json<GroupView>> {
    s.require_not_being_deleted()?;
    let settings = group_settings(&state);
    let name = req.name.as_deref().map(validate_name).transpose()?;
    let description = req
        .description
        .as_deref()
        .map(validate_description)
        .transpose()?;
    if req.who_can_invite == Some(WhoCanInvite::Participants)
        && settings.who_can_invite == WhoCanInvite::Facilitators
    {
        return Err(AppError::bad_request(
            "not_allowed_by_instance",
            "this instance only lets facilitators invite",
        ));
    }
    if let Some(Some(m)) = req.max_participants {
        if !(1..=MAX_PARTICIPANT_LIMIT).contains(&m) {
            return Err(AppError::bad_request(
                "invalid_max_participants",
                format!("the participant limit is between 1 and {MAX_PARTICIPANT_LIMIT}"),
            ));
        }
    }
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let (group, me) = load_in_tx(&mut tx, &s.user.id, &id).await?;
    require_facilitator(&me)?;
    require_writable(&state, &group)?;
    let listed_change = match req.listed {
        Some(want) if want != group.listed => {
            if want {
                require_may_list(&settings, &s.user.roles)?;
            }
            Some(want)
        }
        _ => None,
    };
    let listing_json = match (&req.listing, listed_change) {
        (Some(patch), _) => Some(
            Listing::from_json(group.listing_json.as_deref())
                .updated(patch)
                .to_json(),
        ),
        (None, Some(true)) if group.listing_json.is_none() => Some(Listing::default().to_json()),
        _ => None,
    };
    let meeting_json = match &req.meeting {
        None => None,
        Some(None) => Some(None),
        Some(Some(input)) => {
            let current = group.meeting_json.as_deref().and_then(Meeting::parse);
            let m = meetings::build(input, current.as_ref(), now)
                .map_err(|msg| AppError::bad_request("invalid_meeting", msg))?;
            Some(Some(m.to_json()))
        }
    };
    if let Some(Some(m)) = req.max_participants {
        if m < groups::count_active(&mut *tx, &id).await? {
            return Err(AppError::conflict(
                "limit_below_size",
                "the limit is below the number of people already in the group",
            ));
        }
    }
    let renamed = name.as_ref().is_some_and(|n| *n != group.name);
    groups::update(
        &mut tx,
        &id,
        &GroupUpdate {
            name,
            description,
            who_can_invite: req.who_can_invite.map(Some),
            max_participants: req.max_participants,
            meeting_json,
            listing_json,
            listed: listed_change,
        },
    )
    .await?;
    match listed_change {
        Some(true) => {
            groups::add_history(
                &mut *tx,
                &id,
                HistoryKind::Listed,
                None,
                Some(&s.user.id),
                now,
            )
            .await?;
        }
        Some(false) => {
            groups::add_history(
                &mut *tx,
                &id,
                HistoryKind::Unlisted,
                None,
                Some(&s.user.id),
                now,
            )
            .await?;
            group_listing::void_open(&mut tx, &id, now).await?;
        }
        None => {}
    }
    if renamed {
        groups::add_history(
            &mut *tx,
            &id,
            HistoryKind::Renamed,
            None,
            Some(&s.user.id),
            now,
        )
        .await?;
    }
    tx.commit().await?;
    let (group, me) = load(&state, &s, &id).await?;
    Ok(Json(view(&state, &group, &me).await?))
}

/// [`load`] inside a write transaction.
pub(crate) async fn load_in_tx(
    tx: &mut sqlx::AnyConnection,
    user: &UserId,
    id: &str,
) -> AppResult<(Group, Participant)> {
    let me = groups::active_participant(&mut *tx, id, user)
        .await?
        .ok_or(AppError::NotFound)?;
    let group = groups::by_id(&mut *tx, id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok((group, me))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Archived {
    pub id: String,
    pub archived_at_ms: i64,
    /// The group stays readable until now and is then deleted.
    pub delete_after_ms: i64,
}

/// `DELETE /v1/groups/{id}`: a facilitator archives the group. It is
/// read-only for 30 days, then deleted; everyone in it is told; alliances
/// stay.
pub async fn archive(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
) -> AppResult<Json<Archived>> {
    s.require_not_being_deleted()?;
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let (group, me) = load_in_tx(&mut tx, &s.user.id, &id).await?;
    require_facilitator(&me)?;
    require_writable(&state, &group)?;
    crate::groups::archive(&mut tx, &id, Some(&s.user.id), now).await?;
    tx.commit().await?;
    tracing::info!(group = %id, "group archived by a facilitator");
    let group = groups::by_id(state.db().pool(), &id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(Archived {
        id,
        archived_at_ms: group.archived_at_ms.unwrap_or(now),
        delete_after_ms: group.delete_after_ms.unwrap_or(now),
    }))
}

// ---- Leave, remove, role -----------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Left {
    /// The caller was the last participant, so leaving archived the group.
    pub group_archived: bool,
}

/// `DELETE /v1/groups/{id}/me`: leave, in one step. Alliances stay. The
/// last facilitator can't leave while others remain (make someone else a
/// facilitator first); the last participant leaving archives the group.
pub async fn leave(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
) -> AppResult<Json<Left>> {
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let (group, me) = load_in_tx(&mut tx, &s.user.id, &id).await?;
    require_writable(&state, &group)?;
    let last_participant = groups::count_active(&mut *tx, &id).await? == 1;
    if me.role == Role::Facilitator
        && !last_participant
        && groups::count_active_facilitators(&mut *tx, &id).await? == 1
    {
        return Err(AppError::conflict(
            "last_facilitator",
            "you are the group's only facilitator: make someone else a facilitator first",
        ));
    }
    groups::end_participation(&mut tx, &id, &s.user.id, Ended::Left, now).await?;
    groups::add_history(
        &mut *tx,
        &id,
        HistoryKind::Left,
        Some(&s.user.id),
        Some(&s.user.id),
        now,
    )
    .await?;
    if last_participant {
        crate::groups::archive(&mut tx, &id, Some(&s.user.id), now).await?;
    } else {
        crate::groups::tell_facilitators(&mut tx, &id, NoticeKind::GroupLeft, &s.user.id, now)
            .await?;
    }
    tx.commit().await?;
    tracing::info!(group = %id, archived = last_participant, "participant left a group");
    Ok(Json(Left {
        group_archived: last_participant,
    }))
}

/// `DELETE /v1/groups/{id}/participants/{user_id}`: a facilitator removes
/// someone, who is told. Alliances stay. (To leave yourself, use
/// `DELETE /v1/groups/{id}/me`.)
pub async fn remove(
    State(state): State<AppState>,
    s: SessionUser,
    Path((id, target)): Path<(String, String)>,
) -> AppResult<StatusCode> {
    s.require_not_being_deleted()?;
    let target = UserId::new(target);
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let (group, me) = load_in_tx(&mut tx, &s.user.id, &id).await?;
    require_facilitator(&me)?;
    require_writable(&state, &group)?;
    if target == s.user.id {
        return Err(AppError::bad_request(
            "use_leave",
            "to leave a group, use DELETE /v1/groups/{id}/me",
        ));
    }
    if !groups::end_participation(&mut tx, &id, &target, Ended::Removed, now).await? {
        return Err(AppError::NotFound);
    }
    groups::add_history(
        &mut *tx,
        &id,
        HistoryKind::Removed,
        Some(&target),
        Some(&s.user.id),
        now,
    )
    .await?;
    crate::groups::tell_removed(&mut tx, &target, &s.user.id, now).await?;
    tx.commit().await?;
    tracing::info!(group = %id, "participant removed from a group");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetRole {
    pub facilitator: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleSet {
    pub user_id: UserId,
    pub role: Role,
}

/// `PUT /v1/groups/{id}/participants/{user_id}/role`: a facilitator makes
/// someone a facilitator (at most 32), or steps someone down, themself
/// included, as long as another facilitator remains.
pub async fn set_role(
    State(state): State<AppState>,
    s: SessionUser,
    Path((id, target)): Path<(String, String)>,
    ApiJson(req): ApiJson<SetRole>,
) -> AppResult<Json<RoleSet>> {
    s.require_not_being_deleted()?;
    let target = UserId::new(target);
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let (group, me) = load_in_tx(&mut tx, &s.user.id, &id).await?;
    require_facilitator(&me)?;
    require_writable(&state, &group)?;
    let current = groups::active_participant(&mut *tx, &id, &target)
        .await?
        .ok_or(AppError::NotFound)?;
    let want = if req.facilitator {
        Role::Facilitator
    } else {
        Role::Participant
    };
    if current.role != want {
        let count = groups::count_active_facilitators(&mut *tx, &id).await?;
        if want == Role::Facilitator && count >= MAX_FACILITATORS {
            return Err(AppError::conflict(
                "too_many_facilitators",
                format!("a group has at most {MAX_FACILITATORS} facilitators"),
            ));
        }
        if want == Role::Participant && count <= 1 {
            return Err(AppError::conflict(
                "last_facilitator",
                "a group needs a facilitator: make someone else one first",
            ));
        }
        groups::set_role(&mut *tx, &id, &target, want).await?;
        let kind = if want == Role::Facilitator {
            HistoryKind::FacilitatorAdded
        } else {
            HistoryKind::FacilitatorRemoved
        };
        groups::add_history(&mut *tx, &id, kind, Some(&target), Some(&s.user.id), now).await?;
    }
    tx.commit().await?;
    Ok(Json(RoleSet {
        user_id: target,
        role: want,
    }))
}

/// `POST /v1/groups/{id}/facilitator-offer/accept`: the participant offered
/// the facilitator role after the last facilitator's account was deleted
/// (GROUPS.md §9) takes it, within 14 days.
pub async fn accept_facilitator_offer(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
) -> AppResult<Json<GroupView>> {
    s.require_not_being_deleted()?;
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let (group, me) = load_in_tx(&mut tx, &s.user.id, &id).await?;
    require_writable(&state, &group)?;
    require_offer(&group, &me, now)?;
    groups::set_role(&mut *tx, &id, &s.user.id, Role::Facilitator).await?;
    groups::clear_facilitator_offer(&mut *tx, &id).await?;
    groups::add_history(
        &mut *tx,
        &id,
        HistoryKind::FacilitatorAdded,
        Some(&s.user.id),
        Some(&s.user.id),
        now,
    )
    .await?;
    tx.commit().await?;
    let (group, me) = load(&state, &s, &id).await?;
    Ok(Json(view(&state, &group, &me).await?))
}

/// `POST /v1/groups/{id}/facilitator-offer/decline`: the group then goes on
/// without facilitators until someone else is made one (nobody can: see
/// GROUPS.md §9), and stays unlisted.
pub async fn decline_facilitator_offer(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let (group, me) = load_in_tx(&mut tx, &s.user.id, &id).await?;
    require_offer(&group, &me, now)?;
    groups::clear_facilitator_offer(&mut *tx, &id).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

fn require_offer(group: &Group, me: &Participant, now: i64) -> AppResult<()> {
    let live = group.facilitator_offer_user.as_ref() == Some(&me.user_id)
        && group.facilitator_offer_until_ms.is_some_and(|u| u > now);
    if live {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

// ---- Invitations -------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateInvites {
    #[serde(default)]
    pub emails: Vec<String>,
    #[serde(default)]
    pub user_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteCreated {
    /// The address, or for an invitation to a user, their display name.
    pub invited: String,
    pub expires_at_ms: i64,
    /// Also emailed. Only the invited address or user can use it.
    pub invite_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitesCreated {
    pub invites: Vec<InviteCreated>,
    /// People already in the group, already invited, or not invitable. Not
    /// told apart, so an address can't be probed for an account.
    pub skipped: usize,
}

fn invite_url(state: &AppState, token: &str) -> String {
    format!("{}/group-invite#token={token}", state.config().public_url)
}

/// The invitation email. It names the inviter and the instance, **never the
/// group** (GROUPS.md principle 7).
fn invite_email(state: &AppState, to: &str, inviter: &str, url: &str) -> Email {
    let instance = &state.config().instance.name;
    Email {
        to: to.to_owned(),
        subject: format!("{inviter} invited you to join a group on {instance}"),
        text: format!(
            "{inviter} invited you to join a group on {instance}.\n\n\
             Joining a group shares nothing about your computer or your reports. After you sign \
             in, Faro shows you the group and lets you accept or decline.\n\n\
             Open the invitation (sign in with this email address):\n{url}\n\n\
             The invitation expires in 7 days. If you did not expect it, you can ignore this \
             email.\n"
        ),
    }
}

/// `POST /v1/groups/{id}/invites`: invite people by address or by picking
/// users on the instance (at most 50 at a time). Facilitators, or any
/// participant if the instance and the group allow it. Refused while the
/// group is full.
pub async fn create_invites(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<CreateInvites>,
) -> AppResult<(StatusCode, Json<InvitesCreated>)> {
    s.require_not_being_deleted()?;
    let settings = group_settings(&state);
    if req.emails.len() + req.user_ids.len() > MAX_INVITES_PER_REQUEST {
        return Err(AppError::bad_request(
            "too_many_invitees",
            format!("invite at most {MAX_INVITES_PER_REQUEST} people at a time"),
        ));
    }
    if req.emails.is_empty() && req.user_ids.is_empty() {
        return Err(AppError::bad_request(
            "no_invitees",
            "give at least one email address or user",
        ));
    }
    let emails: Vec<String> = req
        .emails
        .iter()
        .map(|e| {
            normalize_email(e)
                .ok_or_else(|| AppError::bad_request("invalid_email", "invalid email address"))
        })
        .collect::<AppResult<_>>()?;

    let now = state.now_ms();
    let expires_at_ms = now + INVITE_TTL_MS;
    let mut tx = state.db().begin_write().await?;
    let (group, me) = load_in_tx(&mut tx, &s.user.id, &id).await?;
    require_writable(&state, &group)?;
    if !can_invite(&settings, &group, &me) {
        return Err(AppError::Forbidden("not_a_facilitator"));
    }
    ensure_room(&mut tx, &group).await?;
    let live = groups::count_live_invites(&mut *tx, &id, now).await?;

    // (where to send it, who it is bound to, what to show the inviter)
    struct Target {
        to: String,
        email: Option<String>,
        user: Option<UserId>,
        label: String,
    }
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    let mut skipped = 0;
    for email in emails {
        if !seen.insert(email.clone()) || email == s.user.email {
            skipped += 1;
            continue;
        }
        if let Some(u) = users::by_email(&mut *tx, &email).await? {
            if groups::active_participant(&mut *tx, &id, &u.id)
                .await?
                .is_some()
            {
                skipped += 1;
                continue;
            }
        }
        if groups::live_invite_exists(&mut *tx, &id, Some(&email), None, now).await? {
            skipped += 1;
            continue;
        }
        targets.push(Target {
            to: email.clone(),
            label: email.clone(),
            email: Some(email),
            user: None,
        });
    }
    for raw in req.user_ids {
        let uid = UserId::new(raw);
        if !seen.insert(uid.as_str().to_owned()) || uid == s.user.id || !uid.is_well_formed() {
            skipped += 1;
            continue;
        }
        let Some(u) = users::by_id(&mut *tx, &uid)
            .await?
            .filter(|u| !u.disabled && u.deletion.is_none())
        else {
            skipped += 1;
            continue;
        };
        if seen.contains(&u.email)
            || groups::active_participant(&mut *tx, &id, &uid)
                .await?
                .is_some()
            || groups::live_invite_exists(&mut *tx, &id, None, Some(&uid), now).await?
        {
            skipped += 1;
            continue;
        }
        targets.push(Target {
            to: u.email,
            label: u.display_name,
            email: None,
            user: Some(uid),
        });
    }
    if live + targets.len() as i64 > MAX_LIVE_INVITES_PER_GROUP {
        return Err(AppError::conflict(
            "too_many_invites",
            "too many open invitations for this group; wait for some to be answered or expire",
        ));
    }

    let mut created = Vec::new();
    let mut mails = Vec::new();
    for t in targets {
        let token = new_token();
        groups::insert_invite(
            &mut *tx,
            &Invite {
                token_hash: state.hasher().hash(TokenPurpose::Invite, &token),
                group_id: id.clone(),
                inviter_id: s.user.id.clone(),
                email: t.email,
                user_id: t.user,
                created_at_ms: now,
                expires_at_ms,
                used_at_ms: None,
                outcome: None,
            },
        )
        .await?;
        let url = invite_url(&state, &token);
        mails.push(invite_email(&state, &t.to, &s.user.display_name, &url));
        created.push(InviteCreated {
            invited: t.label,
            expires_at_ms,
            invite_url: url,
        });
    }
    tx.commit().await?;
    let mailer = state.mailer();
    for mail in mails {
        let mailer = mailer.clone();
        tokio::spawn(async move {
            if let Err(e) = mailer.send(mail).await {
                tracing::warn!(code = e.code(), "could not send group invitation email");
            }
        });
    }
    tracing::info!(group = %id, invited = created.len(), skipped, "group invitations created");
    Ok((
        StatusCode::CREATED,
        Json(InvitesCreated {
            invites: created,
            skipped,
        }),
    ))
}

/// `409 group_full` when a participant limit is set and reached.
pub(crate) async fn ensure_room(conn: &mut sqlx::AnyConnection, group: &Group) -> AppResult<()> {
    if let Some(max) = group.max_participants {
        if groups::count_active(&mut *conn, &group.id).await? >= max {
            return Err(AppError::conflict("group_full", "This group is full"));
        }
    }
    Ok(())
}

/// `GET /v1/groups/{id}/invites`: who has been invited and whether they
/// answered. Facilitators see every invitation, other participants their
/// own. Declined and expired both read "not_accepted".
pub async fn list_invites(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<InviteStatus>>> {
    let (_, me) = load(&state, &s, &id).await?;
    let only_by = (me.role != Role::Facilitator).then_some(&s.user.id);
    Ok(Json(
        groups::invites_of_group(
            state.db().pool(),
            &id,
            only_by,
            state.now_ms(),
            INVITE_LIST_LIMIT,
        )
        .await?,
    ))
}

/// The invitation a caller names (by the emailed token, or by the
/// `invite_ref` `GET /v1/me/group-invites` gave them), if it is live and
/// theirs. Anything else is `404`.
async fn find_my_invite(
    state: &AppState,
    s: &SessionUser,
    conn: &mut sqlx::AnyConnection,
    token: &str,
) -> AppResult<Invite> {
    let now = state.now_ms();
    let mut found = None;
    if is_token_shaped(token) {
        let hash = state.hasher().hash(TokenPurpose::Invite, token);
        found = groups::find_live_invite(&mut *conn, &hash, now).await?;
    }
    if found.is_none() && token.len() <= 128 && token.bytes().all(|b| b.is_ascii_alphanumeric()) {
        found = groups::find_live_invite(&mut *conn, token, now).await?;
    }
    found
        .filter(|i| i.is_for(&s.user.id, &s.user.email))
        .ok_or(AppError::NotFound)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteInfo {
    /// Pass this in place of the emailed token to accept or decline from
    /// inside Faro.
    pub invite_ref: String,
    pub group_id: String,
    pub group_name: String,
    pub group_description: String,
    pub group_archived: bool,
    pub inviter_display_name: String,
    /// The facilitators' display names (§8.7). Never anyone else.
    pub facilitators: Vec<String>,
    /// `{cadence, weekday, minute_of_day, tz_offset_min, place?, anchor_ms}`
    /// when the group has a schedule.
    pub meeting: Option<serde_json::Value>,
    pub instance_name: String,
    pub expires_at_ms: i64,
    /// How many people are in the group now, so the invitee can see who
    /// would see what they choose to share ("28 people in this group").
    pub participant_count: i64,
}

async fn invite_info(
    state: &AppState,
    i: InviteForMe,
    group: Option<Group>,
) -> AppResult<InviteInfo> {
    let facilitators = groups::facilitators(state.db().pool(), &i.invite.group_id)
        .await?
        .into_iter()
        .map(|p| p.display_name)
        .collect();
    let participant_count = groups::count_active(state.db().pool(), &i.invite.group_id).await?;
    Ok(InviteInfo {
        facilitators,
        meeting: group
            .as_ref()
            .and_then(|g| parse_json_field(&g.meeting_json)),
        invite_ref: i.invite.token_hash,
        group_id: i.invite.group_id,
        group_name: i.group_name,
        group_description: group.map(|g| g.description).unwrap_or_default(),
        group_archived: i.group_archived,
        inviter_display_name: i.inviter_name,
        instance_name: state.config().instance.name.clone(),
        expires_at_ms: i.invite.expires_at_ms,
        participant_count,
    })
}

/// `GET /v1/me/group-invites`: invitations waiting for the caller (the
/// in-app notice), by address or by user.
pub async fn my_invites(
    State(state): State<AppState>,
    s: SessionUser,
) -> AppResult<Json<Vec<InviteInfo>>> {
    let now = state.now_ms();
    let mut out = Vec::new();
    for i in groups::live_invites_for(state.db().pool(), &s.user.id, &s.user.email, now).await? {
        if i.group_archived {
            continue;
        }
        let group = groups::by_id(state.db().pool(), &i.invite.group_id).await?;
        out.push(invite_info(&state, i, group).await?);
    }
    Ok(Json(out))
}

/// `GET /v1/group-invites/{token}`: who invited the caller and which group
/// (its name is shown only here, after sign-in). Only the person the
/// invitation is for can see it; unknown, used, expired and someone else's
/// invitations are indistinguishable (`404`).
pub async fn get_invite(
    State(state): State<AppState>,
    s: SessionUser,
    Path(token): Path<String>,
) -> AppResult<Json<InviteInfo>> {
    let mut conn = state.db().pool().acquire().await?;
    let inv = find_my_invite(&state, &s, &mut conn, &token).await?;
    let mine = groups::live_invites_for(&mut *conn, &s.user.id, &s.user.email, state.now_ms())
        .await?
        .into_iter()
        .find(|i| i.invite.token_hash == inv.token_hash)
        .filter(|i| !i.group_archived)
        .ok_or(AppError::NotFound)?;
    let group = groups::by_id(&mut *conn, &inv.group_id).await?;
    Ok(Json(invite_info(&state, mine, group).await?))
}

/// `POST /v1/group-invites/{token}/accept`: join. Only the invited address
/// or user can; fails if the group is full, closed, or the caller is in
/// their maximum number of groups.
pub async fn accept_invite(
    State(state): State<AppState>,
    s: SessionUser,
    Path(token): Path<String>,
) -> AppResult<(StatusCode, Json<GroupView>)> {
    s.require_not_being_deleted()?;
    require_enabled(&state)?;
    let settings = group_settings(&state);
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let inv = find_my_invite(&state, &s, &mut tx, &token).await?;
    let group = groups::by_id(&mut *tx, &inv.group_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if group.is_archived() {
        return Err(AppError::NotFound);
    }
    if groups::active_participant(&mut *tx, &group.id, &s.user.id)
        .await?
        .is_some()
    {
        return Err(AppError::conflict(
            "already_participant",
            "you are already in this group",
        ));
    }
    // The inviter must still be someone who may invite.
    if groups::active_participant(&mut *tx, &group.id, &inv.inviter_id)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound);
    }
    ensure_room(&mut tx, &group).await?;
    if groups::count_live_groups_of(&mut *tx, &s.user.id).await?
        >= i64::from(settings.max_groups_per_user)
    {
        return Err(too_many_groups(&settings));
    }
    if !groups::close_invite(&mut *tx, &inv.token_hash, &s.user.id, "accepted", now).await? {
        return Err(AppError::NotFound);
    }
    match groups::add_participant(
        &mut *tx,
        &group.id,
        &s.user.id,
        Role::Participant,
        Some(&inv.inviter_id),
        JoinedVia::Invite,
        now,
    )
    .await
    {
        Ok(_) => {}
        Err(e) if is_unique_violation(&e) => {
            return Err(AppError::conflict(
                "already_participant",
                "you are already in this group",
            ))
        }
        Err(e) => return Err(e.into()),
    }
    groups::add_history(
        &mut *tx,
        &group.id,
        HistoryKind::Joined,
        Some(&s.user.id),
        Some(&inv.inviter_id),
        now,
    )
    .await?;
    crate::groups::tell_facilitators(&mut tx, &group.id, NoticeKind::GroupJoined, &s.user.id, now)
        .await?;
    tx.commit().await?;
    tracing::info!(group = %group.id, "group invitation accepted");
    let (group, me) = load(&state, &s, &group.id).await?;
    Ok((StatusCode::CREATED, Json(view(&state, &group, &me).await?)))
}

/// `POST /v1/group-invites/{token}/decline`. The inviter sees "not
/// accepted", the same as for an expired invitation, and nobody is told.
pub async fn decline_invite(
    State(state): State<AppState>,
    s: SessionUser,
    Path(token): Path<String>,
) -> AppResult<StatusCode> {
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let inv = find_my_invite(&state, &s, &mut tx, &token).await?;
    if !groups::close_invite(&mut *tx, &inv.token_hash, &s.user.id, "declined", now).await? {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
