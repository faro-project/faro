//! Listed groups, the directory, join requests and meeting reminder choices
//! (docs/GROUPS.md §8.4, §8.8, §16).
//!
//! * **Listing** is set through `PATCH /v1/groups/{id}` ([`super::groups`])
//!   and, for an admin, `PUT /admin/api/groups/{id}/listed`
//!   ([`super::admin`]). The instance's "who can list" setting decides who
//!   may switch it on.
//! * **The directory** (`GET /v1/group-directory`) is for signed-in users
//!   only: the [`SessionUser`] extractor refuses everyone else, and there is
//!   no other route to it. A listing holds the fields §8.8 allows and
//!   **never a participant id, a name or a count**: facilitators' display
//!   names, and only whether the group is full.
//! * **Join requests** are private to the requester and the facilitators. A
//!   requester is shown "Not accepted" alike for a decline, an expiry and an
//!   unlisting ([`group_listing::MyRequest`]), and the refusal to ask again
//!   is the same `409` whatever ended the request.
//!
//! A join request may carry a note to the facilitators: signed by the
//! requester's member key and sealed to each facilitator's key
//! ([`crate::messages`], GROUPS.md §10.2). Facilitators see that there is
//! one (`note_id`) and read it in their browser; the instance can't.

use super::groups::{
    cursor_of, ensure_room, group_settings, load, load_in_tx, require_enabled, require_facilitator,
    require_writable, too_many_groups,
};
use super::ApiJson;
use crate::auth::session::SessionUser;
use crate::db::repo::group_listing::{self, MeetingPrefs, MyRequest};
use crate::db::repo::group_notices::NoticeKind;
use crate::db::repo::groups::{self, HistoryKind, JoinedVia, Page, Role, LARGE_GROUP};
use crate::db::repo::{is_unique_violation, users};
use crate::error::{AppError, AppResult};
use crate::meetings::{self, Meeting};
use crate::messages::{self, Expect};
use crate::settings::{GroupSettings, WhoCanListGroups};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use faro_proto::group::{GroupMessageKind, SealedGroupMessage};
use faro_proto::UserId;
use serde::{Deserialize, Serialize};

// ---- Listing settings --------------------------------------------------------

/// What a listing shows beyond name, description and facilitators (§8.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listing {
    /// Meeting day and time (default shown).
    pub show_meeting_time: bool,
    /// Meeting place (default hidden: shown once someone has joined).
    pub show_place: bool,
}

impl Default for Listing {
    fn default() -> Self {
        Listing {
            show_meeting_time: true,
            show_place: false,
        }
    }
}

/// A facilitator's change to [`Listing`]: fields left out stay.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListingInput {
    pub show_meeting_time: Option<bool>,
    pub show_place: Option<bool>,
}

impl Listing {
    pub fn from_json(raw: Option<&str>) -> Listing {
        raw.and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default()
    }

    pub fn to_json(self) -> String {
        serde_json::to_string(&self).unwrap_or_else(|_| "{}".to_owned())
    }

    pub fn updated(self, p: &ListingInput) -> Listing {
        Listing {
            show_meeting_time: p.show_meeting_time.unwrap_or(self.show_meeting_time),
            show_place: p.show_place.unwrap_or(self.show_place),
        }
    }
}

/// Whether the caller may switch listing on, by the instance's setting: a
/// facilitator under "facilitators", an admin under "admins" (a facilitator
/// who is also an admin counts), nobody under "nobody".
pub fn require_may_list(settings: &GroupSettings, roles: &users::Roles) -> Result<(), AppError> {
    match settings.who_can_list {
        WhoCanListGroups::Facilitators => Ok(()),
        WhoCanListGroups::Admins if roles.admin => Ok(()),
        WhoCanListGroups::Admins => Err(AppError::Forbidden("listing_needs_admin")),
        WhoCanListGroups::Nobody => Err(AppError::Forbidden("listing_disabled")),
    }
}

/// The directory exists: groups are on and the admin allows listing.
fn directory_open(settings: &GroupSettings) -> bool {
    settings.enabled && settings.who_can_list != WhoCanListGroups::Nobody
}

// ---- The directory -----------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DirectoryQuery {
    pub q: Option<String>,
    pub cursor: Option<String>,
}

/// The meeting as a listing shows it: when, never where.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListedMeeting {
    pub cadence: meetings::Cadence,
    pub weekday: u8,
    pub minute_of_day: u16,
    pub tz_offset_min: i32,
}

/// One listed group. **No participant ids, names or counts.**
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub id: String,
    pub name: String,
    pub description: String,
    /// Display names only.
    pub facilitators: Vec<String>,
    /// Only if the facilitators show it and there is one.
    pub meeting: Option<ListedMeeting>,
    /// Only if the facilitators show it.
    pub place: Option<String>,
    /// A participant limit is set and reached.
    pub full: bool,
    /// The caller has an open request.
    pub requested: bool,
    /// The caller is already in the group.
    pub joined: bool,
}

/// `GET /v1/group-directory?q=&cursor=`: listed groups, 100 per page.
/// Signed-in users only (never served signed out, never by email).
pub async fn directory(
    State(state): State<AppState>,
    s: SessionUser,
    Query(q): Query<DirectoryQuery>,
) -> AppResult<Json<Page<DirectoryEntry>>> {
    if !directory_open(&group_settings(&state)) {
        return Ok(Json(Page {
            items: Vec::new(),
            next_cursor: None,
        }));
    }
    let cursor = cursor_of(&q.cursor)?;
    let page = group_listing::directory(
        state.db().pool(),
        q.q.as_deref(),
        cursor,
        &s.user.id,
        state.now_ms(),
    )
    .await?;
    let items = page
        .items
        .into_iter()
        .map(|r| {
            let listing = Listing::from_json(r.listing_json.as_deref());
            let meeting = r.meeting_json.as_deref().and_then(Meeting::parse);
            DirectoryEntry {
                id: r.id,
                name: r.name,
                description: r.description,
                facilitators: r.facilitator_names,
                place: meeting
                    .as_ref()
                    .and_then(|m| m.place.clone())
                    .filter(|_| listing.show_place),
                meeting: meeting
                    .filter(|_| listing.show_meeting_time)
                    .map(|m| ListedMeeting {
                        cadence: m.cadence,
                        weekday: m.weekday,
                        minute_of_day: m.minute_of_day,
                        tz_offset_min: m.tz_offset_min,
                    }),
                full: r.full,
                requested: r.requested,
                joined: r.joined,
            }
        })
        .collect();
    Ok(Json(Page {
        items,
        next_cursor: page.next_cursor,
    }))
}

// ---- Join requests -----------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateJoinRequest {
    /// A note to the facilitators, at most 500 characters, signed and
    /// sealed in the browser (`for=join_request_note` recipients).
    #[serde(default)]
    pub note: Option<SealedGroupMessage>,
}

/// The facilitators of a listed group, to seal a join-request note to.
/// `404` unless the directory is open and the group listed (as for the
/// join-request route itself).
pub(crate) async fn note_recipients(
    state: &AppState,
    conn: &mut sqlx::AnyConnection,
    id: &str,
) -> AppResult<Vec<UserId>> {
    require_enabled(state)?;
    if !directory_open(&group_settings(state)) {
        return Err(AppError::NotFound);
    }
    groups::by_id(&mut *conn, id)
        .await?
        .filter(|g| g.listed && !g.is_archived())
        .ok_or(AppError::NotFound)?;
    let people: Vec<UserId> = groups::active_user_ids(&mut *conn, id, true).await?;
    if people.is_empty() {
        return Err(AppError::conflict(
            "no_recipients",
            "this group has no facilitator to send a note to",
        ));
    }
    Ok(people)
}

/// `POST /v1/groups/{id}/join-requests`: ask to join a listed group. `404`
/// unless the group is listed (and so for an unlisted one, as for an
/// unknown id).
pub async fn create_request(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<CreateJoinRequest>,
) -> AppResult<(StatusCode, Json<MyRequest>)> {
    s.require_not_being_deleted()?;
    let settings = group_settings(&state);
    require_enabled(&state)?;
    if !directory_open(&settings) {
        return Err(AppError::NotFound);
    }
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let group = groups::by_id(&mut *tx, &id)
        .await?
        .filter(|g| g.listed && !g.is_archived())
        .ok_or(AppError::NotFound)?;
    group_listing::expire_due(&mut tx, now, Some(&s.user.id)).await?;
    if groups::active_participant(&mut *tx, &id, &s.user.id)
        .await?
        .is_some()
    {
        return Err(AppError::conflict(
            "already_participant",
            "you are already in this group",
        ));
    }
    if group_listing::open_of(&mut *tx, &id, &s.user.id, now)
        .await?
        .is_some()
    {
        return Err(AppError::conflict(
            "already_requested",
            "you have already asked to join this group",
        ));
    }
    if group_listing::in_cooldown(&mut *tx, &id, &s.user.id, now).await? {
        return Err(AppError::conflict(
            "request_cooldown",
            "you can't ask this group again yet",
        ));
    }
    if group_listing::count_open(&mut *tx, &s.user.id, now).await?
        >= group_listing::MAX_OPEN_REQUESTS
    {
        return Err(AppError::conflict(
            "too_many_join_requests",
            format!(
                "you can have at most {} requests to join groups open at once",
                group_listing::MAX_OPEN_REQUESTS
            ),
        ));
    }
    ensure_room(&mut tx, &group).await?;
    if groups::count_live_groups_of(&mut *tx, &s.user.id).await?
        >= i64::from(settings.max_groups_per_user)
    {
        return Err(too_many_groups(&settings));
    }
    let note_id = match &body.note {
        None => None,
        Some(note) => {
            let facilitators = note_recipients(&state, &mut tx, &id).await?;
            messages::accept_message(
                &mut tx,
                &state,
                &s.user.id,
                note,
                &Expect {
                    kind: GroupMessageKind::JoinRequestNote,
                    group_id: Some(&id),
                    allowed: &facilitators,
                },
            )
            .await?;
            Some(note.message.body.item_id.clone())
        }
    };
    let req = match group_listing::insert(&mut *tx, &id, &s.user.id, note_id.as_deref(), now).await
    {
        Ok(r) => r,
        Err(e) if is_unique_violation(&e) => {
            return Err(AppError::conflict(
                "already_requested",
                "you have already asked to join this group",
            ))
        }
        Err(e) => return Err(e.into()),
    };
    crate::groups::tell_join_requested(&mut tx, &id, &s.user.id, now).await?;
    tx.commit().await?;
    tracing::info!(group = %id, "join request made");
    Ok((
        StatusCode::CREATED,
        Json(MyRequest {
            id: req.id,
            group_id: id,
            state: "open".to_owned(),
            group_name: Some(group.name),
            created_at_ms: Some(req.created_at_ms),
            expires_at_ms: Some(req.expires_at_ms),
        }),
    ))
}

/// `DELETE /v1/groups/{id}/join-requests/me`: take the request back. It is
/// removed, and the person may ask again.
pub async fn withdraw_request(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    group_listing::expire_due(&mut tx, now, Some(&s.user.id)).await?;
    if !group_listing::withdraw(&mut *tx, &id, &s.user.id, now).await? {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct CursorQuery {
    pub cursor: Option<String>,
}

/// `GET /v1/groups/{id}/join-requests?cursor=`: open requests, for the
/// group's facilitators only. A display name and when it was made: nothing
/// else about the person.
pub async fn list_requests(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
    Query(q): Query<CursorQuery>,
) -> AppResult<Json<Page<group_listing::FacilitatorEntry>>> {
    let (_, me) = load(&state, &s, &id).await?;
    require_facilitator(&me)?;
    let cursor = cursor_of(&q.cursor)?;
    Ok(Json(
        group_listing::list_for_group(state.db().pool(), &id, cursor, state.now_ms()).await?,
    ))
}

/// `GET /v1/me/join-requests`: the caller's own requests. Open ones, and
/// ended ones as "not_accepted" until they could ask again; a decline, an
/// expiry and an unlisting read the same.
pub async fn my_requests(
    State(state): State<AppState>,
    s: SessionUser,
) -> AppResult<Json<Vec<MyRequest>>> {
    Ok(Json(
        group_listing::mine(state.db().pool(), &s.user.id, state.now_ms()).await?,
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Accepted {
    pub id: String,
    pub group_id: String,
}

/// The open request `id` as one of its group's facilitators, or `404`.
async fn request_for_facilitator(
    state: &AppState,
    s: &SessionUser,
    tx: &mut sqlx::AnyConnection,
    id: &str,
) -> AppResult<(group_listing::JoinRequest, groups::Group)> {
    let now = state.now_ms();
    let req = group_listing::open_by_id(&mut *tx, id, now)
        .await?
        .ok_or(AppError::NotFound)?;
    let (group, me) = load_in_tx(tx, &s.user.id, &req.group_id).await?;
    require_facilitator(&me)?;
    require_writable(state, &group)?;
    Ok((req, group))
}

/// `POST /v1/join-requests/{id}/accept`: the person joins with sharing off,
/// and is told. Fails (without ending the request) if the group is full or
/// the person can't join right now; the reason is not given, so a
/// facilitator learns nothing about them.
pub async fn accept_request(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
) -> AppResult<Json<Accepted>> {
    s.require_not_being_deleted()?;
    let settings = group_settings(&state);
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let (req, group) = request_for_facilitator(&state, &s, &mut tx, &id).await?;
    ensure_room(&mut tx, &group).await?;
    let cannot = || {
        AppError::conflict(
            "cannot_accept",
            "this person can't join the group right now",
        )
    };
    let requester = users::by_id(&mut *tx, &req.user_id)
        .await?
        .filter(|u| !u.disabled && u.deletion.is_none())
        .ok_or_else(cannot)?;
    if groups::active_participant(&mut *tx, &group.id, &requester.id)
        .await?
        .is_some()
        || groups::count_live_groups_of(&mut *tx, &requester.id).await?
            >= i64::from(settings.max_groups_per_user)
    {
        return Err(cannot());
    }
    if !group_listing::decide(&mut tx, &id, true, &s.user.id, now).await? {
        return Err(AppError::NotFound);
    }
    match groups::add_participant(
        &mut *tx,
        &group.id,
        &requester.id,
        Role::Participant,
        Some(&s.user.id),
        JoinedVia::Request,
        now,
    )
    .await
    {
        Ok(_) => {}
        Err(e) if is_unique_violation(&e) => return Err(cannot()),
        Err(e) => return Err(e.into()),
    }
    groups::add_history(
        &mut *tx,
        &group.id,
        HistoryKind::Joined,
        Some(&requester.id),
        Some(&s.user.id),
        now,
    )
    .await?;
    crate::groups::tell_join_accepted(&mut tx, &requester.id, &s.user.id, now).await?;
    crate::groups::tell_facilitators(
        &mut tx,
        &group.id,
        NoticeKind::GroupJoined,
        &requester.id,
        now,
    )
    .await?;
    tx.commit().await?;
    tracing::info!(group = %group.id, "join request accepted");
    Ok(Json(Accepted {
        id,
        group_id: group.id,
    }))
}

/// `POST /v1/join-requests/{id}/decline`: the person is shown "Not
/// accepted" and nobody is told. They can't ask this group again for 30
/// days after the request would have expired.
pub async fn decline_request(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    s.require_not_being_deleted()?;
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    request_for_facilitator(&state, &s, &mut tx, &id).await?;
    if !group_listing::decide(&mut tx, &id, false, &s.user.id, now).await? {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- Meeting reminders -------------------------------------------------------

/// The caller's reminder choices for one group, as the group view shows
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MyMeetingReminders {
    /// A reminder before each meeting (default on).
    pub reminders: bool,
    /// Also by email (default on up to 32 participants, off above).
    pub email: bool,
    /// What `email` is when the caller has not chosen.
    pub email_default: bool,
}

fn reminders_of(prefs: MeetingPrefs, participants: i64) -> MyMeetingReminders {
    MyMeetingReminders {
        reminders: prefs.reminders,
        email: meetings::email_wanted(prefs, usize::try_from(participants).unwrap_or(usize::MAX)),
        email_default: participants <= LARGE_GROUP,
    }
}

pub async fn my_reminders(
    pool: &sqlx::AnyPool,
    group: &str,
    user: &UserId,
    participants: i64,
) -> Result<MyMeetingReminders, sqlx::Error> {
    Ok(reminders_of(
        group_listing::get_prefs(pool, group, user).await?,
        participants,
    ))
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetReminders {
    pub reminders: Option<bool>,
    pub email: Option<bool>,
}

/// `PUT /v1/groups/{id}/me/meeting-reminders`: switch the caller's reminders
/// or their email on or off (fields left out stay as they are).
pub async fn set_reminders(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<SetReminders>,
) -> AppResult<Json<MyMeetingReminders>> {
    load(&state, &s, &id).await?;
    let pool = state.db().pool();
    let mut prefs = group_listing::get_prefs(pool, &id, &s.user.id).await?;
    if let Some(r) = req.reminders {
        prefs.reminders = r;
    }
    if let Some(e) = req.email {
        prefs.email = Some(e);
    }
    group_listing::set_prefs(pool, &id, &s.user.id, prefs).await?;
    let n = groups::count_active(pool, &id).await?;
    Ok(Json(reminders_of(prefs, n)))
}
