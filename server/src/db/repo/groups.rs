//! `accountability_groups`, `group_participants`, `group_history` and
//! `group_invites` (docs/GROUPS.md §5, §6, §9, §15).
//!
//! Only SQL lives here; the rules (who may do what, limits, notices) are in
//! [`crate::groups`] and [`crate::api::groups`]. Later work (alliance
//! proposals, listing and join requests, meetings) builds on these
//! functions: they take any executor, so they run on the pool or inside a
//! transaction (`&mut *tx`).
//!
//! **Nothing here touches `ally_links`.** Leaving or archiving a group
//! never ends an alliance (principle 4): it only voids open proposals.
//! `ally_links.origin_group_id` is set NULL by the database when a group
//! is deleted.

use super::parse_col;
use crate::settings::WhoCanInvite;
use crate::tokens::new_hex_id;
use faro_proto::UserId;
use serde::{Deserialize, Serialize};
use sqlx::any::AnyRow;
use sqlx::{Any, Executor, Row};

/// Facilitators per group (GROUPS.md §6): "send to the facilitators" must
/// fit one item's recipient list.
pub const MAX_FACILITATORS: i64 = 32;
/// Participants per page of the roster, history and (later) the directory.
pub const PAGE_SIZE: i64 = 100;
/// Archived groups are read-only this long, then deleted.
pub const ARCHIVE_TTL_MS: i64 = 30 * 24 * 3600 * 1000;
/// How long the earliest participant may accept the facilitator role after
/// the last facilitator's account is purged.
pub const OFFER_TTL_MS: i64 = 14 * 24 * 3600 * 1000;
/// Above this many participants, join and leave notices to facilitators come
/// as one daily summary, and meeting reminders default to no email.
pub const LARGE_GROUP: i64 = 32;

// ---- Types ------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Facilitator,
    Participant,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Facilitator => "facilitator",
            Role::Participant => "participant",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "facilitator" => Some(Role::Facilitator),
            "participant" => Some(Role::Participant),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    Left,
    Removed,
}

impl Ended {
    fn as_str(self) -> &'static str {
        match self {
            Ended::Left => "left",
            Ended::Removed => "removed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinedVia {
    Invite,
    Request,
    Created,
}

impl JoinedVia {
    pub fn as_str(self) -> &'static str {
        match self {
            JoinedVia::Invite => "invite",
            JoinedVia::Request => "request",
            JoinedVia::Created => "created",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryKind {
    Joined,
    Left,
    Removed,
    FacilitatorAdded,
    FacilitatorRemoved,
    Renamed,
    Listed,
    Unlisted,
    Archived,
}

impl HistoryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            HistoryKind::Joined => "joined",
            HistoryKind::Left => "left",
            HistoryKind::Removed => "removed",
            HistoryKind::FacilitatorAdded => "facilitator_added",
            HistoryKind::FacilitatorRemoved => "facilitator_removed",
            HistoryKind::Renamed => "renamed",
            HistoryKind::Listed => "listed",
            HistoryKind::Unlisted => "unlisted",
            HistoryKind::Archived => "archived",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "joined" => HistoryKind::Joined,
            "left" => HistoryKind::Left,
            "removed" => HistoryKind::Removed,
            "facilitator_added" => HistoryKind::FacilitatorAdded,
            "facilitator_removed" => HistoryKind::FacilitatorRemoved,
            "renamed" => HistoryKind::Renamed,
            "listed" => HistoryKind::Listed,
            "unlisted" => HistoryKind::Unlisted,
            "archived" => HistoryKind::Archived,
            _ => return None,
        })
    }
}

/// A group row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_by: Option<UserId>,
    pub created_at_ms: i64,
    /// Raw JSON, owned by the meetings work.
    pub meeting_json: Option<String>,
    /// The group's own limit on who may invite (never wider than the
    /// instance's setting).
    pub who_can_invite: Option<WhoCanInvite>,
    pub listed: bool,
    /// Raw JSON, owned by the listing work.
    pub listing_json: Option<String>,
    pub max_participants: Option<i64>,
    pub archived_at_ms: Option<i64>,
    pub archived_by: Option<UserId>,
    pub delete_after_ms: Option<i64>,
    pub facilitator_offer_user: Option<UserId>,
    pub facilitator_offer_until_ms: Option<i64>,
}

impl Group {
    pub fn is_archived(&self) -> bool {
        self.archived_at_ms.is_some()
    }
}

macro_rules! group_columns {
    () => {
        "g.id, g.name, g.description, g.created_by, g.created_at,
    g.meeting_json, g.settings_json, g.listed, g.listing_json, g.max_participants,
    g.archived_at, g.archived_by, g.delete_after, g.facilitator_offer_user_id,
    g.facilitator_offer_until"
    };
}

fn group_from_row(r: &AnyRow) -> Result<Group, sqlx::Error> {
    let settings: String = r.try_get("settings_json")?;
    let who = serde_json::from_str::<serde_json::Value>(&settings)
        .ok()
        .and_then(|v| {
            v.get("who_can_invite")
                .and_then(|w| w.as_str())
                .and_then(WhoCanInvite::parse)
        });
    Ok(Group {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        description: r.try_get("description")?,
        created_by: r
            .try_get::<Option<String>, _>("created_by")?
            .map(UserId::new),
        created_at_ms: r.try_get("created_at")?,
        meeting_json: r.try_get("meeting_json")?,
        who_can_invite: who,
        listed: r.try_get::<i64, _>("listed")? != 0,
        listing_json: r.try_get("listing_json")?,
        max_participants: r.try_get("max_participants")?,
        archived_at_ms: r.try_get("archived_at")?,
        archived_by: r
            .try_get::<Option<String>, _>("archived_by")?
            .map(UserId::new),
        delete_after_ms: r.try_get("delete_after")?,
        facilitator_offer_user: r
            .try_get::<Option<String>, _>("facilitator_offer_user_id")?
            .map(UserId::new),
        facilitator_offer_until_ms: r.try_get("facilitator_offer_until")?,
    })
}

fn settings_json(who: Option<WhoCanInvite>) -> String {
    match who {
        Some(w) => serde_json::json!({ "who_can_invite": w.as_str() }).to_string(),
        None => "{}".to_owned(),
    }
}

// ---- Groups -----------------------------------------------------------------

/// Insert a group and return its id. The creator's participant row is
/// added separately ([`add_participant`]).
pub async fn insert_group<'e>(
    e: impl Executor<'e, Database = Any>,
    name: &str,
    description: &str,
    created_by: &UserId,
    now_ms: i64,
) -> Result<String, sqlx::Error> {
    let id = new_hex_id();
    sqlx::query(
        "INSERT INTO accountability_groups (id, name, description, created_by, created_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&id)
    .bind(name)
    .bind(description)
    .bind(created_by.as_str())
    .bind(now_ms)
    .execute(e)
    .await?;
    Ok(id)
}

pub async fn by_id<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &str,
) -> Result<Option<Group>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        group_columns!(),
        " FROM accountability_groups g WHERE g.id = $1"
    ))
    .bind(id)
    .fetch_optional(e)
    .await?
    .as_ref()
    .map(group_from_row)
    .transpose()
}

/// What a facilitator may change (`None` leaves a field alone).
#[derive(Debug, Clone, Default)]
pub struct GroupUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
    /// `Some(None)` clears the group's own setting.
    pub who_can_invite: Option<Option<WhoCanInvite>>,
    /// `Some(None)` removes the limit.
    pub max_participants: Option<Option<i64>>,
    /// Raw JSON; `Some(None)` clears the meeting.
    pub meeting_json: Option<Option<String>>,
    pub listing_json: Option<String>,
    pub listed: Option<bool>,
}

pub async fn update(
    conn: &mut sqlx::AnyConnection,
    id: &str,
    u: &GroupUpdate,
) -> Result<(), sqlx::Error> {
    if let Some(n) = &u.name {
        sqlx::query("UPDATE accountability_groups SET name = $1 WHERE id = $2")
            .bind(n)
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }
    if let Some(d) = &u.description {
        sqlx::query("UPDATE accountability_groups SET description = $1 WHERE id = $2")
            .bind(d)
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }
    if let Some(w) = u.who_can_invite {
        sqlx::query("UPDATE accountability_groups SET settings_json = $1 WHERE id = $2")
            .bind(settings_json(w))
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }
    if let Some(m) = u.max_participants {
        sqlx::query("UPDATE accountability_groups SET max_participants = $1 WHERE id = $2")
            .bind(m)
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }
    if let Some(m) = &u.meeting_json {
        sqlx::query("UPDATE accountability_groups SET meeting_json = $1 WHERE id = $2")
            .bind(m.clone())
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }
    if let Some(l) = &u.listing_json {
        sqlx::query("UPDATE accountability_groups SET listing_json = $1 WHERE id = $2")
            .bind(l)
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }
    if let Some(l) = u.listed {
        sqlx::query("UPDATE accountability_groups SET listed = $1 WHERE id = $2")
            .bind(i64::from(l))
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// Archive a group: read-only until `now + ARCHIVE_TTL_MS`, then deleted by
/// the retention worker. Unlists it, withdraws any facilitator offer and
/// voids the open alliance proposals in it (links already started stay).
/// False if it was already archived.
pub async fn archive(
    conn: &mut sqlx::AnyConnection,
    id: &str,
    by: Option<&UserId>,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE accountability_groups
         SET archived_at = $1, archived_by = $2, delete_after = $3, listed = 0,
             facilitator_offer_user_id = NULL, facilitator_offer_until = NULL
         WHERE id = $4 AND archived_at IS NULL",
    )
    .bind(now_ms)
    .bind(by.map(|u| u.as_str().to_owned()))
    .bind(now_ms.saturating_add(ARCHIVE_TTL_MS))
    .bind(id)
    .execute(&mut *conn)
    .await?;
    if r.rows_affected() != 1 {
        return Ok(false);
    }
    super::proposals::void(conn, super::proposals::VoidScope::Group(id)).await?;
    Ok(true)
}

// ---- Participants -----------------------------------------------------------

/// An active participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Participant {
    pub id: String,
    pub group_id: String,
    pub user_id: UserId,
    pub role: Role,
    pub joined_at_ms: i64,
    pub share_status: bool,
    pub share_allies: bool,
}

fn participant_from_row(r: &AnyRow) -> Result<Participant, sqlx::Error> {
    Ok(Participant {
        id: r.try_get("id")?,
        group_id: r.try_get("group_id")?,
        user_id: UserId::new(r.try_get::<String, _>("user_id")?),
        role: parse_col(r, "role", Role::parse)?,
        joined_at_ms: r.try_get("joined_at")?,
        share_status: r.try_get::<i64, _>("share_status")? != 0,
        share_allies: r.try_get::<i64, _>("share_allies")? != 0,
    })
}

macro_rules! participant_columns {
    () => {
        "p.id, p.group_id, p.user_id, p.role, p.joined_at, p.share_status, p.share_allies"
    };
}

/// `user`'s active participation in `group`, if any. Every group route
/// authorizes with this: anyone else gets a 404.
pub async fn active_participant<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    user: &UserId,
) -> Result<Option<Participant>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        participant_columns!(),
        " FROM group_participants p
         WHERE p.group_id = $1 AND p.user_id = $2 AND p.state = 'active'"
    ))
    .bind(group)
    .bind(user.as_str())
    .fetch_optional(e)
    .await?
    .as_ref()
    .map(participant_from_row)
    .transpose()
}

/// Add an active participant. Already being one surfaces as a unique
/// violation.
pub async fn add_participant<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    user: &UserId,
    role: Role,
    invited_by: Option<&UserId>,
    via: JoinedVia,
    now_ms: i64,
) -> Result<String, sqlx::Error> {
    let id = new_hex_id();
    sqlx::query(
        "INSERT INTO group_participants
            (id, group_id, user_id, role, state, invited_by, joined_via, joined_at)
         VALUES ($1, $2, $3, $4, 'active', $5, $6, $7)",
    )
    .bind(&id)
    .bind(group)
    .bind(user.as_str())
    .bind(role.as_str())
    .bind(invited_by.map(|u| u.as_str().to_owned()))
    .bind(via.as_str())
    .bind(now_ms)
    .execute(e)
    .await?;
    Ok(id)
}

/// End `user`'s participation (left or removed). Their open invitations to
/// others are voided with it (an invitation is only as good as its
/// sender's standing), and so are the open alliance proposals to or from
/// them in this group. Alliances, and links already started, are not
/// touched. False if they were not an active participant.
pub async fn end_participation(
    conn: &mut sqlx::AnyConnection,
    group: &str,
    user: &UserId,
    how: Ended,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE group_participants SET state = $1, ended_at = $2
         WHERE group_id = $3 AND user_id = $4 AND state = 'active'",
    )
    .bind(how.as_str())
    .bind(now_ms)
    .bind(group)
    .bind(user.as_str())
    .execute(&mut *conn)
    .await?;
    if r.rows_affected() == 0 {
        return Ok(false);
    }
    sqlx::query(
        "UPDATE group_invites SET used_at = $1, outcome = 'declined'
         WHERE group_id = $2 AND inviter_id = $3 AND used_at IS NULL",
    )
    .bind(now_ms)
    .bind(group)
    .bind(user.as_str())
    .execute(&mut *conn)
    .await?;
    super::proposals::void(conn, super::proposals::VoidScope::InGroup(group, user)).await?;
    Ok(true)
}

pub async fn set_role<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    user: &UserId,
    role: Role,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE group_participants SET role = $1
         WHERE group_id = $2 AND user_id = $3 AND state = 'active'",
    )
    .bind(role.as_str())
    .bind(group)
    .bind(user.as_str())
    .execute(e)
    .await?;
    Ok(r.rows_affected() == 1)
}

pub async fn count_active<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
) -> Result<i64, sqlx::Error> {
    sqlx::query(
        "SELECT COUNT(*) AS n FROM group_participants WHERE group_id = $1 AND state = 'active'",
    )
    .bind(group)
    .fetch_one(e)
    .await?
    .try_get("n")
}

pub async fn count_active_facilitators<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
) -> Result<i64, sqlx::Error> {
    sqlx::query(
        "SELECT COUNT(*) AS n FROM group_participants
         WHERE group_id = $1 AND state = 'active' AND role = 'facilitator'",
    )
    .bind(group)
    .fetch_one(e)
    .await?
    .try_get("n")
}

/// Active participants who may be told things: everyone, or just the
/// facilitators.
pub async fn active_user_ids<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    facilitators_only: bool,
) -> Result<Vec<UserId>, sqlx::Error> {
    let sql = if facilitators_only {
        "SELECT user_id FROM group_participants
         WHERE group_id = $1 AND state = 'active' AND role = 'facilitator'
         ORDER BY joined_at, id"
    } else {
        "SELECT user_id FROM group_participants
         WHERE group_id = $1 AND state = 'active' ORDER BY joined_at, id"
    };
    sqlx::query(sql)
        .bind(group)
        .fetch_all(e)
        .await?
        .iter()
        .map(|r| Ok(UserId::new(r.try_get::<String, _>("user_id")?)))
        .collect()
}

/// The participant who joined first, other than `except`.
pub async fn earliest_participant<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    except: &UserId,
) -> Result<Option<UserId>, sqlx::Error> {
    Ok(sqlx::query(
        "SELECT user_id FROM group_participants
         WHERE group_id = $1 AND state = 'active' AND user_id <> $2
         ORDER BY joined_at, id LIMIT 1",
    )
    .bind(group)
    .bind(except.as_str())
    .fetch_optional(e)
    .await?
    .map(|r| r.try_get::<String, _>("user_id"))
    .transpose()?
    .map(UserId::new))
}

/// Groups `user` is an active participant of that are not archived (what
/// the per-user limit counts).
pub async fn count_live_groups_of<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
) -> Result<i64, sqlx::Error> {
    sqlx::query(
        "SELECT COUNT(*) AS n FROM group_participants p
         JOIN accountability_groups g ON g.id = p.group_id
         WHERE p.user_id = $1 AND p.state = 'active' AND g.archived_at IS NULL",
    )
    .bind(user.as_str())
    .fetch_one(e)
    .await?
    .try_get("n")
}

/// One entry of "groups I'm in".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MyGroup {
    pub group: Group,
    pub role: Role,
    pub participant_count: i64,
}

pub async fn groups_of<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
) -> Result<Vec<MyGroup>, sqlx::Error> {
    let rows = sqlx::query(concat!(
        "SELECT ",
        group_columns!(),
        ", p.role AS my_role,
                (SELECT COUNT(*) FROM group_participants c
                 WHERE c.group_id = g.id AND c.state = 'active') AS participant_count
         FROM group_participants p
         JOIN accountability_groups g ON g.id = p.group_id
         WHERE p.user_id = $1 AND p.state = 'active'
         ORDER BY g.created_at, g.id"
    ))
    .bind(user.as_str())
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(MyGroup {
                group: group_from_row(r)?,
                role: parse_col(r, "my_role", Role::parse)?,
                participant_count: r.try_get("participant_count")?,
            })
        })
        .collect()
}

/// A person named in a group view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Person {
    pub user_id: UserId,
    pub display_name: String,
}

pub async fn facilitators<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
) -> Result<Vec<Person>, sqlx::Error> {
    sqlx::query(
        "SELECT u.id, u.display_name FROM group_participants p
         JOIN users u ON u.id = p.user_id
         WHERE p.group_id = $1 AND p.state = 'active' AND p.role = 'facilitator'
         ORDER BY p.joined_at, p.id",
    )
    .bind(group)
    .fetch_all(e)
    .await?
    .iter()
    .map(|r| {
        Ok(Person {
            user_id: UserId::new(r.try_get::<String, _>("id")?),
            display_name: r.try_get("display_name")?,
        })
    })
    .collect()
}

/// One roster line. Never an email address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterEntry {
    pub user_id: UserId,
    pub display_name: String,
    pub role: Role,
    pub joined_at_ms: i64,
    /// The account is disabled or being deleted: listed but unavailable.
    pub unavailable: bool,
    /// How this person and the viewer are linked as allies, if they are.
    /// The viewer's own line, and people they have no link with, say `null`.
    pub relationship: Option<Relationship>,
}

/// The alliance between the viewer and another person in the group, from
/// the viewer's side. Pending links count only as `waiting` (for safety
/// codes). Declared in the order the roster sorts them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Relationship {
    /// Each is the other's active ally.
    Partners,
    /// They are the viewer's ally.
    YourAlly,
    /// The viewer is their ally.
    TheirAlly,
    /// A link exists but is waiting for approval.
    Waiting,
}

impl Relationship {
    fn from_rank(rank: i64) -> Option<Self> {
        match rank {
            0 => Some(Self::Partners),
            1 => Some(Self::YourAlly),
            2 => Some(Self::TheirAlly),
            3 => Some(Self::Waiting),
            _ => None,
        }
    }
}

/// SQL for the rank of the link between the viewer and `u.id`: 0 to 3 as
/// [`Relationship`], 4 for none. `l1` is the viewer's link to them as
/// member, `l2` theirs to the viewer.
macro_rules! rank_sql {
    () => {
        "(CASE
            WHEN l1.state = 'active' AND l2.state = 'active' THEN 0
            WHEN l1.state = 'active' THEN 1
            WHEN l2.state = 'active' THEN 2
            WHEN l1.state IS NOT NULL OR l2.state IS NOT NULL THEN 3
            ELSE 4 END)"
    };
}

/// Cursor numbers are `rank * RANK_SCALE + joined_at`: ms since 1970 stays
/// below the scale until the year 5138.
const RANK_SCALE: i64 = 100_000_000_000_000;

/// A page of results and the cursor for the next one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

/// Cursors are `<number>:<id>`; anything else is not one.
pub fn parse_cursor(s: &str) -> Option<(i64, String)> {
    let (n, id) = s.split_once(':')?;
    let ok = !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric());
    if !ok {
        return None;
    }
    Some((n.parse().ok()?, id.to_owned()))
}

/// `%`, `_` and `\` in a user's search text are literal.
fn like_pattern(q: &str) -> String {
    let mut out = String::from("%");
    for c in q.trim().to_lowercase().chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

/// The roster, [`PAGE_SIZE`] at a time: people the `viewer` has an alliance
/// with first (partners, then their allies, then people they are allies of,
/// then links waiting for safety codes), everyone else after, each group
/// oldest participant first. The order is the server's, so it holds across
/// pages. `q` filters on display name.
pub async fn roster<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    viewer: &UserId,
    q: Option<&str>,
    cursor: Option<(i64, String)>,
) -> Result<Page<RosterEntry>, sqlx::Error> {
    let (after, after_id) = cursor.unwrap_or((i64::MIN, String::new()));
    let pattern = like_pattern(q.unwrap_or(""));
    let rows = sqlx::query(concat!(
        "SELECT * FROM (
            SELECT p.id AS pid, p.user_id, p.role, p.joined_at, u.display_name, u.disabled,
                   u.deletion_requested_at,
                   CAST(",
        rank_sql!(),
        " AS BIGINT) AS rank
            FROM group_participants p JOIN users u ON u.id = p.user_id
            LEFT JOIN ally_links l1 ON l1.member_id = $2 AND l1.ally_id = u.id
                 AND l1.state <> 'removed' AND u.id <> $2
            LEFT JOIN ally_links l2 ON l2.ally_id = $2 AND l2.member_id = u.id
                 AND l2.state <> 'removed' AND u.id <> $2
            WHERE p.group_id = $1 AND p.state = 'active'
              AND LOWER(u.display_name) LIKE $3 ESCAPE '\\'
         ) r
         WHERE (rank * $6 + joined_at > $4 OR (rank * $6 + joined_at = $4 AND pid > $5))
         ORDER BY rank, joined_at, pid
         LIMIT $7"
    ))
    .bind(group)
    .bind(viewer.as_str())
    .bind(pattern)
    .bind(after)
    .bind(after_id)
    .bind(RANK_SCALE)
    .bind(PAGE_SIZE + 1)
    .fetch_all(e)
    .await?;
    let mut items = Vec::new();
    let mut last = None;
    for r in rows.iter().take(PAGE_SIZE as usize) {
        let joined_at_ms: i64 = r.try_get("joined_at")?;
        let pid: String = r.try_get("pid")?;
        let rank: i64 = r.try_get("rank")?;
        last = Some(format!("{}:{pid}", rank * RANK_SCALE + joined_at_ms));
        items.push(RosterEntry {
            user_id: UserId::new(r.try_get::<String, _>("user_id")?),
            display_name: r.try_get("display_name")?,
            role: parse_col(r, "role", Role::parse)?,
            joined_at_ms,
            unavailable: r.try_get::<i64, _>("disabled")? != 0
                || r.try_get::<Option<i64>, _>("deletion_requested_at")?
                    .is_some(),
            relationship: Relationship::from_rank(rank),
        });
    }
    let next_cursor = if rows.len() as i64 > PAGE_SIZE {
        last
    } else {
        None
    };
    Ok(Page { items, next_cursor })
}

/// A person in the group the viewer has an alliance with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupAlly {
    pub user_id: UserId,
    pub display_name: String,
    pub relationship: Relationship,
}

/// Most people [`allies_in_group`] returns: more than the 32 allies one
/// person can have, plus the members they support.
const ALLIES_IN_GROUP_MAX: i64 = 200;

/// The people in `group` the `viewer` is linked with (the leave
/// confirmation: "You'll stay allies with ..."). Only the viewer's own
/// alliances, so it shows nothing a roster row doesn't.
pub async fn allies_in_group<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    viewer: &UserId,
) -> Result<Vec<GroupAlly>, sqlx::Error> {
    let rows = sqlx::query(concat!(
        "SELECT * FROM (
            SELECT p.user_id, u.display_name, p.joined_at, p.id AS pid,
                   CAST(",
        rank_sql!(),
        " AS BIGINT) AS rank
            FROM group_participants p JOIN users u ON u.id = p.user_id
            LEFT JOIN ally_links l1 ON l1.member_id = $2 AND l1.ally_id = u.id
                 AND l1.state <> 'removed'
            LEFT JOIN ally_links l2 ON l2.ally_id = $2 AND l2.member_id = u.id
                 AND l2.state <> 'removed'
            WHERE p.group_id = $1 AND p.state = 'active' AND u.id <> $2
         ) r
         WHERE rank < 4
         ORDER BY rank, joined_at, pid
         LIMIT $3"
    ))
    .bind(group)
    .bind(viewer.as_str())
    .bind(ALLIES_IN_GROUP_MAX)
    .fetch_all(e)
    .await?;
    rows.iter()
        .filter_map(|r| {
            let rank: i64 = r.try_get("rank").ok()?;
            Some((r, Relationship::from_rank(rank)?))
        })
        .map(|(r, relationship)| {
            Ok(GroupAlly {
                user_id: UserId::new(r.try_get::<String, _>("user_id")?),
                display_name: r.try_get("display_name")?,
                relationship,
            })
        })
        .collect()
}

/// Most people [`search_users`] returns.
pub const USER_SEARCH_MAX: i64 = 20;

/// Instance users whose display name contains `q`, for a facilitator picking
/// people to invite: only an id and a name, and never someone already in
/// the group or whose account is disabled or being deleted. **Display names
/// only**: matching email addresses would tell the searcher whether an
/// address has an account.
pub async fn search_users<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    q: &str,
) -> Result<Vec<Person>, sqlx::Error> {
    sqlx::query(
        "SELECT u.id, u.display_name FROM users u
         WHERE LOWER(u.display_name) LIKE $2 ESCAPE '\\'
           AND u.disabled = 0 AND u.deletion_requested_at IS NULL
           AND NOT EXISTS (SELECT 1 FROM group_participants p
                           WHERE p.group_id = $1 AND p.user_id = u.id AND p.state = 'active')
         ORDER BY LOWER(u.display_name), u.id
         LIMIT $3",
    )
    .bind(group)
    .bind(like_pattern(q))
    .bind(USER_SEARCH_MAX)
    .fetch_all(e)
    .await?
    .iter()
    .map(|r| {
        Ok(Person {
            user_id: UserId::new(r.try_get::<String, _>("id")?),
            display_name: r.try_get("display_name")?,
        })
    })
    .collect()
}

// ---- History ----------------------------------------------------------------

pub async fn add_history<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    kind: HistoryKind,
    subject: Option<&UserId>,
    actor: Option<&UserId>,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO group_history (id, group_id, at, kind, subject_id, actor_id)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(new_hex_id())
    .bind(group)
    .bind(now_ms)
    .bind(kind.as_str())
    .bind(subject.map(|u| u.as_str().to_owned()))
    .bind(actor.map(|u| u.as_str().to_owned()))
    .execute(e)
    .await?;
    Ok(())
}

/// One history line. `subject` / `actor` are `None` for "someone" (the
/// account was deleted) or when the entry has no such person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: String,
    pub at_ms: i64,
    pub kind: HistoryKind,
    pub subject: Option<Person>,
    pub actor: Option<Person>,
}

/// History, newest first, [`PAGE_SIZE`] at a time.
pub async fn history<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    cursor: Option<(i64, String)>,
) -> Result<Page<HistoryEntry>, sqlx::Error> {
    let (before_at, before_id) = cursor.unwrap_or((i64::MAX, "~".to_owned()));
    let rows = sqlx::query(
        "SELECT h.id, h.at, h.kind, h.subject_id, s.display_name AS subject_name,
                h.actor_id, a.display_name AS actor_name
         FROM group_history h
         LEFT JOIN users s ON s.id = h.subject_id
         LEFT JOIN users a ON a.id = h.actor_id
         WHERE h.group_id = $1 AND (h.at < $2 OR (h.at = $2 AND h.id < $3))
         ORDER BY h.at DESC, h.id DESC
         LIMIT $4",
    )
    .bind(group)
    .bind(before_at)
    .bind(before_id)
    .bind(PAGE_SIZE + 1)
    .fetch_all(e)
    .await?;
    let person = |r: &AnyRow, id: &str, name: &str| -> Result<Option<Person>, sqlx::Error> {
        let id: Option<String> = r.try_get(id)?;
        let name: Option<String> = r.try_get(name)?;
        Ok(id.zip(name).map(|(id, display_name)| Person {
            user_id: UserId::new(id),
            display_name,
        }))
    };
    let mut items = Vec::new();
    let mut last = None;
    for r in rows.iter().take(PAGE_SIZE as usize) {
        let id: String = r.try_get("id")?;
        let at_ms: i64 = r.try_get("at")?;
        last = Some(format!("{at_ms}:{id}"));
        items.push(HistoryEntry {
            id,
            at_ms,
            kind: parse_col(r, "kind", HistoryKind::parse)?,
            subject: person(r, "subject_id", "subject_name")?,
            actor: person(r, "actor_id", "actor_name")?,
        });
    }
    let next_cursor = if rows.len() as i64 > PAGE_SIZE {
        last
    } else {
        None
    };
    Ok(Page { items, next_cursor })
}

// ---- Invites ----------------------------------------------------------------

/// An invitation, bound to one address or one user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub token_hash: String,
    pub group_id: String,
    pub inviter_id: UserId,
    pub email: Option<String>,
    pub user_id: Option<UserId>,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub used_at_ms: Option<i64>,
    pub outcome: Option<String>,
}

impl Invite {
    /// Whether `user` is who the invitation is for.
    pub fn is_for(&self, user: &UserId, email: &str) -> bool {
        self.user_id.as_ref() == Some(user) || self.email.as_deref() == Some(email)
    }
}

macro_rules! invite_columns {
    () => {
        "i.token_hash, i.group_id, i.inviter_id, i.email, i.user_id,
    i.created_at, i.expires_at, i.used_at, i.outcome"
    };
}

fn invite_from_row(r: &AnyRow) -> Result<Invite, sqlx::Error> {
    Ok(Invite {
        token_hash: r.try_get("token_hash")?,
        group_id: r.try_get("group_id")?,
        inviter_id: UserId::new(r.try_get::<String, _>("inviter_id")?),
        email: r.try_get("email")?,
        user_id: r.try_get::<Option<String>, _>("user_id")?.map(UserId::new),
        created_at_ms: r.try_get("created_at")?,
        expires_at_ms: r.try_get("expires_at")?,
        used_at_ms: r.try_get("used_at")?,
        outcome: r.try_get("outcome")?,
    })
}

pub async fn insert_invite<'e>(
    e: impl Executor<'e, Database = Any>,
    inv: &Invite,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO group_invites
            (token_hash, group_id, inviter_id, email, user_id, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&inv.token_hash)
    .bind(&inv.group_id)
    .bind(inv.inviter_id.as_str())
    .bind(inv.email.clone())
    .bind(inv.user_id.as_ref().map(|u| u.as_str().to_owned()))
    .bind(inv.created_at_ms)
    .bind(inv.expires_at_ms)
    .execute(e)
    .await?;
    Ok(())
}

/// An unused, unexpired invite by token hash.
pub async fn find_live_invite<'e>(
    e: impl Executor<'e, Database = Any>,
    token_hash: &str,
    now_ms: i64,
) -> Result<Option<Invite>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        invite_columns!(),
        " FROM group_invites i
         WHERE i.token_hash = $1 AND i.used_at IS NULL AND i.expires_at > $2"
    ))
    .bind(token_hash)
    .bind(now_ms)
    .fetch_optional(e)
    .await?
    .as_ref()
    .map(invite_from_row)
    .transpose()
}

/// Atomically close an invite (`accepted` or `declined`). True if it was
/// still live.
pub async fn close_invite<'e>(
    e: impl Executor<'e, Database = Any>,
    token_hash: &str,
    user: &UserId,
    outcome: &str,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE group_invites SET used_at = $1, used_by = $2, outcome = $3
         WHERE token_hash = $4 AND used_at IS NULL AND expires_at > $1",
    )
    .bind(now_ms)
    .bind(user.as_str())
    .bind(outcome)
    .bind(token_hash)
    .execute(e)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// Whether a live invite to `group` already exists for this address or
/// user.
pub async fn live_invite_exists<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    email: Option<&str>,
    user: Option<&UserId>,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "SELECT 1 AS x FROM group_invites
         WHERE group_id = $1 AND used_at IS NULL AND expires_at > $2
           AND (email = $3 OR user_id = $4)",
    )
    .bind(group)
    .bind(now_ms)
    .bind(email.map(str::to_owned))
    .bind(user.map(|u| u.as_str().to_owned()))
    .fetch_optional(e)
    .await?
    .is_some())
}

pub async fn count_live_invites<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    now_ms: i64,
) -> Result<i64, sqlx::Error> {
    sqlx::query(
        "SELECT COUNT(*) AS n FROM group_invites
         WHERE group_id = $1 AND used_at IS NULL AND expires_at > $2",
    )
    .bind(group)
    .bind(now_ms)
    .fetch_one(e)
    .await?
    .try_get("n")
}

/// Whether a live invite to a group that can still be joined exists for
/// `email` (an address may sign up on that strength under `invite-only`
/// registration, when the admin allows it).
pub async fn live_invite_for_email<'e>(
    e: impl Executor<'e, Database = Any>,
    email: &str,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "SELECT 1 AS x FROM group_invites i
         JOIN accountability_groups g ON g.id = i.group_id
         WHERE i.email = $1 AND i.used_at IS NULL AND i.expires_at > $2
           AND g.archived_at IS NULL",
    )
    .bind(email)
    .bind(now_ms)
    .fetch_optional(e)
    .await?
    .is_some())
}

/// An invitation as its recipient sees it (the group's name is shown only
/// after sign-in).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteForMe {
    pub invite: Invite,
    pub group_name: String,
    pub group_archived: bool,
    pub inviter_name: String,
}

/// Live invitations addressed to `user` (by id or by address).
pub async fn live_invites_for<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
    email: &str,
    now_ms: i64,
) -> Result<Vec<InviteForMe>, sqlx::Error> {
    let rows = sqlx::query(concat!(
        "SELECT ",
        invite_columns!(),
        ", g.name AS group_name, g.archived_at AS group_archived_at,
                u.display_name AS inviter_name
         FROM group_invites i
         JOIN accountability_groups g ON g.id = i.group_id
         JOIN users u ON u.id = i.inviter_id
         WHERE (i.user_id = $1 OR i.email = $2) AND i.used_at IS NULL AND i.expires_at > $3
         ORDER BY i.created_at, i.token_hash"
    ))
    .bind(user.as_str())
    .bind(email)
    .bind(now_ms)
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(InviteForMe {
                invite: invite_from_row(r)?,
                group_name: r.try_get("group_name")?,
                group_archived: r.try_get::<Option<i64>, _>("group_archived_at")?.is_some(),
                inviter_name: r.try_get("inviter_name")?,
            })
        })
        .collect()
}

/// An invitation as the group's people see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteStatus {
    /// Where it went: the address, or the invited user's display name.
    pub invited: String,
    pub invited_user_id: Option<UserId>,
    pub inviter: Option<Person>,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    /// `pending`, `accepted`, or `not_accepted` (declined or expired: the
    /// inviter is never told which).
    pub state: String,
}

/// Invitations to a group, newest first; all of them for facilitators,
/// otherwise only `only_by`'s own.
pub async fn invites_of_group<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    only_by: Option<&UserId>,
    now_ms: i64,
    limit: i64,
) -> Result<Vec<InviteStatus>, sqlx::Error> {
    let rows = match only_by {
        None => {
            sqlx::query(
                "SELECT i.email, i.user_id, i.created_at, i.expires_at, i.used_at,
                i.outcome, t.display_name AS target_name, i.inviter_id,
                b.display_name AS inviter_name
         FROM group_invites i
         LEFT JOIN users t ON t.id = i.user_id
         LEFT JOIN users b ON b.id = i.inviter_id
         WHERE i.group_id = $1
         ORDER BY i.created_at DESC, i.token_hash DESC LIMIT $2",
            )
            .bind(group)
            .bind(limit)
            .fetch_all(e)
            .await?
        }
        Some(by) => {
            sqlx::query(
                "SELECT i.email, i.user_id, i.created_at, i.expires_at, i.used_at,
                i.outcome, t.display_name AS target_name, i.inviter_id,
                b.display_name AS inviter_name
         FROM group_invites i
         LEFT JOIN users t ON t.id = i.user_id
         LEFT JOIN users b ON b.id = i.inviter_id
         WHERE i.group_id = $1 AND i.inviter_id = $3
         ORDER BY i.created_at DESC, i.token_hash DESC LIMIT $2",
            )
            .bind(group)
            .bind(limit)
            .bind(by.as_str())
            .fetch_all(e)
            .await?
        }
    };
    rows.iter()
        .map(|r| {
            let email: Option<String> = r.try_get("email")?;
            let target_name: Option<String> = r.try_get("target_name")?;
            let used_at: Option<i64> = r.try_get("used_at")?;
            let outcome: Option<String> = r.try_get("outcome")?;
            let expires_at_ms: i64 = r.try_get("expires_at")?;
            let state = match (used_at, outcome.as_deref()) {
                (Some(_), Some("accepted")) => "accepted",
                (Some(_), _) => "not_accepted",
                (None, _) if expires_at_ms <= now_ms => "not_accepted",
                (None, _) => "pending",
            };
            let inviter_id: Option<String> = r.try_get("inviter_id")?;
            let inviter_name: Option<String> = r.try_get("inviter_name")?;
            Ok(InviteStatus {
                invited: email.or(target_name).unwrap_or_default(),
                invited_user_id: r.try_get::<Option<String>, _>("user_id")?.map(UserId::new),
                inviter: inviter_id
                    .zip(inviter_name)
                    .map(|(id, display_name)| Person {
                        user_id: UserId::new(id),
                        display_name,
                    }),
                created_at_ms: r.try_get("created_at")?,
                expires_at_ms,
                state: state.to_owned(),
            })
        })
        .collect()
}

// ---- Facilitator offer (§9) -------------------------------------------------

/// Offer the facilitator role to `user` until `until_ms`.
pub async fn set_facilitator_offer<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    user: &UserId,
    until_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE accountability_groups
         SET facilitator_offer_user_id = $1, facilitator_offer_until = $2 WHERE id = $3",
    )
    .bind(user.as_str())
    .bind(until_ms)
    .bind(group)
    .execute(e)
    .await?;
    Ok(())
}

pub async fn clear_facilitator_offer<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE accountability_groups
         SET facilitator_offer_user_id = NULL, facilitator_offer_until = NULL WHERE id = $1",
    )
    .bind(group)
    .execute(e)
    .await?;
    Ok(())
}

// ---- Admin view (§11): metadata only ---------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminGroupRow {
    pub id: String,
    pub name: String,
    pub participant_count: i64,
    pub facilitators: Vec<Person>,
    /// Active groups with no facilitator (GROUPS.md §9).
    pub no_facilitator: bool,
    pub listed: bool,
    pub created_at_ms: i64,
    pub archived_at_ms: Option<i64>,
    pub delete_after_ms: Option<i64>,
}

/// Every group, newest first. Counts, names and facilitators only: no
/// roster, no description, nothing inside a group.
pub async fn list_for_admin(e: &sqlx::AnyPool) -> Result<Vec<AdminGroupRow>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT g.id, g.name, g.listed, g.created_at, g.archived_at, g.delete_after,
                (SELECT COUNT(*) FROM group_participants c
                 WHERE c.group_id = g.id AND c.state = 'active') AS participant_count
         FROM accountability_groups g ORDER BY g.created_at DESC, g.id",
    )
    .fetch_all(e)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let id: String = r.try_get("id")?;
        let facilitators = facilitators(e, &id).await?;
        out.push(AdminGroupRow {
            no_facilitator: facilitators.is_empty()
                && r.try_get::<Option<i64>, _>("archived_at")?.is_none(),
            facilitators,
            participant_count: r.try_get("participant_count")?,
            name: r.try_get("name")?,
            listed: r.try_get::<i64, _>("listed")? != 0,
            created_at_ms: r.try_get("created_at")?,
            archived_at_ms: r.try_get("archived_at")?,
            delete_after_ms: r.try_get("delete_after")?,
            id,
        });
    }
    Ok(out)
}

// ---- Account purge and retention (§9, §18) ---------------------------------

/// Run first in the account purge ([`super::deletion::delete_rows`]), in its
/// transaction, before the generic per-table statements remove `user`'s
/// participant rows and anonymize their history entries.
///
/// For each live group where `user` is the last active facilitator: the
/// participant who joined first is offered the role for [`OFFER_TTL_MS`]
/// (returned, so they can be told), or, if nobody else is left, the group is
/// archived. Returns `(group, offered)` pairs.
pub async fn before_user_purge(
    conn: &mut sqlx::AnyConnection,
    user: &UserId,
    now_ms: i64,
) -> Result<Vec<(String, UserId)>, sqlx::Error> {
    let groups: Vec<String> = sqlx::query(
        "SELECT p.group_id FROM group_participants p
         JOIN accountability_groups g ON g.id = p.group_id
         WHERE p.user_id = $1 AND p.state = 'active' AND p.role = 'facilitator'
           AND g.archived_at IS NULL",
    )
    .bind(user.as_str())
    .fetch_all(&mut *conn)
    .await?
    .iter()
    .map(|r| r.try_get("group_id"))
    .collect::<Result<_, _>>()?;
    let mut offered = Vec::new();
    for g in groups {
        let others: i64 = sqlx::query(
            "SELECT COUNT(*) AS n FROM group_participants
             WHERE group_id = $1 AND state = 'active' AND role = 'facilitator' AND user_id <> $2",
        )
        .bind(&g)
        .bind(user.as_str())
        .fetch_one(&mut *conn)
        .await?
        .try_get("n")?;
        if others > 0 {
            continue;
        }
        match earliest_participant(&mut *conn, &g, user).await? {
            Some(next) => {
                set_facilitator_offer(&mut *conn, &g, &next, now_ms.saturating_add(OFFER_TTL_MS))
                    .await?;
                // Without a facilitator the group is unlisted (§9).
                sqlx::query("UPDATE accountability_groups SET listed = 0 WHERE id = $1")
                    .bind(&g)
                    .execute(&mut *conn)
                    .await?;
                super::group_listing::void_open(&mut *conn, &g, now_ms).await?;
                offered.push((g, next));
            }
            None => {
                archive(&mut *conn, &g, None, now_ms).await?;
                add_history(&mut *conn, &g, HistoryKind::Archived, None, None, now_ms).await?;
            }
        }
    }
    Ok(offered)
}

/// What the retention pass removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepSummary {
    pub groups_deleted: u64,
    /// Join requests and meeting notices past their retention.
    pub requests_deleted: u64,
    pub offers_expired: u64,
    pub invites_deleted: u64,
}

/// Invitations are kept this long after they expire, so inviters can see
/// "Not accepted".
pub const INVITE_KEEP_MS: i64 = 30 * 24 * 3600 * 1000;

/// The retention worker's part (GROUPS.md §9, §18): delete groups 30 days
/// after archiving (participants, history and invites go with them through
/// the foreign keys; `ally_links.origin_group_id` becomes NULL and nothing
/// else about an alliance changes), end facilitator offers nobody accepted
/// (the group continues without facilitators, unlisted), and forget old
/// invitations.
pub async fn sweep(
    conn: &mut sqlx::AnyConnection,
    now_ms: i64,
) -> Result<SweepSummary, sqlx::Error> {
    let groups_deleted = sqlx::query(
        "DELETE FROM accountability_groups
         WHERE archived_at IS NOT NULL AND delete_after <= $1",
    )
    .bind(now_ms)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    sqlx::query(
        "UPDATE group_join_requests SET state = 'void', decided_at = $1
         WHERE state = 'open' AND group_id IN
            (SELECT id FROM accountability_groups
             WHERE facilitator_offer_until IS NOT NULL AND facilitator_offer_until <= $1)",
    )
    .bind(now_ms)
    .execute(&mut *conn)
    .await?;
    let offers_expired = sqlx::query(
        "UPDATE accountability_groups
         SET facilitator_offer_user_id = NULL, facilitator_offer_until = NULL, listed = 0
         WHERE facilitator_offer_until IS NOT NULL AND facilitator_offer_until <= $1",
    )
    .bind(now_ms)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    let invites_deleted = sqlx::query("DELETE FROM group_invites WHERE expires_at < $1")
        .bind(now_ms.saturating_sub(INVITE_KEEP_MS))
        .execute(&mut *conn)
        .await?
        .rows_affected();
    let requests_deleted = super::group_listing::sweep(&mut *conn, now_ms).await?;
    Ok(SweepSummary {
        requests_deleted,
        groups_deleted,
        offers_expired,
        invites_deleted,
    })
}
