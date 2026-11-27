//! `group_join_requests`, `group_meeting_prefs` and the directory query
//! (docs/GROUPS.md §8.4, §8.8, §15). Only SQL lives here; the rules are in
//! [`crate::api::group_listing`] and [`crate::meetings`].
//!
//! **Join-request privacy.** A request ends as `not_accepted` (a facilitator
//! declined, or [`REQUEST_TTL_MS`] passed), `void` (the group was unlisted or
//! closed), `withdrawn` or `accepted`. The requester is shown "Not accepted"
//! for the first two, for the same window ([`COOLDOWN_MS`] after the request
//! would have expired), with the same fields, so a decline can't be told
//! from an expiry (§8.8).

use super::groups::{Page, PAGE_SIZE};
use crate::tokens::new_hex_id;
use faro_proto::UserId;
use sqlx::{Any, Executor, Row};

/// An open request expires after 14 days.
pub const REQUEST_TTL_MS: i64 = 14 * 24 * 3600 * 1000;
/// After a request is not accepted the person can't ask the same group for
/// 30 days (counted from when it would have expired, whatever ended it).
pub const COOLDOWN_MS: i64 = 30 * 24 * 3600 * 1000;
/// Open requests one person may have at once.
pub const MAX_OPEN_REQUESTS: i64 = 5;
/// Decided requests are deleted this long after they were decided.
pub const KEEP_MS: i64 = 90 * 24 * 3600 * 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    pub id: String,
    pub group_id: String,
    pub user_id: UserId,
    pub state: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

macro_rules! cols {
    () => {
        "r.id, r.group_id, r.user_id, r.state, r.created_at, r.expires_at"
    };
}

fn request_from_row(r: &sqlx::any::AnyRow) -> Result<JoinRequest, sqlx::Error> {
    Ok(JoinRequest {
        id: r.try_get("id")?,
        group_id: r.try_get("group_id")?,
        user_id: UserId::new(r.try_get::<String, _>("user_id")?),
        state: r.try_get("state")?,
        created_at_ms: r.try_get("created_at")?,
        expires_at_ms: r.try_get("expires_at")?,
    })
}

/// Requests that ran out of time become `not_accepted` (run before reading
/// or writing a person's requests in a write transaction).
pub async fn expire_due(
    conn: &mut sqlx::AnyConnection,
    now_ms: i64,
    user: Option<&UserId>,
) -> Result<u64, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE group_join_requests
         SET state = 'not_accepted', decided_at = expires_at, cooldown_until = expires_at + $1
         WHERE state = 'open' AND expires_at <= $2
           AND ($3 = '' OR user_id = $3)",
    )
    .bind(COOLDOWN_MS)
    .bind(now_ms)
    .bind(user.map_or(String::new(), |u| u.as_str().to_owned()))
    .execute(&mut *conn)
    .await?;
    Ok(r.rows_affected())
}

/// The group is unlisted, closed or out of facilitators: open requests end,
/// without a cool-down.
pub async fn void_open(
    conn: &mut sqlx::AnyConnection,
    group: &str,
    now_ms: i64,
) -> Result<u64, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE group_join_requests SET state = 'void', decided_at = $1
         WHERE group_id = $2 AND state = 'open'",
    )
    .bind(now_ms)
    .bind(group)
    .execute(&mut *conn)
    .await?;
    Ok(r.rows_affected())
}

pub async fn count_open<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
    now_ms: i64,
) -> Result<i64, sqlx::Error> {
    sqlx::query(
        "SELECT COUNT(*) AS n FROM group_join_requests
         WHERE user_id = $1 AND state = 'open' AND expires_at > $2",
    )
    .bind(user.as_str())
    .bind(now_ms)
    .fetch_one(e)
    .await?
    .try_get("n")
}

/// Whether `user` asked `group` and was not accepted less than 30 days ago.
pub async fn in_cooldown<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    user: &UserId,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let n: i64 = sqlx::query(
        "SELECT COUNT(*) AS n FROM group_join_requests
         WHERE group_id = $1 AND user_id = $2 AND state = 'not_accepted' AND cooldown_until > $3",
    )
    .bind(group)
    .bind(user.as_str())
    .bind(now_ms)
    .fetch_one(e)
    .await?
    .try_get("n")?;
    Ok(n > 0)
}

pub async fn open_of<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    user: &UserId,
    now_ms: i64,
) -> Result<Option<JoinRequest>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        cols!(),
        " FROM group_join_requests r
         WHERE r.group_id = $1 AND r.user_id = $2 AND r.state = 'open' AND r.expires_at > $3"
    ))
    .bind(group)
    .bind(user.as_str())
    .bind(now_ms)
    .fetch_optional(e)
    .await?
    .as_ref()
    .map(request_from_row)
    .transpose()
}

pub async fn insert<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    user: &UserId,
    note_id: Option<&str>,
    now_ms: i64,
) -> Result<JoinRequest, sqlx::Error> {
    let id = new_hex_id();
    let expires = now_ms.saturating_add(REQUEST_TTL_MS);
    sqlx::query(
        "INSERT INTO group_join_requests (id, group_id, user_id, state, created_at, expires_at,
                                          note_blob_ref)
         VALUES ($1, $2, $3, 'open', $4, $5, $6)",
    )
    .bind(&id)
    .bind(group)
    .bind(user.as_str())
    .bind(now_ms)
    .bind(expires)
    .bind(note_id)
    .execute(e)
    .await?;
    Ok(JoinRequest {
        id,
        group_id: group.to_owned(),
        user_id: user.clone(),
        state: "open".to_owned(),
        created_at_ms: now_ms,
        expires_at_ms: expires,
    })
}

/// An open, unexpired request by id.
pub async fn open_by_id<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &str,
    now_ms: i64,
) -> Result<Option<JoinRequest>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        cols!(),
        " FROM group_join_requests r
         WHERE r.id = $1 AND r.state = 'open' AND r.expires_at > $2"
    ))
    .bind(id)
    .bind(now_ms)
    .fetch_optional(e)
    .await?
    .as_ref()
    .map(request_from_row)
    .transpose()
}

/// End an open request: `accepted`, or `not_accepted` (with the cool-down).
/// False if it was no longer open.
pub async fn decide(
    conn: &mut sqlx::AnyConnection,
    id: &str,
    accepted: bool,
    by: &UserId,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let r = if accepted {
        sqlx::query(
            "UPDATE group_join_requests
             SET state = 'accepted', decided_at = $1, decided_by = $2
             WHERE id = $3 AND state = 'open' AND expires_at > $1",
        )
        .bind(now_ms)
        .bind(by.as_str())
        .bind(id)
        .execute(&mut *conn)
        .await?
    } else {
        sqlx::query(
            "UPDATE group_join_requests
             SET state = 'not_accepted', decided_at = $1, decided_by = $2,
                 cooldown_until = expires_at + $4
             WHERE id = $3 AND state = 'open' AND expires_at > $1",
        )
        .bind(now_ms)
        .bind(by.as_str())
        .bind(id)
        .bind(COOLDOWN_MS)
        .execute(&mut *conn)
        .await?
    };
    Ok(r.rows_affected() == 1)
}

/// The person takes their request back: it is removed, with no cool-down.
pub async fn withdraw<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    user: &UserId,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE group_join_requests SET state = 'withdrawn', decided_at = $1
         WHERE group_id = $2 AND user_id = $3 AND state = 'open' AND expires_at > $1",
    )
    .bind(now_ms)
    .bind(group)
    .bind(user.as_str())
    .execute(e)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// One open request as a facilitator sees it: a display name and when it
/// was made, nothing else about the person.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FacilitatorEntry {
    pub id: String,
    pub display_name: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    /// The signed, encrypted note to the facilitators
    /// (`GET /v1/group-messages/{id}`), if the person wrote one.
    #[serde(default)]
    pub note_id: Option<String>,
}

/// Open requests to `group`, oldest first.
pub async fn list_for_group<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    cursor: Option<(i64, String)>,
    now_ms: i64,
) -> Result<Page<FacilitatorEntry>, sqlx::Error> {
    let (after_at, after_id) = cursor.unwrap_or((i64::MIN, String::new()));
    let rows = sqlx::query(
        "SELECT r.id, r.created_at, r.expires_at, r.note_blob_ref, u.display_name
         FROM group_join_requests r JOIN users u ON u.id = r.user_id
         WHERE r.group_id = $1 AND r.state = 'open' AND r.expires_at > $2
           AND (r.created_at > $3 OR (r.created_at = $3 AND r.id > $4))
         ORDER BY r.created_at, r.id LIMIT $5",
    )
    .bind(group)
    .bind(now_ms)
    .bind(after_at)
    .bind(after_id)
    .bind(PAGE_SIZE + 1)
    .fetch_all(e)
    .await?;
    let mut items = Vec::new();
    let mut last = None;
    for r in rows.iter().take(PAGE_SIZE as usize) {
        let created: i64 = r.try_get("created_at")?;
        let id: String = r.try_get("id")?;
        last = Some(format!("{created}:{id}"));
        items.push(FacilitatorEntry {
            id,
            display_name: r.try_get("display_name")?,
            created_at_ms: created,
            expires_at_ms: r.try_get("expires_at")?,
            note_id: r.try_get("note_blob_ref")?,
        });
    }
    let next_cursor = if rows.len() as i64 > PAGE_SIZE {
        last
    } else {
        None
    };
    Ok(Page { items, next_cursor })
}

/// A person's own request, for them: `open` with the group's name, or
/// `not_accepted` with nothing else (a decline, an expiry and an unlisting
/// look the same).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MyRequest {
    pub id: String,
    pub group_id: String,
    /// `open` or `not_accepted`.
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<i64>,
}

/// The caller's open requests, and the ones that ended without them being
/// accepted until they could ask again.
pub async fn mine<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
    now_ms: i64,
) -> Result<Vec<MyRequest>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT r.id, r.group_id, r.state, r.created_at, r.expires_at, g.name
         FROM group_join_requests r JOIN accountability_groups g ON g.id = r.group_id
         WHERE r.user_id = $1 AND r.state IN ('open', 'not_accepted', 'void')
           AND r.expires_at + $2 > $3
         ORDER BY r.created_at DESC, r.id",
    )
    .bind(user.as_str())
    .bind(COOLDOWN_MS)
    .bind(now_ms)
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| {
            let state: String = r.try_get("state")?;
            let expires: i64 = r.try_get("expires_at")?;
            let open = state == "open" && expires > now_ms;
            Ok(MyRequest {
                id: r.try_get("id")?,
                group_id: r.try_get("group_id")?,
                state: if open { "open" } else { "not_accepted" }.to_owned(),
                group_name: open.then(|| r.try_get("name")).transpose()?,
                created_at_ms: open.then(|| r.try_get("created_at")).transpose()?,
                expires_at_ms: open.then_some(expires),
            })
        })
        .collect()
}

// ---- Directory ---------------------------------------------------------------

/// A listed group, from the database. [`crate::api::group_listing`] turns it
/// into what a listing shows.
#[derive(Debug, Clone)]
pub struct DirectoryRow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_at_ms: i64,
    pub meeting_json: Option<String>,
    pub listing_json: Option<String>,
    pub facilitator_names: Vec<String>,
    /// A participant limit is set and reached. The count itself never
    /// leaves the database.
    pub full: bool,
    /// The viewer asked and the request is open.
    pub requested: bool,
    /// The viewer is already in the group (their own information).
    pub joined: bool,
}

fn like(q: &str) -> String {
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

/// Listed groups, oldest first, [`PAGE_SIZE`] at a time; `q` matches the
/// name and description.
pub async fn directory<'e>(
    e: impl Executor<'e, Database = Any> + Copy,
    q: Option<&str>,
    cursor: Option<(i64, String)>,
    viewer: &UserId,
    now_ms: i64,
) -> Result<Page<DirectoryRow>, sqlx::Error> {
    let (after_at, after_id) = cursor.unwrap_or((i64::MIN, String::new()));
    let pattern = like(q.unwrap_or(""));
    let rows = sqlx::query(
        "SELECT g.id, g.name, g.description, g.created_at, g.meeting_json, g.listing_json,
                CASE WHEN g.max_participants IS NOT NULL AND g.max_participants <=
                     (SELECT COUNT(*) FROM group_participants c
                      WHERE c.group_id = g.id AND c.state = 'active')
                     THEN 1 ELSE 0 END AS is_full,
                (SELECT COUNT(*) FROM group_join_requests r
                 WHERE r.group_id = g.id AND r.user_id = $1 AND r.state = 'open'
                   AND r.expires_at > $2) AS requested,
                (SELECT COUNT(*) FROM group_participants m
                 WHERE m.group_id = g.id AND m.user_id = $1 AND m.state = 'active') AS joined
         FROM accountability_groups g
         WHERE g.listed = 1 AND g.archived_at IS NULL
           AND (LOWER(g.name) LIKE $3 ESCAPE '\\' OR LOWER(g.description) LIKE $3 ESCAPE '\\')
           AND (g.created_at > $4 OR (g.created_at = $4 AND g.id > $5))
         ORDER BY g.created_at, g.id LIMIT $6",
    )
    .bind(viewer.as_str())
    .bind(now_ms)
    .bind(pattern)
    .bind(after_at)
    .bind(after_id)
    .bind(PAGE_SIZE + 1)
    .fetch_all(e)
    .await?;
    let mut items = Vec::new();
    let mut last = None;
    for r in rows.iter().take(PAGE_SIZE as usize) {
        let id: String = r.try_get("id")?;
        let created: i64 = r.try_get("created_at")?;
        last = Some(format!("{created}:{id}"));
        let names = super::groups::facilitators(e, &id)
            .await?
            .into_iter()
            .map(|p| p.display_name)
            .collect();
        items.push(DirectoryRow {
            name: r.try_get("name")?,
            description: r.try_get("description")?,
            created_at_ms: created,
            meeting_json: r.try_get("meeting_json")?,
            listing_json: r.try_get("listing_json")?,
            facilitator_names: names,
            full: r.try_get::<i64, _>("is_full")? != 0,
            requested: r.try_get::<i64, _>("requested")? != 0,
            joined: r.try_get::<i64, _>("joined")? != 0,
            id,
        });
    }
    let next_cursor = if rows.len() as i64 > PAGE_SIZE {
        last
    } else {
        None
    };
    Ok(Page { items, next_cursor })
}

// ---- Meeting reminder preferences -------------------------------------------

/// A person's stored choices for one group's reminders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeetingPrefs {
    pub reminders: bool,
    /// `None` follows the default (on up to 32 participants, off above).
    pub email: Option<bool>,
}

impl Default for MeetingPrefs {
    fn default() -> Self {
        MeetingPrefs {
            reminders: true,
            email: None,
        }
    }
}

pub async fn get_prefs<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    user: &UserId,
) -> Result<MeetingPrefs, sqlx::Error> {
    Ok(sqlx::query(
        "SELECT reminders, email FROM group_meeting_prefs WHERE group_id = $1 AND user_id = $2",
    )
    .bind(group)
    .bind(user.as_str())
    .fetch_optional(e)
    .await?
    .map(|r| -> Result<_, sqlx::Error> {
        Ok(MeetingPrefs {
            reminders: r.try_get::<i64, _>("reminders")? != 0,
            email: r.try_get::<Option<i64>, _>("email")?.map(|v| v != 0),
        })
    })
    .transpose()?
    .unwrap_or_default())
}

pub async fn set_prefs<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    user: &UserId,
    p: MeetingPrefs,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO group_meeting_prefs (group_id, user_id, reminders, email)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (group_id, user_id) DO UPDATE SET reminders = $3, email = $4",
    )
    .bind(group)
    .bind(user.as_str())
    .bind(i64::from(p.reminders))
    .bind(p.email.map(i64::from))
    .execute(e)
    .await?;
    Ok(())
}

/// A participant to remind, with their stored choices.
#[derive(Debug, Clone)]
pub struct Remindee {
    pub user_id: UserId,
    pub prefs: MeetingPrefs,
}

/// Groups with a meeting schedule that are still open: `(id, meeting_json)`.
pub async fn groups_with_meetings<'e>(
    e: impl Executor<'e, Database = Any>,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    sqlx::query(
        "SELECT id, meeting_json FROM accountability_groups
         WHERE archived_at IS NULL AND meeting_json IS NOT NULL ORDER BY id",
    )
    .fetch_all(e)
    .await?
    .iter()
    .map(|r| Ok((r.try_get("id")?, r.try_get("meeting_json")?)))
    .collect()
}

/// Active participants of `group` with their reminder choices.
pub async fn remindees<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
) -> Result<Vec<Remindee>, sqlx::Error> {
    sqlx::query(
        "SELECT p.user_id, m.reminders, m.email
         FROM group_participants p
         LEFT JOIN group_meeting_prefs m ON m.group_id = p.group_id AND m.user_id = p.user_id
         WHERE p.group_id = $1 AND p.state = 'active' ORDER BY p.joined_at, p.id",
    )
    .bind(group)
    .fetch_all(e)
    .await?
    .iter()
    .map(|r| {
        Ok(Remindee {
            user_id: UserId::new(r.try_get::<String, _>("user_id")?),
            prefs: MeetingPrefs {
                reminders: r.try_get::<Option<i64>, _>("reminders")?.unwrap_or(1) != 0,
                email: r.try_get::<Option<i64>, _>("email")?.map(|v| v != 0),
            },
        })
    })
    .collect()
}

/// Retention (GROUPS.md §18): requests that ran out end, decided ones go 90
/// days later, and meeting-reminder notices after 90 days. Returns the rows
/// deleted.
pub async fn sweep(conn: &mut sqlx::AnyConnection, now_ms: i64) -> Result<u64, sqlx::Error> {
    expire_due(&mut *conn, now_ms, None).await?;
    let old = now_ms.saturating_sub(KEEP_MS);
    let a =
        sqlx::query("DELETE FROM group_join_requests WHERE state <> 'open' AND decided_at < $1")
            .bind(old)
            .execute(&mut *conn)
            .await?
            .rows_affected();
    let b = sqlx::query(
        "DELETE FROM group_notices WHERE kind = 'meeting_reminder' AND created_at < $1",
    )
    .bind(old)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    Ok(a + b)
}
