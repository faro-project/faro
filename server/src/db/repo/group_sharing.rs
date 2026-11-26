//! Opt-in sharing with a group and pairing suggestions (docs/GROUPS.md
//! §8.2, §8.5, §15). Only SQL and the pure status rule live here; the
//! routes are in [`crate::api::group_sharing`].
//!
//! **Nothing here counts people by what they share.** No query in this
//! module (or any route that uses it) returns how many participants have
//! opted in to anything: a status is looked up for named people only, and a
//! person who hasn't shared is `not_shared`, the same as one who never did.
//!
//! **Nothing here records who acted on a suggestion** beyond each person's
//! own private dismissal flag, which no facilitator route reads.

use crate::tokens::new_hex_id;
use faro_proto::UserId;
use serde::{Deserialize, Serialize};
use sqlx::{Any, Executor, Row};
use std::collections::HashMap;

// ---- Status dot ----------------------------------------------------------------

/// The dot beside a participant's name (§8.2). Built only from liveness
/// metadata the server already has: never ratings, flags or tamper details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusDot {
    MonitoringOn,
    Paused,
    NotCheckedIn,
    NoComputer,
    /// They haven't chosen to show it (or turned it off again).
    NotShared,
}

/// What the server knows about one of a person's active computers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceFact {
    pub last_seen_ms: Option<i64>,
    pub last_state: Option<String>,
    /// The computer said goodbye (Faro was uninstalled or shut down).
    pub goodbye: bool,
}

/// The dot for someone who shares their status. A computer is *checked in*
/// when it was heard from within `grace_ms` (the same grace the liveness
/// monitor uses) and hasn't said goodbye.
pub fn dot_for(devices: &[DeviceFact], now_ms: i64, grace_ms: i64) -> StatusDot {
    if devices.is_empty() {
        return StatusDot::NoComputer;
    }
    let fresh: Vec<&DeviceFact> = devices
        .iter()
        .filter(|d| {
            !d.goodbye
                && d.last_seen_ms
                    .is_some_and(|seen| now_ms.saturating_sub(seen) <= grace_ms)
        })
        .collect();
    if fresh.is_empty() {
        StatusDot::NotCheckedIn
    } else if fresh
        .iter()
        .all(|d| d.last_state.as_deref() == Some("paused"))
    {
        StatusDot::Paused
    } else {
        StatusDot::MonitoringOn
    }
}

/// `$first, $first+1, ...` for `n` bound values.
fn placeholders(first: usize, n: usize) -> String {
    (first..first + n)
        .map(|i| format!("${i}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The dot of each of `ids` (people on one page of the roster) as the group
/// sees it. Anyone who isn't sharing their status is `not_shared`, and
/// their computers are never read.
pub async fn statuses<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    ids: &[UserId],
    now_ms: i64,
    grace_ms: i64,
) -> Result<HashMap<UserId, StatusDot>, sqlx::Error> {
    let mut out: HashMap<UserId, StatusDot> = ids
        .iter()
        .map(|id| (id.clone(), StatusDot::NotShared))
        .collect();
    if ids.is_empty() {
        return Ok(out);
    }
    let sql = format!(
        "SELECT p.user_id, d.id AS device_id, d.last_seen_at, d.last_state, d.goodbye_at
         FROM group_participants p
         LEFT JOIN devices d ON d.owner_user_id = p.user_id AND d.status = 'active'
         WHERE p.group_id = $1 AND p.state = 'active' AND p.share_status = 1
           AND p.user_id IN ({})",
        placeholders(2, ids.len())
    );
    let mut q = sqlx::query(sqlx::AssertSqlSafe(sql)).bind(group);
    for id in ids {
        q = q.bind(id.as_str());
    }
    let mut facts: HashMap<UserId, Vec<DeviceFact>> = HashMap::new();
    for r in q.fetch_all(e).await? {
        let user = UserId::new(r.try_get::<String, _>("user_id")?);
        let list = facts.entry(user).or_default();
        if r.try_get::<Option<String>, _>("device_id")?.is_some() {
            list.push(DeviceFact {
                last_seen_ms: r.try_get("last_seen_at")?,
                last_state: r.try_get("last_state")?,
                goodbye: r.try_get::<Option<i64>, _>("goodbye_at")?.is_some(),
            });
        }
    }
    for (user, devices) in facts {
        out.insert(user, dot_for(&devices, now_ms, grace_ms));
    }
    Ok(out)
}

// ---- Sharing -------------------------------------------------------------------

/// Set the caller's two choices in this group. Returns false if they are
/// not an active participant.
pub async fn set_sharing<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    user: &UserId,
    share_status: bool,
    share_allies: bool,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE group_participants SET share_status = $3, share_allies = $4
         WHERE group_id = $1 AND user_id = $2 AND state = 'active'",
    )
    .bind(group)
    .bind(user.as_str())
    .bind(i64::from(share_status))
    .bind(i64::from(share_allies))
    .execute(e)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// Whether `user` shows their allies in this group (`None`: not an active
/// participant).
pub async fn shares_allies<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    user: &UserId,
) -> Result<Option<bool>, sqlx::Error> {
    sqlx::query(
        "SELECT share_allies FROM group_participants
         WHERE group_id = $1 AND user_id = $2 AND state = 'active'",
    )
    .bind(group)
    .bind(user.as_str())
    .fetch_optional(e)
    .await?
    .map(|r| Ok(r.try_get::<i64, _>("share_allies")? != 0))
    .transpose()
}

/// Which way a shared link runs, from the sharer's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedSide {
    /// The listed person is the sharer's ally.
    Ally,
    /// The sharer is the listed person's ally.
    Supports,
}

/// Someone in the group linked to a person who shares their allies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedAlly {
    pub user_id: UserId,
    pub display_name: String,
    pub side: SharedSide,
}

/// More than the 32 allies one person can have, plus the people they
/// support.
const SHARED_ALLIES_MAX: i64 = 200;

/// The people in `group` linked to `sharer` by an **active** link, where
/// both are active participants. The caller checks `share_allies` first.
pub async fn shared_allies<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    sharer: &UserId,
) -> Result<Vec<SharedAlly>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT * FROM (
            SELECT u.id AS other_id, u.display_name, 0 AS side
            FROM ally_links l
            JOIN group_participants p ON p.user_id = l.ally_id AND p.group_id = $1
                 AND p.state = 'active'
            JOIN users u ON u.id = l.ally_id
            WHERE l.member_id = $2 AND l.state = 'active'
            UNION ALL
            SELECT u.id AS other_id, u.display_name, 1 AS side
            FROM ally_links l
            JOIN group_participants p ON p.user_id = l.member_id AND p.group_id = $1
                 AND p.state = 'active'
            JOIN users u ON u.id = l.member_id
            WHERE l.ally_id = $2 AND l.state = 'active'
         ) x
         ORDER BY side, display_name, other_id
         LIMIT $3",
    )
    .bind(group)
    .bind(sharer.as_str())
    .bind(SHARED_ALLIES_MAX)
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(SharedAlly {
                user_id: UserId::new(r.try_get::<String, _>("other_id")?),
                display_name: r.try_get("display_name")?,
                side: if r.try_get::<i64, _>("side")? == 0 {
                    SharedSide::Ally
                } else {
                    SharedSide::Supports
                },
            })
        })
        .collect()
}

// ---- Pairing suggestions -------------------------------------------------------

/// A person on a card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardPerson {
    pub user_id: UserId,
    pub display_name: String,
}

/// A suggestion as a facilitator sees what they posted: the pair and when,
/// never whether anyone acted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostedSuggestion {
    pub id: String,
    pub a: CardPerson,
    pub b: CardPerson,
    pub created_at_ms: i64,
}

/// A suggestion as one of the two people sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Card {
    pub id: String,
    /// The other person.
    pub other: CardPerson,
    pub created_at_ms: i64,
}

/// `(user_a, user_b)` in the order they are stored.
pub fn ordered(a: &UserId, b: &UserId) -> (String, String) {
    if a.as_str() <= b.as_str() {
        (a.as_str().to_owned(), b.as_str().to_owned())
    } else {
        (b.as_str().to_owned(), a.as_str().to_owned())
    }
}

/// Store a suggestion unless this pair already has one (in either order,
/// dismissed or not, so a repeat tells the facilitator nothing). True if it
/// was new.
pub async fn add_suggestion<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    facilitator: &UserId,
    a: &UserId,
    b: &UserId,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let (user_a, user_b) = ordered(a, b);
    let r = sqlx::query(
        "INSERT INTO pairing_suggestions
            (id, group_id, facilitator_id, user_a, user_b, created_at)
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
    )
    .bind(new_hex_id())
    .bind(group)
    .bind(facilitator.as_str())
    .bind(user_a)
    .bind(user_b)
    .bind(now_ms)
    .execute(e)
    .await?;
    Ok(r.rows_affected() > 0)
}

const POSTED_MAX: i64 = 500;

/// What facilitators posted, newest first. No dismissal or outcome.
pub async fn posted<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
) -> Result<Vec<PostedSuggestion>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT s.id, s.created_at, s.user_a, ua.display_name AS name_a,
                s.user_b, ub.display_name AS name_b
         FROM pairing_suggestions s
         JOIN users ua ON ua.id = s.user_a
         JOIN users ub ON ub.id = s.user_b
         WHERE s.group_id = $1
         ORDER BY s.created_at DESC, s.id
         LIMIT $2",
    )
    .bind(group)
    .bind(POSTED_MAX)
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(PostedSuggestion {
                id: r.try_get("id")?,
                a: CardPerson {
                    user_id: UserId::new(r.try_get::<String, _>("user_a")?),
                    display_name: r.try_get("name_a")?,
                },
                b: CardPerson {
                    user_id: UserId::new(r.try_get::<String, _>("user_b")?),
                    display_name: r.try_get("name_b")?,
                },
                created_at_ms: r.try_get("created_at")?,
            })
        })
        .collect()
}

/// Withdraw a suggestion (a facilitator). True if it existed in this group.
pub async fn delete_suggestion<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    id: &str,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query("DELETE FROM pairing_suggestions WHERE id = $1 AND group_id = $2")
        .bind(id)
        .bind(group)
        .execute(e)
        .await?;
    Ok(r.rows_affected() > 0)
}

const CARDS_MAX: i64 = 50;

/// The caller's own cards: suggestions naming them that they haven't
/// dismissed, where the other person is still an active participant.
pub async fn my_cards<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    me: &UserId,
) -> Result<Vec<Card>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT s.id, s.created_at, u.id AS other_id, u.display_name
         FROM pairing_suggestions s
         JOIN users u ON u.id = CASE WHEN s.user_a = $2 THEN s.user_b ELSE s.user_a END
         JOIN group_participants p ON p.user_id = u.id AND p.group_id = $1
              AND p.state = 'active'
         WHERE s.group_id = $1
           AND ((s.user_a = $2 AND s.dismissed_a = 0) OR (s.user_b = $2 AND s.dismissed_b = 0))
         ORDER BY s.created_at DESC, s.id
         LIMIT $3",
    )
    .bind(group)
    .bind(me.as_str())
    .bind(CARDS_MAX)
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(Card {
                id: r.try_get("id")?,
                other: CardPerson {
                    user_id: UserId::new(r.try_get::<String, _>("other_id")?),
                    display_name: r.try_get("display_name")?,
                },
                created_at_ms: r.try_get("created_at")?,
            })
        })
        .collect()
}

/// Dismiss the caller's side of a suggestion. False if it doesn't name them.
pub async fn dismiss<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    id: &str,
    me: &UserId,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE pairing_suggestions
         SET dismissed_a = CASE WHEN user_a = $3 THEN 1 ELSE dismissed_a END,
             dismissed_b = CASE WHEN user_b = $3 THEN 1 ELSE dismissed_b END
         WHERE id = $1 AND group_id = $2 AND (user_a = $3 OR user_b = $3)",
    )
    .bind(id)
    .bind(group)
    .bind(me.as_str())
    .execute(e)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// Which of `ids` are active participants of `group`.
pub async fn active_among<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    ids: &[&UserId],
) -> Result<Vec<UserId>, sqlx::Error> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let sql = format!(
        "SELECT user_id FROM group_participants
         WHERE group_id = $1 AND state = 'active' AND user_id IN ({})",
        placeholders(2, ids.len())
    );
    let mut q = sqlx::query(sqlx::AssertSqlSafe(sql)).bind(group);
    for id in ids {
        q = q.bind(id.as_str());
    }
    q.fetch_all(e)
        .await?
        .iter()
        .map(|r| Ok(UserId::new(r.try_get::<String, _>("user_id")?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const GRACE: i64 = 1000;

    fn dev(seen: Option<i64>, state: Option<&str>, goodbye: bool) -> DeviceFact {
        DeviceFact {
            last_seen_ms: seen,
            last_state: state.map(str::to_owned),
            goodbye,
        }
    }

    #[test]
    fn the_dot_comes_only_from_check_ins() {
        assert_eq!(dot_for(&[], 5000, GRACE), StatusDot::NoComputer);
        assert_eq!(
            dot_for(&[dev(None, None, false)], 5000, GRACE),
            StatusDot::NotCheckedIn
        );
        assert_eq!(
            dot_for(&[dev(Some(100), Some("active"), false)], 5000, GRACE),
            StatusDot::NotCheckedIn
        );
        assert_eq!(
            dot_for(&[dev(Some(4500), Some("active"), false)], 5000, GRACE),
            StatusDot::MonitoringOn
        );
        assert_eq!(
            dot_for(&[dev(Some(4500), Some("paused"), false)], 5000, GRACE),
            StatusDot::Paused
        );
        assert_eq!(
            dot_for(&[dev(Some(4500), Some("active"), true)], 5000, GRACE),
            StatusDot::NotCheckedIn
        );
        // One computer monitoring is enough.
        assert_eq!(
            dot_for(
                &[
                    dev(Some(4500), Some("paused"), false),
                    dev(Some(4900), Some("idle"), false)
                ],
                5000,
                GRACE
            ),
            StatusDot::MonitoringOn
        );
    }
}
