//! The retention worker (§8): hard-deletes expired rows and blobs, daily.
//!
//! | What | Window |
//! |---|---|
//! | event headers (`events`, `event_recipients`) | `event_header_days` (90) |
//! | event and report ciphertext (blob files + `blobs` rows), and report rows | `blob_days` (30) |
//! | alerts (and their notifications), closed liveness episodes, removed ally links, old uptime rows | `alert_days` (90) |
//! | expired sessions, magic links, setup tokens, enroll codes, invites | at expiry |
//! | token hashes of a deleted account's computers (`deleted_device_tokens`) | 365 days |
//! | orphan blob files (no `blobs` row, older than a day) | immediately |
//!
//! **Per-member windows.** Members may choose *shorter* retention, never
//! longer (§8). A member's override is clamped to
//! `[min(MIN_MEMBER_DAYS, instance), instance]`: the lower bound stops a
//! member from shrinking retention to minutes so that a flagged report is
//! gone before an ally has had a chance to open it (§4.3: members cannot
//! delete sent reports early).
//!
//! A window applies **only to data received after it took effect** (its
//! `*_since` time). Everything received earlier keeps the instance window,
//! so shortening retention never makes already-sent items disappear sooner
//! than the rule they were sent under ([`ranges`]). Allies who switched
//! normal alerts off would not even hear about the change, so a retroactive
//! cut would be exactly the quiet early deletion §4.3 forbids.
//!
//! **Order.** Blob rows are deleted in the database first, then the files:
//! a crash in between leaves orphan files (swept on the next run), never
//! rows pointing at missing files.
//!
//! Unblurred frames are never stored anywhere (§3.5), so retention only ever
//! applies to ciphertext and metadata.

use crate::blob::BlobId;
use crate::config::RetentionConfig;
use crate::error::AppError;
use crate::state::AppState;
use faro_proto::UserId;
use serde::{Deserialize, Serialize};
use sqlx::Row;

/// How often the worker runs.
pub const RETENTION_INTERVAL_SECS: u64 = 24 * 3600;
/// Shortest window a member may choose (if the instance allows that long).
pub const MIN_MEMBER_DAYS: u32 = 7;
/// Orphan blob files younger than this are left alone: they may belong to
/// an upload whose database transaction is still in flight.
pub const ORPHAN_GRACE_MS: i64 = 24 * 3600 * 1000;
const DAY_MS: i64 = 24 * 3600 * 1000;
const BLOB_BATCH: i64 = 500;

/// A member's stored override (each field optional).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionOverride {
    pub event_header_days: Option<u32>,
    pub blob_days: Option<u32>,
    pub alert_days: Option<u32>,
}

fn clamp_days(choice: Option<u32>, instance: u32) -> u32 {
    let lo = MIN_MEMBER_DAYS.min(instance);
    choice.map_or(instance, |c| c.clamp(lo, instance))
}

/// The windows that apply to a member: the instance's, shortened by their
/// override within the allowed range.
pub fn effective(instance: &RetentionConfig, o: &RetentionOverride) -> RetentionConfig {
    RetentionConfig {
        event_header_days: clamp_days(o.event_header_days, instance.event_header_days),
        blob_days: clamp_days(o.blob_days, instance.blob_days),
        alert_days: clamp_days(o.alert_days, instance.alert_days),
    }
}

fn days_to_u32(v: Option<i64>) -> Option<u32> {
    v.and_then(|d| u32::try_from(d).ok())
}

/// When each of a member's windows took its current value (Unix ms).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WindowsSince {
    pub event_header: Option<i64>,
    pub blob: Option<i64>,
    pub alert: Option<i64>,
}

impl WindowsSince {
    /// After a change from `old` to `new` effective windows at `now_ms`: a
    /// window whose value changed takes effect now, the others keep theirs.
    pub fn after_change(
        self,
        old: &RetentionConfig,
        new: &RetentionConfig,
        now_ms: i64,
    ) -> WindowsSince {
        let pick = |o: u32, n: u32, since: Option<i64>| {
            if o == n {
                Some(since.unwrap_or(now_ms))
            } else {
                Some(now_ms)
            }
        };
        WindowsSince {
            event_header: pick(
                old.event_header_days,
                new.event_header_days,
                self.event_header,
            ),
            blob: pick(old.blob_days, new.blob_days, self.blob),
            alert: pick(old.alert_days, new.alert_days, self.alert),
        }
    }
}

pub async fn get_override(
    state: &AppState,
    member: &UserId,
) -> Result<RetentionOverride, AppError> {
    Ok(load_override(state.db().pool(), member).await?)
}

/// When a member's windows took effect (all `None` without an override).
pub async fn load_since<'e>(
    e: impl sqlx::Executor<'e, Database = sqlx::Any>,
    member: &UserId,
) -> Result<WindowsSince, sqlx::Error> {
    let row = sqlx::query(
        "SELECT event_header_since, blob_since, alert_since FROM retention_overrides
         WHERE member_id = $1",
    )
    .bind(member.as_str())
    .fetch_optional(e)
    .await?;
    let Some(r) = row else {
        return Ok(WindowsSince::default());
    };
    Ok(WindowsSince {
        event_header: r.try_get("event_header_since")?,
        blob: r.try_get("blob_since")?,
        alert: r.try_get("alert_since")?,
    })
}

/// A member's stored override, on any executor (e.g. inside a transaction).
pub async fn load_override<'e>(
    e: impl sqlx::Executor<'e, Database = sqlx::Any>,
    member: &UserId,
) -> Result<RetentionOverride, sqlx::Error> {
    let row = sqlx::query(
        "SELECT event_header_days, blob_days, alert_days FROM retention_overrides
         WHERE member_id = $1",
    )
    .bind(member.as_str())
    .fetch_optional(e)
    .await?;
    let Some(r) = row else {
        return Ok(RetentionOverride::default());
    };
    Ok(RetentionOverride {
        event_header_days: days_to_u32(r.try_get("event_header_days")?),
        blob_days: days_to_u32(r.try_get("blob_days")?),
        alert_days: days_to_u32(r.try_get("alert_days")?),
    })
}

/// Store a member's override, already clamped by the caller, with when each
/// window took effect.
pub async fn store_override<'e>(
    e: impl sqlx::Executor<'e, Database = sqlx::Any>,
    member: &UserId,
    o: &RetentionOverride,
    since: &WindowsSince,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO retention_overrides (member_id, event_header_days, blob_days, alert_days,
                                          updated_at, event_header_since, blob_since,
                                          alert_since)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (member_id) DO UPDATE SET
            event_header_days = excluded.event_header_days, blob_days = excluded.blob_days,
            alert_days = excluded.alert_days, updated_at = excluded.updated_at,
            event_header_since = excluded.event_header_since,
            blob_since = excluded.blob_since, alert_since = excluded.alert_since",
    )
    .bind(member.as_str())
    .bind(o.event_header_days.map(i64::from))
    .bind(o.blob_days.map(i64::from))
    .bind(o.alert_days.map(i64::from))
    .bind(now_ms)
    .bind(since.event_header)
    .bind(since.blob)
    .bind(since.alert)
    .execute(e)
    .await?;
    Ok(())
}

/// Names of the windows that are shorter in `new` than in `old`, in a fixed
/// order (`event_header_days`, `blob_days`, `alert_days`).
pub fn shortened(old: &RetentionConfig, new: &RetentionConfig) -> Vec<&'static str> {
    [
        (
            "event_header_days",
            old.event_header_days,
            new.event_header_days,
        ),
        ("blob_days", old.blob_days, new.blob_days),
        ("alert_days", old.alert_days, new.alert_days),
    ]
    .into_iter()
    .filter(|(_, o, n)| n < o)
    .map(|(name, _, _)| name)
    .collect()
}

/// What one pass deleted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionSummary {
    pub events: u64,
    pub blobs: u64,
    pub reports: u64,
    pub alerts: u64,
    pub notifications: u64,
    pub expired_secrets: u64,
    pub orphan_files: u64,
    pub other: u64,
}

fn cutoff(now: i64, days: u32) -> i64 {
    now.saturating_sub(i64::from(days).saturating_mul(DAY_MS))
}

/// The receive-time ranges `[from, to)` to delete for one window: anything
/// older than the instance window, plus, for a member's shorter window,
/// anything older than it **that was received after it took effect**
/// (`since`). Without an override (or `since`), only the first.
pub fn ranges(now: i64, instance_days: u32, member: Option<(u32, i64)>) -> Vec<(i64, i64)> {
    let mut out = vec![(i64::MIN, cutoff(now, instance_days))];
    if let Some((days, since)) = member {
        let to = cutoff(now, days);
        if days < instance_days && since < to {
            // Overlap with the first range is harmless (already deleted).
            out.push((since, to));
        }
    }
    out
}

/// Which members a deletion applies to: everyone without an override, or
/// one member with one.
enum Scope<'a> {
    Default,
    Member(&'a str),
}

/// One retention statement in its two fixed forms, one per [`Scope`]. Both
/// are `&'static str` built from literals by [`scoped_sql!`]: the scope
/// changes *which* constant runs, never what is spliced into it. The time
/// range is bound as `$1` (from, inclusive) and `$2` (to, exclusive), the
/// member id (member form only) as `$3`.
struct ScopedSql {
    /// For members without an override.
    default: &'static str,
    /// For one member, bound as `$3`.
    member: &'static str,
}

/// `scoped_sql!(head, time_col, member_col[, tail_default, tail_member])`:
/// `head` (ending in `WHERE` or `AND`) gets `time_col >= $1 AND time_col <
/// $2` and then `AND member_col NOT IN (overrides)` or `AND member_col =
/// $3`, then the matching tail (used for a `LIMIT` whose placeholder number
/// differs).
macro_rules! scoped_sql {
    ($head:literal, $time:literal, $col:literal) => {
        scoped_sql!($head, $time, $col, "", "")
    };
    ($head:literal, $time:literal, $col:literal, $tail_default:literal, $tail_member:literal) => {
        ScopedSql {
            default: concat!(
                $head,
                " ",
                $time,
                " >= $1 AND ",
                $time,
                " < $2 AND ",
                $col,
                " NOT IN (SELECT member_id FROM retention_overrides)",
                $tail_default
            ),
            member: concat!(
                $head,
                " ",
                $time,
                " >= $1 AND ",
                $time,
                " < $2 AND ",
                $col,
                " = $3",
                $tail_member
            ),
        }
    };
}

impl Scope<'_> {
    fn pick(&self, sql: &ScopedSql) -> &'static str {
        match self {
            Scope::Default => sql.default,
            Scope::Member(_) => sql.member,
        }
    }
}

async fn exec_scoped(
    state: &AppState,
    sql: &ScopedSql,
    (from, to): (i64, i64),
    scope: &Scope<'_>,
) -> Result<u64, AppError> {
    let mut q = sqlx::query(scope.pick(sql)).bind(from).bind(to);
    if let Scope::Member(m) = scope {
        q = q.bind(*m);
    }
    Ok(q.execute(state.db().pool()).await?.rows_affected())
}

const SELECT_EXPIRED_BLOBS: ScopedSql = scoped_sql!(
    "SELECT id FROM blobs WHERE",
    "created_at",
    "owner_member_id",
    " ORDER BY created_at LIMIT $3",
    " ORDER BY created_at LIMIT $4"
);
const DELETE_REPORTS: ScopedSql =
    scoped_sql!("DELETE FROM reports WHERE", "received_at", "member_id");
const DELETE_EVENTS: ScopedSql =
    scoped_sql!("DELETE FROM events WHERE", "received_at", "member_id");
const DELETE_ALERTS: ScopedSql = scoped_sql!("DELETE FROM alerts WHERE", "created_at", "member_id");
const DELETE_EPISODES: ScopedSql = scoped_sql!(
    "DELETE FROM liveness_episodes WHERE closed_at IS NOT NULL AND",
    "closed_at",
    "member_id"
);
const DELETE_REMOVED_LINKS: ScopedSql = scoped_sql!(
    "DELETE FROM ally_links WHERE state = 'removed' AND",
    "removed_at",
    "member_id"
);

async fn purge_blobs(
    state: &AppState,
    (from, to): (i64, i64),
    scope: &Scope<'_>,
    s: &mut RetentionSummary,
) -> Result<(), AppError> {
    loop {
        let mut q = sqlx::query(scope.pick(&SELECT_EXPIRED_BLOBS))
            .bind(from)
            .bind(to);
        if let Scope::Member(m) = scope {
            q = q.bind(*m);
        }
        let ids: Vec<String> = q
            .bind(BLOB_BATCH)
            .fetch_all(state.db().pool())
            .await?
            .iter()
            .map(|r| r.try_get("id"))
            .collect::<Result<_, _>>()?;
        if ids.is_empty() {
            return Ok(());
        }
        let mut tx = state.db().begin_write().await?;
        for id in &ids {
            // A report is useless without its ciphertext: the row goes too.
            s.reports += sqlx::query("DELETE FROM reports WHERE blob_id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            // events.blob_id is ON DELETE SET NULL: the header survives
            // until its own (longer) window.
            s.blobs += sqlx::query("DELETE FROM blobs WHERE id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
        }
        tx.commit().await?;
        for id in &ids {
            if let Some(b) = BlobId::parse(id) {
                if let Err(e) = state.blobs().delete(&b).await {
                    // Left as an orphan; the next sweep retries.
                    tracing::warn!(error = %e, "could not delete expired blob file");
                }
            }
        }
        if (ids.len() as i64) < BLOB_BATCH {
            return Ok(());
        }
    }
}

/// The ranges to delete per window kind (see [`ranges`]).
struct Plan {
    events: Vec<(i64, i64)>,
    blobs: Vec<(i64, i64)>,
    alerts: Vec<(i64, i64)>,
}

impl Plan {
    fn new(
        now: i64,
        instance: &RetentionConfig,
        member: Option<(&RetentionConfig, &WindowsSince)>,
    ) -> Plan {
        let m = |days: fn(&RetentionConfig) -> u32, since: fn(&WindowsSince) -> Option<i64>| {
            member.and_then(|(w, s)| since(s).map(|t| (days(w), t)))
        };
        Plan {
            events: ranges(
                now,
                instance.event_header_days,
                m(|w| w.event_header_days, |s| s.event_header),
            ),
            blobs: ranges(now, instance.blob_days, m(|w| w.blob_days, |s| s.blob)),
            alerts: ranges(now, instance.alert_days, m(|w| w.alert_days, |s| s.alert)),
        }
    }
}

async fn purge_scope(
    state: &AppState,
    plan: &Plan,
    scope: Scope<'_>,
    s: &mut RetentionSummary,
) -> Result<(), AppError> {
    for r in &plan.blobs {
        purge_blobs(state, *r, &scope, s).await?;
        // Reports whose blob was already gone.
        s.reports += exec_scoped(state, &DELETE_REPORTS, *r, &scope).await?;
    }
    for r in &plan.events {
        s.events += exec_scoped(state, &DELETE_EVENTS, *r, &scope).await?;
    }
    for r in &plan.alerts {
        s.alerts += exec_scoped(state, &DELETE_ALERTS, *r, &scope).await?;
        s.other += exec_scoped(state, &DELETE_EPISODES, *r, &scope).await?;
        s.other += exec_scoped(state, &DELETE_REMOVED_LINKS, *r, &scope).await?;
    }
    Ok(())
}

impl Plan {
    /// Everything, whenever it was received (account deletion).
    fn everything() -> Plan {
        let all = vec![(i64::MIN, i64::MAX)];
        Plan {
            events: all.clone(),
            blobs: all.clone(),
            alerts: all,
        }
    }
}

/// Delete all of one member's content through the same statements a
/// retention pass uses (blob rows, then their files; reports; events;
/// alerts; closed liveness episodes; removed links), whatever its age. The
/// first stage of the account-deletion purge ([`crate::deletion`]).
pub async fn purge_member(state: &AppState, member: &UserId) -> Result<RetentionSummary, AppError> {
    let mut s = RetentionSummary::default();
    purge_scope(
        state,
        &Plan::everything(),
        Scope::Member(member.as_str()),
        &mut s,
    )
    .await?;
    Ok(s)
}

/// Device tombstones of deleted accounts are kept this long (§12).
pub const DEVICE_TOMBSTONE_DAYS: u32 = 365;

/// One full retention pass.
pub async fn run_once(state: &AppState) -> Result<RetentionSummary, AppError> {
    let now = state.now_ms();
    let instance = state.settings().retention;
    let mut s = RetentionSummary::default();

    purge_scope(
        state,
        &Plan::new(now, &instance, None),
        Scope::Default,
        &mut s,
    )
    .await?;
    let overrides = sqlx::query(
        "SELECT member_id, event_header_days, blob_days, alert_days, updated_at,
                event_header_since, blob_since, alert_since
         FROM retention_overrides",
    )
    .fetch_all(state.db().pool())
    .await?;
    for r in &overrides {
        let member: String = r.try_get("member_id")?;
        let o = RetentionOverride {
            event_header_days: days_to_u32(r.try_get("event_header_days")?),
            blob_days: days_to_u32(r.try_get("blob_days")?),
            alert_days: days_to_u32(r.try_get("alert_days")?),
        };
        let updated_at: i64 = r.try_get("updated_at")?;
        let since = WindowsSince {
            event_header: Some(
                r.try_get::<Option<i64>, _>("event_header_since")?
                    .unwrap_or(updated_at),
            ),
            blob: Some(
                r.try_get::<Option<i64>, _>("blob_since")?
                    .unwrap_or(updated_at),
            ),
            alert: Some(
                r.try_get::<Option<i64>, _>("alert_since")?
                    .unwrap_or(updated_at),
            ),
        };
        let w = effective(&instance, &o);
        let plan = Plan::new(now, &instance, Some((&w, &since)));
        purge_scope(state, &plan, Scope::Member(&member), &mut s).await?;
    }

    let pool = state.db().pool();
    let alert_cut = cutoff(now, instance.alert_days);
    // Notifications outlive nothing they refer to (they cascade), but
    // delivered or suppressed rows are pruned on the alert window too.
    // That includes the emails about admin log entries; the entries
    // themselves are kept and never pruned (only an account's purge NULLs
    // the ids in them).
    s.notifications += sqlx::query("DELETE FROM notifications WHERE created_at < $1")
        .bind(alert_cut)
        .execute(pool)
        .await?
        .rows_affected();
    s.other +=
        sqlx::query("DELETE FROM instance_uptime WHERE stopped_at IS NOT NULL AND stopped_at < $1")
            .bind(alert_cut)
            .execute(pool)
            .await?
            .rows_affected();
    s.other += crate::db::repo::deletion::sweep_device_tombstones(
        pool,
        cutoff(now, DEVICE_TOMBSTONE_DAYS),
    )
    .await?;
    for sql in [
        "DELETE FROM sessions WHERE expires_at < $1",
        "DELETE FROM magic_links WHERE expires_at < $1",
        "DELETE FROM setup_tokens WHERE expires_at < $1",
        "DELETE FROM enroll_codes WHERE expires_at < $1",
        "DELETE FROM invites WHERE expires_at < $1",
    ] {
        s.expired_secrets += sqlx::query(sql)
            .bind(now)
            .execute(pool)
            .await?
            .rows_affected();
    }

    // Groups: archived ones are deleted after 30 days, unaccepted
    // facilitator offers end, old invitations go (GROUPS.md §9, §18).
    {
        let mut conn = state.db().pool().acquire().await?;
        let g = crate::db::repo::groups::sweep(&mut conn, now).await?;
        s.other += g.groups_deleted;
        s.expired_secrets += g.invites_deleted;
    }

    s.orphan_files = sweep_orphans(state, now).await?;
    tracing::info!(
        events = s.events,
        blobs = s.blobs,
        reports = s.reports,
        alerts = s.alerts,
        orphans = s.orphan_files,
        "retention pass finished"
    );
    Ok(s)
}

/// Ids looked up per query by the orphan sweep (well below SQLite's
/// 32766-parameter limit).
const ORPHAN_CHUNK: usize = 200;

/// `prefix` followed by `$1, $2, …, $n)`. Only digits, `$`, `,`, spaces and
/// the closing parenthesis are appended to the caller's constant prefix.
fn in_list_query(prefix: &'static str, n: usize) -> String {
    let mut sql = String::from(prefix);
    for i in 1..=n {
        if i > 1 {
            sql.push_str(", ");
        }
        sql.push('$');
        sql.push_str(&i.to_string());
    }
    sql.push(')');
    sql
}

/// Delete blob files that have no `blobs` row (left by a crash between the
/// file write and the database transaction).
async fn sweep_orphans(state: &AppState, now: i64) -> Result<u64, AppError> {
    let candidates = state
        .blobs()
        .list_older_than(now.saturating_sub(ORPHAN_GRACE_MS))
        .await?;
    let mut deleted = 0;
    for chunk in candidates.chunks(ORPHAN_CHUNK) {
        // SQL-SAFE: the only dynamic part is the placeholder list
        // `$1, …, $n`, generated from the integers 1..=chunk.len() (at most
        // ORPHAN_CHUNK). The blob ids themselves (file names from disk) are
        // bound parameters, never spliced into the string.
        let sql = sqlx::AssertSqlSafe(in_list_query(
            "SELECT id FROM blobs WHERE id IN (",
            chunk.len(),
        ));
        let mut q = sqlx::query(sql);
        for id in chunk {
            q = q.bind(id.as_str());
        }
        let known: std::collections::HashSet<String> = q
            .fetch_all(state.db().pool())
            .await?
            .iter()
            .map(|r| r.try_get("id"))
            .collect::<Result<_, _>>()?;
        for id in chunk {
            if !known.contains(id.as_str()) {
                state.blobs().delete(id).await?;
                deleted += 1;
            }
        }
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overrides_only_shorten_within_bounds() {
        let inst = RetentionConfig::default(); // 90 / 30 / 90
        assert_eq!(effective(&inst, &RetentionOverride::default()), inst);
        let w = effective(
            &inst,
            &RetentionOverride {
                event_header_days: Some(30),
                blob_days: Some(365),
                alert_days: Some(1),
            },
        );
        assert_eq!(w.event_header_days, 30, "shorter is allowed");
        assert_eq!(w.blob_days, 30, "never longer than the instance");
        assert_eq!(w.alert_days, MIN_MEMBER_DAYS, "never below the floor");
        // An instance shorter than the floor wins.
        let tiny = RetentionConfig {
            event_header_days: 3,
            blob_days: 2,
            alert_days: 1,
        };
        let w = effective(
            &tiny,
            &RetentionOverride {
                event_header_days: Some(1),
                blob_days: Some(1),
                alert_days: Some(1),
            },
        );
        assert_eq!((w.event_header_days, w.blob_days, w.alert_days), (3, 2, 1));
    }

    #[test]
    fn scoped_statements_are_fixed() {
        assert_eq!(
            SELECT_EXPIRED_BLOBS.member,
            "SELECT id FROM blobs WHERE created_at >= $1 AND created_at < $2 AND \
             owner_member_id = $3 ORDER BY created_at LIMIT $4"
        );
        assert_eq!(
            DELETE_EVENTS.default,
            "DELETE FROM events WHERE received_at >= $1 AND received_at < $2 AND member_id \
             NOT IN (SELECT member_id FROM retention_overrides)"
        );
        assert_eq!(
            DELETE_EPISODES.member,
            "DELETE FROM liveness_episodes WHERE closed_at IS NOT NULL AND closed_at >= $1 \
             AND closed_at < $2 AND member_id = $3"
        );
    }

    #[test]
    fn a_shorter_window_only_applies_from_when_it_was_chosen() {
        let now = 100 * DAY_MS;
        // No override: only the instance window.
        assert_eq!(ranges(now, 30, None), vec![(i64::MIN, 70 * DAY_MS)]);
        // 7 days chosen on day 90: data from day 90 on goes after 7 days;
        // older data keeps the 30-day window.
        assert_eq!(
            ranges(now, 30, Some((7, 90 * DAY_MS))),
            vec![(i64::MIN, 70 * DAY_MS), (90 * DAY_MS, 93 * DAY_MS)]
        );
        // Chosen today: nothing extra yet.
        assert_eq!(
            ranges(now, 30, Some((7, now))),
            vec![(i64::MIN, 70 * DAY_MS)]
        );
        // Not actually shorter: nothing extra.
        assert_eq!(
            ranges(now, 30, Some((30, 0))),
            vec![(i64::MIN, 70 * DAY_MS)]
        );
        // Long ago: the member window applies to everything still stored.
        assert_eq!(
            ranges(now, 30, Some((7, 0))),
            vec![(i64::MIN, 70 * DAY_MS), (0, 93 * DAY_MS)]
        );
    }

    #[test]
    fn since_moves_only_for_windows_that_change() {
        let inst = RetentionConfig::default();
        let mut shorter = inst.clone();
        shorter.blob_days = 7;
        let s = WindowsSince::default().after_change(&inst, &shorter, 5);
        assert_eq!(
            s,
            WindowsSince {
                event_header: Some(5),
                blob: Some(5),
                alert: Some(5)
            }
        );
        // Re-saving the same values keeps when they took effect.
        let s2 = s.after_change(&shorter, &shorter, 9);
        assert_eq!(s2, s);
        let mut shorter2 = shorter.clone();
        shorter2.alert_days = 10;
        let s3 = s.after_change(&shorter, &shorter2, 9);
        assert_eq!((s3.blob, s3.alert), (Some(5), Some(9)));
    }

    #[test]
    fn in_list_is_placeholders_only() {
        assert_eq!(in_list_query("X IN (", 3), "X IN ($1, $2, $3)");
        let q = in_list_query("", ORPHAN_CHUNK);
        assert!(q
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'$' | b',' | b' ' | b')')));
    }

    #[test]
    fn shortened_windows() {
        let a = RetentionConfig::default();
        let mut b = a.clone();
        assert!(shortened(&a, &b).is_empty());
        b.blob_days -= 1;
        assert_eq!(shortened(&a, &b), vec!["blob_days"]);
        assert!(shortened(&b, &a).is_empty(), "longer is not shorter");
    }

    #[test]
    fn cutoff_saturates() {
        assert_eq!(cutoff(10 * DAY_MS, 3), 7 * DAY_MS);
        assert_eq!(cutoff(i64::MIN + 5, 10), i64::MIN);
    }
}
