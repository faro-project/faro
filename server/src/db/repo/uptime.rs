//! `instance_uptime`: when this instance was running (§3.7).
//!
//! The liveness monitor must never blame a device for silence that overlaps
//! the instance's own downtime. Each server run writes one row, refreshes
//! `last_alive_at` periodically, and sets `stopped_at` on a clean shutdown.
//! After a crash `stopped_at` stays NULL; the next start closes that row
//! with `stopped_at := last_alive_at`, the last moment the instance was
//! known to be up (accurate to one tick).

use sqlx::{Any, Executor, Row};

/// Close rows left open by a crashed run (`stopped_at := last_alive_at`).
pub async fn close_crashed<'e>(e: impl Executor<'e, Database = Any>) -> Result<u64, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE instance_uptime SET stopped_at = last_alive_at WHERE stopped_at IS NULL",
    )
    .execute(e)
    .await?;
    Ok(r.rows_affected())
}

pub async fn start<'e>(
    e: impl Executor<'e, Database = Any>,
    run_id: &str,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO instance_uptime (id, started_at, last_alive_at) VALUES ($1, $2, $2)")
        .bind(run_id)
        .bind(now_ms)
        .execute(e)
        .await?;
    Ok(())
}

pub async fn alive<'e>(
    e: impl Executor<'e, Database = Any>,
    run_id: &str,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE instance_uptime SET last_alive_at = $1 WHERE id = $2")
        .bind(now_ms)
        .bind(run_id)
        .execute(e)
        .await?;
    Ok(())
}

pub async fn stop<'e>(
    e: impl Executor<'e, Database = Any>,
    run_id: &str,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE instance_uptime SET last_alive_at = $1, stopped_at = $1 WHERE id = $2")
        .bind(now_ms)
        .bind(run_id)
        .execute(e)
        .await?;
    Ok(())
}

/// One recorded run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UptimeRow {
    pub started_at_ms: i64,
    pub last_alive_at_ms: i64,
    pub stopped_at_ms: Option<i64>,
}

/// All runs, oldest first (for tests and diagnostics).
pub async fn list<'e>(e: impl Executor<'e, Database = Any>) -> Result<Vec<UptimeRow>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT started_at, last_alive_at, stopped_at FROM instance_uptime
         ORDER BY started_at, id",
    )
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(UptimeRow {
                started_at_ms: r.try_get("started_at")?,
                last_alive_at_ms: r.try_get("last_alive_at")?,
                stopped_at_ms: r.try_get("stopped_at")?,
            })
        })
        .collect()
}
