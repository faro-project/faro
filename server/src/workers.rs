//! In-process background workers (§4.2 "Jobs"): uptime bookkeeping, the
//! notifier and digests, the liveness monitor, retention, the
//! account-deletion purge and the update mirror.
//!
//! Every worker is a periodic loop around a `run_once`-style function that
//! reads time only through [`AppState::now_ms`] (an injectable
//! [`crate::clock::Clock`]), so tests drive the same functions with a
//! [`crate::clock::ManualClock`] instead of waiting. Loops stop promptly when
//! the shared [`CancellationToken`] is cancelled; a pass already running is
//! allowed to finish (each pass is a handful of short transactions).
//!
//! A pass that fails is logged and retried on the next tick; one bad row
//! never stops a worker.

use crate::db::repo::uptime;
use crate::error::AppError;
use crate::state::AppState;
use crate::tokens::new_hex_id;
use crate::{deletion, liveness, notify, retention};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// How often `instance_uptime.last_alive_at` is refreshed. Bounds the error
/// in downtime accounting after a crash.
pub const UPTIME_TICK: Duration = Duration::from_secs(30);

/// Two observations of the clock by this process (uptime ticks, liveness
/// passes) further apart than this mean the process was not running in
/// between, although it never restarted: the host was suspended, the VM
/// paused, or the wall clock jumped forward (a Raspberry Pi without an RTC
/// boots on a stale time and NTP corrects it later). Ticks normally come
/// every 30 s.
pub const SUSPEND_GAP_MS: i64 = 5 * 60 * 1000;

/// This process's row in `instance_uptime`, and when it last resumed.
#[derive(Debug)]
pub struct UptimeRun {
    state: std::sync::Mutex<RunState>,
}

#[derive(Debug, Clone)]
struct RunState {
    run_id: String,
    /// Start of the current stretch of uninterrupted running: the process
    /// start, or the end of the latest suspend / clock jump. This is the
    /// liveness monitor's `run_started`.
    resumed_at_ms: i64,
    /// The latest clock observation.
    last_seen_ms: i64,
    /// A detected gap `(last_alive, resumed)` not yet written to
    /// `instance_uptime` (whoever observes first detects it; the uptime
    /// tick records it).
    unrecorded_gap: Option<(i64, i64)>,
}

impl UptimeRun {
    /// Close any row a crashed predecessor left open (its `stopped_at`
    /// becomes its `last_alive_at`), then record this run's start.
    pub async fn start(state: &AppState) -> Result<Self, sqlx::Error> {
        let now = state.now_ms();
        let mut tx = state.db().begin_write().await?;
        let crashed = uptime::close_crashed(&mut *tx).await?;
        let run_id = new_hex_id();
        uptime::start(&mut *tx, &run_id, now).await?;
        tx.commit().await?;
        if crashed > 0 {
            tracing::warn!(
                "previous run did not shut down cleanly; its downtime is excluded from liveness"
            );
        }
        Ok(UptimeRun {
            state: std::sync::Mutex::new(RunState {
                run_id,
                resumed_at_ms: now,
                last_seen_ms: now,
                unrecorded_gap: None,
            }),
        })
    }

    fn snapshot(&self) -> RunState {
        match self.state.lock() {
            Ok(s) => s.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// When the current stretch of running began (see [`Self::observe`]).
    pub fn started_at_ms(&self) -> i64 {
        self.snapshot().resumed_at_ms
    }

    /// Record a clock observation at `now_ms` and return when the current
    /// stretch of running began. A gap longer than [`SUSPEND_GAP_MS`] since
    /// the previous observation is the instance's own downtime, so the
    /// stretch restarts at `now_ms` (and the liveness monitor waits a full
    /// grace period again).
    pub fn observe(&self, now_ms: i64) -> i64 {
        let mut s = match self.state.lock() {
            Ok(s) => s,
            Err(p) => p.into_inner(),
        };
        if now_ms.saturating_sub(s.last_seen_ms) > SUSPEND_GAP_MS {
            let first = s.unrecorded_gap.map_or(s.last_seen_ms, |(a, _)| a);
            s.unrecorded_gap = Some((first, now_ms));
            s.resumed_at_ms = now_ms;
        }
        // A clock stepping backwards is taken as is: the next forward step
        // is measured from here.
        s.last_seen_ms = now_ms;
        s.resumed_at_ms
    }

    /// The periodic uptime tick. After a suspend the current row is closed
    /// at its last tick and a new one starts, so `instance_uptime` shows the
    /// gap like any other downtime.
    pub async fn tick(&self, state: &AppState) -> Result<(), sqlx::Error> {
        let now = state.now_ms();
        self.observe(now);
        let gap = match self.state.lock() {
            Ok(mut s) => s.unrecorded_gap.take(),
            Err(_) => None,
        };
        if let Some((last_alive, resumed)) = gap {
            tracing::warn!(
                gap_ms = resumed - last_alive,
                "the instance was not running (host suspended or clock jumped); \
                 that gap is excluded from liveness"
            );
            let old = self.snapshot().run_id;
            let new_id = new_hex_id();
            let mut tx = state.db().begin_write().await?;
            uptime::stop(&mut *tx, &old, last_alive).await?;
            uptime::start(&mut *tx, &new_id, resumed).await?;
            tx.commit().await?;
            if let Ok(mut s) = self.state.lock() {
                s.run_id = new_id;
            }
        }
        uptime::alive(state.db().pool(), &self.snapshot().run_id, now).await
    }

    pub async fn stop(&self, state: &AppState) -> Result<(), sqlx::Error> {
        uptime::stop(state.db().pool(), &self.snapshot().run_id, state.now_ms()).await
    }
}

fn spawn_periodic<F, Fut>(
    name: &'static str,
    initial_delay: Duration,
    period: Duration,
    cancel: CancellationToken,
    mut pass: F,
) -> JoinHandle<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), AppError>> + Send,
{
    tokio::spawn(async move {
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(initial_delay) => {}
        }
        let mut every = tokio::time::interval(period);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                _ = every.tick() => {}
            }
            if let Err(e) = pass().await {
                tracing::warn!(worker = name, error = %e, "worker pass failed");
            }
        }
        tracing::debug!(worker = name, "worker stopped");
    })
}

/// Start every worker. They run until `cancel` is cancelled.
pub fn spawn_all(
    state: &AppState,
    run: Arc<UptimeRun>,
    cancel: &CancellationToken,
) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();

    {
        let (state, run) = (state.clone(), run.clone());
        handles.push(spawn_periodic(
            "uptime",
            UPTIME_TICK,
            UPTIME_TICK,
            cancel.clone(),
            move || {
                let (state, run) = (state.clone(), run.clone());
                async move { run.tick(&state).await.map_err(AppError::from) }
            },
        ));
    }
    {
        let state = state.clone();
        handles.push(spawn_periodic(
            "notifier",
            Duration::from_secs(1),
            Duration::from_secs(notify::NOTIFY_INTERVAL_SECS),
            cancel.clone(),
            move || {
                let state = state.clone();
                async move {
                    notify::dispatch(&state).await?;
                    notify::send_immediate(&state).await?;
                    Ok(())
                }
            },
        ));
    }
    {
        let state = state.clone();
        handles.push(spawn_periodic(
            "digest",
            Duration::from_secs(notify::DIGEST_CHECK_SECS),
            Duration::from_secs(notify::DIGEST_CHECK_SECS),
            cancel.clone(),
            move || {
                let state = state.clone();
                async move {
                    // Fan out first so the digest includes the latest items.
                    notify::dispatch(&state).await?;
                    notify::send_digests(&state).await.map(|_| ())
                }
            },
        ));
    }
    {
        let (state, run) = (state.clone(), run);
        handles.push(spawn_periodic(
            "liveness",
            Duration::from_secs(liveness::MONITOR_INTERVAL_SECS),
            Duration::from_secs(liveness::MONITOR_INTERVAL_SECS),
            cancel.clone(),
            move || {
                let (state, run) = (state.clone(), run.clone());
                async move { liveness::pass(&state, &run).await.map(|_| ()) }
            },
        ));
    }
    {
        let state = state.clone();
        // First pass shortly after start, so an instance restarted more
        // often than daily still prunes.
        handles.push(spawn_periodic(
            "retention",
            Duration::from_secs(60),
            Duration::from_secs(retention::RETENTION_INTERVAL_SECS),
            cancel.clone(),
            move || {
                let state = state.clone();
                async move { retention::run_once(&state).await.map(|_| ()) }
            },
        ));
    }
    {
        let state = state.clone();
        handles.push(spawn_periodic(
            "deletion",
            Duration::from_secs(deletion::PURGE_INTERVAL_SECS),
            Duration::from_secs(deletion::PURGE_INTERVAL_SECS),
            cancel.clone(),
            move || {
                let state = state.clone();
                async move { deletion::run_once(&state).await.map(|_| ()) }
            },
        ));
    }
    if let Some(mirror) = state.updates().cloned() {
        let state = state.clone();
        // An online mirror checks upstream every `refresh_secs`; an
        // air-gapped one only re-reads what `updates import` wrote, often.
        let period = if mirror.upstream().is_some() {
            state.config().updates.refresh_secs
        } else {
            60
        };
        handles.push(spawn_periodic(
            "updates",
            Duration::from_secs(5),
            Duration::from_secs(period),
            cancel.clone(),
            move || {
                let (state, mirror) = (state.clone(), mirror.clone());
                async move {
                    let channel =
                        crate::config::parse_update_channel(&state.settings().updates.channel)
                            .map_err(|e| AppError::internal(e.to_string()))?;
                    match mirror.refresh(state.now_ms(), &channel).await {
                        Ok(_) | Err(crate::updates::MirrorError::Busy) => Ok(()),
                        Err(e) => Err(AppError::internal(format!("update mirror: {e}"))),
                    }
                }
            },
        ));
    }
    handles
}

/// Cancel and wait for the workers, giving up after `timeout`.
pub async fn shutdown(cancel: &CancellationToken, handles: Vec<JoinHandle<()>>, timeout: Duration) {
    cancel.cancel();
    let all = async {
        for h in handles {
            let _ = h.await;
        }
    };
    if tokio::time::timeout(timeout, all).await.is_err() {
        tracing::warn!("background workers did not stop in time");
    }
}
