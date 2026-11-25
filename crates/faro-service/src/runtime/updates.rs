//! The update task: [`ClientUpdater::check`] on a jittered timer.

use crate::update::{ClientUpdater, Outcome, Settled};
use rand::Rng;
use std::time::Duration;
use tokio::sync::watch;

/// When the first check runs, if not overridden: a few minutes after start,
/// so a freshly updated service settles first, and so many computers
/// rebooted at once don't hit the instance together.
pub fn default_first_check() -> Duration {
    Duration::from_secs(rand::thread_rng().gen_range(120..=600))
}

/// `every`, ±10 %.
fn jitter(every: Duration) -> Duration {
    every.mul_f64(rand::thread_rng().gen_range(0.9..=1.1))
}

/// Check after `first`, then about every `every`, until `stop` flips.
pub async fn update_loop(
    updater: ClientUpdater,
    first: Duration,
    every: Duration,
    mut stop: watch::Receiver<bool>,
) {
    match updater.settle_pending() {
        Ok(Some(Settled::Installed { version })) => {
            tracing::info!(%version, "now running the update");
        }
        Ok(Some(Settled::Failed { version, failures })) => {
            tracing::warn!(%version, failures, "the last update attempt did not install");
        }
        Ok(None) => {}
        Err(e) => tracing::warn!(error = %e, "cannot read the update record"),
    }
    let mut wait = first;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = stop.wait_for(|s| *s) => return,
        }
        if *stop.borrow() {
            return;
        }
        match updater.check().await {
            Ok(Outcome::Installing { version }) => {
                // The install job stops this service shortly; until it
                // does, carry on as normal.
                tracing::info!(%version, "update install started");
            }
            Ok(Outcome::GaveUp { version }) => {
                tracing::warn!(%version, "not retrying an update that failed to install");
            }
            Ok(o) => tracing::debug!(outcome = ?o, "update check"),
            Err(e) => tracing::warn!(error = %e, "update check failed; will retry"),
        }
        wait = jitter(every);
    }
}
