//! The update task: [`ClientUpdater::check`], then
//! [`ClientUpdater::check_artifacts`], on a jittered timer.

use super::core::Control;
use crate::update::artifacts::{ArtifactOutcome, Artifacts};
use crate::update::{ClientUpdater, Outcome, Settled};
use faro_proto::body::TamperSignal;
use rand::Rng;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// Longest reason put into a tamper event.
const MAX_REASON_CHARS: usize = 200;

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

/// The tamper signal for a package that failed its signature check
/// (ARCHITECTURE.md §3.7, "Binary or model integrity failure").
pub fn rejected_package_signal(version: &faro_update::Version, reason: &str) -> TamperSignal {
    let reason: String = reason.chars().take(MAX_REASON_CHARS).collect();
    TamperSignal::IntegrityFailure {
        component: format!("update package {version}: {reason}"),
    }
}

/// Check after `first`, then about every `every`, until `stop` flips. A
/// rejected package is reported to the core through `control` as tamper,
/// once per run of the service: a report lost to a restart before
/// activation is made again, and a lasting attack is reported again after
/// each restart.
///
/// After the client package, models and blocklists: what installs goes to
/// the core through `artifacts`' swaps, unless a client install has just
/// started (the service stops soon, and the new one checks again).
pub async fn update_loop(
    updater: ClientUpdater,
    artifacts: Artifacts,
    first: Duration,
    every: Duration,
    control: mpsc::Sender<Control>,
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
    let mut reported = std::collections::BTreeSet::new();
    let mut wait = first;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = stop.wait_for(|s| *s) => return,
        }
        if *stop.borrow() {
            return;
        }
        let outcome = updater.check().await;
        if !matches!(outcome, Ok(Outcome::Installing { .. })) {
            check_artifacts(&updater, &artifacts).await;
        }
        match outcome {
            Ok(Outcome::Installing { version }) => {
                // The install job stops this service shortly; until it
                // does, carry on as normal.
                tracing::info!(%version, "update install started");
            }
            Ok(Outcome::GaveUp { version }) => {
                tracing::warn!(%version, "not retrying an update that failed to install");
            }
            Ok(Outcome::Rejected { version, reason })
            | Ok(Outcome::PreviouslyRejected { version, reason }) => {
                if reported.insert(version.to_string()) {
                    // Before activation the core isn't reading yet; the
                    // signal waits in the channel until it is.
                    let sig = rejected_package_signal(&version, &reason);
                    if let Err(e) = control.try_send(Control::Tamper(sig)) {
                        reported.remove(&version.to_string());
                        tracing::error!(error = %e, "could not report the rejected update package");
                    }
                }
            }
            Ok(o) => tracing::debug!(outcome = ?o, "update check"),
            Err(e) => tracing::warn!(error = %e, "update check failed; will retry"),
        }
        wait = jitter(every);
    }
}

/// Models and blocklists. A signed one that fails its checks is a broken
/// release, not an attack on this computer: it is logged and skipped, and
/// the copy in use stays.
async fn check_artifacts(updater: &ClientUpdater, artifacts: &Artifacts) {
    match updater.check_artifacts(artifacts).await {
        Ok(results) => {
            for (kind, r) in results {
                match r {
                    Ok(ArtifactOutcome::Installed { version }) => {
                        tracing::info!(?kind, %version, "update installed; switching to it");
                    }
                    Ok(ArtifactOutcome::Rejected { version, reason }) => {
                        tracing::error!(?kind, %version, %reason, "update refused");
                    }
                    Ok(o) => tracing::debug!(?kind, outcome = ?o, "update check"),
                    Err(e) => {
                        tracing::warn!(?kind, error = %e, "update check failed; will retry")
                    }
                }
            }
        }
        Err(e) => tracing::warn!(error = %e, "update check failed; will retry"),
    }
}
