//! The HTTP(S) listener, background workers and graceful shutdown.
//!
//! [`run`] serves plain HTTP: for `--dev`, or behind a TLS-terminating
//! reverse proxy / tunnel (`--behind-proxy`: Caddy, nginx, Traefik,
//! Cloudflare Tunnel, Tailscale Funnel). [`run_tls`] serves the same router
//! over built-in TLS ([`crate::tls`]: ACME or static certificates).
//!
//! Both record this run in `instance_uptime` ([`UptimeRun`]), start the
//! background workers ([`crate::workers`]) and, on shutdown, drain in-flight
//! requests, stop the workers, record the clean stop and close the pool.

use crate::router;
use crate::state::AppState;
use crate::tls::{TlsListener, TlsMode};
use crate::workers::{self, UptimeRun};
use axum::serve::ListenerExt;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

pub use crate::workers::UPTIME_TICK;

/// How long workers get to finish their current pass on shutdown.
const WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("cannot listen: {0}")]
    Io(#[from] std::io::Error),
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Tls(#[from] crate::tls::TlsError),
}

/// Serve plain HTTP on `listener` until `shutdown` resolves.
pub async fn run(
    state: AppState,
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ServeError> {
    run_inner(state, Transport::Plain(listener), shutdown).await
}

/// Serve HTTPS on `listener` with `mode` until `shutdown` resolves.
pub async fn run_tls(
    state: AppState,
    listener: TcpListener,
    mode: TlsMode,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ServeError> {
    run_inner(state, Transport::Tls(listener, mode), shutdown).await
}

enum Transport {
    Plain(TcpListener),
    Tls(TcpListener, TlsMode),
}

async fn run_inner(
    state: AppState,
    transport: Transport,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ServeError> {
    let run = Arc::new(UptimeRun::start(&state).await?);
    let cancel = CancellationToken::new();
    let handles = workers::spawn_all(&state, run.clone(), &cancel);

    let app = router::build(state.clone());
    let served = match transport {
        Transport::Plain(listener) => {
            if let Ok(addr) = listener.local_addr() {
                tracing::info!(%addr, "faro-server listening (http)");
            }
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown)
            .await
        }
        Transport::Tls(listener, mode) => {
            let tls = TlsListener::new(listener, mode)?;
            if let Ok(addr) = axum::serve::Listener::local_addr(&tls) {
                tracing::info!(%addr, "faro-server listening (https)");
            }
            // `tap_io` is a no-op wrapper that gives the TLS listener
            // axum's ConnectInfo<SocketAddr> (used for rate limiting).
            axum::serve(
                tls.tap_io(|_| {}),
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown)
            .await
        }
    };

    workers::shutdown(&cancel, handles, WORKER_SHUTDOWN_TIMEOUT).await;
    if let Err(e) = run.stop(&state).await {
        tracing::warn!(error = %e, "could not record clean shutdown");
    }
    state.db().close().await;
    served?;
    tracing::info!("faro-server stopped");
    Ok(())
}

/// Resolves on Ctrl-C or (on Unix) SIGTERM, which is what `docker stop` sends.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            // No Ctrl-C handler available: never resolve this branch.
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
    tracing::info!("shutdown requested");
}
