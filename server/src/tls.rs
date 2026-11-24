//! Built-in HTTPS (§4.2, §9): automatic certificates via ACME
//! (`rustls-acme`, TLS-ALPN-01) or a static certificate from PEM files.
//!
//! Both modes feed one [`TlsListener`], an [`axum::serve::Listener`] whose
//! accept loop runs in its own task: every TCP connection gets its TLS
//! handshake in a separate task with a timeout and a concurrency cap, so a
//! slow or malicious client can never stall `accept` for everyone else.
//!
//! * **ACME.** `rustls-acme` obtains and renews the certificate for
//!   `tls.acme_domain` and caches it with the account key in
//!   `<data_dir>/acme` (0700). Validation uses TLS-ALPN-01 on the HTTPS
//!   port itself, so no port-80 listener is needed: a connection offering
//!   only the `acme-tls/1` ALPN protocol is answered with the challenge
//!   certificate and closed. Until the first certificate arrives, ordinary
//!   handshakes fail (there is nothing to present).
//! * **Static.** `tls.cert_path` (full chain) and `tls.key_path` (PKCS#8,
//!   PKCS#1 or SEC1 key), read at startup; restart to pick up a renewal.
//!
//! Connections are TLS 1.3 only (§9 "TLS 1.3 everywhere"), with the ring
//! provider, and offer `http/1.1` via ALPN.

use crate::config::Config;
use axum::serve::Listener;
use futures_util::StreamExt;
use rustls::server::{Acceptor, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio_rustls::server::TlsStream;
use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor};
use tokio_util::sync::CancellationToken;

/// A TLS handshake must finish within this long.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Concurrent in-progress handshakes.
pub const MAX_PENDING_HANDSHAKES: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("cannot read TLS {what} {path}: {source}")]
    Pem {
        what: &'static str,
        path: std::path::PathBuf,
        #[source]
        source: rustls_pki_types::pem::Error,
    },
    #[error("TLS certificate file {0} contains no certificates")]
    NoCertificates(std::path::PathBuf),
    #[error("invalid TLS configuration: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("cannot create ACME cache directory {path}: {source}")]
    CacheDir {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// How connections are terminated.
#[derive(Clone)]
pub enum TlsMode {
    Static(Arc<ServerConfig>),
    Acme {
        default: Arc<ServerConfig>,
        challenge: Arc<ServerConfig>,
    },
}

impl std::fmt::Debug for TlsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TlsMode::Static(_) => "TlsMode::Static",
            TlsMode::Acme { .. } => "TlsMode::Acme",
        })
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn builder() -> Result<rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier>, TlsError> {
    Ok(ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?)
}

/// Load a static certificate chain and key.
pub fn load_static(cert_path: &Path, key_path: &Path) -> Result<TlsMode, TlsError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .and_then(|it| it.collect::<Result<Vec<_>, _>>())
        .map_err(|source| TlsError::Pem {
            what: "certificate",
            path: cert_path.to_owned(),
            source,
        })?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificates(cert_path.to_owned()));
    }
    let key = PrivateKeyDer::from_pem_file(key_path).map_err(|source| TlsError::Pem {
        what: "key",
        path: key_path.to_owned(),
        source,
    })?;
    let mut cfg = builder()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsMode::Static(Arc::new(cfg)))
}

/// Set up ACME for `config.tls.acme_domain` and start the task that orders
/// and renews certificates. The task stops when `cancel` fires.
pub fn start_acme(
    config: &Config,
    cancel: CancellationToken,
) -> Result<(TlsMode, tokio::task::JoinHandle<()>), TlsError> {
    let domain = config
        .tls
        .acme_domain
        .clone()
        .ok_or_else(|| TlsError::Rustls(rustls::Error::General("no acme_domain".into())))?;
    let cache = config.data_dir.join("acme");
    std::fs::create_dir_all(&cache).map_err(|source| TlsError::CacheDir {
        path: cache.clone(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // The cache holds the certificate's private key and the account key.
        let _ = std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o700));
    }
    let mut acme = rustls_acme::AcmeConfig::new([domain.clone()])
        .contact(
            config
                .tls
                .acme_contact
                .iter()
                .map(|c| format!("mailto:{c}")),
        )
        .cache(rustls_acme::caches::DirCache::new(cache));
    acme = match &config.tls.acme_directory {
        Some(url) => acme.directory(url),
        None => acme.directory_lets_encrypt(config.tls.acme_production),
    };
    let mut state = acme.state();
    let challenge = state.challenge_rustls_config_with_provider(provider());
    let mut default = builder()?
        .with_no_client_auth()
        .with_cert_resolver(state.resolver());
    default.alpn_protocols = vec![b"http/1.1".to_vec()];

    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                ev = state.next() => match ev {
                    Some(Ok(ok)) => tracing::info!(domain = %domain, event = ?ok, "ACME"),
                    // rustls-acme backs off and retries internally.
                    Some(Err(err)) => tracing::warn!(domain = %domain, error = %err, "ACME error"),
                    None => break,
                },
            }
        }
    });
    Ok((
        TlsMode::Acme {
            default: Arc::new(default),
            challenge,
        },
        task,
    ))
}

/// The background task ordering and renewing ACME certificates.
pub type AcmeTask = tokio::task::JoinHandle<()>;

/// The TLS mode configured for `config`, if any (plus the ACME task).
pub fn from_config(
    config: &Config,
    cancel: CancellationToken,
) -> Result<Option<(TlsMode, Option<AcmeTask>)>, TlsError> {
    if config.tls.acme_domain.is_some() {
        let (mode, task) = start_acme(config, cancel)?;
        return Ok(Some((mode, Some(task))));
    }
    match (&config.tls.cert_path, &config.tls.key_path) {
        (Some(c), Some(k)) => Ok(Some((load_static(c, k)?, None))),
        _ => Ok(None),
    }
}

/// Complete one handshake. `None` for ACME challenge connections and
/// failures (logged at debug: scanners make plenty).
async fn handshake(mode: &TlsMode, tcp: TcpStream) -> Option<TlsStream<TcpStream>> {
    match mode {
        TlsMode::Static(cfg) => TlsAcceptor::from(cfg.clone()).accept(tcp).await.ok(),
        TlsMode::Acme { default, challenge } => {
            let start = LazyConfigAcceptor::new(Acceptor::default(), tcp)
                .await
                .ok()?;
            if rustls_acme::is_tls_alpn_challenge(&start.client_hello()) {
                tracing::info!("answering ACME TLS-ALPN-01 validation");
                if let Ok(mut tls) = start.into_stream(challenge.clone()).await {
                    use tokio::io::AsyncWriteExt;
                    let _ = tls.shutdown().await;
                }
                return None;
            }
            start.into_stream(default.clone()).await.ok()
        }
    }
}

/// A listener yielding established TLS streams.
pub struct TlsListener {
    rx: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for TlsListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsListener")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl TlsListener {
    pub fn new(tcp: TcpListener, mode: TlsMode) -> std::io::Result<Self> {
        let local = tcp.local_addr()?;
        let (tx, rx) = mpsc::channel(128);
        let task = tokio::spawn(async move {
            let limit = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
            loop {
                let (stream, peer) = match tcp.accept().await {
                    Ok(x) => x,
                    Err(e) => {
                        // Typically EMFILE; back off instead of spinning.
                        tracing::warn!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Ok(permit) = limit.clone().acquire_owned().await else {
                    break;
                };
                let (conn_tx, mode) = (tx.clone(), mode.clone());
                tokio::spawn(async move {
                    let _permit = permit;
                    let done = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&mode, stream));
                    match done.await {
                        Ok(Some(tls)) => {
                            let _ = conn_tx.send((tls, peer)).await;
                        }
                        Ok(None) => tracing::debug!("TLS handshake failed"),
                        Err(_) => tracing::debug!("TLS handshake timed out"),
                    }
                });
                if tx.is_closed() {
                    break;
                }
            }
        });
        Ok(TlsListener { rx, local, task })
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(x) => x,
            // The accept task only ends when the listener is dropped.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}
