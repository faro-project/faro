//! Fetching update metadata and packages from the instance's mirror
//! (`/v1/updates`, PROTOCOL.md §8).
//!
//! Like [`crate::client`], it trusts nothing it reads. Metadata is capped
//! per role before it reaches `faro-update`. Packages stream through a
//! [`TargetVerifier`] against the *signed* length, never `Content-Length`.
//! Redirects are refused. Unlike the API client there is no total request
//! timeout, since a package can take minutes on a slow link; a connection
//! that sends nothing for [`READ_TIMEOUT`] is dropped instead.
//!
//! [`verify_metadata`] walks root rotations, the timestamp and the targets
//! it commits to (PROTOCOL.md §8.2 steps 1 and 2), for client packages and
//! data bundles alike.

use crate::client::{ClientError, ClientOptions};
use faro_proto::api::{UpdatesInfo, UPDATES_PATH};
use faro_update::metadata::{MAX_ROOT_BYTES, MAX_TARGETS_BYTES, MAX_TIMESTAMP_BYTES};
use faro_update::{
    StreamError, TargetInfo, TargetVerifier, TrustedState, UpdateError, Updater, VerifiedTargets,
};
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use url::Url;

/// A stalled download is abandoned after this long without data.
pub const READ_TIMEOUT: Duration = Duration::from_secs(60);
/// Cap on `GET /v1/updates`.
const INFO_LIMIT: usize = 4 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("{path} is larger than {limit} bytes")]
    TooLarge { path: String, limit: usize },
    #[error("the instance returned HTTP {status} for {path}")]
    Status { path: String, status: u16 },
    #[error(transparent)]
    Verify(#[from] StreamError),
    #[error("cannot write the download to {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Reads the instance's mirror.
#[derive(Debug, Clone)]
pub struct UpdateFetcher {
    http: reqwest::Client,
    base: Url,
}

impl UpdateFetcher {
    /// `base` is the enrolled instance URL.
    pub fn new(base: Url, opts: &ClientOptions) -> Result<Self, FetchError> {
        let mut b = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(opts.timeout.min(Duration::from_secs(15)))
            .read_timeout(READ_TIMEOUT)
            .user_agent(opts.user_agent())
            .https_only(base.scheme() == "https");
        if let Some(path) = &opts.ca_file {
            for cert in crate::client::load_ca_file(path)? {
                b = b.add_root_certificate(cert);
            }
        }
        let http = b.build().map_err(|e| ClientError::Build(e.to_string()))?;
        Ok(UpdateFetcher { http, base })
    }

    fn url(&self, rel: &str) -> Result<Url, FetchError> {
        let path = format!("{}/{rel}", UPDATES_PATH.trim_start_matches('/'));
        let path = path.trim_end_matches('/');
        Ok(self
            .base
            .join(path)
            .map_err(|e| ClientError::Url(e.to_string()))?)
    }

    /// GET; `None` on 404.
    async fn get(&self, rel: &str) -> Result<Option<reqwest::Response>, FetchError> {
        let url = self.url(rel)?;
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(ClientError::Transport)?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(FetchError::Status {
                path: rel.to_owned(),
                status: status.as_u16(),
            });
        }
        Ok(Some(resp))
    }

    /// `GET /v1/updates`.
    pub async fn info(&self) -> Result<Option<UpdatesInfo>, FetchError> {
        let Some(bytes) = self.meta("", INFO_LIMIT).await? else {
            return Ok(None);
        };
        Ok(Some(
            serde_json::from_slice(&bytes).map_err(ClientError::Json)?,
        ))
    }

    /// A metadata document of at most `limit` bytes; `None` on 404.
    pub async fn meta(&self, rel: &str, limit: usize) -> Result<Option<Vec<u8>>, FetchError> {
        let Some(mut resp) = self.get(rel).await? else {
            return Ok(None);
        };
        let too_large = || FetchError::TooLarge {
            path: rel.to_owned(),
            limit,
        };
        if resp.content_length().is_some_and(|n| n > limit as u64) {
            return Err(too_large());
        }
        let mut out = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(ClientError::Transport)? {
            if out.len() + chunk.len() > limit {
                return Err(too_large());
            }
            out.extend_from_slice(&chunk);
        }
        Ok(Some(out))
    }

    /// Download `info` into `dest` (created new), verified against its
    /// signed length and BLAKE3. `Ok(false)`: the mirror doesn't have it.
    /// On `Err` the caller deletes `dest`.
    pub async fn artifact(
        &self,
        info: &TargetInfo,
        max_len: u64,
        dest: &Path,
    ) -> Result<bool, FetchError> {
        let mut verifier = TargetVerifier::new(info, max_len)?;
        let rel = format!("targets/{}", info.name);
        let Some(mut resp) = self.get(&rel).await? else {
            return Ok(false);
        };
        let io = |source| FetchError::Io {
            path: dest.display().to_string(),
            source,
        };
        let mut opts = tokio::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut out = opts.open(dest).await.map_err(io)?;
        while let Some(chunk) = resp.chunk().await.map_err(ClientError::Transport)? {
            verifier.update(&chunk)?;
            out.write_all(&chunk).await.map_err(io)?;
        }
        verifier.finish()?;
        out.flush().await.map_err(io)?;
        out.sync_all().await.map_err(io)?;
        Ok(true)
    }
}

/// Most root rotations walked in one check.
pub const MAX_ROOT_STEPS: u64 = 64;

/// Why [`verify_metadata`] stopped.
#[derive(Debug, thiserror::Error)]
pub enum MetadataError<E: std::error::Error + 'static> {
    #[error(transparent)]
    Fetch(#[from] FetchError),
    #[error("update metadata rejected: {0}")]
    Verify(#[from] UpdateError),
    #[error("the instance's mirror has no {0}")]
    Missing(&'static str),
    /// The caller's `save` failed.
    #[error(transparent)]
    Save(E),
}

/// Roots, timestamp, targets. One retry if the mirror switched release
/// between the timestamp and the targets.
///
/// `save` persists the trust state; it is called after every step that
/// can change it, `Ok` or `Err` (a rejected document can still raise the
/// observed-time mark that stops a rolled-back clock from reviving expired
/// metadata). The caller saves once more when this returns.
pub async fn verify_metadata<E: std::error::Error + 'static>(
    fetch: &UpdateFetcher,
    u: &mut Updater,
    now_ms: impl Fn() -> i64,
    mut save: impl FnMut(&Updater) -> Result<(), E>,
) -> Result<VerifiedTargets, MetadataError<E>> {
    for _ in 0..MAX_ROOT_STEPS {
        let next = u.state().root().version + 1;
        let Some(bytes) = fetch
            .meta(&format!("roots/{next}.json"), MAX_ROOT_BYTES)
            .await?
        else {
            break;
        };
        u.update_root(&bytes)?;
        save(u).map_err(MetadataError::Save)?;
        tracing::info!(version = next, "update root rotated");
    }
    let mut retried = false;
    loop {
        let now = now_ms();
        let ts = fetch
            .meta("timestamp.json", MAX_TIMESTAMP_BYTES)
            .await?
            .ok_or(MetadataError::Missing("timestamp.json"))?;
        u.verify_timestamp(&ts, now)?;
        save(u).map_err(MetadataError::Save)?;
        let tg = fetch
            .meta("targets.json", MAX_TARGETS_BYTES)
            .await?
            .ok_or(MetadataError::Missing("targets.json"))?;
        match u.verify_targets(&tg, now) {
            Err(UpdateError::TimestampMismatch(_)) if !retried => {
                retried = true;
                save(u).map_err(MetadataError::Save)?;
            }
            r => return Ok(r?),
        }
    }
}

/// The updater to verify with: the `stored` trust state, or the `shipped`
/// root (the one this client was built or installed with) when there is no
/// stored state, the shipped root is newer (an upgrade brought a rotated
/// root) or it differs at the same version. Fails only if the shipped root
/// isn't a valid signed root.
pub fn trusted_updater(
    shipped: &[u8],
    stored: Option<TrustedState>,
) -> Result<Updater, UpdateError> {
    let shipped = Updater::bootstrap(shipped)?;
    let Some(stored) = stored else {
        return Ok(shipped);
    };
    let (have, want) = (stored.root().version, shipped.state().root().version);
    if have < want
        || (have == want && stored.root_payload_hash() != shipped.state().root_payload_hash())
    {
        return Ok(shipped);
    }
    Ok(Updater::from_state(stored))
}
