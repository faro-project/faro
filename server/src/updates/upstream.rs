//! Where the mirror gets releases from: the project's HTTPS publishing
//! location, or a directory (an air-gapped import, and tests).
//!
//! Both use the same layout, which is also what the mirror serves under
//! `/v1/updates` (PROTOCOL.md §8):
//!
//! ```text
//! roots/<n>.json      root rotations, n >= 2 (root 1 ships with the software)
//! timestamp.json
//! targets.json
//! targets/<name>      artifacts, by their name in targets.json
//! ```
//!
//! Nothing here trusts what it reads. Metadata is size-capped before it is
//! handed to `faro-update` for verification, and artifacts are streamed
//! through a [`TargetVerifier`], so an upstream (or a man in the middle, or a
//! corrupted USB stick) can waste a download but never get unverified bytes
//! into the cache.

use faro_update::{StreamError, TargetInfo, TargetVerifier};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// Connect timeout for upstream requests.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// An upstream that sends nothing for this long is given up on.
const READ_TIMEOUT: Duration = Duration::from_secs(60);
/// Redirects followed (release hosts commonly redirect to a CDN).
const MAX_REDIRECTS: usize = 5;

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("upstream request for {path} failed: {source}")]
    Http {
        path: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("upstream returned HTTP {status} for {path}")]
    Status { path: String, status: u16 },
    #[error("{path} is larger than {max} bytes")]
    TooLarge { path: String, max: usize },
    #[error("cannot read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Verify(#[from] StreamError),
}

/// A source of releases.
#[derive(Debug, Clone)]
pub enum Upstream {
    /// `https://…` base URL, without a trailing `/`.
    Http {
        client: reqwest::Client,
        base: String,
    },
    /// A directory with the layout above.
    Dir(PathBuf),
}

impl Upstream {
    /// An HTTPS upstream. `allow_http` (dev only) also permits `http://`,
    /// including on redirects.
    pub fn http(base: &str, allow_http: bool) -> Result<Self, reqwest::Error> {
        let policy = reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= MAX_REDIRECTS {
                attempt.error("too many redirects")
            } else if attempt.url().scheme() == "https" || allow_http {
                attempt.follow()
            } else {
                attempt.error("refusing a redirect away from https")
            }
        });
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .redirect(policy)
            .user_agent(concat!("faro-server/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Upstream::Http {
            client,
            base: base.trim_end_matches('/').to_owned(),
        })
    }

    /// A short description for logs and status output (never includes
    /// credentials: the config rejects URLs with `@`).
    pub fn describe(&self) -> String {
        match self {
            Upstream::Http { base, .. } => base.clone(),
            Upstream::Dir(d) => d.display().to_string(),
        }
    }

    /// Fetch a metadata file of at most `max` bytes. `Ok(None)` means the
    /// upstream doesn't have it (HTTP 404, or no such file).
    pub async fn get_meta(&self, path: &str, max: usize) -> Result<Option<Vec<u8>>, FetchError> {
        match self {
            Upstream::Http { client, base } => {
                let resp = send(client, base, path).await?;
                let Some(mut resp) = resp else {
                    return Ok(None);
                };
                let mut out = Vec::new();
                while let Some(chunk) = resp.chunk().await.map_err(|source| FetchError::Http {
                    path: path.to_owned(),
                    source,
                })? {
                    if out.len() + chunk.len() > max {
                        return Err(FetchError::TooLarge {
                            path: path.to_owned(),
                            max,
                        });
                    }
                    out.extend_from_slice(&chunk);
                }
                Ok(Some(out))
            }
            Upstream::Dir(dir) => {
                let file = dir.join(path);
                let meta = match tokio::fs::metadata(&file).await {
                    Ok(m) => m,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                    Err(source) => return Err(io_err(path, source)),
                };
                if meta.len() > max as u64 {
                    return Err(FetchError::TooLarge {
                        path: path.to_owned(),
                        max,
                    });
                }
                let bytes = tokio::fs::read(&file)
                    .await
                    .map_err(|source| io_err(path, source))?;
                if bytes.len() > max {
                    return Err(FetchError::TooLarge {
                        path: path.to_owned(),
                        max,
                    });
                }
                Ok(Some(bytes))
            }
        }
    }

    /// Download artifact `info` into `dest` (a new file), verifying it
    /// against its signed length and BLAKE3 on the way. On `Err` the caller
    /// deletes `dest`. `Ok(false)`: the upstream doesn't have it.
    pub async fn fetch_artifact(
        &self,
        info: &TargetInfo,
        max_len: u64,
        dest: &Path,
    ) -> Result<bool, FetchError> {
        let path = format!("targets/{}", info.name);
        let mut verifier = TargetVerifier::new(info, max_len)?;
        let mut out = tokio::fs::File::create(dest)
            .await
            .map_err(|source| io_err(&path, source))?;
        match self {
            Upstream::Http { client, base } => {
                let Some(mut resp) = send(client, base, &path).await? else {
                    return Ok(false);
                };
                while let Some(chunk) = resp.chunk().await.map_err(|source| FetchError::Http {
                    path: path.clone(),
                    source,
                })? {
                    verifier.update(&chunk)?;
                    out.write_all(&chunk)
                        .await
                        .map_err(|source| io_err(&path, source))?;
                }
            }
            Upstream::Dir(dir) => {
                use tokio::io::AsyncReadExt;
                let mut src = match tokio::fs::File::open(dir.join(&path)).await {
                    Ok(f) => f,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                    Err(source) => return Err(io_err(&path, source)),
                };
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    // One byte past the signed length is enough to detect
                    // an overlong file.
                    let want = usize::try_from(verifier.remaining().saturating_add(1))
                        .map_or(buf.len(), |r| r.min(buf.len()));
                    let n = src
                        .read(&mut buf[..want])
                        .await
                        .map_err(|source| io_err(&path, source))?;
                    if n == 0 {
                        break;
                    }
                    verifier.update(&buf[..n])?;
                    out.write_all(&buf[..n])
                        .await
                        .map_err(|source| io_err(&path, source))?;
                }
            }
        }
        verifier.finish()?;
        out.flush().await.map_err(|source| io_err(&path, source))?;
        out.sync_all()
            .await
            .map_err(|source| io_err(&path, source))?;
        Ok(true)
    }
}

/// GET `base/path`; `None` on 404.
async fn send(
    client: &reqwest::Client,
    base: &str,
    path: &str,
) -> Result<Option<reqwest::Response>, FetchError> {
    let resp = client
        .get(format!("{base}/{path}"))
        .send()
        .await
        .map_err(|source| FetchError::Http {
            path: path.to_owned(),
            source,
        })?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(FetchError::Status {
            path: path.to_owned(),
            status: status.as_u16(),
        });
    }
    Ok(Some(resp))
}

fn io_err(path: &str, source: std::io::Error) -> FetchError {
    FetchError::Io {
        path: path.to_owned(),
        source,
    }
}
