//! `faro-release`: minimal project release tooling for Faro update metadata.
//!
//! ```text
//! faro-release keygen          --out root-a.key.json
//! faro-release describe-target --file Faro-1.4.0.pkg
//! faro-release sign-root       --metadata root.json --key root-a.key.json [--key ...] --out 1.root.json
//! faro-release add-signature   --envelope 1.root.json --key root-b.key.json --out 1.root.json
//! faro-release sign-targets    --metadata targets.json --key targets.key.json --out targets.json.signed
//! faro-release sign-timestamp  --targets targets.json.signed --version 42 --expires-ms 1800000000000 \
//!                              --key timestamp.key.json --out timestamp.json
//! faro-release verify          --root 1.root.json [--root-update 2.root.json ...] \
//!                              --timestamp timestamp.json --targets targets.json.signed [--now-ms N]
//! ```
//!
//! `root.json` / `targets.json` are the unsigned [`faro_update::Root`] /
//! [`faro_update::Targets`] payloads as JSON. Root key holders typically sign
//! on separate offline machines: one runs `sign-root` with their key, the
//! others pass the envelope around with `add-signature` until the threshold
//! is met. Key files hold a raw Ed25519 seed; they are created `0600` and
//! never overwritten.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use faro_crypto::{SigningKey, Zeroizing};
use faro_proto::encoding::{b64_decode, b64_encode};
use faro_proto::keys::key_id;
use faro_proto::Hash32;
use faro_update::{Envelope, MetadataSigner, Role, Root, Targets, TargetsMeta, Timestamp, Updater};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "faro-release", about = "Sign and verify Faro update metadata")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an Ed25519 key file.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the length and BLAKE3 of an artifact for a targets entry.
    DescribeTarget {
        #[arg(long)]
        file: PathBuf,
    },
    /// Sign an unsigned root payload.
    SignRoot {
        #[arg(long)]
        metadata: PathBuf,
        #[arg(long = "key", required = true)]
        keys: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Add one more signature to an existing envelope.
    AddSignature {
        #[arg(long)]
        envelope: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign an unsigned targets payload.
    SignTargets {
        #[arg(long)]
        metadata: PathBuf,
        #[arg(long = "key", required = true)]
        keys: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Create and sign a timestamp committing to a signed targets file.
    SignTimestamp {
        #[arg(long)]
        targets: PathBuf,
        #[arg(long)]
        version: u64,
        #[arg(long)]
        expires_ms: i64,
        #[arg(long = "key", required = true)]
        keys: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a full metadata set exactly as a client would.
    Verify {
        /// Trusted initial root (as embedded in installers).
        #[arg(long)]
        root: PathBuf,
        /// Subsequent roots, in order.
        #[arg(long = "root-update")]
        root_updates: Vec<PathBuf>,
        #[arg(long)]
        timestamp: PathBuf,
        #[arg(long)]
        targets: PathBuf,
        /// Override "now" (Unix ms); defaults to the system clock.
        #[arg(long)]
        now_ms: Option<i64>,
    },
}

/// On-disk key file. The seed is sensitive; the rest is informational.
///
/// `secret` is borrowed rather than owned so the encoded seed never lives in
/// a `String` we can't wipe: on write it points into a [`Zeroizing`] buffer,
/// and on read it is a zero-copy slice of the [`Zeroizing`] file contents
/// (base64url never needs JSON escapes, so borrowing always succeeds for a
/// well-formed key file).
#[derive(Serialize, Deserialize)]
struct KeyFile<'a> {
    keyid: String,
    public: String,
    #[serde(borrow)]
    secret: &'a str,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen { out } => keygen(&out),
        Cmd::DescribeTarget { file } => {
            let bytes =
                std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            println!(
                "{}",
                serde_json::json!({
                    "length": bytes.len(),
                    "blake3": Hash32::of(&bytes),
                })
            );
            Ok(())
        }
        Cmd::SignRoot {
            metadata,
            keys,
            out,
        } => {
            let root: Root = read_json(&metadata)?;
            sign_and_write(&root, &keys, &out)
        }
        Cmd::SignTargets {
            metadata,
            keys,
            out,
        } => {
            let t: Targets = read_json(&metadata)?;
            sign_and_write(&t, &keys, &out)
        }
        Cmd::AddSignature { envelope, key, out } => {
            let mut env: Envelope = read_json(&envelope)?;
            let key = load_key(&key)?;
            env.add_signature(&key)?;
            write_file(&out, &env.to_bytes())
        }
        Cmd::SignTimestamp {
            targets,
            version,
            expires_ms,
            keys,
            out,
        } => {
            let targets_bytes = read(&targets)?;
            // The signer is trusted to know what it is signing, so reading
            // the unverified payload here is fine.
            let env = Envelope::parse(Role::Targets, &targets_bytes)?;
            let t: Targets =
                serde_json::from_slice(&env.unverified_payload()?).context("targets payload")?;
            let ts = Timestamp {
                version,
                expires_ms,
                targets_meta: TargetsMeta::describe(&targets_bytes, t.version),
            };
            sign_and_write(&ts, &keys, &out)
        }
        Cmd::Verify {
            root,
            root_updates,
            timestamp,
            targets,
            now_ms,
        } => {
            let now = match now_ms {
                Some(n) => n,
                None => i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?,
            };
            let mut up = Updater::bootstrap(&read(&root)?).context("initial root")?;
            for r in &root_updates {
                up.update_root(&read(r)?)
                    .with_context(|| format!("root update {}", r.display()))?;
            }
            let ts = up
                .verify_timestamp(&read(&timestamp)?, now)
                .context("timestamp")?;
            let vt = up
                .verify_targets(&read(&targets)?, now)
                .context("targets")?;
            println!(
                "OK: root v{}, timestamp v{} (expires {}), targets v{}",
                up.state().root().version,
                ts.version,
                ts.expires_ms,
                vt.targets().version
            );
            for t in vt.iter() {
                println!(
                    "  {} {} {}/{} {} [{}] {} bytes {}",
                    t.name,
                    serde_json::to_string(&t.custom.kind)?,
                    t.custom.platform,
                    t.custom.arch,
                    t.custom.version,
                    t.custom.channels.join(","),
                    t.length,
                    t.blake3
                );
            }
            Ok(())
        }
    }
}

fn keygen(out: &Path) -> Result<()> {
    let key = SigningKey::generate();
    let secret = Zeroizing::new(b64_encode(key.to_bytes().as_slice()));
    let kf = KeyFile {
        keyid: key_id(key.public().as_bytes()),
        public: key.public().to_b64(),
        secret: secret.as_str(),
    };
    // Pre-size the buffer so serialization never reallocates and leaves an
    // un-wiped copy of the seed behind in a freed allocation.
    let mut json = Zeroizing::new(Vec::with_capacity(4096));
    serde_json::to_writer_pretty(&mut *json, &kf)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(out)
        .with_context(|| format!("creating {} (refusing to overwrite)", out.display()))?;
    std::io::Write::write_all(&mut f, &json)?;
    println!("{} {}", kf.keyid, kf.public);
    Ok(())
}

fn load_key(path: &Path) -> Result<SigningKey> {
    let raw = Zeroizing::new(read(path)?);
    let kf: KeyFile =
        serde_json::from_slice(&raw).with_context(|| format!("parsing {}", path.display()))?;
    let seed = Zeroizing::new(b64_decode(kf.secret).context("key secret is not base64url")?);
    let Ok(seed32) = <[u8; 32]>::try_from(seed.as_slice()) else {
        bail!("{}: secret must be 32 bytes", path.display());
    };
    let seed32 = Zeroizing::new(seed32);
    let key = SigningKey::from_bytes(&seed32);
    let id = key_id(key.public().as_bytes());
    if id != kf.keyid {
        bail!(
            "{}: keyid {} does not match the secret (expected {id})",
            path.display(),
            kf.keyid
        );
    }
    Ok(key)
}

fn sign_and_write<T: faro_update::RoleMetadata>(
    meta: &T,
    keys: &[PathBuf],
    out: &Path,
) -> Result<()> {
    let keys = keys
        .iter()
        .map(|p| load_key(p))
        .collect::<Result<Vec<_>>>()?;
    let bytes = MetadataSigner::new(keys.iter()).sign_to_bytes(meta)?;
    write_file(out, &bytes)
}

fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&read(path)?).with_context(|| format!("parsing {}", path.display()))
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    println!("wrote {}", path.display());
    Ok(())
}
