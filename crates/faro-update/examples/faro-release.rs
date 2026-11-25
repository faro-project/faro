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
//!                              --timestamp timestamp.json --targets targets.json.signed [--now-ms N] \
//!                              [--published-timestamp old/timestamp.json --published-targets old/targets.json] \
//!                              [--artifacts layout/targets]
//!
//! # Used by the release workflow (release/build-layout.sh):
//! faro-release next-targets    --root 1.root.json [--root-update 2.root.json ...] \
//!                              [--published-timestamp old/timestamp.json --published-targets old/targets.json] \
//!                              --expires-ms 1800000000000 --out targets.unsigned.json
//! faro-release add-target      --metadata targets.unsigned.json --file Faro-1.4.0.pkg \
//!                              --name client/macos/Faro-1.4.0.pkg --kind client --platform macos \
//!                              --arch any --version 1.4.0 --channel stable --channel beta [--min-os 13]
//! faro-release inspect         --root 1.root.json [--root-update 2.root.json ...] \
//!                              --published-timestamp old/timestamp.json --published-targets old/targets.json
//! ```
//!
//! `root.json` / `targets.json` are the unsigned [`faro_update::Root`] /
//! [`faro_update::Targets`] payloads as JSON. Root key holders typically sign
//! on separate offline machines: one runs `sign-root` with their key, the
//! others pass the envelope around with `add-signature` until the threshold
//! is met. Key files hold a raw Ed25519 seed; they are created `0600` and
//! never overwritten.
//!
//! `next-targets` starts the next release from the published one. It
//! verifies the published timestamp and targets against the root chain
//! (signatures and consistency, not expiry, so a listing that has lapsed can
//! still be carried forward), then writes an unsigned payload with the same
//! entries, `version + 1` and a new expiry. `add-target` adds one artifact to
//! it. A name that is already listed with different content is refused: a
//! published name never changes meaning. `verify` given the published
//! documents first trusts those, then checks the new set the way an
//! up-to-date client would, so a version that went backwards fails here
//! instead of on every client.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use faro_crypto::{SigningKey, Zeroizing};
use faro_proto::encoding::{b64_decode, b64_encode};
use faro_proto::keys::key_id;
use faro_proto::Hash32;
use faro_update::{
    verify_target_stream, Envelope, MetadataSigner, Role, RoleMetadata, Root, TargetCustom,
    TargetFile, TargetKind, Targets, TargetsMeta, Timestamp, Updater, VerifiedTargets, Version,
};
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
        #[command(flatten)]
        published: Published,
        /// Directory of artifacts under their target names. Every listed
        /// target found there must match its signed length and BLAKE3, and
        /// every target that the published listing doesn't have must be
        /// there.
        #[arg(long)]
        artifacts: Option<PathBuf>,
    },
    /// Start the next unsigned targets payload from the published one.
    NextTargets {
        /// Trusted initial root.
        #[arg(long)]
        root: PathBuf,
        /// Subsequent roots, in order.
        #[arg(long = "root-update")]
        root_updates: Vec<PathBuf>,
        #[command(flatten)]
        published: Published,
        #[arg(long)]
        expires_ms: i64,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify the published documents (ignoring expiry) and print their
    /// versions and expiries as JSON.
    Inspect {
        #[arg(long)]
        root: PathBuf,
        #[arg(long = "root-update")]
        root_updates: Vec<PathBuf>,
        #[arg(long)]
        published_timestamp: PathBuf,
        #[arg(long)]
        published_targets: PathBuf,
    },
    /// Add one artifact to an unsigned targets payload, in place.
    AddTarget {
        #[arg(long)]
        metadata: PathBuf,
        #[arg(long)]
        file: PathBuf,
        /// Target name: the path it is served under, below `targets/`.
        #[arg(long)]
        name: String,
        /// `client`, `model`, `blocklist` or `server`.
        #[arg(long)]
        kind: String,
        #[arg(long)]
        platform: String,
        #[arg(long)]
        arch: String,
        #[arg(long)]
        version: Version,
        #[arg(long = "channel", required = true)]
        channels: Vec<String>,
        #[arg(long)]
        min_os: Option<String>,
    },
}

/// The documents now at the publishing location. Both or neither (the
/// first release).
#[derive(clap::Args)]
struct Published {
    #[arg(long, requires = "published_targets")]
    published_timestamp: Option<PathBuf>,
    #[arg(long, requires = "published_timestamp")]
    published_targets: Option<PathBuf>,
}

impl Published {
    fn read(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        match (&self.published_timestamp, &self.published_targets) {
            (Some(ts), Some(tg)) => Ok(Some((read(ts)?, read(tg)?))),
            _ => Ok(None),
        }
    }
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
            let (length, blake3) = describe_file(&file)?;
            println!(
                "{}",
                serde_json::json!({
                    "length": length,
                    "blake3": blake3,
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
            published,
            artifacts,
        } => {
            let now = match now_ms {
                Some(n) => n,
                None => i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?,
            };
            let roots = read_roots(&root, &root_updates)?;
            let (mut up, previous) = match published.read()? {
                Some((ts, tg)) => {
                    let (up, vt) = verify_published(&roots, &ts, &tg)?;
                    (up, Some(vt))
                }
                None => (updater_with(&roots, roots.len() - 1)?, None),
            };
            let ts = up
                .verify_timestamp(&read(&timestamp)?, now)
                .context("timestamp")?;
            let vt = up
                .verify_targets(&read(&targets)?, now)
                .context("targets")?;
            println!(
                "OK: root v{}, timestamp v{} (expires {}), targets v{} (expires {})",
                up.state().root().version,
                ts.version,
                ts.expires_ms,
                vt.targets().version,
                vt.targets().expires_ms,
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
            if let Some(dir) = artifacts {
                let checked = check_artifacts(&vt, previous.as_ref(), &dir)?;
                println!("OK: {checked} artifacts in {} match", dir.display());
            }
            Ok(())
        }
        Cmd::NextTargets {
            root,
            root_updates,
            published,
            expires_ms,
            out,
        } => {
            let roots = read_roots(&root, &root_updates)?;
            let previous = match published.read()? {
                Some((ts, tg)) => Some(verify_published(&roots, &ts, &tg)?.1),
                None => None,
            };
            let next = next_targets(previous.as_ref(), expires_ms)?;
            write_json(&out, &next)?;
            println!(
                "targets v{} with {} entries carried over",
                next.version,
                next.targets.len()
            );
            Ok(())
        }
        Cmd::Inspect {
            root,
            root_updates,
            published_timestamp,
            published_targets,
        } => {
            let roots = read_roots(&root, &root_updates)?;
            let ts_bytes = read(&published_timestamp)?;
            let (_, vt) = verify_published(&roots, &ts_bytes, &read(&published_targets)?)?;
            // The timestamp verified above; read its fields from the payload.
            let ts: Timestamp = serde_json::from_slice(
                &Envelope::parse(Role::Timestamp, &ts_bytes)?.unverified_payload()?,
            )?;
            println!(
                "{}",
                serde_json::json!({
                    "timestamp": { "version": ts.version, "expires_ms": ts.expires_ms },
                    "targets": {
                        "version": vt.targets().version,
                        "expires_ms": vt.targets().expires_ms,
                        "entries": vt.targets().targets.len(),
                    },
                })
            );
            Ok(())
        }
        Cmd::AddTarget {
            metadata,
            file,
            name,
            kind,
            platform,
            arch,
            version,
            channels,
            min_os,
        } => {
            let mut t: Targets = read_json(&metadata)?;
            let kind = parse_kind(&kind)?;
            let (length, blake3) = describe_file(&file)?;
            let entry = TargetFile {
                length,
                blake3,
                custom: TargetCustom {
                    kind,
                    platform,
                    arch,
                    version,
                    channels,
                    min_os,
                },
            };
            if !add_target(&mut t, &name, entry)? {
                println!("{name} is already listed with the same content");
            }
            write_json(&metadata, &t)
        }
    }
}

fn parse_kind(kind: &str) -> Result<TargetKind> {
    serde_json::from_value(serde_json::Value::String(kind.to_owned()))
        .with_context(|| format!("--kind {kind:?}: expected client, model, blocklist or server"))
}

fn read_roots(root: &Path, updates: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
    std::iter::once(root)
        .chain(updates.iter().map(PathBuf::as_path))
        .map(read)
        .collect()
}

/// An updater that trusts `roots[0]` and has walked the rotations up to and
/// including `roots[last]`.
fn updater_with(roots: &[Vec<u8>], last: usize) -> Result<Updater> {
    let mut up = Updater::bootstrap(&roots[0]).context("initial root")?;
    for (i, r) in roots.iter().enumerate().take(last + 1).skip(1) {
        up.update_root(r)
            .with_context(|| format!("root update {i} (root v{})", i + 1))?;
    }
    Ok(up)
}

/// Verify the published timestamp and targets against the root chain,
/// ignoring expiry. Returns an updater that has walked every root and
/// remembers the published versions, and the published listing.
///
/// The published set may have been signed under an older root, before a
/// rotation that replaced the targets or timestamp key. So each prefix of
/// the chain is tried, newest first, the way a client that saw the set back
/// then verified it. The later roots are applied afterwards, which forgets
/// the remembered versions of a role whose key was replaced, as on a client.
fn verify_published(
    roots: &[Vec<u8>],
    timestamp: &[u8],
    targets: &[u8],
) -> Result<(Updater, VerifiedTargets)> {
    let mut last_err = None;
    for k in (0..roots.len()).rev() {
        let mut up = updater_with(roots, k)?;
        // `i64::MIN` as "now": expiry is not checked, and the state keeps no
        // observed time that would affect checking the new set.
        let attempt = up
            .verify_timestamp(timestamp, i64::MIN)
            .context("published timestamp")
            .and_then(|_| {
                up.verify_targets(targets, i64::MIN)
                    .context("published targets")
            });
        match attempt {
            Ok(vt) => {
                for (i, r) in roots.iter().enumerate().skip(k + 1) {
                    up.update_root(r)
                        .with_context(|| format!("root update {i} (root v{})", i + 1))?;
                }
                return Ok((up, vt));
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err
        .expect("there is at least one root")
        .context("the published metadata does not verify against any root in the chain"))
}

/// The unsigned payload for the next release: the published entries, the
/// next version and a new expiry.
fn next_targets(previous: Option<&VerifiedTargets>, expires_ms: i64) -> Result<Targets> {
    let (version, targets) = match previous {
        Some(p) => (
            p.targets()
                .version
                .checked_add(1)
                .context("targets version overflow")?,
            p.targets().targets.clone(),
        ),
        None => (1, Default::default()),
    };
    let next = Targets {
        version,
        expires_ms,
        targets,
    };
    next.validate().map_err(anyhow::Error::msg)?;
    Ok(next)
}

/// Add `entry` under `name`. Returns `false` if the identical entry was
/// already there (a release that is run again). A different entry under a
/// listed name is refused.
fn add_target(t: &mut Targets, name: &str, entry: TargetFile) -> Result<bool> {
    if let Some(existing) = t.targets.get(name) {
        if *existing == entry {
            return Ok(false);
        }
        bail!(
            "{name} is already listed with different content; \
             a published target name is never reused"
        );
    }
    t.targets.insert(name.to_owned(), entry);
    if let Err(e) = t.validate() {
        t.targets.remove(name);
        bail!(e);
    }
    Ok(true)
}

/// Length and BLAKE3 of a file, read in chunks.
fn describe_file(path: &Path) -> Result<(u64, Hash32)> {
    let mut f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    let length = std::io::copy(&mut f, &mut hasher)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok((length, Hash32(*hasher.finalize().as_bytes())))
}

/// Check the artifacts in `dir` against the verified listing. Every target
/// found there must match. Every target the published listing doesn't have
/// (so not already at the publishing location) must be there. Returns how
/// many artifacts were checked.
fn check_artifacts(
    vt: &VerifiedTargets,
    previous: Option<&VerifiedTargets>,
    dir: &Path,
) -> Result<usize> {
    let mut checked = 0;
    for t in vt.iter() {
        let path = dir.join(&t.name);
        match std::fs::File::open(&path) {
            Ok(f) => {
                verify_target_stream(std::io::BufReader::new(f), &t, u64::MAX)
                    .with_context(|| format!("{} does not match targets.json", path.display()))?;
                checked += 1;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if previous.and_then(|p| p.get(&t.name)).is_none() {
                    bail!("{} is listed but missing from {}", t.name, dir.display());
                }
            }
            Err(e) => return Err(e).with_context(|| format!("opening {}", path.display())),
        }
    }
    Ok(checked)
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

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_file(path, &bytes)
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    println!("wrote {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_update::RoleKeys;
    use std::collections::BTreeMap;

    const NOW: i64 = 1_800_000_000_000;
    const DAY: i64 = 86_400_000;

    struct Keys {
        root: SigningKey,
        targets: SigningKey,
        timestamp: SigningKey,
    }

    impl Keys {
        fn new() -> Self {
            Keys {
                root: SigningKey::generate(),
                targets: SigningKey::generate(),
                timestamp: SigningKey::generate(),
            }
        }

        /// Root `version`, signed by `self` and, for a rotation, by `old`.
        fn root(&self, version: u64, old: Option<&Keys>) -> Vec<u8> {
            let ids = |k: &SigningKey| key_id(k.public().as_bytes());
            let mut keys = BTreeMap::new();
            for k in [&self.root, &self.targets, &self.timestamp] {
                keys.insert(ids(k), k.public());
            }
            let root = Root {
                version,
                expires_ms: NOW + 365 * DAY,
                keys,
                roles: faro_update::RootRoles {
                    root: RoleKeys::new([ids(&self.root)], 1),
                    targets: RoleKeys::new([ids(&self.targets)], 1),
                    timestamp: RoleKeys::new([ids(&self.timestamp)], 1),
                },
            };
            let signers: Vec<&SigningKey> = std::iter::once(&self.root)
                .chain(old.map(|o| &o.root))
                .collect();
            MetadataSigner::new(signers.into_iter())
                .sign_to_bytes(&root)
                .unwrap()
        }

        fn sign_targets(&self, t: &Targets) -> Vec<u8> {
            MetadataSigner::new([&self.targets].into_iter())
                .sign_to_bytes(t)
                .unwrap()
        }

        fn sign_timestamp(&self, targets: &[u8], targets_version: u64, version: u64) -> Vec<u8> {
            let ts = Timestamp {
                version,
                expires_ms: NOW + 3 * DAY,
                targets_meta: TargetsMeta::describe(targets, targets_version),
            };
            MetadataSigner::new([&self.timestamp].into_iter())
                .sign_to_bytes(&ts)
                .unwrap()
        }
    }

    fn entry(content: &[u8], version: &str, channels: &[&str]) -> TargetFile {
        TargetFile {
            length: content.len() as u64,
            blake3: Hash32::of(content),
            custom: TargetCustom {
                kind: TargetKind::Client,
                platform: "macos".into(),
                arch: "any".into(),
                version: Version::parse(version).unwrap(),
                channels: channels.iter().map(|c| c.to_string()).collect(),
                min_os: Some("13".into()),
            },
        }
    }

    /// Sign `t` and a timestamp for it; returns (timestamp, targets).
    fn publish(keys: &Keys, t: &Targets, ts_version: u64) -> (Vec<u8>, Vec<u8>) {
        let targets = keys.sign_targets(t);
        let ts = keys.sign_timestamp(&targets, t.version, ts_version);
        (ts, targets)
    }

    fn first_release() -> Targets {
        let mut t = next_targets(None, NOW + 180 * DAY).unwrap();
        assert_eq!(t.version, 1);
        add_target(
            &mut t,
            "client/macos/Faro-0.1.0-beta.1.pkg",
            entry(b"one", "0.1.0-beta.1", &["beta"]),
        )
        .unwrap();
        t
    }

    #[test]
    fn next_release_carries_entries_and_bumps_the_version() {
        let keys = Keys::new();
        let roots = vec![keys.root(1, None)];
        let t1 = first_release();
        let (ts1, tg1) = publish(&keys, &t1, 100);

        let (_, prev) = verify_published(&roots, &ts1, &tg1).unwrap();
        let mut t2 = next_targets(Some(&prev), NOW + 180 * DAY).unwrap();
        assert_eq!(t2.version, 2);
        assert_eq!(t2.targets, t1.targets);
        assert!(add_target(
            &mut t2,
            "client/macos/Faro-0.1.0.pkg",
            entry(b"two", "0.1.0", &["stable", "beta"]),
        )
        .unwrap());
        // Running the same release again is a no-op.
        assert!(!add_target(
            &mut t2,
            "client/macos/Faro-0.1.0.pkg",
            entry(b"two", "0.1.0", &["stable", "beta"]),
        )
        .unwrap());
        // A listed name never gets new content.
        let err = add_target(
            &mut t2,
            "client/macos/Faro-0.1.0-beta.1.pkg",
            entry(b"other", "0.1.0-beta.1", &["beta"]),
        )
        .unwrap_err();
        assert!(err.to_string().contains("never reused"), "{err:#}");

        // The new set verifies on top of the published one.
        let (ts2, tg2) = publish(&keys, &t2, 101);
        let (mut up, _) = verify_published(&roots, &ts1, &tg1).unwrap();
        up.verify_timestamp(&ts2, NOW).unwrap();
        let vt = up.verify_targets(&tg2, NOW).unwrap();
        assert_eq!(vt.targets().targets.len(), 2);
    }

    #[test]
    fn invalid_entries_are_refused_and_not_kept() {
        let keys = Keys::new();
        let mut t = first_release();
        let mut bad = entry(b"x", "1.0.0", &["stable"]);
        bad.custom.channels = vec!["stable-1".into()];
        assert!(add_target(&mut t, "client/macos/x.pkg", bad).is_err());
        assert!(!t.targets.contains_key("client/macos/x.pkg"));
        assert!(add_target(&mut t, "../x.pkg", entry(b"x", "1.0.0", &["stable"])).is_err());
        assert!(parse_kind("server").is_ok());
        assert!(parse_kind("installer").is_err());
    }

    #[test]
    fn a_timestamp_version_that_goes_back_is_caught() {
        let keys = Keys::new();
        let roots = vec![keys.root(1, None)];
        let t1 = first_release();
        let (ts1, tg1) = publish(&keys, &t1, 100);

        // Same targets, re-signed timestamp with a lower version (a runner
        // whose clock went backwards).
        let ts_old = keys.sign_timestamp(&tg1, t1.version, 99);
        let (mut up, _) = verify_published(&roots, &ts1, &tg1).unwrap();
        assert!(up.verify_timestamp(&ts_old, NOW).is_err());

        // A higher version over the same targets is the daily re-sign.
        let ts_new = keys.sign_timestamp(&tg1, t1.version, 101);
        let (mut up, _) = verify_published(&roots, &ts1, &tg1).unwrap();
        up.verify_timestamp(&ts_new, NOW).unwrap();
        up.verify_targets(&tg1, NOW).unwrap();
    }

    #[test]
    fn expired_published_metadata_still_carries_forward() {
        let keys = Keys::new();
        let roots = vec![keys.root(1, None)];
        let mut t1 = first_release();
        t1.expires_ms = NOW - DAY;
        let (ts1, tg1) = publish(&keys, &t1, 100);
        let (_, prev) = verify_published(&roots, &ts1, &tg1).unwrap();
        assert_eq!(next_targets(Some(&prev), NOW + DAY).unwrap().version, 2);
    }

    #[test]
    fn published_metadata_from_before_a_key_rotation_verifies() {
        let old = Keys::new();
        let new = Keys::new();
        let roots = vec![old.root(1, None), new.root(2, Some(&old))];
        let t1 = first_release();
        let (ts1, tg1) = publish(&old, &t1, 100);

        let (mut up, prev) = verify_published(&roots, &ts1, &tg1).unwrap();
        assert_eq!(up.state().root().version, 2);
        // The targets key was replaced, so the new keys start over; the
        // entries are still carried forward.
        let t2 = next_targets(Some(&prev), NOW + DAY).unwrap();
        let (ts2, tg2) = publish(&new, &t2, 101);
        up.verify_timestamp(&ts2, NOW).unwrap();
        up.verify_targets(&tg2, NOW).unwrap();
    }

    #[test]
    fn metadata_from_another_project_is_refused() {
        let ours = Keys::new();
        let theirs = Keys::new();
        let roots = vec![ours.root(1, None)];
        let t1 = first_release();
        let (ts, tg) = publish(&theirs, &t1, 100);
        assert!(verify_published(&roots, &ts, &tg).is_err());
    }

    #[test]
    fn artifacts_are_checked_against_the_listing() {
        let keys = Keys::new();
        let roots = vec![keys.root(1, None)];
        let dir = tempfile::tempdir().unwrap();
        let t1 = first_release();
        let (ts1, tg1) = publish(&keys, &t1, 100);
        let (mut up, _) = verify_published(&roots, &ts1, &tg1).unwrap();
        let vt1 = up.verify_targets(&tg1, NOW).unwrap();

        // Missing and new: refused.
        assert!(check_artifacts(&vt1, None, dir.path()).is_err());
        // Missing but already published: fine.
        assert_eq!(check_artifacts(&vt1, Some(&vt1), dir.path()).unwrap(), 0);

        let path = dir.path().join("client/macos/Faro-0.1.0-beta.1.pkg");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"one").unwrap();
        assert_eq!(check_artifacts(&vt1, None, dir.path()).unwrap(), 1);
        std::fs::write(&path, b"onf").unwrap();
        assert!(check_artifacts(&vt1, Some(&vt1), dir.path()).is_err());
        assert_eq!(
            describe_file(&path).unwrap(),
            (3, Hash32::of(b"onf")),
            "describe_file hashes the whole file"
        );
    }
}
