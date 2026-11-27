//! A toy "project" for tests of update consumers (the server mirror, the
//! client service): its own root, targets and timestamp keys, publishing
//! signed releases in the upstream layout (PROTOCOL.md §8):
//!
//! ```text
//! roots/<n>.json  timestamp.json  targets.json  targets/<name>
//! ```
//!
//! Only built with the `testing` feature. Never enable it in a shipped
//! binary: it holds private keys in memory and exists to sign whatever a
//! test asks for.

use crate::envelope::Envelope;
use crate::metadata::{
    Role, RoleKeys, Root, RootRoles, TargetCustom, TargetFile, TargetKind, Targets, TargetsMeta,
    Timestamp,
};
use crate::signer::MetadataSigner;
use faro_crypto::SigningKey;
use faro_proto::keys::key_id;
use faro_proto::Hash32;
use semver::Version;
use std::collections::BTreeMap;
use std::path::Path;

/// One day in milliseconds.
pub const DAY_MS: i64 = 86_400_000;

/// An artifact to publish.
#[derive(Debug, Clone)]
pub struct Artifact {
    pub name: String,
    pub kind: TargetKind,
    pub platform: String,
    pub arch: String,
    pub version: Version,
    pub channels: Vec<String>,
    pub min_os: Option<String>,
    pub min_client: Option<Version>,
    pub content: Vec<u8>,
}

impl Artifact {
    /// A `stable` artifact with `content` as its bytes.
    pub fn new(
        name: &str,
        kind: TargetKind,
        platform: &str,
        arch: &str,
        version: &str,
        content: &[u8],
    ) -> Self {
        Artifact {
            name: name.to_owned(),
            kind,
            platform: platform.to_owned(),
            arch: arch.to_owned(),
            version: Version::parse(version).expect("valid semver"),
            channels: vec![crate::STABLE_CHANNEL.to_owned()],
            min_os: None,
            min_client: None,
            content: content.to_vec(),
        }
    }

    /// Replace the channels.
    pub fn channels(mut self, channels: &[&str]) -> Self {
        self.channels = channels.iter().map(|c| (*c).to_owned()).collect();
        self
    }

    /// Set the minimum client version.
    pub fn min_client(mut self, version: &str) -> Self {
        self.min_client = Some(Version::parse(version).expect("valid semver"));
        self
    }

    fn file(&self) -> TargetFile {
        TargetFile {
            length: self.content.len() as u64,
            blake3: Hash32::of(&self.content),
            custom: TargetCustom {
                kind: self.kind,
                platform: self.platform.clone(),
                arch: self.arch.clone(),
                version: self.version.clone(),
                channels: self.channels.clone(),
                min_os: self.min_os.clone(),
                min_client: self.min_client.clone(),
            },
        }
    }
}

/// The signed documents of one release.
#[derive(Debug, Clone)]
pub struct Release {
    pub timestamp: Vec<u8>,
    pub targets: Vec<u8>,
}

/// A project with one root key (threshold 1) plus a targets key and a
/// timestamp key.
#[derive(Debug)]
pub struct ToyProject {
    root_key: SigningKey,
    targets_key: SigningKey,
    timestamp_key: SigningKey,
    root_version: u64,
    targets_version: u64,
    timestamp_version: u64,
    root_expires_ms: i64,
}

impl ToyProject {
    /// A new project whose root expires at `root_expires_ms`.
    pub fn new(root_expires_ms: i64) -> Self {
        ToyProject {
            root_key: SigningKey::generate(),
            targets_key: SigningKey::generate(),
            timestamp_key: SigningKey::generate(),
            root_version: 1,
            targets_version: 0,
            timestamp_version: 0,
            root_expires_ms,
        }
    }

    /// Like [`new`](Self::new), with every key derived from `seed`, so two
    /// processes build byte-identical documents (Ed25519 signing is
    /// deterministic). The fuzz targets rely on this: their seed corpus is
    /// written by one program and must verify against the root another one
    /// trusts.
    pub fn from_seed(seed: [u8; 32], root_expires_ms: i64) -> Self {
        let key = |role: &str| {
            let context = format!("faro-update testing ToyProject {role} key");
            SigningKey::from_bytes(&blake3::derive_key(&context, &seed))
        };
        ToyProject {
            root_key: key("root"),
            targets_key: key("targets"),
            timestamp_key: key("timestamp"),
            ..ToyProject::new(root_expires_ms)
        }
    }

    /// Sign arbitrary `payload` bytes as `role` with that role's key and
    /// return the serialized envelope. Unlike every other method this does
    /// **not** validate the payload: it is for testing how verifiers treat
    /// documents that carry a valid project signature but are malformed
    /// (a buggy release tool, or a compromised key).
    pub fn sign_raw(&self, role: Role, payload: &[u8]) -> Vec<u8> {
        let key = match role {
            Role::Root => &self.root_key,
            Role::Targets => &self.targets_key,
            Role::Timestamp => &self.timestamp_key,
        };
        Envelope::sign_raw(role.payload_type(), payload, &[key]).to_bytes()
    }

    fn root_meta(&self, version: u64) -> Root {
        let id = |k: &SigningKey| key_id(k.public().as_bytes());
        let keys = [&self.root_key, &self.targets_key, &self.timestamp_key]
            .into_iter()
            .map(|k| (id(k), k.public()))
            .collect::<BTreeMap<_, _>>();
        Root {
            version,
            expires_ms: self.root_expires_ms,
            keys,
            roles: RootRoles {
                root: RoleKeys::new([id(&self.root_key)], 1),
                targets: RoleKeys::new([id(&self.targets_key)], 1),
                timestamp: RoleKeys::new([id(&self.timestamp_key)], 1),
            },
        }
    }

    /// The signed first root, as shipped with the software.
    pub fn first_root(&self) -> Vec<u8> {
        MetadataSigner::new([&self.root_key])
            .sign_to_bytes(&self.root_meta(1))
            .expect("valid root")
    }

    /// Sign the next root version (same keys; the old root key signs it,
    /// which is also the new root key). Returns `(version, envelope)`.
    pub fn rotate_root(&mut self) -> (u64, Vec<u8>) {
        self.root_version += 1;
        let env = MetadataSigner::new([&self.root_key])
            .sign_to_bytes(&self.root_meta(self.root_version))
            .expect("valid root");
        (self.root_version, env)
    }

    /// Sign a release listing `artifacts`, expiring at `expires_ms`.
    pub fn release(&mut self, artifacts: &[Artifact], expires_ms: i64) -> Release {
        self.release_expiring(artifacts, expires_ms, expires_ms)
    }

    /// Like [`release`](Self::release), with the targets and timestamp
    /// expiring at different times (as real releases do: weeks for the
    /// targets, about a day for the timestamp).
    pub fn release_expiring(
        &mut self,
        artifacts: &[Artifact],
        targets_expires_ms: i64,
        timestamp_expires_ms: i64,
    ) -> Release {
        self.targets_version += 1;
        self.timestamp_version += 1;
        let targets = Targets {
            version: self.targets_version,
            expires_ms: targets_expires_ms,
            targets: artifacts
                .iter()
                .map(|a| (a.name.clone(), a.file()))
                .collect(),
        };
        let targets = MetadataSigner::new([&self.targets_key])
            .sign_to_bytes(&targets)
            .expect("valid targets");
        let ts = Timestamp {
            version: self.timestamp_version,
            expires_ms: timestamp_expires_ms,
            targets_meta: TargetsMeta::describe(&targets, self.targets_version),
        };
        let timestamp = MetadataSigner::new([&self.timestamp_key])
            .sign_to_bytes(&ts)
            .expect("valid timestamp");
        Release { timestamp, targets }
    }

    /// A new timestamp for the latest targets (the daily re-sign).
    pub fn refresh_timestamp(&mut self, release: &Release, expires_ms: i64) -> Release {
        self.timestamp_version += 1;
        let ts = Timestamp {
            version: self.timestamp_version,
            expires_ms,
            targets_meta: TargetsMeta::describe(&release.targets, self.targets_version),
        };
        Release {
            timestamp: MetadataSigner::new([&self.timestamp_key])
                .sign_to_bytes(&ts)
                .expect("valid timestamp"),
            targets: release.targets.clone(),
        }
    }

    /// Sign a release and write it, with every artifact, into `dir` in the
    /// upstream layout, replacing a previous release there.
    pub fn publish(
        &mut self,
        dir: &Path,
        artifacts: &[Artifact],
        expires_ms: i64,
    ) -> std::io::Result<Release> {
        let release = self.release(artifacts, expires_ms);
        write_release(dir, &release)?;
        for a in artifacts {
            write_artifact(dir, a)?;
        }
        Ok(release)
    }
}

/// Write `release`'s documents into `dir`.
pub fn write_release(dir: &Path, release: &Release) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("targets.json"), &release.targets)?;
    std::fs::write(dir.join("timestamp.json"), &release.timestamp)
}

/// Write one artifact's bytes to `dir/targets/<name>`.
pub fn write_artifact(dir: &Path, a: &Artifact) -> std::io::Result<()> {
    let path = dir.join("targets").join(&a.name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, &a.content)
}

/// Write a root rotation to `dir/roots/<version>.json`.
pub fn write_root(dir: &Path, version: u64, envelope: &[u8]) -> std::io::Result<()> {
    let roots = dir.join("roots");
    std::fs::create_dir_all(&roots)?;
    std::fs::write(roots.join(format!("{version}.json")), envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{UpdateError, Updater};

    #[test]
    fn seeded_projects_sign_identical_documents() {
        let mut a = ToyProject::from_seed([1; 32], DAY_MS);
        let mut b = ToyProject::from_seed([1; 32], DAY_MS);
        let c = ToyProject::from_seed([2; 32], DAY_MS);
        assert_eq!(a.first_root(), b.first_root());
        assert_ne!(a.first_root(), c.first_root());
        let art = Artifact::new("a", TargetKind::Model, "any", "any", "1.0.0", b"x");
        let ra = a.release(std::slice::from_ref(&art), DAY_MS);
        let rb = b.release(&[art], DAY_MS);
        assert_eq!((ra.timestamp, ra.targets), (rb.timestamp, rb.targets));
    }

    #[test]
    fn sign_raw_signs_without_validating() {
        let p = ToyProject::from_seed([1; 32], DAY_MS);
        let mut u = Updater::bootstrap(&p.first_root()).unwrap();
        // Signed by the timestamp key, so it gets past the signatures and
        // fails only on the payload.
        let env = p.sign_raw(Role::Timestamp, b"not json");
        assert!(matches!(
            u.verify_timestamp(&env, 0),
            Err(UpdateError::InvalidMetadata { .. })
        ));
        // Another role's key does not count.
        let env = p.sign_raw(Role::Targets, b"{}");
        let env = String::from_utf8(env)
            .unwrap()
            .replace("targets+json", "timestamp+json");
        assert!(matches!(
            u.verify_timestamp(env.as_bytes(), 0),
            Err(UpdateError::ThresholdNotMet { .. })
        ));
    }
}
