//! Shared fixtures: a toy "project" with root/targets/timestamp keys that
//! can mint metadata at will, including deliberately broken metadata.
#![allow(dead_code)]

use faro_crypto::SigningKey;
use faro_proto::keys::key_id;
use faro_proto::Hash32;
use faro_update::{
    Envelope, MetadataSigner, Role, RoleKeys, Root, RootRoles, TargetCustom, TargetFile,
    TargetKind, Targets, TargetsMeta, Timestamp, Updater, Version,
};
use std::collections::BTreeMap;

pub const DAY: i64 = 86_400_000;
/// A fixed "now" so tests are deterministic.
pub const T0: i64 = 1_800_000_000_000;

pub fn id(k: &SigningKey) -> String {
    key_id(k.public().as_bytes())
}

pub fn ids(keys: &[&SigningKey]) -> Vec<String> {
    keys.iter().map(|k| id(k)).collect()
}

pub struct KeySet {
    pub root: Vec<SigningKey>,
    pub root_threshold: u32,
    pub targets: SigningKey,
    pub timestamp: SigningKey,
}

impl KeySet {
    pub fn new() -> Self {
        KeySet {
            root: (0..3).map(|_| SigningKey::generate()).collect(),
            root_threshold: 2,
            targets: SigningKey::generate(),
            timestamp: SigningKey::generate(),
        }
    }

    pub fn root_refs(&self) -> Vec<&SigningKey> {
        self.root.iter().collect()
    }

    pub fn root_meta(&self, version: u64, expires_ms: i64) -> Root {
        let mut keys = BTreeMap::new();
        for k in self.root.iter().chain([&self.targets, &self.timestamp]) {
            keys.insert(id(k), k.public());
        }
        Root {
            version,
            expires_ms,
            keys,
            roles: RootRoles {
                root: RoleKeys::new(ids(&self.root_refs()), self.root_threshold),
                targets: RoleKeys::new(vec![id(&self.targets)], 1),
                timestamp: RoleKeys::new(vec![id(&self.timestamp)], 1),
            },
        }
    }
}

pub fn sign_root(root: &Root, signers: &[&SigningKey]) -> Vec<u8> {
    MetadataSigner::new(signers.iter().copied())
        .sign_to_bytes(root)
        .unwrap()
}

/// Sign arbitrary (possibly invalid) metadata without validation.
pub fn sign_unchecked<T: serde::Serialize>(
    role: Role,
    meta: &T,
    signers: &[&SigningKey],
) -> Vec<u8> {
    let payload = serde_json::to_vec(meta).unwrap();
    Envelope::sign_raw(role.payload_type(), &payload, signers).to_bytes()
}

pub fn target(
    kind: TargetKind,
    platform: &str,
    arch: &str,
    version: &str,
    channels: &[&str],
    content: &[u8],
) -> TargetFile {
    TargetFile {
        length: content.len() as u64,
        blake3: Hash32::of(content),
        custom: TargetCustom {
            kind,
            platform: platform.into(),
            arch: arch.into(),
            version: Version::parse(version).unwrap(),
            channels: channels.iter().map(|c| c.to_string()).collect(),
            min_os: None,
        },
    }
}

pub fn targets_meta(version: u64, expires_ms: i64, entries: Vec<(&str, TargetFile)>) -> Targets {
    Targets {
        version,
        expires_ms,
        targets: entries
            .into_iter()
            .map(|(n, f)| (n.to_string(), f))
            .collect(),
    }
}

pub fn sign_targets(t: &Targets, key: &SigningKey) -> Vec<u8> {
    MetadataSigner::new([key]).sign_to_bytes(t).unwrap()
}

pub fn timestamp_for(
    version: u64,
    expires_ms: i64,
    targets_bytes: &[u8],
    targets_version: u64,
) -> Timestamp {
    Timestamp {
        version,
        expires_ms,
        targets_meta: TargetsMeta::describe(targets_bytes, targets_version),
    }
}

pub fn sign_ts(ts: &Timestamp, key: &SigningKey) -> Vec<u8> {
    MetadataSigner::new([key]).sign_to_bytes(ts).unwrap()
}

/// A small, valid targets listing.
pub fn simple_targets(version: u64, expires_ms: i64) -> Targets {
    targets_meta(
        version,
        expires_ms,
        vec![(
            "client/macos/aarch64/faro.pkg",
            target(
                TargetKind::Client,
                "macos",
                "aarch64",
                &format!("1.{version}.0"),
                &["stable"],
                format!("payload v{version}").as_bytes(),
            ),
        )],
    )
}

/// One fully signed release (targets + matching timestamp).
pub struct Release {
    pub targets: Vec<u8>,
    pub timestamp: Vec<u8>,
}

pub fn release(keys: &KeySet, ts_version: u64, targets_version: u64, expires_ms: i64) -> Release {
    let targets = sign_targets(&simple_targets(targets_version, expires_ms), &keys.targets);
    let ts = timestamp_for(ts_version, expires_ms, &targets, targets_version);
    Release {
        timestamp: sign_ts(&ts, &keys.timestamp),
        targets,
    }
}

/// Bootstrapped updater for `keys` with root v1 valid for a year.
pub fn updater(keys: &KeySet) -> Updater {
    let root = keys.root_meta(1, T0 + 365 * DAY);
    let bytes = sign_root(&root, &keys.root_refs());
    Updater::bootstrap(&bytes).unwrap()
}
