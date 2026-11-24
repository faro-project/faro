//! The three role documents (root, targets, timestamp) and their structural
//! validation.
//!
//! These structs are the *payloads* carried inside a signed
//! [`Envelope`](crate::Envelope). Their top-level fields use
//! `deny_unknown_fields`: a client must never act on a signed document it only
//! partially understands. Evolving a role's schema therefore means a new
//! `payload_type` (e.g. `application/vnd.faro.targets.v2+json`) that old
//! clients reject cleanly instead of misreading. The one deliberately open
//! object is [`TargetCustom`], which carries per-artifact hints and may grow
//! optional fields over time.

use faro_proto::keys::key_id;
use faro_proto::{Hash32, SignPublicKey};
use semver::Version;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Hard cap on a serialized root envelope. Roots hold a handful of keys.
pub const MAX_ROOT_BYTES: usize = 256 * 1024;
/// Hard cap on a serialized timestamp envelope. Timestamps are tiny.
pub const MAX_TIMESTAMP_BYTES: usize = 64 * 1024;
/// Hard cap on a serialized targets envelope. Generous: a release lists a
/// few dozen artifacts per platform/arch/channel.
pub const MAX_TARGETS_BYTES: usize = 8 * 1024 * 1024;
/// Upper bound on keys in a root, to bound verification and storage work.
pub const MAX_ROOT_KEYS: usize = 64;
/// Upper bound on entries in a targets document.
pub const MAX_TARGETS: usize = 10_000;

/// Name of the channel that `stable-1` pins relative to.
pub const STABLE_CHANNEL: &str = "stable";

/// The three signing roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Offline, threshold-signed; delegates trust to every role (incl. itself).
    Root,
    /// Lists the downloadable artifacts with their lengths and hashes.
    Targets,
    /// Online, short-lived; commits to the current targets document.
    Timestamp,
}

impl Role {
    /// DSSE-style payload type bound into every signature, so a signed
    /// document can never be replayed as a different role.
    pub fn payload_type(self) -> &'static str {
        match self {
            Role::Root => "application/vnd.faro.root+json",
            Role::Targets => "application/vnd.faro.targets+json",
            Role::Timestamp => "application/vnd.faro.timestamp+json",
        }
    }

    /// Hard size cap on a serialized envelope for this role.
    pub fn max_envelope_bytes(self) -> usize {
        match self {
            Role::Root => MAX_ROOT_BYTES,
            Role::Targets => MAX_TARGETS_BYTES,
            Role::Timestamp => MAX_TIMESTAMP_BYTES,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Root => "root",
            Role::Targets => "targets",
            Role::Timestamp => "timestamp",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Common behaviour of the three role payloads.
pub trait RoleMetadata: Serialize + DeserializeOwned {
    /// Which role this payload belongs to.
    const ROLE: Role;
    /// Monotonic version; never decreases for a given role.
    fn version(&self) -> u64;
    /// Unix milliseconds after which the document must not be trusted.
    fn expires_ms(&self) -> i64;
    /// Structural checks that serde alone cannot express. Run on every
    /// parsed payload and before signing, so the signer refuses to produce
    /// documents clients would reject.
    fn validate(&self) -> Result<(), String>;
}

/// Which keys may sign for a role, and how many must.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleKeys {
    /// Key ids (see [`faro_proto::keys::key_id`]) authorised for this role.
    pub keyids: Vec<String>,
    /// Minimum number of distinct authorised keys that must sign.
    pub threshold: u32,
}

impl RoleKeys {
    pub fn new(keyids: impl IntoIterator<Item = String>, threshold: u32) -> Self {
        RoleKeys {
            keyids: keyids.into_iter().collect(),
            threshold,
        }
    }

    /// The key-id set, for comparing role assignments across root versions
    /// regardless of list order.
    pub(crate) fn keyid_set(&self) -> BTreeSet<&str> {
        self.keyids.iter().map(String::as_str).collect()
    }

    fn validate(&self, role: Role, keys: &BTreeMap<String, SignPublicKey>) -> Result<(), String> {
        if self.threshold == 0 {
            return Err(format!("{role} threshold must be at least 1"));
        }
        let set = self.keyid_set();
        if set.len() != self.keyids.len() {
            return Err(format!("{role} lists a key id more than once"));
        }
        if (self.threshold as usize) > set.len() {
            return Err(format!(
                "{role} threshold {} exceeds its {} keys",
                self.threshold,
                set.len()
            ));
        }
        if let Some(missing) = set.iter().find(|id| !keys.contains_key(**id)) {
            return Err(format!("{role} references unknown key id {missing:?}"));
        }
        Ok(())
    }
}

/// Role assignments inside a root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootRoles {
    pub root: RoleKeys,
    pub targets: RoleKeys,
    pub timestamp: RoleKeys,
}

impl RootRoles {
    pub fn get(&self, role: Role) -> &RoleKeys {
        match role {
            Role::Root => &self.root,
            Role::Targets => &self.targets,
            Role::Timestamp => &self.timestamp,
        }
    }
}

/// The root of trust. Shipped inside every installer; rotated by signing
/// `version + 1` with both the old and new root key sets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Root {
    pub version: u64,
    pub expires_ms: i64,
    /// Every key any role may use, by key id. Each id must equal
    /// `key_id(pubkey)` so an id can never be re-pointed at another key.
    pub keys: BTreeMap<String, SignPublicKey>,
    pub roles: RootRoles,
}

impl Root {
    /// Public keys authorised for `role`, by key id.
    pub(crate) fn role_keys(&self, role: Role) -> &RoleKeys {
        self.roles.get(role)
    }
}

impl RoleMetadata for Root {
    const ROLE: Role = Role::Root;

    fn version(&self) -> u64 {
        self.version
    }

    fn expires_ms(&self) -> i64 {
        self.expires_ms
    }

    fn validate(&self) -> Result<(), String> {
        if self.version == 0 {
            return Err("version must be at least 1".into());
        }
        if self.keys.len() > MAX_ROOT_KEYS {
            return Err(format!(
                "{} keys exceeds the limit of {MAX_ROOT_KEYS}",
                self.keys.len()
            ));
        }
        for (id, pk) in &self.keys {
            if key_id(pk.as_bytes()) != *id {
                return Err(format!("key id {id:?} does not match its public key"));
            }
        }
        for role in [Role::Root, Role::Targets, Role::Timestamp] {
            self.roles.get(role).validate(role, &self.keys)?;
        }
        Ok(())
    }
}

/// What kind of artifact a target is. Clients only ever select the kinds
/// they consume; the server mirror fetches all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    /// Desktop client installer / update package.
    Client,
    /// On-device detection model.
    Model,
    /// Domain / URL blocklist.
    Blocklist,
    /// `faro-server` release.
    Server,
}

/// Per-artifact selection hints. Deliberately not `deny_unknown_fields`, so
/// new optional hints can be added without a payload-type bump; anything a
/// client must understand to stay safe belongs at the top level instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetCustom {
    pub kind: TargetKind,
    /// `macos`, `windows`, `linux`, or `any` for platform-independent
    /// artifacts such as models and blocklists.
    pub platform: String,
    /// `aarch64`, `x86_64`, ... or `any`.
    pub arch: String,
    pub version: Version,
    /// Channels this artifact is released to (`stable`, `beta`, ...).
    pub channels: Vec<String>,
    /// Minimum OS version, dotted numeric (`"13"`, `"10.0.19045"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_os: Option<String>,
}

/// One downloadable artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetFile {
    /// Exact length in bytes. Downloads are cut off past this.
    pub length: u64,
    /// BLAKE3 of the full artifact.
    pub blake3: Hash32,
    pub custom: TargetCustom,
}

/// The list of artifacts, signed by the targets role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Targets {
    pub version: u64,
    pub expires_ms: i64,
    /// Target name (a relative path the mirror serves it under) → file.
    pub targets: BTreeMap<String, TargetFile>,
}

impl RoleMetadata for Targets {
    const ROLE: Role = Role::Targets;

    fn version(&self) -> u64 {
        self.version
    }

    fn expires_ms(&self) -> i64 {
        self.expires_ms
    }

    fn validate(&self) -> Result<(), String> {
        if self.version == 0 {
            return Err("version must be at least 1".into());
        }
        if self.targets.len() > MAX_TARGETS {
            return Err(format!(
                "{} targets exceeds the limit of {MAX_TARGETS}",
                self.targets.len()
            ));
        }
        for (name, file) in &self.targets {
            if !is_valid_target_name(name) {
                return Err(format!("invalid target name {name:?}"));
            }
            let c = &file.custom;
            if !is_valid_token(&c.platform) {
                return Err(format!(
                    "target {name:?}: invalid platform {:?}",
                    c.platform
                ));
            }
            if !is_valid_token(&c.arch) {
                return Err(format!("target {name:?}: invalid arch {:?}", c.arch));
            }
            if c.channels.is_empty() {
                return Err(format!("target {name:?}: no channels"));
            }
            let mut seen = BTreeSet::new();
            for ch in &c.channels {
                if !is_valid_channel_name(ch) {
                    return Err(format!("target {name:?}: invalid channel {ch:?}"));
                }
                if !seen.insert(ch.as_str()) {
                    return Err(format!("target {name:?}: duplicate channel {ch:?}"));
                }
            }
            if let Some(min_os) = &c.min_os {
                if parse_os_version(min_os).is_none() {
                    return Err(format!("target {name:?}: invalid min_os {min_os:?}"));
                }
            }
        }
        Ok(())
    }
}

/// The timestamp's commitment to one exact targets document. Folding TUF's
/// snapshot role in here is safe because Faro has a single targets file (no
/// delegations): pinning its version, length and hash is all a snapshot
/// would add.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetsMeta {
    /// `version` inside the committed targets payload.
    pub version: u64,
    /// Exact byte length of the targets *envelope* as served.
    pub length: u64,
    /// BLAKE3 of the targets envelope bytes as served.
    pub blake3: Hash32,
}

impl TargetsMeta {
    /// Describe a serialized targets envelope, for the timestamp signer.
    pub fn describe(targets_envelope_bytes: &[u8], version: u64) -> Self {
        TargetsMeta {
            version,
            length: targets_envelope_bytes.len() as u64,
            blake3: Hash32::of(targets_envelope_bytes),
        }
    }
}

/// Short-lived freshness statement, signed by the online timestamp key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timestamp {
    pub version: u64,
    pub expires_ms: i64,
    pub targets_meta: TargetsMeta,
}

impl RoleMetadata for Timestamp {
    const ROLE: Role = Role::Timestamp;

    fn version(&self) -> u64 {
        self.version
    }

    fn expires_ms(&self) -> i64 {
        self.expires_ms
    }

    fn validate(&self) -> Result<(), String> {
        if self.version == 0 {
            return Err("version must be at least 1".into());
        }
        if self.targets_meta.version == 0 {
            return Err("targets_meta.version must be at least 1".into());
        }
        if self.targets_meta.length == 0 || self.targets_meta.length > MAX_TARGETS_BYTES as u64 {
            return Err(format!(
                "targets_meta.length {} outside 1..={MAX_TARGETS_BYTES}",
                self.targets_meta.length
            ));
        }
        Ok(())
    }
}

/// Target names double as mirror paths, so they are restricted to
/// `/`-separated segments of `[A-Za-z0-9._-]` that start with an
/// alphanumeric. That rules out absolute paths, `.`/`..` traversal,
/// backslashes and empty segments by construction.
pub fn is_valid_target_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name.split('/').all(|seg| {
            let mut chars = seg.chars();
            matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
                && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        })
}

/// Platform / arch tokens: `[a-z0-9_]{1,32}`.
fn is_valid_token(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Channel names: `[a-z][a-z0-9]{0,31}`. No hyphens, so a channel can never
/// collide with a pin expression such as `stable-1`.
pub fn is_valid_channel_name(s: &str) -> bool {
    let mut bytes = s.bytes();
    (1..=32).contains(&s.len())
        && matches!(bytes.next(), Some(b) if b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// Parse a dotted numeric OS version with one to three components
/// (`"13"` → 13.0.0, `"10.0.19045"` → 10.0.19045).
pub fn parse_os_version(s: &str) -> Option<Version> {
    let mut parts = [0u64; 3];
    for (n, p) in s.split('.').enumerate() {
        if n == 3 || p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        parts[n] = p.parse().ok()?;
    }
    Some(Version::new(parts[0], parts[1], parts[2]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_names() {
        for ok in ["faro-1.2.3-macos.pkg", "client/macos/aarch64/faro.pkg", "a"] {
            assert!(is_valid_target_name(ok), "{ok}");
        }
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../b",
            "a//b",
            "a/",
            ".hidden",
            "a\\b",
            "a b",
            "ü",
            &"a".repeat(256),
        ] {
            assert!(!is_valid_target_name(bad), "{bad}");
        }
    }

    #[test]
    fn channel_names() {
        assert!(is_valid_channel_name("stable"));
        assert!(is_valid_channel_name("beta2"));
        assert!(!is_valid_channel_name("stable-1"));
        assert!(!is_valid_channel_name("Stable"));
        assert!(!is_valid_channel_name("1beta"));
        assert!(!is_valid_channel_name(""));
    }

    #[test]
    fn os_versions() {
        assert_eq!(parse_os_version("13"), Some(Version::new(13, 0, 0)));
        assert_eq!(parse_os_version("13.4"), Some(Version::new(13, 4, 0)));
        assert_eq!(
            parse_os_version("10.0.19045"),
            Some(Version::new(10, 0, 19045))
        );
        for bad in ["", "1.", ".1", "1.2.3.4", "a", "-1", "1.+2"] {
            assert_eq!(parse_os_version(bad), None, "{bad}");
        }
    }

    #[test]
    fn payload_types_are_distinct() {
        let set: BTreeSet<_> = [Role::Root, Role::Targets, Role::Timestamp]
            .iter()
            .map(|r| r.payload_type())
            .collect();
        assert_eq!(set.len(), 3);
    }
}
