//! Key identifiers and the member-signed **endorsements** that make the key
//! directory trustworthy even if the instance is not (§5.2, §5.3).
//!
//! A device encrypts only to keys the member signed with the signing key the
//! device pinned at enrollment. The instance stores and serves these
//! documents but cannot forge them.
//!
//! Individual [`AllyEndorsement`]s record that a member approved an ally, but
//! they cannot express **removal**: a removed ally's old endorsement still
//! verifies, so an instance that kept serving it could keep that ally reading.
//! The authority for "who may a device encrypt to right now" is therefore the
//! [`RecipientManifest`]: a single member-signed, **versioned** list that
//! devices only ever move forward through (see `docs/PROTOCOL.md` §5.1).

use crate::encoding::{Canonical, EncPublicKey, Hash32, SignPublicKey, Signature};
use crate::ids::{DeviceId, InstanceId, UserId};
use serde::{Deserialize, Serialize};

const TAG_RECIPIENT_MANIFEST_V1: &str = "faro/recipient-manifest/v1";
const TAG_RECIPIENT_MANIFEST_V2: &str = "faro/recipient-manifest/v2";
const TAG_ALLY_ENDORSEMENT: &str = "faro/ally-endorsement/v1";
const TAG_DEVICE_ENDORSEMENT: &str = "faro/device-endorsement/v2";
const TAG_MEMBER_SELF: &str = "faro/member-enc-key/v1";
const TAG_KEY_ID: &str = "faro/key-id/v1";
const TAG_SAFETY: &str = "faro/safety-code/v1";
const TAG_KEY_REWRAP: &str = "faro/key-rewrap/v1";
const TAG_ALLY_KEY_REWRAP: &str = "faro/ally-key-rewrap/v1";

/// Short, stable identifier for a public key: first 8 bytes of a tagged
/// BLAKE3 hash, lowercase hex (16 chars).
pub fn key_id(pubkey: &[u8]) -> String {
    let h = Hash32::of(&Canonical::new(TAG_KEY_ID).bytes(pubkey).finish());
    hex::encode(&h.0[..8])
}

/// Upper bound on allies in one manifest. Keeps manifests (and the work a
/// device does per item, one sealed box per recipient) bounded even if the
/// instance serves a hostile document.
pub const MAX_MANIFEST_ALLIES: usize = 32;

/// The original manifest format: ally ids and keys, no names.
pub const MANIFEST_FORMAT_V1: u16 = 1;
/// Format 2 adds each ally's display name, inside the signed bytes.
pub const MANIFEST_FORMAT_V2: u16 = 2;

/// Most characters (Unicode scalar values) [`sanitize_ally_name`] keeps:
/// the instance's own display-name limit.
pub const MAX_ALLY_NAME_CHARS: usize = 64;
/// Longest ally name, in UTF-8 bytes, a manifest may carry
/// ([`RecipientManifest::validate`]): [`MAX_ALLY_NAME_CHARS`] of at most 4
/// bytes each, so every sanitized name fits.
pub const MAX_ALLY_NAME_BYTES: usize = 4 * MAX_ALLY_NAME_CHARS;

/// One ally entry in a [`RecipientManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestAlly {
    pub ally_id: UserId,
    pub enc_pubkey: EncPublicKey,
    /// The ally's display name when the member signed (format 2 only, where
    /// every ally has one; empty if the ally had none). It is untrusted text
    /// that a person typed, so show it only through
    /// [`ManifestAlly::display_name`]. A format 1 manifest has no names, and
    /// one that carries any fails [`RecipientManifest::validate`]: a name
    /// there would not be covered by the member's signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl ManifestAlly {
    /// The signed name, sanitized again for display ([`sanitize_ally_name`]),
    /// or `None` if the manifest has none for this ally (format 1, or an
    /// ally without a usable name).
    ///
    /// Call it only on a manifest that passed `validate` and its signature
    /// check: in a format 1 document, a name is not signed.
    pub fn display_name(&self) -> Option<String> {
        self.name
            .as_deref()
            .map(sanitize_ally_name)
            .filter(|n| !n.is_empty())
    }
}

/// Whether [`sanitize_ally_name`] removes `c`: C0 and C1 controls, `DEL`,
/// and the characters that reorder or hide text (bidi embeddings, overrides,
/// isolates and marks, `U+FEFF`, interlinear annotations). An explicit list,
/// not a Unicode property, so every implementation removes exactly the same
/// characters whatever its Unicode version.
fn stripped_from_names(c: char) -> bool {
    matches!(c,
        '\u{0}'..='\u{8}' | '\u{e}'..='\u{1f}' | '\u{7f}'..='\u{84}' | '\u{86}'..='\u{9f}'
        | '\u{61c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}'
        | '\u{2066}'..='\u{2069}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}')
}

/// Whether [`sanitize_ally_name`] turns `c` into a space: tab, line feed,
/// vertical tab, form feed, carriage return, `NEL`, and the line and
/// paragraph separators.
fn spaced_in_names(c: char) -> bool {
    matches!(c, '\u{9}'..='\u{d}' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

/// Make an ally display name safe to sign and to show (PROTOCOL.md §5.1).
/// The member's web app applies it before signing a format 2 manifest, and
/// devices apply it again before showing a name. The web app's port
/// (`sanitizeAllyName`) must agree byte for byte, which the shared test
/// vectors check. In order:
///
/// 1. remove C0 and C1 controls, `DEL` and the bidi and other invisible
///    format characters listed in PROTOCOL.md, and turn tabs and line
///    breaks into spaces;
/// 2. normalize to NFC;
/// 3. collapse runs of `U+0020` into one, and trim them from both ends;
/// 4. keep at most [`MAX_ALLY_NAME_CHARS`] scalar values, then trim a
///    trailing space again.
///
/// The result is at most [`MAX_ALLY_NAME_BYTES`] bytes.
pub fn sanitize_ally_name(input: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let cleaned: String = input
        .chars()
        .filter(|&c| !stripped_from_names(c))
        .map(|c| if spaced_in_names(c) { ' ' } else { c })
        .collect();
    let mut out = String::with_capacity(cleaned.len().min(MAX_ALLY_NAME_BYTES));
    let mut chars = 0;
    for c in cleaned.nfc() {
        if c == ' ' && (out.is_empty() || out.ends_with(' ')) {
            continue;
        }
        if chars == MAX_ALLY_NAME_CHARS {
            break;
        }
        out.push(c);
        chars += 1;
    }
    while out.ends_with(' ') {
        out.pop();
    }
    out
}

/// "As of version N, member M on instance I wants devices to encrypt to
/// exactly: their own key K_m, and these allies with these keys."
///
/// * Versions start at 1 and strictly increase per member. Every change
///   (approve, remove, ally key rotation, member key rotation) is a new
///   version signed by the member.
/// * Devices persist the highest `(version, hash)` they accepted and refuse
///   anything older (**rollback**: re-serving a pre-removal manifest) or a
///   different document at the same version (**equivocation**).
/// * Allies are sorted strictly ascending by `ally_id`, so one logical set has
///   exactly one encoding, and duplicates are impossible.
///
/// There are two formats (PROTOCOL.md §5.1). Format 1 lists ids and keys.
/// Format 2 also carries each ally's display name inside the signed bytes,
/// under its own domain-separation tag, so devices can name allies without
/// trusting the instance. Format 1 documents keep their exact JSON and
/// bytes: `format` is left out of their JSON, and a missing `format` reads
/// as 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientManifest {
    /// [`MANIFEST_FORMAT_V1`] or [`MANIFEST_FORMAT_V2`].
    #[serde(default = "manifest_format_v1", skip_serializing_if = "is_format_v1")]
    pub format: u16,
    pub instance_id: InstanceId,
    pub member_id: UserId,
    pub version: u64,
    pub issued_at_ms: i64,
    pub member_enc_pubkey: EncPublicKey,
    pub allies: Vec<ManifestAlly>,
}

fn manifest_format_v1() -> u16 {
    MANIFEST_FORMAT_V1
}

fn is_format_v1(f: &u16) -> bool {
    *f == MANIFEST_FORMAT_V1
}

/// Structural problems with a manifest that need no keys to detect.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("unknown recipient manifest format {0}")]
    UnknownFormat(u16),
    #[error("a format 1 manifest carries no ally names, but it names {0}")]
    UnsignedName(UserId),
    #[error("a format 2 manifest names every ally, but {0} has no name")]
    MissingName(UserId),
    #[error("the name of {0} is longer than {MAX_ALLY_NAME_BYTES} bytes")]
    NameTooLong(UserId),
    #[error("manifest version must be at least 1")]
    ZeroVersion,
    #[error("manifest lists {0} allies, more than the maximum of {MAX_MANIFEST_ALLIES}")]
    TooManyAllies(usize),
    #[error("manifest allies are not sorted strictly by ally_id (unsorted or duplicate: {0})")]
    NotSorted(UserId),
    #[error("manifest lists the member as their own ally")]
    MemberIsAlly,
    #[error("malformed id in manifest: {0}")]
    MalformedId(String),
}

impl RecipientManifest {
    /// Check the structural rules from the type docs. Signature checks are
    /// the caller's job (`faro_crypto::verify_signed`).
    ///
    /// Names are checked for their length only, never for their content:
    /// devices sanitize them again before showing them, and refusing a
    /// manifest over a name would make every recipient change, removals
    /// included, depend on two Unicode implementations agreeing.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.format != MANIFEST_FORMAT_V1 && self.format != MANIFEST_FORMAT_V2 {
            return Err(ManifestError::UnknownFormat(self.format));
        }
        if self.version == 0 {
            return Err(ManifestError::ZeroVersion);
        }
        if self.allies.len() > MAX_MANIFEST_ALLIES {
            return Err(ManifestError::TooManyAllies(self.allies.len()));
        }
        if !self.instance_id.is_well_formed() {
            return Err(ManifestError::MalformedId(self.instance_id.to_string()));
        }
        if !self.member_id.is_well_formed() {
            return Err(ManifestError::MalformedId(self.member_id.to_string()));
        }
        for (i, a) in self.allies.iter().enumerate() {
            if !a.ally_id.is_well_formed() {
                return Err(ManifestError::MalformedId(a.ally_id.to_string()));
            }
            if a.ally_id == self.member_id {
                return Err(ManifestError::MemberIsAlly);
            }
            if i > 0 && self.allies[i - 1].ally_id >= a.ally_id {
                return Err(ManifestError::NotSorted(a.ally_id.clone()));
            }
            match (self.format, &a.name) {
                (MANIFEST_FORMAT_V1, Some(_)) => {
                    return Err(ManifestError::UnsignedName(a.ally_id.clone()))
                }
                (MANIFEST_FORMAT_V2, None) => {
                    return Err(ManifestError::MissingName(a.ally_id.clone()))
                }
                (_, Some(n)) if n.len() > MAX_ALLY_NAME_BYTES => {
                    return Err(ManifestError::NameTooLong(a.ally_id.clone()))
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Canonical bytes the member signs. Callers must [`validate`] first;
    /// the encoding itself is total so it never panics on a bounded manifest.
    ///
    /// [`validate`]: Self::validate
    ///
    /// Format 1 is tagged `faro/recipient-manifest/v1`, and each ally is its
    /// id and key. Every other format is encoded like format 2, tagged
    /// `faro/recipient-manifest/v<format>`, with each ally's id, key and name
    /// (an absent name, which `validate` refuses in format 2, as empty). So
    /// the formats can never share bytes, and neither can a format 1
    /// document and a format 2 one whose allies all have empty names.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let tag = match self.format {
            MANIFEST_FORMAT_V1 => TAG_RECIPIENT_MANIFEST_V1.to_owned(),
            MANIFEST_FORMAT_V2 => TAG_RECIPIENT_MANIFEST_V2.to_owned(),
            other => format!("faro/recipient-manifest/v{other}"),
        };
        let mut c = Canonical::new(&tag)
            .str(self.instance_id.as_str())
            .str(self.member_id.as_str())
            .u64(self.version)
            .i64(self.issued_at_ms)
            .fixed(self.member_enc_pubkey.as_bytes())
            .u64(self.allies.len() as u64);
        for a in &self.allies {
            c = c.str(a.ally_id.as_str()).fixed(a.enc_pubkey.as_bytes());
            if self.format != MANIFEST_FORMAT_V1 {
                c = c.str(a.name.as_deref().unwrap_or(""));
            }
        }
        c.finish()
    }

    /// Identity of this exact document: `BLAKE3(signing_bytes)`.
    pub fn hash(&self) -> Hash32 {
        Hash32::of(&self.signing_bytes())
    }

    /// The `(version, hash)` pair devices persist and reports carry.
    pub fn reference(&self) -> ManifestRef {
        ManifestRef {
            version: self.version,
            hash: self.hash(),
        }
    }
}

/// A pointer to one exact manifest version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ManifestRef {
    pub version: u64,
    pub hash: Hash32,
}

/// "Member M, on instance I, approves ally A whose encryption key is K."
///
/// Kept as the record of an individual approval (and for the safety-code
/// flow). Devices do **not** use endorsements to pick recipients; they use
/// the [`RecipientManifest`], which can express removal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllyEndorsement {
    pub instance_id: InstanceId,
    pub member_id: UserId,
    pub ally_id: UserId,
    pub ally_enc_pubkey: EncPublicKey,
    /// Unix ms when the member approved this key. Lets devices prefer the newest.
    pub endorsed_at_ms: i64,
}

impl AllyEndorsement {
    pub fn signing_bytes(&self) -> Vec<u8> {
        Canonical::new(TAG_ALLY_ENDORSEMENT)
            .str(self.instance_id.as_str())
            .str(self.member_id.as_str())
            .str(self.ally_id.as_str())
            .fixed(self.ally_enc_pubkey.as_bytes())
            .i64(self.endorsed_at_ms)
            .finish()
    }
}

/// "Member M, on instance I, owns device D whose signing key is K."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEndorsement {
    pub instance_id: InstanceId,
    pub member_id: UserId,
    pub device_id: DeviceId,
    pub device_sign_pubkey: SignPublicKey,
    pub endorsed_at_ms: i64,
    /// The member's current [`RecipientManifest`] when they approved this
    /// device. The device's **first** accepted manifest must be at least this
    /// version (and exactly this document at this version), so an instance
    /// can't bootstrap a new or reinstalled device onto a pre-removal
    /// manifest. See `docs/PROTOCOL.md` §5.1 "Bootstrapping".
    pub min_manifest: ManifestRef,
}

impl DeviceEndorsement {
    pub fn signing_bytes(&self) -> Vec<u8> {
        Canonical::new(TAG_DEVICE_ENDORSEMENT)
            .str(self.instance_id.as_str())
            .str(self.member_id.as_str())
            .str(self.device_id.as_str())
            .fixed(self.device_sign_pubkey.as_bytes())
            .i64(self.endorsed_at_ms)
            .u64(self.min_manifest.version)
            .fixed(self.min_manifest.hash.as_bytes())
            .finish()
    }
}

/// The member binding their own encryption key to their signing key, so
/// devices can encrypt a copy of every item to the member (transparency, §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberEncKeyBinding {
    pub instance_id: InstanceId,
    pub member_id: UserId,
    pub member_enc_pubkey: EncPublicKey,
    pub endorsed_at_ms: i64,
}

impl MemberEncKeyBinding {
    pub fn signing_bytes(&self) -> Vec<u8> {
        Canonical::new(TAG_MEMBER_SELF)
            .str(self.instance_id.as_str())
            .str(self.member_id.as_str())
            .fixed(self.member_enc_pubkey.as_bytes())
            .i64(self.endorsed_at_ms)
            .finish()
    }
}

/// "Member M on instance I, holding signing key K, replaces the stored
/// wrapped copies of their private keys with these", for example after a
/// passphrase change (PROTOCOL.md §4.3).
///
/// The wrapped copies are opaque to the instance, so it can't tell a good
/// replacement from garbage. Requiring the member's signature means that a
/// stolen session alone can't overwrite them and lock the member out of
/// their own keys. The three wrapped values are carried as the exact JSON
/// text that was signed, so no JSON canonicalization is needed: the
/// instance verifies the bytes it received, then parses them.
///
/// `issued_at_ms` must be within the request clock skew of the instance's
/// time and later than the previous change, so an old request can't be
/// replayed to restore an old passphrase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRewrap {
    pub instance_id: InstanceId,
    pub member_id: UserId,
    pub sign_pubkey: SignPublicKey,
    pub issued_at_ms: i64,
    pub wrapped_sign_key: String,
    pub wrapped_enc_key: String,
    pub recovery_wrapped: String,
}

impl KeyRewrap {
    pub fn signing_bytes(&self) -> Vec<u8> {
        Canonical::new(TAG_KEY_REWRAP)
            .str(self.instance_id.as_str())
            .str(self.member_id.as_str())
            .fixed(self.sign_pubkey.as_bytes())
            .i64(self.issued_at_ms)
            .str(&self.wrapped_sign_key)
            .str(&self.wrapped_enc_key)
            .str(&self.recovery_wrapped)
            .finish()
    }
}

/// "Ally A on instance I replaces the wrapped copy of their key with this",
/// after a passphrase change or for a new recovery code (PROTOCOL.md §4.3).
///
/// The ally's key is X25519 and can't sign, so possession is proven another
/// way: the instance seals a 32-byte challenge to `enc_pubkey`, and the
/// ally's browser opens it and sends [`AllyKeyRewrap::proof`], a BLAKE3 MAC
/// over this request keyed with the challenge. The browser never returns
/// the challenge itself, so the instance can't use it to open other sealed
/// boxes (such as item keys) addressed to the ally. `wrapped_privkey` is
/// the exact JSON text that was MACed, as in [`KeyRewrap`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllyKeyRewrap {
    pub instance_id: InstanceId,
    pub ally_id: UserId,
    pub enc_pubkey: EncPublicKey,
    /// The challenge's time, as the instance issued it.
    pub issued_at_ms: i64,
    pub wrapped_privkey: String,
}

impl AllyKeyRewrap {
    pub fn proof_bytes(&self) -> Vec<u8> {
        Canonical::new(TAG_ALLY_KEY_REWRAP)
            .str(self.instance_id.as_str())
            .str(self.ally_id.as_str())
            .fixed(self.enc_pubkey.as_bytes())
            .i64(self.issued_at_ms)
            .str(&self.wrapped_privkey)
            .finish()
    }

    /// `BLAKE3-keyed(challenge, proof_bytes)`.
    pub fn proof(&self, challenge: &[u8; 32]) -> Hash32 {
        Hash32(*blake3::keyed_hash(challenge, &self.proof_bytes()).as_bytes())
    }
}

/// An [`AllyKeyRewrap`] with its proof, flattened like [`Signed`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenAllyKeyRewrap {
    #[serde(flatten)]
    pub body: AllyKeyRewrap,
    pub proof: Hash32,
}

/// Any endorsement plus the member's signature over its `signing_bytes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed<T> {
    #[serde(flatten)]
    pub body: T,
    pub sig: Signature,
}

/// Human-comparable **safety code** for a pair of keys (§5.2 item 4).
///
/// Order-independent: both parties compute the same code. Twelve groups of
/// five digits, like Signal's safety numbers.
pub fn safety_code(a: &[u8], b: &[u8]) -> String {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let h = Hash32::of(&Canonical::new(TAG_SAFETY).bytes(lo).bytes(hi).finish());
    digits_from_hash(&h)
}

/// Twelve groups of five digits from 60 bytes of BLAKE3 XOF output of `h`
/// (each byte mod 10), as safety codes print them.
pub(crate) fn digits_from_hash(h: &Hash32) -> String {
    // Expand to 60 digits with an XOF so every group has uniform-ish entropy.
    let mut xof = blake3::Hasher::new();
    xof.update(h.as_bytes());
    let mut out = [0u8; 60];
    xof.finalize_xof().fill(&mut out);
    let digits: Vec<u8> = out.iter().map(|b| b'0' + (b % 10)).collect();
    digits
        .chunks(5)
        .map(|c| std::str::from_utf8(c).unwrap().to_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(allies: &[&str]) -> RecipientManifest {
        RecipientManifest {
            format: MANIFEST_FORMAT_V1,
            instance_id: InstanceId::new("inst_a"),
            member_id: UserId::new("usr_m"),
            version: 1,
            issued_at_ms: 1,
            member_enc_pubkey: EncPublicKey([1; 32]),
            allies: allies
                .iter()
                .map(|a| ManifestAlly {
                    ally_id: UserId::new(*a),
                    enc_pubkey: EncPublicKey([2; 32]),
                    name: None,
                })
                .collect(),
        }
    }

    /// `manifest` in format 2, each ally named after their id.
    fn named(allies: &[&str]) -> RecipientManifest {
        let mut m = manifest(allies);
        m.format = MANIFEST_FORMAT_V2;
        for a in &mut m.allies {
            a.name = Some(format!("Name of {}", a.ally_id));
        }
        m
    }

    #[test]
    fn format_1_keeps_its_bytes_and_json() {
        // The exact encoding signed before format 2 existed.
        let m = manifest(&["usr_a"]);
        let want = Canonical::new("faro/recipient-manifest/v1")
            .str("inst_a")
            .str("usr_m")
            .u64(1)
            .i64(1)
            .fixed(&[1; 32])
            .u64(1)
            .str("usr_a")
            .fixed(&[2; 32])
            .finish();
        assert_eq!(m.signing_bytes(), want);
        let v = serde_json::to_value(&m).unwrap();
        assert!(v.get("format").is_none(), "{v}");
        assert!(v["allies"][0].get("name").is_none(), "{v}");
        // A document from before format 2 reads as format 1.
        let mut old = v.clone();
        old.as_object_mut().unwrap().remove("format");
        let back: RecipientManifest = serde_json::from_value(old).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn format_2_encodes_names_under_its_own_tag() {
        let m = named(&["usr_a"]);
        let want = Canonical::new("faro/recipient-manifest/v2")
            .str("inst_a")
            .str("usr_m")
            .u64(1)
            .i64(1)
            .fixed(&[1; 32])
            .u64(1)
            .str("usr_a")
            .fixed(&[2; 32])
            .str("Name of usr_a")
            .finish();
        assert_eq!(m.signing_bytes(), want);
        assert_eq!(m.validate(), Ok(()));
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["format"], 2);
        assert_eq!(v["allies"][0]["name"], "Name of usr_a");
        let back: RecipientManifest = serde_json::from_value(v).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.reference(), m.reference());

        // Every name is bound, and the formats never share bytes, not even
        // with empty names.
        let mut renamed = m.clone();
        renamed.allies[0].name = Some("Someone else".into());
        assert_ne!(renamed.hash(), m.hash());
        let mut empty = m.clone();
        empty.allies[0].name = Some(String::new());
        assert_eq!(empty.validate(), Ok(()));
        assert_ne!(empty.signing_bytes(), manifest(&["usr_a"]).signing_bytes());
        assert_ne!(named(&[]).signing_bytes(), manifest(&[]).signing_bytes());
        // A name can't absorb the next ally's bytes.
        let two = named(&["usr_a", "usr_b"]);
        let mut one = named(&["usr_a"]);
        one.allies[0].name = Some(format!("Name of usr_a{}", "x".repeat(40)));
        assert_ne!(two.signing_bytes(), one.signing_bytes());
    }

    #[test]
    fn names_must_match_the_format() {
        // A name in format 1 isn't signed, so the document is refused.
        let mut m = manifest(&["usr_a", "usr_b"]);
        m.allies[1].name = Some("Mallory".into());
        assert_eq!(
            m.validate(),
            Err(ManifestError::UnsignedName(UserId::new("usr_b")))
        );
        let mut m = named(&["usr_a", "usr_b"]);
        m.allies[0].name = None;
        assert_eq!(
            m.validate(),
            Err(ManifestError::MissingName(UserId::new("usr_a")))
        );
        let mut m = named(&["usr_a"]);
        m.allies[0].name = Some("é".repeat(MAX_ALLY_NAME_BYTES / 2));
        assert_eq!(m.validate(), Ok(()));
        m.allies[0].name = Some("x".repeat(MAX_ALLY_NAME_BYTES + 1));
        assert_eq!(
            m.validate(),
            Err(ManifestError::NameTooLong(UserId::new("usr_a")))
        );
        for f in [0, 3, u16::MAX] {
            let mut m = named(&["usr_a"]);
            m.format = f;
            assert_eq!(m.validate(), Err(ManifestError::UnknownFormat(f)));
            assert_ne!(m.signing_bytes(), named(&["usr_a"]).signing_bytes());
        }
    }

    #[test]
    fn display_names_are_sanitized() {
        let mut m = named(&["usr_a", "usr_b"]);
        m.allies[0].name = Some("  Sam\u{202e}evil\u{202c}\n Smith ".into());
        m.allies[1].name = Some("\u{200f}\u{0}".into());
        assert_eq!(m.allies[0].display_name().as_deref(), Some("Samevil Smith"));
        assert_eq!(m.allies[1].display_name(), None);
        assert_eq!(manifest(&["usr_a"]).allies[0].display_name(), None);
    }

    #[test]
    fn ally_name_sanitizer() {
        let cases: &[(&str, &str)] = &[
            ("Sam", "Sam"),
            ("  Sam   Smith  ", "Sam Smith"),
            ("Sam\tSmith\r\nJr", "Sam Smith Jr"),
            ("a\u{2028}b\u{2029}c\u{85}d", "a b c d"),
            ("e\u{301}", "\u{e9}"),
            ("\u{212b}", "\u{c5}"),
            ("Sam\u{202e}evil", "Samevil"),
            ("\u{2066}x\u{2069}\u{200e}\u{200f}\u{61c}", "x"),
            ("\u{0}\u{1b}[31mred\u{7f}\u{9b}", "[31mred"),
            ("zero\u{feff}width\u{fff9}", "zerowidth"),
            // Joiners stay: emoji sequences and some scripts need them.
            (
                "\u{1f469}\u{200d}\u{1f467} \u{645}\u{200c}\u{646}",
                "\u{1f469}\u{200d}\u{1f467} \u{645}\u{200c}\u{646}",
            ),
            // A control between a letter and its accent: removed first,
            // so NFC still composes them.
            ("e\u{0}\u{301}", "\u{e9}"),
            ("", ""),
            (" \u{202e} ", ""),
        ];
        for (input, want) in cases {
            assert_eq!(sanitize_ally_name(input), *want, "{input:?}");
        }
        let long = "é".repeat(MAX_ALLY_NAME_CHARS + 10);
        assert_eq!(
            sanitize_ally_name(&long).chars().count(),
            MAX_ALLY_NAME_CHARS
        );
        // Cut at the limit, then no trailing space.
        let spaced = format!("{} b", "a".repeat(MAX_ALLY_NAME_CHARS - 1));
        assert_eq!(
            sanitize_ally_name(&spaced),
            "a".repeat(MAX_ALLY_NAME_CHARS - 1)
        );
        let wide = "\u{1f600}".repeat(MAX_ALLY_NAME_CHARS * 2);
        assert_eq!(sanitize_ally_name(&wide).len(), MAX_ALLY_NAME_BYTES);
    }

    proptest::proptest! {
        #[test]
        fn sanitized_names_are_stable_and_bounded(s in "\\PC*|[\\x00-\\x20\\u{80}-\\u{a0}\\u{200b}-\\u{2070}e\\u{301}\\u{1100}\\u{1161}\\u{11a8}]*") {
            let once = sanitize_ally_name(&s);
            proptest::prop_assert_eq!(sanitize_ally_name(&once), once.clone());
            proptest::prop_assert!(once.len() <= MAX_ALLY_NAME_BYTES);
            proptest::prop_assert!(!once.starts_with(' ') && !once.ends_with(' '));
            proptest::prop_assert!(!once.chars().any(|c| stripped_from_names(c) || spaced_in_names(c)));
        }
    }

    #[test]
    fn manifest_validation() {
        assert_eq!(manifest(&["usr_a", "usr_b"]).validate(), Ok(()));
        assert_eq!(manifest(&[]).validate(), Ok(()));
        assert!(matches!(
            manifest(&["usr_b", "usr_a"]).validate(),
            Err(ManifestError::NotSorted(_))
        ));
        assert!(matches!(
            manifest(&["usr_a", "usr_a"]).validate(),
            Err(ManifestError::NotSorted(_))
        ));
        assert_eq!(
            manifest(&["usr_m"]).validate(),
            Err(ManifestError::MemberIsAlly)
        );
        assert!(matches!(
            manifest(&["dev_x"]).validate(),
            Err(ManifestError::MalformedId(_))
        ));
        let mut m = manifest(&[]);
        m.version = 0;
        assert_eq!(m.validate(), Err(ManifestError::ZeroVersion));
        let ids: Vec<String> = (0..=MAX_MANIFEST_ALLIES)
            .map(|i| format!("usr_{i:03}"))
            .collect();
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        assert_eq!(
            manifest(&refs).validate(),
            Err(ManifestError::TooManyAllies(MAX_MANIFEST_ALLIES + 1))
        );
    }

    #[test]
    fn manifest_bytes_bind_every_field() {
        let base = manifest(&["usr_a"]);
        let b = base.signing_bytes();
        let mut v = Vec::new();
        let mut m = base.clone();
        m.version = 2;
        v.push(m);
        let mut m = base.clone();
        m.issued_at_ms = 2;
        v.push(m);
        let mut m = base.clone();
        m.member_enc_pubkey = EncPublicKey([9; 32]);
        v.push(m);
        let mut m = base.clone();
        m.allies[0].enc_pubkey = EncPublicKey([9; 32]);
        v.push(m);
        let mut m = base.clone();
        m.allies[0].ally_id = UserId::new("usr_b");
        v.push(m);
        let mut m = base.clone();
        m.allies.clear();
        v.push(m);
        let mut m = base.clone();
        m.member_id = UserId::new("usr_n");
        v.push(m);
        let mut m = base.clone();
        m.instance_id = InstanceId::new("inst_b");
        v.push(m);
        for m in v {
            assert_ne!(m.signing_bytes(), b, "{m:?}");
            assert_ne!(m.hash(), base.hash());
        }
    }

    #[test]
    fn manifest_length_prefix_prevents_ambiguity() {
        // Two allies vs one ally whose id would absorb the next entry's bytes
        // must not collide (the u64 count + per-field lengths prevent it).
        let two = manifest(&["usr_a", "usr_b"]);
        let one = manifest(&["usr_a"]);
        assert_ne!(two.signing_bytes(), one.signing_bytes());
    }

    #[test]
    fn manifest_json_roundtrip() {
        let m = manifest(&["usr_a"]);
        let back: RecipientManifest =
            serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.reference(), m.reference());
    }

    #[test]
    fn key_id_shape() {
        let id = key_id(&[1u8; 32]);
        assert_eq!(id.len(), 16);
        assert_ne!(id, key_id(&[2u8; 32]));
    }

    #[test]
    fn safety_code_symmetric() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = safety_code(&a, &b);
        assert_eq!(c, safety_code(&b, &a));
        assert_eq!(c.split(' ').count(), 12);
        assert_ne!(c, safety_code(&a, &[3u8; 32]));
    }

    #[test]
    fn endorsements_are_domain_separated() {
        let ally = AllyEndorsement {
            instance_id: InstanceId::new("inst_a"),
            member_id: UserId::new("usr_m"),
            ally_id: UserId::new("usr_a"),
            ally_enc_pubkey: EncPublicKey([9; 32]),
            endorsed_at_ms: 1,
        };
        let dev = DeviceEndorsement {
            instance_id: InstanceId::new("inst_a"),
            member_id: UserId::new("usr_m"),
            device_id: DeviceId::new("dev_a"),
            device_sign_pubkey: SignPublicKey([9; 32]),
            endorsed_at_ms: 1,
            min_manifest: ManifestRef {
                version: 1,
                hash: Hash32::ZERO,
            },
        };
        assert_ne!(ally.signing_bytes()[..20], dev.signing_bytes()[..20]);
    }

    #[test]
    fn signed_flattens() {
        let s = Signed {
            body: MemberEncKeyBinding {
                instance_id: InstanceId::new("inst_a"),
                member_id: UserId::new("usr_m"),
                member_enc_pubkey: EncPublicKey([1; 32]),
                endorsed_at_ms: 5,
            },
            sig: Signature([0; 64]),
        };
        let v: serde_json::Value = serde_json::to_value(&s).unwrap();
        assert!(v.get("member_id").is_some() && v.get("sig").is_some());
        let back: Signed<MemberEncKeyBinding> = serde_json::from_value(v).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn ally_rewrap_proof_covers_the_challenge_and_every_field() {
        let r = AllyKeyRewrap {
            instance_id: InstanceId::new("inst_a"),
            ally_id: UserId::new("usr_a"),
            enc_pubkey: EncPublicKey([1; 32]),
            issued_at_ms: 5,
            wrapped_privkey: "{}".into(),
        };
        let p = r.proof(&[7; 32]);
        assert_eq!(p, r.proof(&[7; 32]));
        assert_ne!(p, r.proof(&[8; 32]));
        let changed = [
            AllyKeyRewrap {
                instance_id: InstanceId::new("inst_b"),
                ..r.clone()
            },
            AllyKeyRewrap {
                ally_id: UserId::new("usr_b"),
                ..r.clone()
            },
            AllyKeyRewrap {
                enc_pubkey: EncPublicKey([2; 32]),
                ..r.clone()
            },
            AllyKeyRewrap {
                issued_at_ms: 6,
                ..r.clone()
            },
            AllyKeyRewrap {
                wrapped_privkey: "{ }".into(),
                ..r.clone()
            },
        ];
        for c in changed {
            assert_ne!(c.proof(&[7; 32]), p, "{c:?}");
        }
        let v = serde_json::to_value(ProvenAllyKeyRewrap { body: r, proof: p }).unwrap();
        assert!(v.get("ally_id").is_some() && v.get("proof").is_some());
    }
}
