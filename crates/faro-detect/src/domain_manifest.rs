//! The manifest that ships next to a compiled domain bundle, and loading
//! a bundle with it (§3.5 "Context signals", §11).
//!
//! `domains-compile` writes the manifest. It names the bundle file and pins
//! its length and BLAKE3, and it carries every source's licence and
//! attribution and the licence texts, so it is enough to comply on its own.
//! [`load_domains`] checks all of that before a client uses a bundle, with
//! the same rules the compiler applies ([`crate::attribution`]): a bundle
//! that couldn't have been built from approved sources is never loaded.

use crate::attribution::{check_attribution, license_is_allowed, spdx_ids, Attribution};
use crate::classifier::read_capped;
use crate::domains::{Category, DomainCategorizer};
use crate::error::DetectError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// `format` of every manifest this crate reads and writes.
pub const DOMAINS_MANIFEST_FORMAT: &str = "faro-domains-manifest/1";
/// Largest manifest accepted.
const MAX_MANIFEST_BYTES: u64 = 4 << 20;
/// Largest bundle accepted.
const MAX_BUNDLE_BYTES: u64 = 256 << 20;

/// `domains.manifest.json`. It has no timestamps, so identical inputs give
/// an identical manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainsManifest {
    /// [`DOMAINS_MANIFEST_FORMAT`].
    pub format: String,
    /// A sentence that makes the manifest read on its own.
    pub notice: String,
    /// The bundle's version (semver), `bundle_version` in `sources.toml`.
    /// Bumped whenever the sources change, so the update channel can tell
    /// bundles apart.
    pub version: String,
    pub bundle: DomainsBundleInfo,
    /// Distinct domains in the bundle.
    pub domains: usize,
    /// True only for `--allow-unapproved` builds, which must never ship.
    pub unapproved_included: bool,
    pub sources: Vec<DomainSource>,
    /// The full text of every licence that requires it, by SPDX id.
    pub license_texts: BTreeMap<String, String>,
}

/// The bundle file the manifest describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainsBundleInfo {
    /// A plain file name, next to the manifest.
    pub file: String,
    pub bytes: u64,
    /// Lowercase hex BLAKE3.
    pub blake3: String,
}

/// One source compiled into the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainSource {
    pub name: String,
    pub category: Category,
    /// The upstream syntax (`hosts` or `domains`).
    pub format: String,
    /// SPDX licence expression of the list.
    pub license: String,
    pub approved: bool,
    /// The URL (at a fixed revision) or local path it came from.
    pub origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    /// Lowercase hex BLAKE3 of the source file.
    pub blake3: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution: Option<Attribution>,
    /// Non-empty, non-comment lines.
    pub lines: usize,
    /// Domains accepted (some may also be in other sources).
    pub domains: usize,
    /// Tokens that couldn't be used (IP literals, local names, bad syntax).
    pub skipped: usize,
}

/// A plain file name: no directories, not hidden.
pub(crate) fn is_plain_file_name(name: &str) -> bool {
    let mut b = name.bytes();
    (1..=128).contains(&name.len())
        && matches!(b.next(), Some(c) if c.is_ascii_alphanumeric())
        && b.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl DomainsManifest {
    /// Everything a shipped bundle's manifest must satisfy: the format, a
    /// version, a plain bundle file name, only approved sources whose
    /// licences are on the allowlist, and the attribution and licence
    /// texts those licences ask for.
    pub fn validate(&self) -> Result<(), DetectError> {
        let bad = |m: String| Err(DetectError::Manifest(m));
        if self.format != DOMAINS_MANIFEST_FORMAT {
            return bad(format!(
                "domain manifest format {:?} (expected {DOMAINS_MANIFEST_FORMAT})",
                self.format
            ));
        }
        if self.version.trim().is_empty() {
            return bad("the domain manifest has no version".into());
        }
        if !is_plain_file_name(&self.bundle.file) {
            return bad(format!(
                "bundle file {:?} must be a plain file name",
                self.bundle.file
            ));
        }
        if !is_hex64(&self.bundle.blake3) {
            return bad("bundle.blake3 must be 64 lowercase hex characters".into());
        }
        if self.unapproved_included {
            return bad("the bundle includes unapproved sources and must never ship".into());
        }
        if self.sources.is_empty() {
            return bad("the domain manifest lists no sources".into());
        }
        for (id, text) in &self.license_texts {
            if text.trim().is_empty() {
                return bad(format!("license_texts: empty text for {id}"));
            }
        }
        for s in &self.sources {
            if !s.approved {
                return bad(format!("source {} is not approved", s.name));
            }
            if !license_is_allowed(&s.license) {
                return Err(DetectError::License(s.license.clone()));
            }
            check_attribution(spdx_ids(&s.license), s.attribution.as_ref(), |id| {
                self.license_texts.contains_key(id)
            })
            .map_err(|e| DetectError::Manifest(format!("source {}: {e}", s.name)))?;
        }
        Ok(())
    }

    /// The plain-text notice for the bundle: `heading`, the manifest's
    /// [`notice`](Self::notice), then each source with where it comes from
    /// and its attribution, then the licence texts. Only manifest text, so
    /// the notice says exactly what the manifest does. The package installs
    /// it as `notices/domains.txt`, and the service writes one for a list
    /// from the update channel.
    pub fn notice_text(&self, heading: &str) -> String {
        let mut out = format!("{heading}\n{}\n", self.notice);
        for s in &self.sources {
            out.push_str(&format!("\n{} ({}, {})\n", s.name, s.category, s.license));
            out.push_str(&format!("From:    {}\n", s.origin));
            if let Some(a) = &s.attribution {
                out.push_str(&a.notice_lines());
            }
        }
        for (id, text) in &self.license_texts {
            out.push_str(&format!("\n--- {id} ---\n{}\n", text.trim_end()));
        }
        out
    }
}

/// A domain bundle checked against its manifest.
#[derive(Debug)]
pub struct LoadedDomains {
    pub categorizer: DomainCategorizer,
    pub manifest: DomainsManifest,
}

/// Read and check a manifest, then load the bundle it names (next to it)
/// and check the bundle's length, BLAKE3 and domain count. A bundle that
/// doesn't match is [`DetectError::Integrity`].
pub fn load_domains(manifest_path: impl AsRef<Path>) -> Result<LoadedDomains, DetectError> {
    let manifest_path = manifest_path.as_ref();
    let raw = read_capped(manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest: DomainsManifest =
        serde_json::from_slice(&raw).map_err(|e| DetectError::Manifest(e.to_string()))?;
    manifest.validate()?;
    let dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let bytes = read_capped(&dir.join(&manifest.bundle.file), MAX_BUNDLE_BYTES)?;
    let actual = blake3::hash(&bytes).to_hex().to_string();
    if actual != manifest.bundle.blake3 || bytes.len() as u64 != manifest.bundle.bytes {
        return Err(DetectError::Integrity {
            component: format!("domain bundle {}", manifest.version),
            expected: manifest.bundle.blake3.clone(),
            actual,
        });
    }
    let categorizer = DomainCategorizer::from_bytes(&bytes)?;
    if categorizer.len() != manifest.domains {
        return Err(DetectError::Manifest(format!(
            "the bundle has {} domains, the manifest says {}",
            categorizer.len(),
            manifest.domains
        )));
    }
    Ok(LoadedDomains {
        categorizer,
        manifest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::DomainCategorizerBuilder;

    fn attribution() -> Attribution {
        Attribution {
            author: "A".into(),
            copyright: vec!["Copyright (c) 2026 A".into()],
            source_url: "https://example.org/a".into(),
            license_url: "https://example.org/a/LICENSE".into(),
            changes: "Parsed into a bundle.".into(),
        }
    }

    /// Write a bundle and its manifest into `dir`; returns the manifest path.
    fn write(dir: &Path, edit: impl FnOnce(&mut DomainsManifest)) -> std::path::PathBuf {
        let mut b = DomainCategorizerBuilder::new();
        b.add_domain("adult.example", Category::Adult).unwrap();
        b.add_domain("bet.example", Category::Gambling).unwrap();
        let bytes = b.build().unwrap().to_bytes();
        std::fs::write(dir.join("domains.bin"), &bytes).unwrap();
        let mut m = DomainsManifest {
            format: DOMAINS_MANIFEST_FORMAT.into(),
            notice: "Test.".into(),
            version: "1.0.0".into(),
            bundle: DomainsBundleInfo {
                file: "domains.bin".into(),
                bytes: bytes.len() as u64,
                blake3: blake3::hash(&bytes).to_hex().to_string(),
            },
            domains: 2,
            unapproved_included: false,
            sources: vec![DomainSource {
                name: "a".into(),
                category: Category::Adult,
                format: "domains".into(),
                license: "MIT".into(),
                approved: true,
                origin: "a.txt".into(),
                homepage: None,
                blake3: "0".repeat(64),
                attribution: Some(attribution()),
                lines: 2,
                domains: 2,
                skipped: 0,
            }],
            license_texts: [("MIT".to_owned(), "Permission is hereby granted".to_owned())].into(),
        };
        edit(&mut m);
        let p = dir.join("domains.manifest.json");
        std::fs::write(&p, serde_json::to_vec(&m).unwrap()).unwrap();
        p
    }

    #[test]
    fn a_valid_bundle_loads() {
        let dir = tempfile::tempdir().unwrap();
        let l = load_domains(write(dir.path(), |_| {})).unwrap();
        assert_eq!(l.manifest.version, "1.0.0");
        assert_eq!(
            l.categorizer.categorize_url("https://www.adult.example/x"),
            [Category::Adult]
        );
    }

    #[test]
    fn manifests_that_could_not_ship_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let refused = |edit: fn(&mut DomainsManifest)| {
            let p = write(dir.path(), edit);
            load_domains(p).expect_err("refused")
        };
        assert!(matches!(
            refused(|m| m.sources[0].license = "GPL-3.0-only".into()),
            DetectError::License(_)
        ));
        assert!(matches!(
            refused(|m| m.sources[0].license = "MIT OR GPL-3.0-only".into()),
            DetectError::License(_)
        ));
        for edit in [
            (|m: &mut DomainsManifest| m.sources[0].attribution = None) as fn(&mut _),
            |m| m.license_texts.clear(),
            |m| m.unapproved_included = true,
            |m| m.sources[0].approved = false,
            |m| m.sources.clear(),
            |m| m.format = "faro-domains-manifest/2".into(),
            |m| m.version = " ".into(),
            |m| m.bundle.file = "../domains.bin".into(),
            |m| m.bundle.file = ".domains.bin".into(),
            |m| m.domains = 3,
        ] {
            assert!(
                matches!(refused(edit), DetectError::Manifest(_)),
                "{edit:?}"
            );
        }
        assert!(matches!(
            refused(|m| m.bundle.blake3 = "1".repeat(64)),
            DetectError::Integrity { .. }
        ));
        assert!(matches!(
            refused(|m| m.bundle.bytes += 1),
            DetectError::Integrity { .. }
        ));
        // Unknown fields are refused, not ignored.
        let p = write(dir.path(), |_| {});
        let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        v["extra"] = serde_json::json!(true);
        std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(matches!(load_domains(&p), Err(DetectError::Manifest(_))));
    }

    #[test]
    fn the_notice_carries_every_attribution_and_licence_text() {
        let dir = tempfile::tempdir().unwrap();
        let m = load_domains(write(dir.path(), |_| {})).unwrap().manifest;
        let text = m.notice_text("Domain list 1.0.0.");
        assert_eq!(
            text,
            "Domain list 1.0.0.\nTest.\n\
             \na (adult, MIT)\n\
             From:    a.txt\n\
             Author:  A\n         Copyright (c) 2026 A\n\
             Source:  https://example.org/a\n\
             Licence: https://example.org/a/LICENSE\n\
             Changes: Parsed into a bundle.\n\
             \n--- MIT ---\nPermission is hereby granted\n"
        );
    }

    #[test]
    fn plain_file_names() {
        for ok in ["domains.bin", "a", "opennsfw-int8.onnx"] {
            assert!(is_plain_file_name(ok), "{ok}");
        }
        for bad in ["", ".x", "a/b", "../a", "a\\b", "a b", &"a".repeat(129)] {
            assert!(!is_plain_file_name(bad), "{bad}");
        }
    }
}
