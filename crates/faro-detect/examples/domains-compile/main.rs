//! `domains-compile`: builds the [`DomainCategorizer`] bundle from licensed,
//! hash-pinned blocklists (ARCHITECTURE.md §3.5 "Context signals", §11).
//!
//! ```text
//! domains-compile fetch --config crates/faro-detect/domains/sources.toml
//! domains-compile build --config crates/faro-detect/domains/sources.toml --out target/domains/domains.bin
//! domains-compile hash  FILE...
//! ```
//!
//! The config (`sources.toml`) lists every source with its category, format,
//! SPDX licence, its review state and the BLAKE3 of the exact file to use.
//! A source is either a `url`, which `fetch` downloads into `--sources-dir`
//! (named after the source), or a local `path` relative to the config file.
//! `build` reads only those files, refuses any whose hash differs from its
//! pin, and writes the bundle plus a JSON manifest
//! ([`faro_detect::DomainsManifest`]: the config's `bundle_version`,
//! sources, licences, attribution, entry counts, BLAKE3 of the bundle).
//! Clients load the two with [`faro_detect::load_domains`], which checks
//! all of it again. The same config and inputs always give byte-identical
//! outputs.
//!
//! A source is in one of three states:
//!
//! * **approved** (`approved = true`): always included. Its licence must be on
//!   the Apache-2.0-compatible allowlist ([`ALLOWED_MODEL_LICENSES`]), and if
//!   that licence requires attribution, the source must carry it (and the
//!   config the licence text, where the licence asks for the text to travel
//!   with copies), or the config is rejected. The manifest ships next to the
//!   bundle, so it carries all of this and is enough to comply on its own.
//! * **pending** (`approved = false`): left out unless `--allow-unapproved`
//!   is given, which is for local experiments only. A bundle built that way
//!   says so in its manifest and must never ship.
//! * **refused** (`refused = "reason"`): the maintainer turned it down. It is
//!   kept in the config so nobody proposes it again, and it is never fetched
//!   or compiled, even with `--allow-unapproved`.
//!
//! This is a project tool, not part of any shipped client. Parsing is
//! [`DomainCategorizerBuilder::add_source`], exactly as the library does it.

use anyhow::{bail, ensure, Context, Result};
use clap::{Parser, Subcommand};
use faro_detect::attribution::{
    check_attribution, license_is_allowed, spdx_ids, Attribution, AttributionError,
};
use faro_detect::{
    Category, CompileStats, DomainCategorizer, DomainCategorizerBuilder, DomainSource,
    DomainsBundleInfo, DomainsManifest, DOMAINS_MANIFEST_FORMAT,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const CONFIG_VERSION: u32 = 1;
/// Largest source file accepted (the biggest lists in use are a few MB).
const MAX_SOURCE_BYTES: u64 = 256 << 20;
const DEFAULT_SOURCES_DIR: &str = "target/domains/sources";
const MAX_NAME_LEN: usize = 64;

/// The opening of every manifest, so it reads on its own.
const MANIFEST_NOTICE: &str = "The domain bundle described here is compiled from the \
     third-party lists below and is distributed under their licences. Each source lists its \
     authors, copyright notices, where it comes from, its licence and what was changed; \
     `license_texts` holds the full text of every licence that requires it, which applies \
     together with that source's copyright notices.";

#[derive(Parser)]
#[command(
    name = "domains-compile",
    about = "Compile licensed, hash-pinned blocklists into a Faro domain bundle"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Download the `url` sources into --sources-dir, verifying each pinned hash.
    Fetch {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = DEFAULT_SOURCES_DIR)]
        sources_dir: PathBuf,
        /// Also fetch pending sources (local experiments only). Refused
        /// sources are never fetched.
        #[arg(long)]
        allow_unapproved: bool,
    },
    /// Compile the bundle and write it with its JSON manifest.
    Build {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = DEFAULT_SOURCES_DIR)]
        sources_dir: PathBuf,
        /// The bundle to write, for example target/domains/domains.bin.
        #[arg(long)]
        out: PathBuf,
        /// Where to write the manifest [default: --out with the extension
        /// `manifest.json`].
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Include pending sources. For local experiments only: the manifest
        /// records it and such a bundle must never ship. Refused sources are
        /// never included.
        #[arg(long)]
        allow_unapproved: bool,
    },
    /// Print the BLAKE3 of files, for pinning a new version of a source.
    Hash {
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Fetch {
            config,
            sources_dir,
            allow_unapproved,
        } => {
            let cfg = Config::load(&config)?;
            fetch(&cfg, &sources_dir, allow_unapproved)
        }
        Cmd::Build {
            config,
            sources_dir,
            out,
            manifest,
            allow_unapproved,
        } => {
            let manifest = manifest.unwrap_or_else(|| out.with_extension("manifest.json"));
            let (excluded, m) = build(&config, &sources_dir, &out, &manifest, allow_unapproved)?;
            for e in &excluded {
                match &e.why {
                    Why::Refused(reason) => {
                        eprintln!("left out {} (refused: {reason})", e.name)
                    }
                    Why::Pending(terms) => {
                        eprintln!(
                            "left out {} ({}, pending approval); --allow-unapproved includes \
                             it for local experiments only",
                            e.name, e.license
                        );
                        if let Some(terms) = terms {
                            eprintln!("  terms: {terms}");
                        }
                    }
                }
            }
            eprintln!(
                "wrote {} ({} domains from {} sources, {} bytes, blake3 {}) and {}",
                out.display(),
                m.domains,
                m.sources.len(),
                m.bundle.bytes,
                m.bundle.blake3,
                manifest.display()
            );
            if m.unapproved_included {
                eprintln!("warning: this bundle includes unapproved sources; never ship it");
            }
            Ok(())
        }
        Cmd::Hash { files } => {
            for f in files {
                let bytes = fs::read(&f).with_context(|| format!("reading {}", f.display()))?;
                println!("{}  {}", blake3_hex(&bytes), f.display());
            }
            Ok(())
        }
    }
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// `sources.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u32,
    /// The bundle's own version (`MAJOR.MINOR.PATCH`), copied into the
    /// manifest. Bump it whenever a source or pin changes: the update
    /// channel publishes each version once and never changes its bytes.
    bundle_version: String,
    /// Full licence texts by SPDX id, for licences in
    /// [`faro_detect::attribution::TEXT_REQUIRED_LICENSES`]. Copied into the manifest.
    #[serde(default)]
    license_texts: BTreeMap<String, String>,
    #[serde(rename = "source", default)]
    sources: Vec<Source>,
}

/// One `[[source]]` entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    /// Unique; also the file name under `--sources-dir`.
    name: String,
    category: Category,
    format: Format,
    /// SPDX licence expression of the list itself.
    license: String,
    /// Signed off for redistribution in shipped bundles.
    approved: bool,
    /// Turned down by the maintainer, with the reason. Never compiled.
    refused: Option<String>,
    /// An https URL that `fetch` downloads; pin it to an immutable revision.
    url: Option<String>,
    /// Or a local file, relative to the config file's directory.
    path: Option<String>,
    /// Lowercase hex BLAKE3 of the exact file.
    blake3: String,
    homepage: Option<String>,
    /// What the upstream terms say (shown while the source is pending).
    terms: Option<String>,
    /// Required for approved sources whose licence asks for attribution.
    attribution: Option<Attribution>,
}

/// The upstream's syntax. Both are parsed by
/// [`DomainCategorizerBuilder::add_source`]; the field documents what the
/// upstream publishes and is recorded in the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Format {
    /// `0.0.0.0 example.com [aliases…]`.
    Hosts,
    /// One domain per line, matching the domain and its subdomains.
    Domains,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Format::Hosts => "hosts",
            Format::Domains => "domains",
        })
    }
}

impl Config {
    fn load(path: &Path) -> Result<Config> {
        let text =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Config::parse(&text).with_context(|| format!("in {}", path.display()))
    }

    fn parse(text: &str) -> Result<Config> {
        let config: Config = toml::from_str(text).context("parsing the sources config")?;
        ensure!(
            config.version == CONFIG_VERSION,
            "unsupported config version {} (expected {CONFIG_VERSION})",
            config.version
        );
        ensure!(
            is_release_version(&config.bundle_version),
            "bundle_version {:?} must be MAJOR.MINOR.PATCH (with an optional -pre-release)",
            config.bundle_version
        );
        for (id, text) in &config.license_texts {
            ensure!(
                !text.trim().is_empty(),
                "license_texts: empty text for {id}"
            );
        }
        let mut names = BTreeSet::new();
        for s in &config.sources {
            s.validate(&config.license_texts)?;
            ensure!(
                names.insert(s.name.as_str()),
                "duplicate source name {:?}",
                s.name
            );
        }
        Ok(config)
    }
}

/// `MAJOR.MINOR.PATCH`, optionally `-pre` (semver without build metadata,
/// which can't appear in a target name).
fn is_release_version(v: &str) -> bool {
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (v, None),
    };
    let numeric = |p: &str| {
        !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && (p == "0" || !p.starts_with('0'))
    };
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| numeric(p))
        && pre.is_none_or(|p| {
            p.split('.').all(|id| {
                !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        })
}

impl Source {
    fn validate(&self, license_texts: &BTreeMap<String, String>) -> Result<()> {
        let name = &self.name;
        ensure!(
            !name.is_empty()
                && name.len() <= MAX_NAME_LEN
                && name.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'-'
                    || b == b'_'),
            "source name {name:?} must be 1-{MAX_NAME_LEN} lowercase letters, digits, '-' or '_'"
        );
        match (&self.url, &self.path) {
            (Some(url), None) => {
                ensure!(
                    url.starts_with("https://"),
                    "source {name}: url must be https"
                )
            }
            (None, Some(path)) => ensure!(!path.is_empty(), "source {name}: empty path"),
            _ => bail!("source {name}: give exactly one of `url` or `path`"),
        }
        ensure!(
            self.blake3.len() == 64
                && self
                    .blake3
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "source {name}: blake3 must be 64 lowercase hex digits"
        );
        if let Some(reason) = &self.refused {
            ensure!(
                !reason.trim().is_empty(),
                "source {name}: `refused` needs a reason"
            );
            ensure!(
                !self.approved,
                "source {name} can't be both approved and refused"
            );
        }
        if self.approved {
            ensure!(
                license_is_allowed(&self.license),
                "source {name} is approved, but its licence {:?} is not on the \
                 Apache-2.0-compatible allowlist (ARCHITECTURE.md §11)",
                self.license
            );
            self.validate_attribution(license_texts)?;
        }
        Ok(())
    }

    /// An approved source must carry everything its licence asks to travel
    /// with the bundle.
    fn validate_attribution(&self, license_texts: &BTreeMap<String, String>) -> Result<()> {
        let name = &self.name;
        let checked = check_attribution(spdx_ids(&self.license), self.attribution.as_ref(), |id| {
            license_texts.contains_key(id)
        });
        match checked {
            Ok(()) => Ok(()),
            Err(AttributionError::Missing) => bail!(
                "source {name}: its licence {} requires attribution, but it has no \
                 [source.attribution]",
                self.license
            ),
            Err(AttributionError::NoLicenseText(id)) => bail!(
                "source {name}: {id} requires its text to travel with the bundle; add it to \
                 [license_texts]"
            ),
            Err(e) => bail!("source {name}: {e}"),
        }
    }

    fn included(&self, allow_unapproved: bool) -> bool {
        self.refused.is_none() && (self.approved || allow_unapproved)
    }

    fn local_path(&self, config_dir: &Path, sources_dir: &Path) -> PathBuf {
        match &self.path {
            Some(p) => config_dir.join(p),
            None => sources_dir.join(&self.name),
        }
    }

    fn origin(&self) -> &str {
        self.url
            .as_deref()
            .or(self.path.as_deref())
            .unwrap_or_default()
    }
}

/// Read a source file and check it against its pin.
fn read_verified(path: &Path, s: &Source) -> Result<Vec<u8>> {
    let len = fs::metadata(path)
        .with_context(|| format!("source {}: reading {}", s.name, path.display()))?
        .len();
    ensure!(
        len <= MAX_SOURCE_BYTES,
        "source {}: {} is {len} bytes, more than the {MAX_SOURCE_BYTES} allowed",
        s.name,
        path.display()
    );
    let bytes =
        fs::read(path).with_context(|| format!("source {}: reading {}", s.name, path.display()))?;
    let actual = blake3_hex(&bytes);
    ensure!(
        actual == s.blake3,
        "source {}: {} has blake3 {actual}, but the config pins {}. If upstream changed \
         on purpose, review the change and update the pin",
        s.name,
        path.display(),
        s.blake3
    );
    Ok(bytes)
}

/// Download every included `url` source that isn't already present and
/// correct. A download only replaces the file once it matches its pin.
fn fetch(config: &Config, sources_dir: &Path, allow_unapproved: bool) -> Result<()> {
    fs::create_dir_all(sources_dir)
        .with_context(|| format!("creating {}", sources_dir.display()))?;
    for s in &config.sources {
        let Some(url) = &s.url else { continue };
        if let Some(reason) = &s.refused {
            eprintln!("{}: refused ({reason}), not fetched", s.name);
            continue;
        }
        if !s.included(allow_unapproved) {
            eprintln!("{}: pending approval ({}), not fetched", s.name, s.license);
            continue;
        }
        let dest = sources_dir.join(&s.name);
        if dest.exists() && read_verified(&dest, s).is_ok() {
            eprintln!("{}: already present", s.name);
            continue;
        }
        let part = sources_dir.join(format!("{}.part", s.name));
        let status = Command::new("curl")
            .args(["--fail", "--silent", "--show-error", "--location"])
            .args(["--proto", "=https", "--proto-redir", "=https"])
            .args(["--max-filesize", &MAX_SOURCE_BYTES.to_string()])
            .arg("--output")
            .arg(&part)
            .arg(url)
            .status()
            .context("running curl")?;
        let verified = if status.success() {
            read_verified(&part, s)
        } else {
            Err(anyhow::anyhow!(
                "source {}: downloading {url} failed ({status})",
                s.name
            ))
        };
        if let Err(e) = verified {
            let _ = fs::remove_file(&part);
            return Err(e);
        }
        fs::rename(&part, &dest).with_context(|| format!("writing {}", dest.display()))?;
        eprintln!("{}: fetched and verified", s.name);
    }
    Ok(())
}

/// A source left out of a build.
#[derive(Debug)]
struct Excluded {
    name: String,
    license: String,
    why: Why,
}

#[derive(Debug, PartialEq, Eq)]
enum Why {
    /// Refused by the maintainer, with the reason.
    Refused(String),
    /// Not approved yet, with what its terms say.
    Pending(Option<String>),
}

/// The result of [`compile`].
#[derive(Debug)]
struct Compiled {
    version: String,
    bundle: Vec<u8>,
    domains: usize,
    sources: Vec<DomainSource>,
    /// The texts of the licences of the included sources.
    license_texts: BTreeMap<String, String>,
    excluded: Vec<Excluded>,
}

/// Build the bundle from the config's sources, in config order.
fn compile(
    config: &Config,
    config_dir: &Path,
    sources_dir: &Path,
    allow_unapproved: bool,
) -> Result<Compiled> {
    let mut builder = DomainCategorizerBuilder::new();
    let mut sources = Vec::new();
    let mut excluded = Vec::new();
    let mut license_texts = BTreeMap::new();
    for s in &config.sources {
        if !s.included(allow_unapproved) {
            let why = match &s.refused {
                Some(reason) => Why::Refused(reason.clone()),
                None => Why::Pending(s.terms.clone()),
            };
            excluded.push(Excluded {
                name: s.name.clone(),
                license: s.license.clone(),
                why,
            });
            continue;
        }
        let path = s.local_path(config_dir, sources_dir);
        if s.url.is_some() && !path.exists() {
            bail!(
                "source {}: {} is missing; run `domains-compile fetch` first",
                s.name,
                path.display()
            );
        }
        let bytes = read_verified(&path, s)?;
        let text =
            std::str::from_utf8(&bytes).with_context(|| format!("source {}: not UTF-8", s.name))?;
        let stats = builder
            .add_source(text, s.category)
            .with_context(|| format!("source {}", s.name))?;
        ensure!(
            stats.domains > 0,
            "source {}: no domains found; is it really a {} list?",
            s.name,
            s.format
        );
        for id in spdx_ids(&s.license) {
            if let Some(text) = config.license_texts.get(id) {
                license_texts.insert(id.to_owned(), text.clone());
            }
        }
        sources.push(source_report(s, stats));
    }
    ensure!(!sources.is_empty(), "no sources to compile");
    let categorizer = builder.build()?;
    let bundle = categorizer.to_bytes();
    // Load it back the way a client will, so a bundle that doesn't parse
    // never leaves this tool.
    let check = DomainCategorizer::from_bytes(&bundle)?;
    ensure!(
        check.len() == categorizer.len(),
        "bundle round trip lost entries"
    );
    Ok(Compiled {
        version: config.bundle_version.clone(),
        bundle,
        domains: categorizer.len(),
        sources,
        license_texts,
        excluded,
    })
}

fn source_report(s: &Source, stats: CompileStats) -> DomainSource {
    DomainSource {
        name: s.name.clone(),
        category: s.category,
        format: s.format.to_string(),
        license: s.license.clone(),
        approved: s.approved,
        origin: s.origin().to_owned(),
        homepage: s.homepage.clone(),
        blake3: s.blake3.clone(),
        attribution: s.attribution.clone(),
        lines: stats.lines,
        domains: stats.domains,
        skipped: stats.skipped,
    }
}

/// The JSON written next to the bundle ([`DomainsManifest`]). It has no
/// timestamps, so identical inputs give an identical manifest.
fn manifest(compiled: &Compiled, bundle_file: &str) -> DomainsManifest {
    DomainsManifest {
        format: DOMAINS_MANIFEST_FORMAT.to_owned(),
        notice: MANIFEST_NOTICE.to_owned(),
        version: compiled.version.clone(),
        bundle: DomainsBundleInfo {
            file: bundle_file.to_owned(),
            bytes: compiled.bundle.len() as u64,
            blake3: blake3_hex(&compiled.bundle),
        },
        domains: compiled.domains,
        unapproved_included: compiled.sources.iter().any(|s| !s.approved),
        sources: compiled.sources.clone(),
        license_texts: compiled.license_texts.clone(),
    }
}

/// `build`: load the config, compile, and write the bundle and manifest.
fn build(
    config_path: &Path,
    sources_dir: &Path,
    out: &Path,
    manifest_path: &Path,
    allow_unapproved: bool,
) -> Result<(Vec<Excluded>, DomainsManifest)> {
    let config = Config::load(config_path)?;
    let config_dir = config_path.parent().unwrap_or(Path::new("."));
    let compiled = compile(&config, config_dir, sources_dir, allow_unapproved)?;
    let m = write_outputs(&compiled, out, manifest_path)?;
    Ok((compiled.excluded, m))
}

fn write_outputs(compiled: &Compiled, out: &Path, manifest_path: &Path) -> Result<DomainsManifest> {
    let file = out
        .file_name()
        .and_then(|f| f.to_str())
        .with_context(|| format!("{} has no file name", out.display()))?;
    let m = manifest(compiled, file);
    let mut json = serde_json::to_vec_pretty(&m)?;
    json.push(b'\n');
    for path in [out, manifest_path] {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
    }
    fs::write(out, &compiled.bundle).with_context(|| format!("writing {}", out.display()))?;
    fs::write(manifest_path, json)
        .with_context(|| format!("writing {}", manifest_path.display()))?;
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_FILES: &[&str] = &[
        "sources.toml",
        "adult.hosts",
        "gambling.txt",
        "unapproved.txt",
        "refused.txt",
    ];

    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/domains-compile/fixtures")
    }

    fn fixture_config() -> Config {
        Config::load(&fixtures().join("sources.toml")).unwrap()
    }

    /// The fixture has only `path` sources, so no sources dir is read.
    fn compile_fixture(allow_unapproved: bool) -> Result<Compiled> {
        compile(
            &fixture_config(),
            &fixtures(),
            &fixtures().join("no-such-dir"),
            allow_unapproved,
        )
    }

    fn excluded(c: &Compiled) -> Vec<(&str, &Why)> {
        c.excluded.iter().map(|e| (&*e.name, &e.why)).collect()
    }

    /// One source `s`, then `extra` (its remaining keys, possibly followed
    /// by `[source.attribution]` and `[license_texts]` tables).
    fn source_toml(extra: &str) -> String {
        format!(
            "version = 1\nbundle_version = \"1.0.0\"\n[[source]]\nname = \"s\"\n\
             category = \"adult\"\nformat = \"domains\"\n\
             blake3 = \"{}\"\n{extra}\n",
            "0".repeat(64)
        )
    }

    const ATTRIBUTION: &str = "[source.attribution]\nauthor = \"A\"\n\
         copyright = [\"Copyright (c) 2026 A\"]\nsource_url = \"https://a.test/list\"\n\
         license_url = \"https://a.test/LICENSE\"\nchanges = \"Converted.\"";
    const MIT_TEXT: &str = "[license_texts]\nMIT = \"Permission is hereby granted...\"";

    #[test]
    fn compiles_the_fixture_and_loads_it_back() {
        let c = compile_fixture(false).unwrap();
        let d = DomainCategorizer::from_bytes(&c.bundle).unwrap();
        assert_eq!(d.len(), c.domains);
        assert_eq!(c.domains, 4);

        // Label-suffix matching.
        assert_eq!(
            d.categorize_url("https://adult-fixture.test/x"),
            vec![Category::Adult]
        );
        assert_eq!(
            d.categorize_url("http://a.b.adult-fixture.test/"),
            vec![Category::Adult]
        );
        assert!(d.categorize_url("https://notadult-fixture.test").is_empty());
        assert!(d
            .categorize_url("https://adult-fixture.test.example.org")
            .is_empty());
        assert_eq!(d.categorize_url("second-adult.test"), vec![Category::Adult]);
        assert_eq!(
            d.categorize_url("https://casino-fixture.test"),
            vec![Category::Gambling]
        );
        assert_eq!(
            d.categorize_url("live.bets-fixture.test"),
            vec![Category::Gambling]
        );
        assert!(d.categorize_url("localhost").is_empty());

        // The pending and the refused source were both left out.
        assert!(d.categorize_url("unapproved-fixture.test").is_empty());
        assert!(d.categorize_url("refused-fixture.test").is_empty());
        assert_eq!(
            excluded(&c),
            [
                (
                    "fixture-unapproved",
                    &Why::Pending(Some("Copyleft; not Apache-2.0 compatible.".into()))
                ),
                (
                    "fixture-refused",
                    &Why::Refused("Turned down in review.".into())
                ),
            ]
        );

        let m = manifest(&c, "domains.bin");
        assert_eq!(m.format, DOMAINS_MANIFEST_FORMAT);
        assert_eq!(m.version, "1.0.0");
        assert_eq!(m.bundle.blake3, blake3_hex(&c.bundle));
        assert_eq!(m.bundle.bytes, c.bundle.len() as u64);
        assert!(!m.unapproved_included);
        let names: Vec<_> = m.sources.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["fixture-adult", "fixture-gambling"]);
        let adult = &m.sources[0];
        assert_eq!(
            (adult.lines, adult.domains, adult.skipped),
            (4, 2, 2),
            "localhost and the IP literal are skipped"
        );
        assert_eq!(adult.license, "MIT");
        assert_eq!(adult.origin, "adult.hosts");
        // Only the texts of included licences travel.
        assert_eq!(m.license_texts.keys().collect::<Vec<_>>(), ["MIT"]);
    }

    #[test]
    fn builds_are_reproducible() {
        let a = compile_fixture(false).unwrap();
        let b = compile_fixture(false).unwrap();
        assert_eq!(a.bundle, b.bundle);
        let ja = serde_json::to_string(&manifest(&a, "domains.bin")).unwrap();
        let jb = serde_json::to_string(&manifest(&b, "domains.bin")).unwrap();
        assert_eq!(ja, jb);
    }

    #[test]
    fn bundle_versions() {
        for ok in ["1.0.0", "0.10.2", "2.0.0-rc.1"] {
            assert!(is_release_version(ok), "{ok}");
        }
        for bad in [
            "",
            "1",
            "1.0",
            "1.0.0+b",
            "01.0.0",
            "1.0.0-",
            "1.0.0-a..b",
            "v1.0.0",
        ] {
            assert!(!is_release_version(bad), "{bad}");
        }
        let ok = "path = \"x\"\nlicense = \"CC0-1.0\"\napproved = true";
        let text = source_toml(ok).replace("\"1.0.0\"", "\"1.0\"");
        assert!(format!("{:#}", Config::parse(&text).unwrap_err()).contains("bundle_version"));
    }

    /// A client refuses what `--allow-unapproved` builds.
    #[test]
    fn unapproved_builds_never_load() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("domains.bin");
        let manifest_path = out.with_extension("manifest.json");
        build(
            &fixtures().join("sources.toml"),
            &fixtures().join("no-such-dir"),
            &out,
            &manifest_path,
            true,
        )
        .unwrap();
        assert!(faro_detect::load_domains(&manifest_path).is_err());
    }

    #[test]
    fn pending_sources_need_the_flag() {
        let c = compile_fixture(true).unwrap();
        let d = DomainCategorizer::from_bytes(&c.bundle).unwrap();
        assert_eq!(
            d.categorize_url("unapproved-fixture.test"),
            vec![Category::Adult]
        );
        let m = manifest(&c, "domains.bin");
        assert!(m.unapproved_included);
        assert!(!m.sources[2].approved);
        // Its licence has no text in the config, so none is copied.
        assert!(!m.license_texts.contains_key("GPL-3.0-only"));
    }

    #[test]
    fn refused_sources_are_rejected_even_with_the_flag() {
        let c = compile_fixture(true).unwrap();
        let d = DomainCategorizer::from_bytes(&c.bundle).unwrap();
        assert!(d.categorize_url("refused-fixture.test").is_empty());
        assert_eq!(
            excluded(&c),
            [(
                "fixture-refused",
                &Why::Refused("Turned down in review.".into())
            )]
        );
        assert!(manifest(&c, "domains.bin")
            .sources
            .iter()
            .all(|s| s.name != "fixture-refused"));

        // Nor can a refused source be approved.
        let both = source_toml(&format!(
            "path = \"x\"\nlicense = \"MIT\"\napproved = true\nrefused = \"No.\"\n\
             {ATTRIBUTION}\n{MIT_TEXT}"
        ));
        let err = Config::parse(&both).unwrap_err();
        assert!(format!("{err:#}").contains("both approved and refused"));
        let no_reason =
            source_toml("path = \"x\"\nlicense = \"MIT\"\napproved = false\nrefused = \" \"");
        assert!(Config::parse(&no_reason).is_err());
    }

    #[test]
    fn a_changed_input_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        for f in FIXTURE_FILES {
            fs::copy(fixtures().join(f), dir.path().join(f)).unwrap();
        }
        let config = Config::load(&dir.path().join("sources.toml")).unwrap();
        compile(&config, dir.path(), dir.path(), false).unwrap();

        let mut text = fs::read_to_string(dir.path().join("gambling.txt")).unwrap();
        text.push_str("sneaky.test\n");
        fs::write(dir.path().join("gambling.txt"), text).unwrap();
        let err = compile(&config, dir.path(), dir.path(), false).unwrap_err();
        assert!(format!("{err:#}").contains("the config pins"), "{err:#}");
    }

    #[test]
    fn url_sources_are_read_from_the_sources_dir() {
        let dir = tempfile::tempdir().unwrap();
        let body = b"fetched-fixture.test\n";
        let text = format!(
            "version = 1\nbundle_version = \"1.0.0\"\n[[source]]\nname = \"remote\"\n\
             category = \"gambling\"\n\
             format = \"domains\"\nlicense = \"CC0-1.0\"\napproved = true\n\
             url = \"https://example.invalid/list.txt\"\nblake3 = \"{}\"\n",
            blake3_hex(body)
        );
        let config = Config::parse(&text).unwrap();
        let err = compile(&config, dir.path(), dir.path(), false).unwrap_err();
        assert!(format!("{err:#}").contains("fetch"), "{err:#}");

        fs::write(dir.path().join("remote"), body).unwrap();
        let c = compile(&config, dir.path(), dir.path(), false).unwrap();
        let d = DomainCategorizer::from_bytes(&c.bundle).unwrap();
        assert_eq!(
            d.categorize_url("fetched-fixture.test"),
            vec![Category::Gambling]
        );
        assert_eq!(c.sources[0].origin, "https://example.invalid/list.txt");
    }

    #[test]
    fn writes_bundle_and_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out/domains.bin");
        let manifest_path = out.with_extension("manifest.json");
        let (excluded, _) = build(
            &fixtures().join("sources.toml"),
            &fixtures().join("no-such-dir"),
            &out,
            &manifest_path,
            false,
        )
        .unwrap();
        assert_eq!(excluded.len(), 2);
        let bundle = fs::read(&out).unwrap();
        assert!(DomainCategorizer::from_bytes(&bundle).is_ok());
        // A client loads it with every check (faro_detect::load_domains).
        let loaded = faro_detect::load_domains(&manifest_path).unwrap();
        assert_eq!(loaded.manifest.version, "1.0.0");
        assert_eq!(loaded.categorizer.len(), 4);
        let m: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        assert_eq!(m["bundle"]["file"], "domains.bin");
        assert_eq!(m["bundle"]["blake3"], blake3_hex(&bundle));
        assert!(m["notice"].as_str().unwrap().contains("license_texts"));
        let adult = &m["sources"][0];
        assert_eq!(adult["category"], "adult");
        assert_eq!(adult["format"], "hosts");
        assert_eq!(
            adult["attribution"]["copyright"][0],
            "Copyright (c) 2026 Fixture Author"
        );
        assert!(m["license_texts"]["MIT"]
            .as_str()
            .unwrap()
            .starts_with("Permission is hereby granted"));
        let gambling = &m["sources"][1];
        assert_eq!(gambling["license"], "CC-BY-4.0");
        assert_eq!(gambling["domains"], 2);
        assert_eq!(gambling["attribution"]["author"], "Fixture Collective");
        assert!(gambling["attribution"]["changes"]
            .as_str()
            .unwrap()
            .contains("Converted"));
    }

    #[test]
    fn build_fails_without_required_attribution() {
        let dir = tempfile::tempdir().unwrap();
        for f in FIXTURE_FILES {
            fs::copy(fixtures().join(f), dir.path().join(f)).unwrap();
        }
        let config = dir.path().join("sources.toml");
        let out = dir.path().join("domains.bin");
        let run = || {
            build(
                &config,
                dir.path(),
                &out,
                &out.with_extension("json"),
                false,
            )
        };
        run().unwrap();
        fs::remove_file(&out).unwrap();

        // Drop the CC-BY-4.0 source's attribution table.
        let text = fs::read_to_string(&config).unwrap();
        let start = text
            .find("[source.attribution]\nauthor = \"Fixture Collective\"")
            .unwrap();
        let end = start + text[start..].find("\n\n").unwrap();
        fs::write(&config, format!("{}{}", &text[..start], &text[end..])).unwrap();
        let err = run().unwrap_err();
        assert!(
            format!("{err:#}")
                .contains("fixture-gambling: its licence CC-BY-4.0 requires attribution"),
            "{err:#}"
        );
        assert!(!out.exists(), "nothing is written");
    }

    #[test]
    fn attribution_rules() {
        let parse = |licence: &str, approved: bool, tables: &str| {
            Config::parse(&source_toml(&format!(
                "path = \"x\"\nlicense = \"{licence}\"\napproved = {approved}\n{tables}"
            )))
        };
        let full = format!("{ATTRIBUTION}\n{MIT_TEXT}");
        assert!(parse("MIT", true, &full).is_ok());
        assert!(parse("MIT", true, "").is_err(), "no attribution");
        assert!(parse("MIT", true, ATTRIBUTION).is_err(), "no MIT text");
        assert!(parse("MIT", true, MIT_TEXT).is_err(), "no attribution");
        let no_copyright = full.replace("copyright = [\"Copyright (c) 2026 A\"]\n", "");
        assert!(
            parse("MIT", true, &no_copyright).is_err(),
            "MIT needs copyright"
        );
        let no_changes = full.replace("changes = \"Converted.\"", "changes = \"\"");
        assert!(parse("MIT", true, &no_changes).is_err());
        // CC BY 4.0: attribution, but no text and no copyright line needed.
        assert!(parse("CC-BY-4.0", true, "").is_err());
        assert!(parse("CC-BY-4.0", true, &no_copyright.replace(MIT_TEXT, "")).is_ok());
        // Combined licences need everything each one needs.
        assert!(parse("MIT AND CC-BY-4.0", true, &full).is_ok());
        assert!(parse("MIT AND CC-BY-4.0", true, ATTRIBUTION).is_err());
        // Public-domain dedications need nothing.
        assert!(parse("CC0-1.0", true, "").is_ok());
        // Pending sources aren't checked until they're approved.
        assert!(parse("MIT", false, "").is_ok());
        // A missing author is a parse error.
        let no_author = full.replace("author = \"A\"\n", "");
        assert!(parse("MIT", true, &no_author).is_err());
    }

    #[test]
    fn approved_sources_need_a_permissive_licence() {
        let full = format!("{ATTRIBUTION}\n{MIT_TEXT}");
        let parse = |licence: &str, approved: bool| {
            Config::parse(&source_toml(&format!(
                "path = \"x\"\nlicense = \"{licence}\"\napproved = {approved}\n{full}"
            )))
        };
        assert!(parse("MIT", true).is_ok());
        assert!(parse("MIT AND CC-BY-4.0", true).is_ok());
        assert!(parse("(MIT AND CC0-1.0)", true).is_ok());
        assert!(parse("GPL-3.0-only", true).is_err());
        assert!(parse("CC-BY-SA-4.0", true).is_err());
        assert!(parse("MIT OR GPL-3.0-only", true).is_err());
        assert!(parse("Apache-2.0 WITH LLVM-exception", true).is_err());
        assert!(parse("NOASSERTION", true).is_err());
        assert!(parse("", true).is_err());
        // Unapproved entries may carry any licence; they're left out at build time.
        assert!(parse("GPL-3.0-only", false).is_ok());
    }

    #[test]
    fn config_is_validated() {
        let ok = "path = \"x\"\nlicense = \"CC0-1.0\"\napproved = true";
        assert!(Config::parse(&source_toml(ok)).is_ok());
        for bad in [
            // both or neither of url and path
            "path = \"x\"\nurl = \"https://a.test/x\"\nlicense = \"CC0-1.0\"\napproved = true",
            "license = \"CC0-1.0\"\napproved = true",
            // not https
            "url = \"http://a.test/x\"\nlicense = \"CC0-1.0\"\napproved = true",
            // unknown field
            "path = \"x\"\nlicense = \"CC0-1.0\"\napproved = true\nlicence = \"MIT\"",
            // missing approved flag
            "path = \"x\"\nlicense = \"CC0-1.0\"",
        ] {
            assert!(Config::parse(&source_toml(bad)).is_err(), "{bad}");
        }
        let bad_hash = source_toml(ok).replace(&"0".repeat(64), &"A".repeat(64));
        assert!(Config::parse(&bad_hash).is_err());
        let bad_name = source_toml(ok).replace("name = \"s\"", "name = \"../s\"");
        assert!(Config::parse(&bad_name).is_err());
        let bad_category = source_toml(ok).replace("\"adult\"", "\"porn\"");
        assert!(Config::parse(&bad_category).is_err());
        let bad_version = source_toml(ok).replace("version = 1", "version = 2");
        assert!(Config::parse(&bad_version).is_err());
        let empty_text = source_toml(&format!("{ok}\n[license_texts]\nMIT = \" \""));
        assert!(Config::parse(&empty_text).is_err());
        let twice = format!(
            "{}{}",
            source_toml(ok),
            source_toml(ok).replace("version = 1\nbundle_version = \"1.0.0\"\n", "")
        );
        assert!(format!("{:#}", Config::parse(&twice).unwrap_err()).contains("duplicate"));
    }

    /// The checked-in config: valid, every approved source pinned to a
    /// StevenBlack/hosts commit and attributed, and the maintainer's
    /// refusals recorded.
    #[test]
    fn checked_in_sources_are_pinned_licensed_and_attributed() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("domains/sources.toml");
        let config = Config::load(&path).unwrap();
        let approved: Vec<&Source> = config.sources.iter().filter(|s| s.approved).collect();
        for category in [Category::Adult, Category::Gambling] {
            assert!(
                approved.iter().any(|s| s.category == category),
                "{category}"
            );
        }
        let prefix = "https://raw.githubusercontent.com/StevenBlack/hosts/";
        for s in &approved {
            let url = s.url.as_deref().unwrap();
            let rev = url.strip_prefix(prefix).unwrap().split('/').next().unwrap();
            assert!(
                rev.len() == 40 && rev.bytes().all(|b| b.is_ascii_hexdigit()),
                "{} must be pinned to a commit",
                s.name
            );
            assert!(
                ["MIT", "CC-BY-4.0"].contains(&s.license.as_str()),
                "{}",
                s.name
            );
            assert!(s.attribution.is_some(), "{}", s.name);
        }
        assert!(approved.iter().any(|s| s.name == "stevenblack-porn-tiuxo"));
        for name in [
            "stevenblack-porn-brijrajparmar27",
            "oisd-nsfw",
            "ut1-gambling",
        ] {
            let s = config.sources.iter().find(|s| s.name == name).unwrap();
            assert!(s.refused.is_some() && !s.included(true), "{name}");
        }
        assert!(
            config
                .sources
                .iter()
                .all(|s| s.approved || s.refused.is_some()),
            "no source is left pending"
        );
    }
}
