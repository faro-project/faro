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
//! SPDX licence, an `approved` flag and the BLAKE3 of the exact file to use.
//! A source is either a `url`, which `fetch` downloads into `--sources-dir`
//! (named after the source), or a local `path` relative to the config file.
//! `build` reads only those files, refuses any whose hash differs from its
//! pin, and writes the bundle plus a JSON manifest (sources, licences, entry
//! counts, BLAKE3 of the bundle). The same config and inputs always give
//! byte-identical outputs.
//!
//! Unapproved sources are left out of `fetch` and `build` unless
//! `--allow-unapproved` is given, which is for local experiments only: a
//! bundle built that way says so in its manifest and must never ship. An
//! approved source must carry a licence from the Apache-2.0-compatible
//! allowlist ([`ALLOWED_MODEL_LICENSES`]), or the config is rejected.
//!
//! This is a project tool, not part of any shipped client. Parsing is
//! [`DomainCategorizerBuilder::add_source`], exactly as the library does it.

use anyhow::{bail, ensure, Context, Result};
use clap::{Parser, Subcommand};
use faro_detect::{
    Category, CompileStats, DomainCategorizer, DomainCategorizerBuilder, ALLOWED_MODEL_LICENSES,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const CONFIG_VERSION: u32 = 1;
const MANIFEST_FORMAT: &str = "faro-domains-manifest/1";
/// Largest source file accepted (the biggest lists in use are a few MB).
const MAX_SOURCE_BYTES: u64 = 256 << 20;
const DEFAULT_SOURCES_DIR: &str = "target/domains/sources";
const MAX_NAME_LEN: usize = 64;

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
        /// Also fetch unapproved sources (local experiments only).
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
        /// Include unapproved sources. For local experiments only: the
        /// manifest records it and such a bundle must never ship.
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
            let cfg = Config::load(&config)?;
            let manifest = manifest.unwrap_or_else(|| out.with_extension("manifest.json"));
            let compiled = compile(&cfg, config_dir(&config), &sources_dir, allow_unapproved)?;
            for s in &compiled.refused {
                eprintln!(
                    "refused unapproved source {} ({}); --allow-unapproved includes it for local \
                     experiments only",
                    s.name, s.license
                );
                if let Some(terms) = &s.terms {
                    eprintln!("  terms: {terms}");
                }
            }
            let m = write_outputs(&compiled, &out, &manifest)?;
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

fn config_dir(config: &Path) -> &Path {
    config.parent().unwrap_or(Path::new("."))
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// `sources.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u32,
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
    /// An https URL that `fetch` downloads; pin it to an immutable revision.
    url: Option<String>,
    /// Or a local file, relative to the config file's directory.
    path: Option<String>,
    /// Lowercase hex BLAKE3 of the exact file.
    blake3: String,
    homepage: Option<String>,
    /// What the upstream terms say (shown when the source is refused).
    terms: Option<String>,
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
        let mut names = BTreeSet::new();
        for s in &config.sources {
            s.validate()?;
            ensure!(
                names.insert(s.name.as_str()),
                "duplicate source name {:?}",
                s.name
            );
        }
        Ok(config)
    }
}

/// Whether every identifier in an SPDX expression is on the allowlist.
/// Deliberately conservative: `OR` is treated like `AND`, and `WITH`
/// exceptions are not accepted.
fn license_is_permissive(expr: &str) -> bool {
    let mut ids = 0;
    for token in expr
        .split(|c: char| c.is_whitespace() || c == '(' || c == ')')
        .filter(|t| !t.is_empty())
    {
        match token {
            "AND" | "OR" => {}
            id if ALLOWED_MODEL_LICENSES.contains(&id) => ids += 1,
            _ => return false,
        }
    }
    ids > 0
}

impl Source {
    fn validate(&self) -> Result<()> {
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
        if self.approved {
            ensure!(
                license_is_permissive(&self.license),
                "source {name} is approved, but its licence {:?} is not on the \
                 Apache-2.0-compatible allowlist (ARCHITECTURE.md §11)",
                self.license
            );
        }
        Ok(())
    }

    fn included(&self, allow_unapproved: bool) -> bool {
        self.approved || allow_unapproved
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
        if !s.included(allow_unapproved) {
            eprintln!("{}: unapproved ({}), not fetched", s.name, s.license);
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

/// A source left out because it isn't approved.
#[derive(Debug)]
struct Refused {
    name: String,
    license: String,
    terms: Option<String>,
}

/// The result of [`compile`].
#[derive(Debug)]
struct Compiled {
    bundle: Vec<u8>,
    domains: usize,
    sources: Vec<SourceReport>,
    refused: Vec<Refused>,
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
    let mut refused = Vec::new();
    for s in &config.sources {
        if !s.included(allow_unapproved) {
            refused.push(Refused {
                name: s.name.clone(),
                license: s.license.clone(),
                terms: s.terms.clone(),
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
        sources.push(SourceReport::new(s, stats));
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
        bundle,
        domains: categorizer.len(),
        sources,
        refused,
    })
}

/// The JSON written next to the bundle. It has no timestamps, so identical
/// inputs give an identical manifest.
#[derive(Debug, Serialize)]
struct Manifest {
    format: &'static str,
    bundle: BundleInfo,
    /// Distinct domains in the bundle.
    domains: usize,
    /// True only for `--allow-unapproved` builds, which must never ship.
    unapproved_included: bool,
    sources: Vec<SourceReport>,
}

#[derive(Debug, Serialize)]
struct BundleInfo {
    file: String,
    bytes: u64,
    blake3: String,
}

#[derive(Debug, Clone, Serialize)]
struct SourceReport {
    name: String,
    category: Category,
    format: Format,
    license: String,
    approved: bool,
    origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    homepage: Option<String>,
    blake3: String,
    /// Non-empty, non-comment lines.
    lines: usize,
    /// Domains accepted (some may also be in other sources).
    domains: usize,
    /// Tokens that couldn't be used (IP literals, local names, bad syntax).
    skipped: usize,
}

impl SourceReport {
    fn new(s: &Source, stats: CompileStats) -> Self {
        SourceReport {
            name: s.name.clone(),
            category: s.category,
            format: s.format,
            license: s.license.clone(),
            approved: s.approved,
            origin: s.origin().to_owned(),
            homepage: s.homepage.clone(),
            blake3: s.blake3.clone(),
            lines: stats.lines,
            domains: stats.domains,
            skipped: stats.skipped,
        }
    }
}

fn manifest(compiled: &Compiled, bundle_file: &str) -> Manifest {
    Manifest {
        format: MANIFEST_FORMAT,
        bundle: BundleInfo {
            file: bundle_file.to_owned(),
            bytes: compiled.bundle.len() as u64,
            blake3: blake3_hex(&compiled.bundle),
        },
        domains: compiled.domains,
        unapproved_included: compiled.sources.iter().any(|s| !s.approved),
        sources: compiled.sources.clone(),
    }
}

fn write_outputs(compiled: &Compiled, out: &Path, manifest_path: &Path) -> Result<Manifest> {
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

    fn source_toml(extra: &str) -> String {
        format!(
            "version = 1\n[[source]]\nname = \"s\"\ncategory = \"adult\"\nformat = \"domains\"\n\
             blake3 = \"{}\"\n{extra}\n",
            "0".repeat(64)
        )
    }

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

        // The unapproved source was refused.
        assert!(d.categorize_url("unapproved-fixture.test").is_empty());
        let refused: Vec<_> = c.refused.iter().map(|r| (&*r.name, &*r.license)).collect();
        assert_eq!(refused, [("fixture-unapproved", "GPL-3.0-only")]);

        let m = manifest(&c, "domains.bin");
        assert_eq!(m.format, MANIFEST_FORMAT);
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
    fn unapproved_sources_need_the_flag() {
        let c = compile_fixture(true).unwrap();
        let d = DomainCategorizer::from_bytes(&c.bundle).unwrap();
        assert_eq!(
            d.categorize_url("unapproved-fixture.test"),
            vec![Category::Adult]
        );
        assert!(c.refused.is_empty());
        let m = manifest(&c, "domains.bin");
        assert!(m.unapproved_included);
        assert!(!m.sources[2].approved);
    }

    #[test]
    fn a_changed_input_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        for f in [
            "sources.toml",
            "adult.hosts",
            "gambling.txt",
            "unapproved.txt",
        ] {
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
            "version = 1\n[[source]]\nname = \"remote\"\ncategory = \"gambling\"\n\
             format = \"domains\"\nlicense = \"MIT\"\napproved = true\n\
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
        let c = compile_fixture(false).unwrap();
        let out = dir.path().join("out/domains.bin");
        let manifest_path = out.with_extension("manifest.json");
        write_outputs(&c, &out, &manifest_path).unwrap();
        let bundle = fs::read(&out).unwrap();
        assert!(DomainCategorizer::from_bytes(&bundle).is_ok());
        let m: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        assert_eq!(m["bundle"]["file"], "domains.bin");
        assert_eq!(m["bundle"]["blake3"], blake3_hex(&bundle));
        assert_eq!(m["sources"][0]["category"], "adult");
        assert_eq!(m["sources"][0]["format"], "hosts");
        assert_eq!(m["sources"][1]["domains"], 2);
    }

    #[test]
    fn approved_sources_need_a_permissive_licence() {
        let parse = |licence: &str, approved: bool| {
            Config::parse(&source_toml(&format!(
                "path = \"x\"\nlicense = \"{licence}\"\napproved = {approved}"
            )))
        };
        assert!(parse("MIT", true).is_ok());
        assert!(parse("MIT AND CC-BY-4.0", true).is_ok());
        assert!(parse("(MIT AND CC0-1.0)", true).is_ok());
        assert!(parse("GPL-3.0-only", true).is_err());
        assert!(parse("CC-BY-SA-4.0", true).is_err());
        assert!(parse("MIT OR GPL-3.0-only", true).is_err());
        assert!(parse("NOASSERTION", true).is_err());
        assert!(parse("", true).is_err());
        // Unapproved entries may carry any licence; they're refused at build time.
        assert!(parse("GPL-3.0-only", false).is_ok());
    }

    #[test]
    fn config_is_validated() {
        let ok = "path = \"x\"\nlicense = \"MIT\"\napproved = true";
        assert!(Config::parse(&source_toml(ok)).is_ok());
        for bad in [
            // both or neither of url and path
            "path = \"x\"\nurl = \"https://a.test/x\"\nlicense = \"MIT\"\napproved = true",
            "license = \"MIT\"\napproved = true",
            // not https
            "url = \"http://a.test/x\"\nlicense = \"MIT\"\napproved = true",
            // unknown field
            "path = \"x\"\nlicense = \"MIT\"\napproved = true\nlicence = \"MIT\"",
            // missing approved flag
            "path = \"x\"\nlicense = \"MIT\"",
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
        let twice = format!(
            "{}{}",
            source_toml(ok),
            source_toml(ok).replace("version = 1\n", "")
        );
        assert!(format!("{:#}", Config::parse(&twice).unwrap_err()).contains("duplicate"));
    }

    /// The checked-in config: valid, every approved source pinned to a
    /// StevenBlack/hosts commit, OISD and UT1 present but not approved.
    #[test]
    fn checked_in_sources_are_pinned_and_licensed() {
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
            assert_eq!(s.license, "MIT", "{}", s.name);
        }
        for upstream in ["oisd-", "ut1-"] {
            let listed: Vec<&Source> = config
                .sources
                .iter()
                .filter(|s| s.name.starts_with(upstream))
                .collect();
            assert!(!listed.is_empty(), "{upstream}");
            assert!(listed.iter().all(|s| !s.approved && s.terms.is_some()));
        }
    }
}
