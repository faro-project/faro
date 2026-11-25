//! The version inside a macOS update package: checked before install.
//!
//! The signed metadata says which version a package is (`targets.json`),
//! and [`super::signature`] checks that Faro signed and notarized it.
//! Someone holding the online keys (targets and timestamp) could still
//! list an *old* package Faro really signed under a higher version. Its
//! signature passes, and the client would go back to an old release while
//! it thinks it moved forward. So the service also reads the version the
//! package carries, and installs it only if that version is the target's
//! and above the installed one (PROTOCOL.md §8.2, step 6).
//!
//! **Where the version is.** `build-pkg.sh` passes the full semver version
//! (`0.1.0-beta.1`) to `pkgbuild --version`, which writes it into the
//! component's `PackageInfo` (`<pkg-info identifier="org.faro.pkg"
//! version="…">`). The same version goes into the `Distribution`'s
//! `pkg-ref`. Every Faro package has carried both since the first one.
//! The app bundle's version can't serve: bundle versions are plain
//! integers, so it says `0.1.0` for `0.1.0-beta.1`. `check-pkg.sh` checks
//! that both are the package's version and that the packaged
//! `faro-service` reports the same one.
//!
//! **How it is read.** A flat package is a xar archive. This module reads
//! it directly. It runs nothing and unpacks nothing to disk: it reads the
//! header, the zlib-compressed table of contents (TOC), and two small files
//! from the heap: `Distribution`, then the `PackageInfo` of the one
//! component the Distribution installs. Every byte it uses is checked
//! against the archive's own checksums. The TOC must match the checksum the
//! package signature covers, and each file must match its archived and
//! extracted checksums in the TOC. So the version read is the one Faro
//! signed, in the same bytes `installer` will use.
//!
//! **Outcomes**, as for the signature:
//!
//! - [`Rejected`] (tamper): the version is not the target's, or not above
//!   the installed one (semver precedence: `0.1.0-beta.1 < 0.1.0`), the
//!   identifier is not [`PKG_IDENTIFIER`], or a checksum doesn't match.
//! - [`Unconfirmed`]: the file can't be read, or the archive isn't in a form
//!   this reader knows: an unsupported checksum or encoding, an entry that
//!   is missing or given twice, a version that isn't semver, or a
//!   `Distribution` and `PackageInfo` that disagree. Nothing is installed.

use super::signature::PackageCheckError::{self, Rejected, Unconfirmed};
use faro_update::Version;
use std::cmp::Ordering;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// The identifier of Faro's component package (`pkgbuild --identifier`).
pub const PKG_IDENTIFIER: &str = "org.faro.pkg";

/// The xar magic, at offset 0.
const MAGIC: &[u8; 4] = b"xar!";
/// The header with a SHA-1 TOC checksum, and with a named one.
const HEADER_SHA1: u16 = 28;
const HEADER_NAMED: u16 = 64;
/// Limits. A Faro package's TOC is a few kilobytes, and `Distribution` and
/// `PackageInfo` are under one.
const MAX_TOC_COMPRESSED: u64 = 1 << 20;
const MAX_TOC: u64 = 8 << 20;
const MAX_FILE: u64 = 1 << 20;
const MAX_XML_NODES: u32 = 200_000;

/// Read `pkg`'s version and check it against the target's and the
/// installed one. Returns the version read.
pub fn check_version(
    pkg: &Path,
    target: &Version,
    installed: &Version,
) -> Result<Version, PackageCheckError> {
    let found = read_version(pkg)?;
    judge_version(&found, target, installed)?;
    Ok(found)
}

/// The package's version must be exactly the target's (`targets.json`) and
/// above the installed version.
pub fn judge_version(
    found: &Version,
    target: &Version,
    installed: &Version,
) -> Result<(), PackageCheckError> {
    if found != target {
        return Err(Rejected(format!(
            "the package is version {found}, but the update metadata says {target}"
        )));
    }
    if found.cmp_precedence(installed) != Ordering::Greater {
        return Err(Rejected(format!(
            "the package is version {found}, not above the installed {installed}"
        )));
    }
    Ok(())
}

/// The version of Faro's component in the package at `pkg`.
pub fn read_version(pkg: &Path) -> Result<Version, PackageCheckError> {
    let mut f = std::fs::File::open(pkg)
        .map_err(|e| Unconfirmed(format!("cannot open {}: {e}", pkg.display())))?;
    read_version_from(&mut f)
}

/// The version of Faro's component in the flat package `r`.
pub fn read_version_from<R: Read + Seek>(r: &mut R) -> Result<Version, PackageCheckError> {
    let mut xar = Xar::open(r)?;
    let toc = xar.toc_text()?;
    let doc = parse_xml(&toc, "the TOC")?;
    let root = doc.root_element();
    if !root.has_tag_name("xar") {
        return Err(bad("the TOC is not a xar TOC"));
    }
    let toc = one(root, "toc")?;
    let top: Vec<_> = elements(toc, "file").collect();

    let dist = xar.read_file(file_data(named(&top, "Distribution")?)?, "Distribution")?;
    let dist = utf8(dist, "Distribution")?;
    let (component, dist_version) = component_ref(&parse_xml(&dist, "Distribution")?)?;

    let dir = named(&top, &component)?;
    if leaf_text(one(dir, "type")?)? != "directory" {
        return Err(bad(format!("{component} is not a component package")));
    }
    let children: Vec<_> = elements(dir, "file").collect();
    let info = file_data(named(&children, "PackageInfo")?)?;
    let info = utf8(xar.read_file(info, "PackageInfo")?, "PackageInfo")?;
    let version = package_info_version(&parse_xml(&info, "PackageInfo")?)?;

    if version != dist_version {
        return Err(bad(format!(
            "PackageInfo says version {version}, the Distribution {dist_version}"
        )));
    }
    Ok(version)
}

fn bad(msg: impl Into<String>) -> PackageCheckError {
    Unconfirmed(msg.into())
}

/// A checksum algorithm xar uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algo {
    Sha1,
    Sha256,
    Sha512,
}

impl Algo {
    /// From a TOC `style` or a header's checksum name. MD5 and `none` are
    /// not accepted.
    fn named(s: &str) -> Option<Algo> {
        match s {
            "sha1" => Some(Algo::Sha1),
            "sha256" => Some(Algo::Sha256),
            "sha512" => Some(Algo::Sha512),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Algo::Sha1 => "sha1",
            Algo::Sha256 => "sha256",
            Algo::Sha512 => "sha512",
        }
    }

    fn len(self) -> usize {
        match self {
            Algo::Sha1 => 20,
            Algo::Sha256 => 32,
            Algo::Sha512 => 64,
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        match self {
            Algo::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Algo::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Algo::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }
}

/// A checksum from the TOC: `<archived-checksum style="sha1">hex</…>`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Checksum {
    algo: Algo,
    value: Vec<u8>,
}

/// How a file is stored in the heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    /// `application/octet-stream`: as is.
    Stored,
    /// `application/x-gzip`: a zlib stream (xar's name for it).
    Zlib,
}

/// A file's `<data>` in the TOC.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Data {
    offset: u64,
    /// Bytes in the heap.
    length: u64,
    /// Bytes once decoded.
    size: u64,
    encoding: Encoding,
    archived: Checksum,
    extracted: Checksum,
}

/// An open xar archive.
struct Xar<'r, R> {
    r: &'r mut R,
    len: u64,
    algo: Algo,
    header: u64,
    toc_compressed: u64,
    toc_size: u64,
}

impl<'r, R: Read + Seek> Xar<'r, R> {
    /// Read and check the header.
    fn open(r: &'r mut R) -> Result<Self, PackageCheckError> {
        let io = |e: std::io::Error| bad(format!("cannot read the package: {e}"));
        let len = r.seek(SeekFrom::End(0)).map_err(io)?;
        r.seek(SeekFrom::Start(0)).map_err(io)?;
        let mut h = [0u8; HEADER_NAMED as usize];
        let short = |_| bad("the package is too short to be a xar archive");
        r.read_exact(&mut h[..HEADER_SHA1 as usize])
            .map_err(short)?;
        if &h[..4] != MAGIC {
            return Err(bad("the package is not a xar archive"));
        }
        let be16 = |i: usize| u16::from_be_bytes([h[i], h[i + 1]]);
        let be64 = |i: usize| u64::from_be_bytes(h[i..i + 8].try_into().expect("8 bytes"));
        let (size, version) = (be16(4), be16(6));
        let (toc_compressed, toc_size) = (be64(8), be64(16));
        let algo_id = u32::from_be_bytes(h[24..28].try_into().expect("4 bytes"));
        if version != 1 {
            return Err(bad(format!("unsupported xar version {version}")));
        }
        let algo = match (algo_id, size) {
            (1, HEADER_SHA1) => Algo::Sha1,
            (3, HEADER_NAMED) => {
                r.read_exact(&mut h[HEADER_SHA1 as usize..])
                    .map_err(short)?;
                let name = &h[HEADER_SHA1 as usize..];
                let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                std::str::from_utf8(&name[..end])
                    .ok()
                    .and_then(Algo::named)
                    .ok_or_else(|| bad("unsupported xar TOC checksum"))?
            }
            _ => {
                return Err(bad(format!(
                    "unsupported xar header (checksum {algo_id}, {size} bytes)"
                )))
            }
        };
        if toc_compressed == 0 || toc_compressed > MAX_TOC_COMPRESSED || toc_size > MAX_TOC {
            return Err(bad("the xar TOC is too large"));
        }
        Ok(Xar {
            r,
            len,
            algo,
            header: u64::from(size),
            toc_compressed,
            toc_size,
        })
    }

    /// Where the heap starts.
    fn heap(&self) -> u64 {
        self.header + self.toc_compressed
    }

    /// `len` bytes at `offset` in the heap.
    fn read_heap(&mut self, offset: u64, len: u64) -> Result<Vec<u8>, PackageCheckError> {
        let start = self.heap().checked_add(offset);
        let end = start.and_then(|s| s.checked_add(len));
        let (Some(start), Some(end)) = (start, end) else {
            return Err(bad("a xar offset overflows"));
        };
        if end > self.len {
            return Err(bad("a xar entry runs past the end of the package"));
        }
        self.read_at(start, len)
    }

    fn read_at(&mut self, start: u64, len: u64) -> Result<Vec<u8>, PackageCheckError> {
        let io = |e: std::io::Error| bad(format!("cannot read the package: {e}"));
        self.r.seek(SeekFrom::Start(start)).map_err(io)?;
        let mut buf = vec![0u8; usize::try_from(len).map_err(|_| bad("too large"))?];
        self.r.read_exact(&mut buf).map_err(io)?;
        Ok(buf)
    }

    /// The TOC, decompressed, after checking it against the checksum the
    /// package signature covers.
    fn toc_text(&mut self) -> Result<String, PackageCheckError> {
        if self.heap() > self.len {
            return Err(bad("the xar TOC runs past the end of the package"));
        }
        let compressed = self.read_at(self.header, self.toc_compressed)?;
        let toc = inflate(&compressed, self.toc_size, "the TOC")?;
        let toc = utf8(toc, "the TOC")?;
        let doc = parse_xml(&toc, "the TOC")?;
        let sum = one(one(doc.root_element(), "toc")?, "checksum")?;
        if attr(sum, "style")? != self.algo.name() {
            return Err(bad("the TOC checksum style differs from the xar header's"));
        }
        let offset = number(one(sum, "offset")?)?;
        let size = number(one(sum, "size")?)?;
        if size != self.algo.len() as u64 {
            return Err(bad("the TOC checksum has the wrong size"));
        }
        let stored = self.read_heap(offset, size)?;
        if stored != self.algo.digest(&compressed) {
            return Err(Rejected(
                "the package's table of contents doesn't match its checksum".into(),
            ));
        }
        Ok(toc)
    }

    /// A file's contents, checked against both of its checksums.
    fn read_file(&mut self, d: Data, what: &str) -> Result<Vec<u8>, PackageCheckError> {
        if d.length > MAX_FILE || d.size > MAX_FILE {
            return Err(bad(format!("{what} is too large")));
        }
        let raw = self.read_heap(d.offset, d.length)?;
        if d.archived.algo.digest(&raw) != d.archived.value {
            return Err(Rejected(format!(
                "{what} doesn't match its archived checksum"
            )));
        }
        let data = match d.encoding {
            Encoding::Stored if d.size == d.length => raw,
            Encoding::Stored => return Err(bad(format!("{what}: stored with a different size"))),
            Encoding::Zlib => inflate(&raw, d.size, what)?,
        };
        if d.extracted.algo.digest(&data) != d.extracted.value {
            return Err(Rejected(format!(
                "{what} doesn't match its extracted checksum"
            )));
        }
        Ok(data)
    }
}

/// Decompress one complete zlib stream of exactly `size` bytes, with
/// nothing after it.
fn inflate(compressed: &[u8], size: u64, what: &str) -> Result<Vec<u8>, PackageCheckError> {
    let mut z = flate2::read::ZlibDecoder::new(compressed);
    let mut out = Vec::new();
    (&mut z)
        .take(size + 1)
        .read_to_end(&mut out)
        .map_err(|e| bad(format!("{what} doesn't decompress: {e}")))?;
    if out.len() as u64 != size {
        return Err(bad(format!(
            "{what} decompresses to {} bytes, not {size}",
            out.len()
        )));
    }
    if z.total_in() != compressed.len() as u64 {
        return Err(bad(format!("{what} has data after its zlib stream")));
    }
    Ok(out)
}

fn utf8(b: Vec<u8>, what: &str) -> Result<String, PackageCheckError> {
    String::from_utf8(b).map_err(|_| bad(format!("{what} is not UTF-8")))
}

/// Parse XML strictly: no DTD, bounded size.
fn parse_xml<'a>(text: &'a str, what: &str) -> Result<roxmltree::Document<'a>, PackageCheckError> {
    let opt = roxmltree::ParsingOptions {
        allow_dtd: false,
        nodes_limit: MAX_XML_NODES,
        ..Default::default()
    };
    roxmltree::Document::parse_with_options(text, opt)
        .map_err(|e| bad(format!("{what} is not well-formed XML: {e}")))
}

type Node<'a, 'i> = roxmltree::Node<'a, 'i>;

/// The child elements of `n` called `name`.
fn elements<'a, 'i>(n: Node<'a, 'i>, name: &'static str) -> impl Iterator<Item = Node<'a, 'i>> {
    n.children()
        .filter(move |c| c.is_element() && c.has_tag_name(name))
}

/// The one child element of `n` called `name`.
fn one<'a, 'i>(n: Node<'a, 'i>, name: &'static str) -> Result<Node<'a, 'i>, PackageCheckError> {
    let mut it = elements(n, name);
    match (it.next(), it.next()) {
        (Some(c), None) => Ok(c),
        (None, _) => Err(bad(format!("no <{name}> in <{}>", n.tag_name().name()))),
        (Some(_), Some(_)) => Err(bad(format!(
            "more than one <{name}> in <{}>",
            n.tag_name().name()
        ))),
    }
}

fn attr<'a>(n: Node<'a, '_>, name: &str) -> Result<&'a str, PackageCheckError> {
    n.attribute(name)
        .ok_or_else(|| bad(format!("<{}> has no {name} attribute", n.tag_name().name())))
}

/// The text of an element that holds only text (or nothing).
fn leaf_text<'a>(n: Node<'a, '_>) -> Result<&'a str, PackageCheckError> {
    let mut it = n.children();
    match (it.next(), it.next()) {
        (None, _) => Ok(""),
        (Some(t), None) if t.is_text() => Ok(t.text().unwrap_or("")),
        _ => Err(bad(format!(
            "<{}> holds more than text",
            n.tag_name().name()
        ))),
    }
}

/// A decimal number, digits only.
fn number(n: Node<'_, '_>) -> Result<u64, PackageCheckError> {
    let s = leaf_text(n)?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad(format!("<{}> is not a number", n.tag_name().name())));
    }
    s.parse()
        .map_err(|_| bad(format!("<{}> is out of range", n.tag_name().name())))
}

/// A `<file>`'s name. productbuild writes `<name>` twice for files in a
/// directory; every copy must agree.
fn file_name<'a>(f: Node<'a, '_>) -> Result<&'a str, PackageCheckError> {
    let mut name = None;
    for n in elements(f, "name") {
        let s = leaf_text(n)?;
        if name.is_some_and(|m| m != s) {
            return Err(bad("a xar file has two different names"));
        }
        name = Some(s);
    }
    match name {
        Some(s) if !s.is_empty() && s != "." && s != ".." && !s.contains('/') => Ok(s),
        Some(s) => Err(bad(format!("a xar file is named {s:?}"))),
        None => Err(bad("a xar file has no name")),
    }
}

/// The one file called `name` among `files`.
fn named<'a, 'i>(files: &[Node<'a, 'i>], name: &str) -> Result<Node<'a, 'i>, PackageCheckError> {
    let mut found = None;
    for &f in files {
        if file_name(f)? == name {
            if found.is_some() {
                return Err(bad(format!("the package has two entries called {name}")));
            }
            found = Some(f);
        }
    }
    found.ok_or_else(|| bad(format!("the package has no {name}")))
}

/// A regular file's `<data>`.
fn file_data(f: Node<'_, '_>) -> Result<Data, PackageCheckError> {
    let name = file_name(f)?;
    if leaf_text(one(f, "type")?)? != "file" {
        return Err(bad(format!("{name} is not a regular file")));
    }
    let d = one(f, "data")?;
    let encoding = match attr(one(d, "encoding")?, "style")? {
        "application/octet-stream" => Encoding::Stored,
        "application/x-gzip" => Encoding::Zlib,
        other => return Err(bad(format!("{name} has an unsupported encoding {other}"))),
    };
    let checksum = |tag: &'static str| -> Result<Checksum, PackageCheckError> {
        let c = one(d, tag)?;
        let style = attr(c, "style")?;
        let algo = Algo::named(style)
            .ok_or_else(|| bad(format!("{name}: unsupported checksum {style}")))?;
        let value = hex::decode(leaf_text(c)?)
            .ok()
            .filter(|v| v.len() == algo.len())
            .ok_or_else(|| bad(format!("{name}: malformed {tag}")))?;
        Ok(Checksum { algo, value })
    };
    Ok(Data {
        offset: number(one(d, "offset")?)?,
        length: number(one(d, "length")?)?,
        size: number(one(d, "size")?)?,
        encoding,
        archived: checksum("archived-checksum")?,
        extracted: checksum("extracted-checksum")?,
    })
}

/// A strict semver version from the package.
fn semver(s: &str, what: &str) -> Result<Version, PackageCheckError> {
    Version::parse(s).map_err(|e| bad(format!("{what} version {s:?} is not semver: {e}")))
}

/// From the Distribution: the one component it installs (`#name`, a
/// directory in the archive) and its version. Every `pkg-ref` for that
/// identifier that names a version must name the same one.
fn component_ref(doc: &roxmltree::Document<'_>) -> Result<(String, Version), PackageCheckError> {
    let root = doc.root_element();
    if !root.has_tag_name("installer-gui-script") {
        return Err(bad("the Distribution is not an installer-gui-script"));
    }
    let refs: Vec<_> = root
        .descendants()
        .filter(|n| n.is_element() && n.has_tag_name("pkg-ref"))
        .collect();
    // A pkg-ref with text names a component; others only describe it.
    let names_component = |r: &&Node<'_, '_>| {
        r.children()
            .any(|c| c.is_text() && c.text().is_some_and(|t| !t.trim().is_empty()))
    };
    let mut components = refs.iter().filter(names_component);
    let (Some(&c), None) = (components.next(), components.next()) else {
        return Err(bad("the Distribution must install exactly one component"));
    };
    let id = attr(c, "id")?;
    if id != PKG_IDENTIFIER {
        return Err(Rejected(format!(
            "the package installs {id}, not {PKG_IDENTIFIER}"
        )));
    }
    let name = leaf_text(c)?
        .strip_prefix('#')
        .filter(|n| !n.is_empty() && *n != "." && *n != ".." && !n.contains('/'))
        .ok_or_else(|| bad("the Distribution's component is not inside the package"))?;
    let version = semver(attr(c, "version")?, "the Distribution's")?;
    for r in &refs {
        if r.attribute("id") == Some(id) {
            if let Some(v) = r.attribute("version") {
                if semver(v, "the Distribution's")? != version {
                    return Err(bad("the Distribution names two versions"));
                }
            }
        }
    }
    Ok((name.to_owned(), version))
}

/// From `PackageInfo`: `<pkg-info identifier="org.faro.pkg" version="…">`.
fn package_info_version(doc: &roxmltree::Document<'_>) -> Result<Version, PackageCheckError> {
    let root = doc.root_element();
    if !root.has_tag_name("pkg-info") {
        return Err(bad("PackageInfo is not a pkg-info document"));
    }
    let id = attr(root, "identifier")?;
    if id != PKG_IDENTIFIER {
        return Err(Rejected(format!(
            "the component is {id}, not {PKG_IDENTIFIER}"
        )));
    }
    semver(attr(root, "version")?, "PackageInfo's")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    const V: &str = "0.1.0-beta.1";

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    fn distribution(id: &str, version: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n\
             <installer-gui-script minSpecVersion=\"2\">\n\
             \x20   <title>Faro</title>\n\
             \x20   <choices-outline><line choice=\"{id}\"/></choices-outline>\n\
             \x20   <choice id=\"{id}\" visible=\"false\" title=\"Faro\">\n\
             \x20       <pkg-ref id=\"{id}\"/>\n\
             \x20   </choice>\n\
             \x20   <pkg-ref id=\"{id}\" version=\"{version}\" onConclusion=\"none\" installKBytes=\"2\">#faro-component.pkg</pkg-ref>\n\
             \x20   <pkg-ref id=\"{id}\"><bundle-version/></pkg-ref>\n\
             </installer-gui-script>"
        )
    }

    fn package_info(id: &str, version: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
             <pkg-info overwrite-permissions=\"true\" relocatable=\"false\" identifier=\"{id}\" \
             postinstall-action=\"none\" version=\"{version}\" format-version=\"2\" \
             install-location=\"/\" auth=\"root\">\n\
             \x20   <payload numberOfFiles=\"7\" installKBytes=\"2\"/>\n\
             \x20   <bundle-version/>\n\
             </pkg-info>"
        )
    }

    /// A file for [`Fake`]: in `dir` (or at the top), stored or zlib.
    #[derive(Clone)]
    struct FakeFile {
        dir: Option<&'static str>,
        name: String,
        data: Vec<u8>,
        encoding: &'static str,
        checksum: &'static str,
    }

    fn file(dir: Option<&'static str>, name: &str, data: impl Into<Vec<u8>>) -> FakeFile {
        FakeFile {
            dir,
            name: name.into(),
            data: data.into(),
            encoding: "application/x-gzip",
            checksum: "sha1",
        }
    }

    /// Writes a flat package in the layout productbuild uses.
    #[derive(Clone)]
    struct Fake {
        algo: Algo,
        files: Vec<FakeFile>,
    }

    const COMPONENT: Option<&str> = Some("faro-component.pkg");

    impl Fake {
        fn new(dist: &str, info: &str) -> Self {
            Fake {
                algo: Algo::Sha1,
                files: vec![
                    file(None, "Distribution", dist),
                    file(COMPONENT, "Bom", "bom"),
                    file(COMPONENT, "Payload", "payload"),
                    file(COMPONENT, "PackageInfo", info),
                ],
            }
        }

        fn good(version: &str) -> Self {
            Fake::new(
                &distribution(PKG_IDENTIFIER, version),
                &package_info(PKG_IDENTIFIER, version),
            )
        }

        fn file_mut(&mut self, name: &str) -> &mut FakeFile {
            self.files.iter_mut().find(|f| f.name == name).unwrap()
        }

        fn build(&self) -> Vec<u8> {
            let zlib = |b: &[u8]| {
                let mut z = flate2::write::ZlibEncoder::new(Vec::new(), Default::default());
                z.write_all(b).unwrap();
                z.finish().unwrap()
            };
            let mut heap = vec![0u8; self.algo.len()];
            let entry = |f: &FakeFile, heap: &mut Vec<u8>| {
                let raw = if f.encoding == "application/x-gzip" {
                    zlib(&f.data)
                } else {
                    f.data.clone()
                };
                let algo = Algo::named(f.checksum).unwrap_or(Algo::Sha1);
                let xml = format!(
                    "<data><length>{}</length><offset>{}</offset><size>{}</size>\
                     <encoding style=\"{}\"/>\
                     <extracted-checksum style=\"{}\">{}</extracted-checksum>\
                     <archived-checksum style=\"{}\">{}</archived-checksum></data>\
                     <type>file</type>",
                    raw.len(),
                    heap.len(),
                    f.data.len(),
                    f.encoding,
                    f.checksum,
                    hex::encode(algo.digest(&f.data)),
                    f.checksum,
                    hex::encode(algo.digest(&raw)),
                );
                heap.extend_from_slice(&raw);
                xml
            };
            let mut toc = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<xar><toc>\
                 <creation-time>2026-11-25T12:00:00</creation-time>\
                 <checksum style=\"{}\"><offset>0</offset><size>{}</size></checksum>",
                self.algo.name(),
                self.algo.len()
            );
            let mut dirs: Vec<&str> = Vec::new();
            for f in &self.files {
                match f.dir {
                    None => {
                        let e = entry(f, &mut heap);
                        toc += &format!("<file id=\"9\">{e}<name>{}</name></file>", f.name);
                    }
                    Some(d) if !dirs.contains(&d) => dirs.push(d),
                    Some(_) => {}
                }
            }
            for d in dirs {
                toc += &format!("<file id=\"1\"><type>directory</type><name>{d}</name>");
                for f in self.files.iter().filter(|f| f.dir == Some(d)) {
                    let e = entry(f, &mut heap);
                    toc += &format!(
                        "<file id=\"2\">{e}<name>{0}</name><name>{0}</name></file>",
                        f.name
                    );
                }
                toc += "</file>";
            }
            toc += "</toc></xar>";
            let toc_c = zlib(toc.as_bytes());
            let sum = self.algo.digest(&toc_c);
            heap[..sum.len()].copy_from_slice(&sum);
            let (size, id) = match self.algo {
                Algo::Sha1 => (HEADER_SHA1, 1u32),
                _ => (HEADER_NAMED, 3),
            };
            let mut out = Vec::new();
            out.extend_from_slice(MAGIC);
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&(toc_c.len() as u64).to_be_bytes());
            out.extend_from_slice(&(toc.len() as u64).to_be_bytes());
            out.extend_from_slice(&id.to_be_bytes());
            if size == HEADER_NAMED {
                let mut name = [0u8; 36];
                name[..self.algo.name().len()].copy_from_slice(self.algo.name().as_bytes());
                out.extend_from_slice(&name);
            }
            out.extend_from_slice(&toc_c);
            out.extend_from_slice(&heap);
            out
        }
    }

    fn read(bytes: Vec<u8>) -> Result<Version, PackageCheckError> {
        read_version_from(&mut Cursor::new(bytes))
    }

    fn unconfirmed(r: Result<Version, PackageCheckError>) -> String {
        match r {
            Err(Unconfirmed(m)) => m,
            other => panic!("expected unconfirmed, got {other:?}"),
        }
    }

    fn rejected(r: Result<Version, PackageCheckError>) -> String {
        match r {
            Err(Rejected(m)) => m,
            other => panic!("expected rejected, got {other:?}"),
        }
    }

    #[test]
    fn reads_the_full_semver_version() {
        assert_eq!(read(Fake::good(V).build()), Ok(v(V)));
        assert_eq!(read(Fake::good("1.2.3").build()), Ok(v("1.2.3")));
        let mut sha256 = Fake::good(V);
        sha256.algo = Algo::Sha256;
        for f in &mut sha256.files {
            f.checksum = "sha256";
        }
        assert_eq!(read(sha256.build()), Ok(v(V)), "a SHA-256 archive");
        let mut stored = Fake::good(V);
        stored.file_mut("PackageInfo").encoding = "application/octet-stream";
        stored.file_mut("Distribution").encoding = "application/octet-stream";
        assert_eq!(read(stored.build()), Ok(v(V)), "files stored as is");
    }

    #[test]
    fn the_version_must_be_the_target_and_above_the_installed() {
        let ok = judge_version(&v("1.2.0"), &v("1.2.0"), &v("1.1.9"));
        assert_eq!(ok, Ok(()));
        // An old package listed under a higher version.
        assert_eq!(
            judge_version(&v(V), &v("99.0.0"), &v(V)),
            Err(Rejected(format!(
                "the package is version {V}, but the update metadata says 99.0.0"
            )))
        );
        // The same version, or an older one.
        for installed in ["1.2.0", "1.2.1", "2.0.0", "1.2.0+other"] {
            let r = judge_version(&v("1.2.0"), &v("1.2.0"), &v(installed));
            assert!(matches!(r, Err(Rejected(_))), "{installed}: {r:?}");
        }
        // A pre-release sorts below its release.
        assert!(matches!(
            judge_version(&v(V), &v(V), &v("0.1.0")),
            Err(Rejected(_))
        ));
        assert_eq!(judge_version(&v("0.1.0"), &v("0.1.0"), &v(V)), Ok(()));
        assert_eq!(
            judge_version(&v("0.1.0-beta.2"), &v("0.1.0-beta.2"), &v(V)),
            Ok(())
        );
        // Equal means equal, build metadata too.
        assert!(matches!(
            judge_version(&v("1.2.0+b"), &v("1.2.0+a"), &v("1.1.0")),
            Err(Rejected(_))
        ));
        assert!(matches!(
            judge_version(&v(V), &v("0.1.0"), &v("0.0.9")),
            Err(Rejected(_))
        ));
    }

    #[test]
    fn check_version_reads_then_judges() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("p.pkg");
        std::fs::write(&pkg, Fake::good(V).build()).unwrap();
        assert_eq!(check_version(&pkg, &v(V), &v("0.0.1")), Ok(v(V)));
        assert!(matches!(
            check_version(&pkg, &v("99.0.0"), &v("0.0.1")),
            Err(Rejected(_))
        ));
        assert!(matches!(
            check_version(&dir.path().join("missing.pkg"), &v(V), &v("0.0.1")),
            Err(Unconfirmed(_))
        ));
    }

    /// The TOC of a [`Fake`] archive, decompressed.
    fn toc_of(bytes: &[u8]) -> String {
        let n = u64::from_be_bytes(bytes[8..16].try_into().unwrap()) as usize;
        let mut out = String::new();
        flate2::read::ZlibDecoder::new(&bytes[HEADER_SHA1 as usize..HEADER_SHA1 as usize + n])
            .read_to_string(&mut out)
            .unwrap();
        out
    }

    /// `bytes` (SHA-1) with its TOC replaced by `toc` and the TOC checksum
    /// redone, as if Faro had built it that way.
    fn with_toc(bytes: &[u8], toc: &str) -> Vec<u8> {
        let old = u64::from_be_bytes(bytes[8..16].try_into().unwrap()) as usize;
        let mut heap = bytes[HEADER_SHA1 as usize + old..].to_vec();
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), Default::default());
        z.write_all(toc.as_bytes()).unwrap();
        let toc_c = z.finish().unwrap();
        let mut out = bytes[..HEADER_SHA1 as usize].to_vec();
        out[8..16].copy_from_slice(&(toc_c.len() as u64).to_be_bytes());
        out[16..24].copy_from_slice(&(toc.len() as u64).to_be_bytes());
        out.extend_from_slice(&toc_c);
        heap[..20].copy_from_slice(&Algo::Sha1.digest(&toc_c));
        out.extend_from_slice(&heap);
        out
    }

    #[test]
    fn bytes_that_dont_match_their_checksums_are_rejected() {
        // PackageInfo changed in the heap, the TOC not: the TOC still
        // matches the signature, so only the file's checksum catches it.
        let mut f = Fake::good(V);
        f.file_mut("PackageInfo").encoding = "application/octet-stream";
        let mut bytes = f.build();
        let quoted = format!("\"{V}\"");
        let at = bytes
            .windows(quoted.len())
            .rposition(|w| w == quoted.as_bytes())
            .unwrap();
        bytes[at + 1] = b'9';
        assert_eq!(
            rejected(read(bytes)),
            "PackageInfo doesn't match its archived checksum"
        );

        // The TOC changed after signing.
        let mut bytes = Fake::good(V).build();
        let heap =
            HEADER_SHA1 as usize + u64::from_be_bytes(bytes[8..16].try_into().unwrap()) as usize;
        bytes[heap] ^= 1;
        assert_eq!(
            rejected(read(bytes)),
            "the package's table of contents doesn't match its checksum"
        );

        // Archived bytes that match, decoded bytes that don't.
        let mut f = Fake::good(V);
        f.file_mut("PackageInfo").encoding = "application/octet-stream";
        let bytes = f.build();
        let info = package_info(PKG_IDENTIFIER, V);
        let real = hex::encode(Algo::Sha1.digest(info.as_bytes()));
        let wrong = hex::encode(Algo::Sha1.digest(b"something else"));
        let toc = toc_of(&bytes).replacen(
            &format!("<extracted-checksum style=\"sha1\">{real}"),
            &format!("<extracted-checksum style=\"sha1\">{wrong}"),
            1,
        );
        assert_eq!(
            rejected(read(with_toc(&bytes, &toc))),
            "PackageInfo doesn't match its extracted checksum"
        );
    }

    #[test]
    fn another_component_is_rejected() {
        let other = "org.example.pkg";
        let f = Fake::new(&distribution(PKG_IDENTIFIER, V), &package_info(other, V));
        assert_eq!(
            rejected(read(f.build())),
            format!("the component is {other}, not {PKG_IDENTIFIER}")
        );
        let f = Fake::new(&distribution(other, V), &package_info(other, V));
        assert_eq!(
            rejected(read(f.build())),
            format!("the package installs {other}, not {PKG_IDENTIFIER}")
        );
    }

    #[test]
    fn versions_that_arent_strict_semver_are_unconfirmed() {
        for bad in [
            "", "1.2", "v1.2.3", " 1.2.3", "1.2.3 ", "01.2.3", "1.2.3-", "0.1.0",
        ] {
            let version = if bad == "0.1.0" { "0.1.0" } else { bad };
            let f = Fake::new(
                &distribution(PKG_IDENTIFIER, V),
                &package_info(PKG_IDENTIFIER, version),
            );
            let m = unconfirmed(read(f.build()));
            if bad == "0.1.0" {
                // Valid, but not the Distribution's version.
                assert_eq!(
                    m,
                    format!("PackageInfo says version 0.1.0, the Distribution {V}")
                );
            } else {
                assert!(m.contains("not semver"), "{bad:?}: {m}");
            }
        }
        // No version at all.
        let info = package_info(PKG_IDENTIFIER, V).replace(&format!(" version=\"{V}\""), "");
        let f = Fake::new(&distribution(PKG_IDENTIFIER, V), &info);
        assert!(unconfirmed(read(f.build())).contains("no version attribute"));
        // Two pkg-refs with different versions.
        let dist = distribution(PKG_IDENTIFIER, V).replace(
            "<bundle-version/></pkg-ref>",
            "<bundle-version/></pkg-ref><pkg-ref id=\"org.faro.pkg\" version=\"99.0.0\"/>",
        );
        let f = Fake::new(&dist, &package_info(PKG_IDENTIFIER, V));
        assert_eq!(
            unconfirmed(read(f.build())),
            "the Distribution names two versions"
        );
    }

    #[test]
    fn missing_or_repeated_entries_are_unconfirmed() {
        let good = Fake::good(V);

        let mut f = good.clone();
        f.files.retain(|f| f.name != "PackageInfo");
        assert_eq!(
            unconfirmed(read(f.build())),
            "the package has no PackageInfo"
        );

        let mut f = good.clone();
        f.files.retain(|f| f.name != "Distribution");
        assert_eq!(
            unconfirmed(read(f.build())),
            "the package has no Distribution"
        );

        let mut f = good.clone();
        let mut second = f.file_mut("PackageInfo").clone();
        second.data = package_info(PKG_IDENTIFIER, "99.0.0").into_bytes();
        f.files.push(second);
        assert_eq!(
            unconfirmed(read(f.build())),
            "the package has two entries called PackageInfo"
        );

        let mut f = good.clone();
        f.files.push(file(
            None,
            "Distribution",
            distribution(PKG_IDENTIFIER, "99.0.0"),
        ));
        assert_eq!(
            unconfirmed(read(f.build())),
            "the package has two entries called Distribution"
        );

        // The Distribution names a component that isn't there.
        let dist = distribution(PKG_IDENTIFIER, V).replace("#faro-component.pkg", "#other.pkg");
        let f = Fake::new(&dist, &package_info(PKG_IDENTIFIER, V));
        assert_eq!(unconfirmed(read(f.build())), "the package has no other.pkg");

        // Two components, or one outside the package.
        let dist = distribution(PKG_IDENTIFIER, V).replace(
            "<bundle-version/></pkg-ref>",
            "<bundle-version/></pkg-ref><pkg-ref id=\"org.example\" version=\"1.0.0\">#x.pkg</pkg-ref>",
        );
        let f = Fake::new(&dist, &package_info(PKG_IDENTIFIER, V));
        assert_eq!(
            unconfirmed(read(f.build())),
            "the Distribution must install exactly one component"
        );
        for target in [
            "faro-component.pkg",
            "#../faro-component.pkg",
            "#",
            "file:///tmp/x.pkg",
        ] {
            let dist = distribution(PKG_IDENTIFIER, V).replace("#faro-component.pkg", target);
            let f = Fake::new(&dist, &package_info(PKG_IDENTIFIER, V));
            assert_eq!(
                unconfirmed(read(f.build())),
                "the Distribution's component is not inside the package",
                "{target}"
            );
        }

        // A file whose two names differ.
        let bytes = good.build();
        let toc = toc_of(&bytes).replacen(
            "<name>PackageInfo</name><name>PackageInfo</name>",
            "<name>PackageInfo</name><name>Other</name>",
            1,
        );
        assert_eq!(
            unconfirmed(read(with_toc(&bytes, &toc))),
            "a xar file has two different names"
        );
    }

    #[test]
    fn unsupported_or_malformed_archives_are_unconfirmed() {
        let good = Fake::good(V).build();
        // Not a xar archive, or cut short.
        for bytes in [
            Vec::new(),
            b"not a xar archive at all, just some bytes".to_vec(),
            good[..20].to_vec(),
            good[..40].to_vec(),
            good[..good.len() - 10].to_vec(),
        ] {
            unconfirmed(read(bytes));
        }
        // Another xar version, or an MD5 TOC checksum.
        let mut b = good.clone();
        b[7] = 2;
        assert!(unconfirmed(read(b)).contains("xar version 2"));
        let mut b = good.clone();
        b[27] = 2;
        assert!(unconfirmed(read(b)).contains("unsupported xar header"));
        // A TOC larger than its limit.
        let mut b = good.clone();
        b[16..24].copy_from_slice(&(MAX_TOC + 1).to_be_bytes());
        assert_eq!(unconfirmed(read(b)), "the xar TOC is too large");
        // A TOC size that doesn't match.
        let mut b = good.clone();
        let n = u64::from_be_bytes(b[16..24].try_into().unwrap());
        b[16..24].copy_from_slice(&(n - 1).to_be_bytes());
        assert!(unconfirmed(read(b)).contains("decompresses to"));

        // Files stored in a way this reader doesn't know, or with MD5.
        let mut f = Fake::good(V);
        f.file_mut("PackageInfo").encoding = "application/x-bzip2";
        assert!(unconfirmed(read(f.build())).contains("unsupported encoding"));
        let mut f = Fake::good(V);
        f.file_mut("PackageInfo").checksum = "md5";
        assert!(unconfirmed(read(f.build())).contains("unsupported checksum md5"));

        // An offset past the end of the package.
        let toc = toc_of(&good);
        let at = toc.rfind("<offset>").unwrap();
        let end = toc[at..].find("</offset>").unwrap() + at;
        let toc = format!("{}<offset>99999999{}", &toc[..at], &toc[end..]);
        assert_eq!(
            unconfirmed(read(with_toc(&good, &toc))),
            "a xar entry runs past the end of the package"
        );

        // XML with a DTD, or not XML.
        let info = package_info(PKG_IDENTIFIER, V).replace(
            "<pkg-info",
            "<!DOCTYPE pkg-info [<!ENTITY v \"99.0.0\">]>\n<pkg-info",
        );
        let f = Fake::new(&distribution(PKG_IDENTIFIER, V), &info);
        assert!(unconfirmed(read(f.build())).contains("not well-formed XML"));
        let f = Fake::new(&distribution(PKG_IDENTIFIER, V), "<pkg-info version=\"1\"");
        assert!(unconfirmed(read(f.build())).contains("not well-formed XML"));
    }

    /// A real flat package, built by Apple's own tools, as build-pkg.sh
    /// builds Faro's (pkgbuild, then productbuild).
    #[cfg(target_os = "macos")]
    #[test]
    fn reads_a_package_apples_tools_built() {
        use std::process::Command;
        if !Path::new("/usr/bin/pkgbuild").exists() || !Path::new("/usr/bin/productbuild").exists()
        {
            eprintln!("no pkgbuild/productbuild; skipped");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root/Library/Faro");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("x.txt"), "x").unwrap();
        let run = |c: &mut Command| {
            let out = c.output().unwrap();
            assert!(out.status.success(), "{c:?}: {out:?}");
        };
        run(Command::new("/usr/bin/pkgbuild")
            .current_dir(dir.path())
            .args([
                "--root",
                "root",
                "--identifier",
                PKG_IDENTIFIER,
                "--version",
                V,
            ])
            .args(["--install-location", "/", "faro-component.pkg"]));
        let template = include_str!("../../../../installers/macos/Distribution.xml.in");
        let dist = template
            .replace("@VERSION@", V)
            .replace("@ARCHS@", "arm64,x86_64")
            .lines()
            .filter(|l| !l.contains("<welcome") && !l.contains("<conclusion"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(dir.path().join("Distribution.xml"), dist).unwrap();
        run(Command::new("/usr/bin/productbuild")
            .current_dir(dir.path())
            .args(["--distribution", "Distribution.xml", "--package-path", "."])
            .arg("Faro.pkg"));
        let pkg = dir.path().join("Faro.pkg");
        assert_eq!(read_version(&pkg), Ok(v(V)));
        assert_eq!(check_version(&pkg, &v(V), &v("0.0.1")), Ok(v(V)));
        assert!(matches!(
            check_version(&pkg, &v("99.0.0"), &v("0.0.1")),
            Err(Rejected(_))
        ));
        // The component on its own is no product archive.
        assert!(matches!(
            read_version(&dir.path().join("faro-component.pkg")),
            Err(Unconfirmed(_))
        ));
    }
}
