//! Domain categorisation from open blocklists (§3.5 "Context signals").
//!
//! Blocklists (StevenBlack/hosts is MIT; check every source's licence, §11)
//! are compiled offline into a compact [`fst::Map`] and shipped as a signed
//! bundle through the update channel. At runtime a URL is reduced to its
//! host and matched by **label suffix**: `a.b.example.com` matches an entry
//! for `example.com`, but `notexample.com` does not.
//!
//! Keys are the host's labels reversed (`example.com` → `com.example`), so
//! every label-suffix of a host is a byte-prefix of its key; a lookup is at
//! most one `get` per label. The value is a bitmask of [`Category`] bits;
//! entries from several lists are OR-ed together.

use crate::error::DetectError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// Number of built-in category bits; custom categories start after these.
const BUILTIN_BITS: u8 = 4;
/// Highest custom category index (bits 4..=63).
pub const MAX_CUSTOM_CATEGORY: u8 = 63 - BUILTIN_BITS;

const BUNDLE_MAGIC: &[u8; 8] = b"FARODOM\x01";
const MAX_HOST_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;
const MAX_CUSTOM_NAME_LEN: usize = 64;

/// Host names that appear in hosts files but are not real domains.
const LOCAL_NAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
];

/// A domain category. Serialised as `"adult"`, `"gambling"`, `"violence"`,
/// `"proxy_vpn"` or `"custom_N"` (N in `0..=59`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Category {
    Adult,
    Gambling,
    Violence,
    ProxyVpn,
    /// Operator- or member-defined list, index `0..=MAX_CUSTOM_CATEGORY`.
    Custom(u8),
}

impl Category {
    /// Bit index in the bundle's bitmask, or `None` for an out-of-range
    /// custom index.
    pub fn bit(self) -> Option<u8> {
        match self {
            Category::Adult => Some(0),
            Category::Gambling => Some(1),
            Category::Violence => Some(2),
            Category::ProxyVpn => Some(3),
            Category::Custom(n) if n <= MAX_CUSTOM_CATEGORY => Some(BUILTIN_BITS + n),
            Category::Custom(_) => None,
        }
    }

    fn mask(self) -> Result<u64, DetectError> {
        self.bit().map(|b| 1u64 << b).ok_or_else(|| {
            DetectError::Config(format!("custom category index out of range: {self}"))
        })
    }

    fn from_bit(bit: u8) -> Option<Category> {
        match bit {
            0 => Some(Category::Adult),
            1 => Some(Category::Gambling),
            2 => Some(Category::Violence),
            3 => Some(Category::ProxyVpn),
            b if b < 64 => Some(Category::Custom(b - BUILTIN_BITS)),
            _ => None,
        }
    }

    /// Categories present in a bitmask, in bit order.
    pub fn from_mask(mask: u64) -> Vec<Category> {
        (0..64u8)
            .filter(|b| mask & (1u64 << b) != 0)
            .filter_map(Category::from_bit)
            .collect()
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Category::Adult => f.write_str("adult"),
            Category::Gambling => f.write_str("gambling"),
            Category::Violence => f.write_str("violence"),
            Category::ProxyVpn => f.write_str("proxy_vpn"),
            Category::Custom(n) => write!(f, "custom_{n}"),
        }
    }
}

impl FromStr for Category {
    type Err = DetectError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let c = match s {
            "adult" => Category::Adult,
            "gambling" => Category::Gambling,
            "violence" => Category::Violence,
            "proxy_vpn" => Category::ProxyVpn,
            _ => {
                let n = s
                    .strip_prefix("custom_")
                    .and_then(|n| n.parse::<u8>().ok())
                    .filter(|n| *n <= MAX_CUSTOM_CATEGORY)
                    .ok_or_else(|| DetectError::Config(format!("unknown category {s:?}")))?;
                Category::Custom(n)
            }
        };
        Ok(c)
    }
}

impl TryFrom<String> for Category {
    type Error = DetectError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<Category> for String {
    fn from(c: Category) -> String {
        c.to_string()
    }
}

/// Reduce a URL (or bare host) to a normalised host: scheme, userinfo,
/// port, path, query and fragment stripped; lowercased; trailing dot and
/// one leading `www.` removed. Returns `None` for IP literals, empty or
/// syntactically invalid hosts.
pub fn normalize_host(input: &str) -> Option<String> {
    let s = input.trim();
    // Only treat "xxx://" as a scheme when xxx looks like one, so a query
    // string such as "a.com/?u=http://b.com" is not mistaken for it.
    let rest = match s.find("://") {
        Some(i)
            if i > 0
                && s[..i]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b)) =>
        {
            &s[i + 3..]
        }
        _ => s.strip_prefix("//").unwrap_or(s),
    };
    let authority = rest.split(['/', '?', '#', '\\']).next().unwrap_or_default();
    let host_port = authority.rsplit('@').next().unwrap_or_default();
    if host_port.starts_with('[') {
        return None; // IPv6 literal
    }
    let host = host_port.split(':').next().unwrap_or_default();
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > MAX_HOST_LEN * 4 {
        return None;
    }
    let mut host = host.to_lowercase();
    if host.len() > MAX_HOST_LEN {
        return None;
    }
    if let Some(stripped) = host.strip_prefix("www.") {
        if stripped.contains('.') {
            host = stripped.to_owned();
        }
    }
    let valid_labels = host.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= MAX_LABEL_LEN
            && l.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || !c.is_ascii())
    });
    if !valid_labels || host.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(host)
}

fn reversed_key(host: &str) -> String {
    let mut key = String::with_capacity(host.len());
    for (i, label) in host.rsplit('.').enumerate() {
        if i > 0 {
            key.push('.');
        }
        key.push_str(label);
    }
    key
}

/// What [`DomainCategorizerBuilder::add_source`] did with a list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompileStats {
    /// Non-empty, non-comment lines seen.
    pub lines: usize,
    /// Domains accepted (including ones already present from other lists).
    pub domains: usize,
    /// Tokens or lines that could not be used (IP literals, local names,
    /// malformed hosts, unrecognised syntax).
    pub skipped: usize,
}

/// Collects blocklist entries and compiles them into a [`DomainCategorizer`].
#[derive(Debug, Default, Clone)]
pub struct DomainCategorizerBuilder {
    entries: BTreeMap<String, u64>,
    names: BTreeMap<u8, String>,
}

impl DomainCategorizerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one domain (or URL) under `category`.
    pub fn add_domain(&mut self, domain: &str, category: Category) -> Result<(), DetectError> {
        let mask = category.mask()?;
        let host = Self::entry_host(domain)
            .ok_or_else(|| DetectError::DomainBundle(format!("not a domain: {domain:?}")))?;
        *self.entries.entry(reversed_key(&host)).or_insert(0) |= mask;
        Ok(())
    }

    /// Normalise a blocklist token: adblock-style `||host^`, a `*.` wildcard
    /// prefix, then [`normalize_host`]. Local names are rejected.
    fn entry_host(token: &str) -> Option<String> {
        let t = token.strip_prefix("||").unwrap_or(token);
        let t = t.strip_suffix('^').unwrap_or(t);
        let t = t.strip_prefix("*.").unwrap_or(t);
        normalize_host(t).filter(|h| !LOCAL_NAMES.contains(&h.as_str()))
    }

    /// Add a blocklist in hosts format (`0.0.0.0 example.com [aliases…]`)
    /// or plain domain-per-line format. `#` starts a comment anywhere on a
    /// line; lines starting with `!` (adblock comments) are ignored.
    pub fn add_source(
        &mut self,
        text: &str,
        category: Category,
    ) -> Result<CompileStats, DetectError> {
        let mask = category.mask()?;
        let mut stats = CompileStats::default();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() || line.starts_with('!') {
                continue;
            }
            stats.lines += 1;
            let mut tokens = line.split_whitespace();
            let Some(first) = tokens.next() else { continue };
            let domains: Vec<&str> = if first.parse::<IpAddr>().is_ok() {
                tokens.collect()
            } else if tokens.next().is_none() {
                vec![first]
            } else {
                stats.skipped += 1;
                continue;
            };
            if domains.is_empty() {
                stats.skipped += 1;
            }
            for d in domains {
                match Self::entry_host(d) {
                    Some(h) => {
                        *self.entries.entry(reversed_key(&h)).or_insert(0) |= mask;
                        stats.domains += 1;
                    }
                    None => stats.skipped += 1,
                }
            }
        }
        Ok(stats)
    }

    /// Give a custom category a human-readable name (used as the reason
    /// label instead of `custom_N`).
    pub fn set_custom_name(&mut self, index: u8, name: &str) -> Result<(), DetectError> {
        if index > MAX_CUSTOM_CATEGORY {
            return Err(DetectError::Config(format!(
                "custom index {index} out of range"
            )));
        }
        let name = name.trim();
        if name.is_empty()
            || name.len() > MAX_CUSTOM_NAME_LEN
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(DetectError::Config(format!(
                "invalid custom category name {name:?}"
            )));
        }
        self.names.insert(index, name.to_owned());
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn build(self) -> Result<DomainCategorizer, DetectError> {
        let mut b = fst::MapBuilder::memory();
        // BTreeMap<String, _> iterates in byte-lexicographic order, which is
        // exactly the order fst requires.
        for (k, v) in &self.entries {
            b.insert(k, *v)
                .map_err(|e| DetectError::DomainBundle(e.to_string()))?;
        }
        let bytes = b
            .into_inner()
            .map_err(|e| DetectError::DomainBundle(e.to_string()))?;
        let map = fst::Map::new(bytes).map_err(|e| DetectError::DomainBundle(e.to_string()))?;
        Ok(DomainCategorizer {
            map,
            names: self.names,
        })
    }
}

/// A compiled, immutable domain → categories index.
#[derive(Clone)]
pub struct DomainCategorizer {
    map: fst::Map<Vec<u8>>,
    names: BTreeMap<u8, String>,
}

impl fmt::Debug for DomainCategorizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomainCategorizer")
            .field("domains", &self.map.len())
            .field("custom_names", &self.names)
            .finish()
    }
}

impl DomainCategorizer {
    /// Number of distinct domains in the index.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Category bitmask for an already-normalised host.
    fn mask_for_host(&self, host: &str) -> u64 {
        let mut mask = 0u64;
        let mut key = String::with_capacity(host.len());
        for (i, label) in host.rsplit('.').enumerate() {
            if i > 0 {
                key.push('.');
            }
            key.push_str(label);
            if let Some(v) = self.map.get(&key) {
                mask |= v;
            }
        }
        mask
    }

    /// Category bitmask for a URL or host (0 if none or unparsable).
    pub fn mask_for_url(&self, url: &str) -> u64 {
        normalize_host(url).map_or(0, |h| self.mask_for_host(&h))
    }

    /// Categories of a URL or host, in bit order.
    pub fn categorize_url(&self, url: &str) -> Vec<Category> {
        Category::from_mask(self.mask_for_url(url))
    }

    /// Reason label for a category: the custom name if one was set.
    pub fn label(&self, category: Category) -> String {
        match category {
            Category::Custom(n) => self
                .names
                .get(&n)
                .cloned()
                .unwrap_or_else(|| category.to_string()),
            other => other.to_string(),
        }
    }

    /// Serialise the compiled bundle (to be signed and shipped via updates).
    ///
    /// Layout: magic `FARODOM\x01`; `u16` LE custom-name count; per name
    /// `u8` index, `u16` LE length, UTF-8 bytes; `u64` LE fst length; fst
    /// bytes (which carry their own CRC32C checksum).
    pub fn to_bytes(&self) -> Vec<u8> {
        let fst_bytes = self.map.as_fst().as_bytes();
        let mut out = Vec::with_capacity(fst_bytes.len() + 64);
        out.extend_from_slice(BUNDLE_MAGIC);
        out.extend_from_slice(&(self.names.len() as u16).to_le_bytes());
        for (idx, name) in &self.names {
            out.push(*idx);
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(name.as_bytes());
        }
        out.extend_from_slice(&(fst_bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(fst_bytes);
        out
    }

    /// Parse and fully verify a bundle produced by [`Self::to_bytes`].
    ///
    /// The bundle's signature is checked by the update channel before this
    /// runs; this still validates structure and the fst checksum so a
    /// truncated or corrupted file is rejected instead of misbehaving.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DetectError> {
        let err = |m: &str| DetectError::DomainBundle(m.to_owned());
        let mut r = Reader(bytes);
        if r.take(BUNDLE_MAGIC.len())
            .ok_or_else(|| err("truncated magic"))?
            != BUNDLE_MAGIC
        {
            return Err(err("bad magic"));
        }
        let count = r.u16().ok_or_else(|| err("truncated name count"))?;
        let mut names = BTreeMap::new();
        for _ in 0..count {
            let idx = r.u8().ok_or_else(|| err("truncated name index"))?;
            let len = usize::from(r.u16().ok_or_else(|| err("truncated name length"))?);
            let raw = r.take(len).ok_or_else(|| err("truncated name"))?;
            let name = std::str::from_utf8(raw).map_err(|_| err("name is not utf-8"))?;
            if idx > MAX_CUSTOM_CATEGORY || name.is_empty() || len > MAX_CUSTOM_NAME_LEN {
                return Err(err("invalid custom name entry"));
            }
            if names.insert(idx, name.to_owned()).is_some() {
                return Err(err("duplicate custom name index"));
            }
        }
        let fst_len = r.u64().ok_or_else(|| err("truncated fst length"))?;
        let fst_len = usize::try_from(fst_len).map_err(|_| err("fst too large"))?;
        let fst_bytes = r.take(fst_len).ok_or_else(|| err("truncated fst"))?;
        if !r.0.is_empty() {
            return Err(err("trailing bytes"));
        }
        let map = fst::Map::new(fst_bytes.to_vec())
            .map_err(|e| DetectError::DomainBundle(e.to_string()))?;
        map.as_fst()
            .verify()
            .map_err(|e| DetectError::DomainBundle(format!("checksum: {e}")))?;
        Ok(DomainCategorizer { map, names })
    }
}

/// Minimal bounds-checked little-endian reader.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2)?.try_into().ok().map(u16::from_le_bytes)
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8)?.try_into().ok().map(u64::from_le_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample() -> DomainCategorizer {
        let mut b = DomainCategorizerBuilder::new();
        let hosts = "\
# StevenBlack-style header
127.0.0.1 localhost
127.0.0.1 localhost.localdomain
0.0.0.0 0.0.0.0
::1 ip6-localhost ip6-loopback
0.0.0.0 example.com
0.0.0.0 www.adult-site.test  alias.test   # inline comment
0.0.0.0 Shouty.Example.ORG
";
        let st = b.add_source(hosts, Category::Adult).unwrap();
        assert_eq!(st.domains, 4);
        let plain = "\
! adblock comment
bet.test
||casino.test^
*.wild.test
example.com
this line has spaces
";
        let st = b.add_source(plain, Category::Gambling).unwrap();
        assert_eq!(st.domains, 4);
        assert_eq!(st.skipped, 1);
        b.add_domain("xxx", Category::Adult).unwrap(); // whole TLD
        b.add_domain("dating.test", Category::Custom(3)).unwrap();
        b.set_custom_name(3, "dating").unwrap();
        b.build().unwrap()
    }

    #[test]
    fn normalisation() {
        let n = |s| normalize_host(s);
        assert_eq!(
            n("https://user:pw@WWW.Example.COM:8443/p?q#f").as_deref(),
            Some("example.com")
        );
        assert_eq!(n("example.com.").as_deref(), Some("example.com"));
        assert_eq!(
            n("  //cdn.example.com/x ").as_deref(),
            Some("cdn.example.com")
        );
        assert_eq!(
            n("example.com/?u=http://evil.test").as_deref(),
            Some("example.com")
        );
        assert_eq!(n("www.com").as_deref(), Some("www.com"));
        assert_eq!(n("http://192.168.1.1/admin"), None);
        assert_eq!(n("http://[::1]:80/"), None);
        assert_eq!(n("http://a..b/"), None);
        assert_eq!(n(""), None);
        assert_eq!(n("http://exa mple.com"), None);
        assert_eq!(n(&"a.".repeat(200)), None);
    }

    #[test]
    fn suffix_matching_on_label_boundaries() {
        let d = sample();
        assert_eq!(
            d.categorize_url("https://example.com/"),
            vec![Category::Adult, Category::Gambling]
        );
        assert_eq!(
            d.categorize_url("http://a.b.example.com/x"),
            vec![Category::Adult, Category::Gambling]
        );
        assert!(d.categorize_url("https://notexample.com").is_empty());
        assert!(d.categorize_url("https://example.com.evil.test").is_empty());
        assert!(d.categorize_url("https://example.co").is_empty());
        assert_eq!(d.categorize_url("adult-site.test"), vec![Category::Adult]);
        assert_eq!(
            d.categorize_url("https://www.adult-site.test"),
            vec![Category::Adult]
        );
        assert_eq!(
            d.categorize_url("HTTPS://SHOUTY.example.org"),
            vec![Category::Adult]
        );
        assert_eq!(d.categorize_url("casino.test"), vec![Category::Gambling]);
        assert_eq!(d.categorize_url("a.wild.test"), vec![Category::Gambling]);
        assert_eq!(d.categorize_url("anything.xxx"), vec![Category::Adult]);
        assert_eq!(d.categorize_url("dating.test"), vec![Category::Custom(3)]);
        assert_eq!(d.label(Category::Custom(3)), "dating");
        assert_eq!(d.label(Category::Custom(4)), "custom_4");
        assert!(d.categorize_url("localhost").is_empty());
        assert!(d.categorize_url("http://0.0.0.0/").is_empty());
    }

    #[test]
    fn bundle_roundtrip_and_corruption() {
        let d = sample();
        let bytes = d.to_bytes();
        let back = DomainCategorizer::from_bytes(&bytes).unwrap();
        assert_eq!(back.len(), d.len());
        assert_eq!(
            back.categorize_url("x.example.com"),
            d.categorize_url("x.example.com")
        );
        assert_eq!(back.label(Category::Custom(3)), "dating");

        assert!(DomainCategorizer::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(DomainCategorizer::from_bytes(&extra).is_err());
        let mut bad_magic = bytes.clone();
        bad_magic[0] ^= 1;
        assert!(DomainCategorizer::from_bytes(&bad_magic).is_err());
        // Flip every byte of the fst body in turn: must never be accepted
        // silently with different content, and never panic.
        let fst_start = bytes.len() - d.map.as_fst().as_bytes().len();
        for i in fst_start..bytes.len() {
            let mut b = bytes.clone();
            b[i] ^= 0x5a;
            assert!(DomainCategorizer::from_bytes(&b).is_err(), "byte {i}");
        }
    }

    #[test]
    fn category_strings_roundtrip() {
        for c in [
            Category::Adult,
            Category::Gambling,
            Category::Violence,
            Category::ProxyVpn,
            Category::Custom(0),
            Category::Custom(MAX_CUSTOM_CATEGORY),
        ] {
            assert_eq!(c.to_string().parse::<Category>().unwrap(), c);
            let j = serde_json::to_string(&c).unwrap();
            assert_eq!(serde_json::from_str::<Category>(&j).unwrap(), c);
        }
        assert!("custom_60".parse::<Category>().is_err());
        assert!("nope".parse::<Category>().is_err());
        assert!(Category::Custom(60).bit().is_none());
        let mut b = DomainCategorizerBuilder::new();
        assert!(b.add_domain("a.test", Category::Custom(200)).is_err());
        assert!(b.set_custom_name(1, "has space").is_err());
    }

    #[test]
    fn from_mask_all_bits() {
        let all = Category::from_mask(u64::MAX);
        assert_eq!(all.len(), 64);
        assert!(all.iter().all(|c| c.bit().is_some()));
    }

    proptest! {
        #[test]
        fn arbitrary_urls_never_panic(s in ".{0,300}") {
            let d = sample();
            let _ = d.categorize_url(&s);
            let _ = normalize_host(&s);
        }

        #[test]
        fn arbitrary_sources_never_panic(s in "(.{0,40}\n){0,20}") {
            let mut b = DomainCategorizerBuilder::new();
            let _ = b.add_source(&s, Category::Violence);
            let _ = b.build().unwrap();
        }

        #[test]
        fn arbitrary_bundles_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = DomainCategorizer::from_bytes(&bytes);
            let mut framed = BUNDLE_MAGIC.to_vec();
            framed.extend_from_slice(&bytes);
            let _ = DomainCategorizer::from_bytes(&framed);
        }

        #[test]
        fn subdomains_always_match(sub in "[a-z0-9]{1,10}(\\.[a-z0-9]{1,10}){0,3}") {
            let d = sample();
            let url = format!("https://{sub}.casino.test/path");
            prop_assert_eq!(d.categorize_url(&url), vec![Category::Gambling]);
            let glued = format!("https://{sub}casino.test/");
            prop_assert!(!d.categorize_url(&glued).contains(&Category::Gambling));
        }
    }
}
