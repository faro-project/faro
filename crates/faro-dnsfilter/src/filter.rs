//! The block decision (IOS.md §7.2 and §7.3).
//!
//! [`Filter::decide`] looks at the name only. A name matches a list entry
//! if it is the entry or ends with `.` and the entry (parent-domain
//! matching on label boundaries: `a.example.com` matches `example.com`,
//! `notexample.com` does not). The rules, first match wins:
//!
//! 1. **Always blocked** ([`ALWAYS_BLOCKED`]): encrypted-DNS bootstrap names
//!    and iCloud Private Relay, whatever the member picks.
//! 2. **The instance host** is always allowed (exact name only), so the
//!    phone can always reach its instance.
//! 3. **The member's block list.**
//! 4. **The member's allow list.** It can lift a category block for a name
//!    the bundle lists wrongly, never an always-blocked one. The block list
//!    comes first, so when the two lists overlap the stricter one wins.
//! 5. **The bundle:** blocked if the name or a parent is in a category the
//!    member blocks. `adult` is always one of them.
//!
//! The filter keeps no state about queries. It never records a name, so
//! deciding about an allowed name leaves nothing behind.

use faro_detect::{Category, DomainCategorizer};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::sync::Arc;

/// Version of [`ALWAYS_BLOCKED`]. Bump it whenever the list changes.
pub const ALWAYS_BLOCKED_VERSION: u32 = 1;

/// What an always-blocked name is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlwaysBlockedKind {
    /// The bootstrap name of a DNS-over-HTTPS or DNS-over-TLS resolver.
    /// Blocking it pushes apps and browsers with their own encrypted DNS
    /// back to system DNS.
    EncryptedDns,
    /// iCloud Private Relay. `NXDOMAIN` for these is Apple's documented way
    /// for a network to turn Private Relay off.
    PrivateRelay,
}

/// Names blocked whatever the member picks (IOS.md §7.3), matched with
/// their subdomains.
pub const ALWAYS_BLOCKED: &[(&str, AlwaysBlockedKind)] = {
    use AlwaysBlockedKind::{EncryptedDns as Doh, PrivateRelay as Relay};
    &[
        // Google Public DNS.
        ("dns.google", Doh),
        ("dns.google.com", Doh),
        // Cloudflare 1.1.1.1, its family filters and the Firefox endpoint
        // (all under cloudflare-dns.com).
        ("cloudflare-dns.com", Doh),
        ("mozilla.cloudflare-dns.com", Doh),
        ("one.one.one.one", Doh),
        // Quad9.
        ("dns.quad9.net", Doh),
        ("dns9.quad9.net", Doh),
        ("dns10.quad9.net", Doh),
        ("dns11.quad9.net", Doh),
        // OpenDNS.
        ("doh.opendns.com", Doh),
        ("doh.familyshield.opendns.com", Doh),
        // AdGuard DNS.
        ("dns.adguard-dns.com", Doh),
        ("family.adguard-dns.com", Doh),
        ("unfiltered.adguard-dns.com", Doh),
        ("dns.adguard.com", Doh),
        // NextDNS (configurations are subdomains of dns.nextdns.io).
        ("dns.nextdns.io", Doh),
        // Mullvad.
        ("dns.mullvad.net", Doh),
        ("doh.mullvad.net", Doh),
        // Control D.
        ("freedns.controld.com", Doh),
        ("dns.controld.com", Doh),
        // Firefox's canary domain: NXDOMAIN tells Firefox to leave its own
        // DNS-over-HTTPS off on this network.
        ("use-application-dns.net", Doh),
        // Discovery of Designated Resolvers (RFC 9462): `_dns.resolver.arpa`
        // asks the network's resolver for an encrypted one to upgrade to.
        // The special-use domain has no other purpose.
        ("resolver.arpa", Doh),
        // iCloud Private Relay.
        ("mask.icloud.com", Relay),
        ("mask-h2.icloud.com", Relay),
    ]
};

/// What a blocked lookup is counted under. The counters use its
/// [`Display`](fmt::Display) string: a bundle category (`adult`,
/// `gambling`, `custom_3`…), `encrypted_dns`, `private_relay` or
/// `member_list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BlockCategory {
    /// A category of the domain bundle.
    Bundle(Category),
    EncryptedDns,
    PrivateRelay,
    /// The member's block list, for a name the bundle doesn't list.
    MemberList,
}

impl BlockCategory {
    /// The bundle category, if this is one.
    pub fn bundle(self) -> Option<Category> {
        match self {
            BlockCategory::Bundle(c) => Some(c),
            _ => None,
        }
    }
}

impl fmt::Display for BlockCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockCategory::Bundle(c) => fmt::Display::fmt(c, f),
            BlockCategory::EncryptedDns => f.write_str("encrypted_dns"),
            BlockCategory::PrivateRelay => f.write_str("private_relay"),
            BlockCategory::MemberList => f.write_str("member_list"),
        }
    }
}

impl std::str::FromStr for BlockCategory {
    type Err = faro_detect::DetectError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "encrypted_dns" => BlockCategory::EncryptedDns,
            "private_relay" => BlockCategory::PrivateRelay,
            "member_list" => BlockCategory::MemberList,
            other => BlockCategory::Bundle(other.parse()?),
        })
    }
}

/// Which rule blocked a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockReason {
    /// [`ALWAYS_BLOCKED`], at [`ALWAYS_BLOCKED_VERSION`].
    AlwaysBlocked,
    /// The member's block list.
    MemberBlockList,
    /// The name or a parent is in a category the member blocks.
    Category,
}

impl fmt::Display for BlockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockReason::AlwaysBlocked => {
                write!(f, "always blocked (list v{ALWAYS_BLOCKED_VERSION})")
            }
            BlockReason::MemberBlockList => f.write_str("member block list"),
            BlockReason::Category => f.write_str("blocked category"),
        }
    }
}

/// The decision about one name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block {
        category: BlockCategory,
        reason: BlockReason,
    },
}

impl Verdict {
    pub fn is_blocked(&self) -> bool {
        matches!(self, Verdict::Block { .. })
    }
}

/// Most entries a member list may have.
pub const MAX_LIST_ENTRIES: usize = 10_000;

/// What the member picked (IOS.md §9). Serialisable so the app can hand it
/// to the tunnel.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterConfig {
    /// Categories to block on top of `adult`, which is always blocked.
    #[serde(default)]
    pub categories: BTreeSet<Category>,
    /// Names to block, with their subdomains.
    #[serde(default)]
    pub block: Vec<String>,
    /// Names to allow, with their subdomains, unless always blocked or on
    /// the block list.
    #[serde(default)]
    pub allow: Vec<String>,
    /// The instance's host name, always allowed.
    #[serde(default)]
    pub instance_host: Option<String>,
}

/// Why a [`FilterConfig`] was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("not a host name: {0:?}")]
    BadName(String),
    #[error("a list has more than {MAX_LIST_ENTRIES} entries")]
    TooManyEntries,
    #[error("category {0} has no bit in the bundle")]
    BadCategory(Category),
}

/// Lowercase and check a name given in a list or in the config: ASCII
/// letters, digits, `-` and `_`, labels of 1 to 63 bytes, at most 253
/// bytes, one trailing dot and a leading `*.` allowed and removed. A
/// leading `www.` is kept (unlike the bundle compiler), so an entry never
/// covers more than its author wrote.
pub fn normalize_entry(entry: &str) -> Option<String> {
    let e = entry.trim();
    let e = e.strip_prefix("*.").unwrap_or(e);
    let e = e.strip_suffix('.').unwrap_or(e);
    if e.is_empty() || e.len() > crate::dns::MAX_NAME {
        return None;
    }
    let ok = e.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= crate::dns::MAX_LABEL
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    ok.then(|| e.to_ascii_lowercase())
}

/// The name and each of its parents, longest first:
/// `a.b.c` gives `a.b.c`, `b.c`, `c`.
fn suffixes(name: &str) -> impl Iterator<Item = &str> {
    let mut rest = Some(name);
    std::iter::from_fn(move || {
        let current = rest?;
        rest = current.split_once('.').map(|(_, tail)| tail);
        Some(current)
    })
    .filter(|s| !s.is_empty())
}

/// A set of names matched with their subdomains.
#[derive(Debug, Clone, Default)]
struct SuffixSet(HashSet<String>);

impl SuffixSet {
    fn from_entries(entries: &[String]) -> Result<Self, ConfigError> {
        if entries.len() > MAX_LIST_ENTRIES {
            return Err(ConfigError::TooManyEntries);
        }
        entries
            .iter()
            .map(|e| normalize_entry(e).ok_or_else(|| ConfigError::BadName(e.clone())))
            .collect::<Result<_, _>>()
            .map(SuffixSet)
    }

    fn matches(&self, name: &str) -> bool {
        !self.0.is_empty() && suffixes(name).any(|s| self.0.contains(s))
    }
}

/// Whether `name` (lowercased) is always blocked, and why.
pub fn always_blocked(name: &str) -> Option<AlwaysBlockedKind> {
    suffixes(name).find_map(|s| {
        ALWAYS_BLOCKED
            .iter()
            .find(|(entry, _)| *entry == s)
            .map(|(_, kind)| *kind)
    })
}

/// The block decision for one member's choices and one bundle.
#[derive(Clone)]
pub struct Filter {
    categorizer: Arc<DomainCategorizer>,
    /// Bundle bits of the blocked categories.
    blocked_mask: u64,
    block: SuffixSet,
    allow: SuffixSet,
    instance_host: Option<String>,
}

impl fmt::Debug for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Filter")
            .field("categorizer", &self.categorizer)
            .field(
                "blocked_categories",
                &Category::from_mask(self.blocked_mask),
            )
            .field("block_entries", &self.block.0.len())
            .field("allow_entries", &self.allow.0.len())
            .field("instance_host", &self.instance_host)
            .finish()
    }
}

impl Filter {
    /// A filter over `categorizer` with the member's `config`.
    pub fn new(
        categorizer: impl Into<Arc<DomainCategorizer>>,
        config: &FilterConfig,
    ) -> Result<Self, ConfigError> {
        let mut blocked_mask = 1u64 << Category::Adult.bit().unwrap_or(0);
        for &c in &config.categories {
            let bit = c.bit().ok_or(ConfigError::BadCategory(c))?;
            blocked_mask |= 1u64 << bit;
        }
        let instance_host = match &config.instance_host {
            Some(h) => Some(normalize_entry(h).ok_or_else(|| ConfigError::BadName(h.clone()))?),
            None => None,
        };
        Ok(Filter {
            categorizer: categorizer.into(),
            blocked_mask,
            block: SuffixSet::from_entries(&config.block)?,
            allow: SuffixSet::from_entries(&config.allow)?,
            instance_host,
        })
    }

    /// The categorizer this filter uses, to build another filter over the
    /// same bundle without copying it.
    pub fn categorizer(&self) -> &Arc<DomainCategorizer> {
        &self.categorizer
    }

    /// Whether `name` (lowercased, without the trailing dot) is the
    /// instance host, which is always allowed.
    pub fn is_instance_host(&self, name: &str) -> bool {
        self.instance_host.as_deref() == Some(name)
    }

    /// Categories this filter blocks, `adult` among them.
    pub fn blocked_categories(&self) -> Vec<Category> {
        Category::from_mask(self.blocked_mask)
    }

    /// Decide about `name`. `qtype` is not used today: every type of record
    /// for a blocked name is blocked. Uppercase letters and one trailing dot
    /// are accepted; [`crate::DnsName`] gives names in the usual form.
    pub fn decide(&self, name: &str, qtype: u16) -> Verdict {
        let _ = qtype;
        let name = name.strip_suffix('.').unwrap_or(name);
        if name.bytes().any(|b| b.is_ascii_uppercase()) {
            return self.decide_lower(&name.to_ascii_lowercase());
        }
        self.decide_lower(name)
    }

    fn decide_lower(&self, name: &str) -> Verdict {
        if let Some(kind) = always_blocked(name) {
            return Verdict::Block {
                category: match kind {
                    AlwaysBlockedKind::EncryptedDns => BlockCategory::EncryptedDns,
                    AlwaysBlockedKind::PrivateRelay => BlockCategory::PrivateRelay,
                },
                reason: BlockReason::AlwaysBlocked,
            };
        }
        if self.instance_host.as_deref() == Some(name) {
            return Verdict::Allow;
        }
        if self.block.matches(name) {
            // Counted under the bundle's category when it lists the name,
            // so an adult site the member also listed is still counted
            // (and itemised) as adult.
            let mask = self.categorizer.mask_for_url(name);
            let category = Category::from_mask(mask)
                .first()
                .map_or(BlockCategory::MemberList, |c| BlockCategory::Bundle(*c));
            return Verdict::Block {
                category,
                reason: BlockReason::MemberBlockList,
            };
        }
        if self.allow.matches(name) {
            return Verdict::Allow;
        }
        let mask = self.categorizer.mask_for_url(name) & self.blocked_mask;
        match Category::from_mask(mask).first() {
            Some(c) => Verdict::Block {
                category: BlockCategory::Bundle(*c),
                reason: BlockReason::Category,
            },
            None => Verdict::Allow,
        }
    }
}
