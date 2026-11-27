//! Bursts of blocked lookups (IOS.md §11).
//!
//! One blocked lookup isn't intent: link previews, ads and prefetching make
//! lookups the member never saw. A burst is, so it becomes a
//! `blocked_burst` candidate, which the tunnel turns into a `flag` event.
//! The thresholds start conservative and are all here, as constants. Beta
//! data will set them (IOS.md §19).
//!
//! A candidate needs at least [`BURST_MIN_LOOKUPS`] blocked lookups of
//! [`BURST_CATEGORY`], across at least [`BURST_MIN_DOMAINS`] registrable
//! domains, within [`BURST_WINDOW_SECS`], all while the screen was on. After
//! one, the detector starts over and stays quiet for [`BURST_COOLDOWN_SECS`],
//! so one long session gives one flag per cooldown rather than one per
//! lookup.

use crate::filter::BlockCategory;
use faro_detect::Category;
use std::collections::{BTreeSet, VecDeque};
use std::fmt;

/// The category whose lookups make a burst.
pub const BURST_CATEGORY: Category = Category::Adult;
/// Fewest blocked lookups in the window.
pub const BURST_MIN_LOOKUPS: usize = 6;
/// Fewest distinct registrable domains among them.
pub const BURST_MIN_DOMAINS: usize = 3;
/// The window, in seconds.
pub const BURST_WINDOW_SECS: i64 = 180;
/// Quiet time after a candidate, in seconds.
pub const BURST_COOLDOWN_SECS: i64 = 600;
/// Most lookups held in the window. When more arrive, the oldest go first,
/// which can only make a burst less likely.
pub const MAX_BURST_EVENTS: usize = 64;

const WINDOW_MS: i64 = BURST_WINDOW_SECS * 1000;

/// The thresholds a detector uses. [`Default`] is the constants above.
/// Only a development build ever makes anything else, and only lower
/// (more sensitive) values: see [`crate::dev`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BurstThresholds {
    pub min_lookups: usize,
    pub min_domains: usize,
    pub cooldown_secs: i64,
}

impl Default for BurstThresholds {
    fn default() -> Self {
        BurstThresholds {
            min_lookups: BURST_MIN_LOOKUPS,
            min_domains: BURST_MIN_DOMAINS,
            cooldown_secs: BURST_COOLDOWN_SECS,
        }
    }
}

/// Second-level labels under which a country-code TLD sells names
/// (`example.co.uk`). Without the Public Suffix List the registrable domain
/// is a guess: the last two labels, or three under one of these. Getting it
/// wrong merges sites, which only makes a burst less likely.
const SECOND_LEVELS: &[&str] = &[
    "ac", "co", "com", "edu", "go", "gob", "gov", "gv", "ltd", "mil", "ne", "net", "nic", "or",
    "org", "plc", "sch",
];

/// The registrable domain of a name, as far as can be told without the
/// Public Suffix List: `cdn.example.com` gives `example.com`,
/// `a.example.co.uk` gives `example.co.uk`.
pub fn registrable_domain(name: &str) -> &str {
    // The last three dots, from the right.
    let mut dots = name.rmatch_indices('.').map(|(i, _)| i);
    let (Some(last), Some(second)) = (dots.next(), dots.next()) else {
        return name;
    };
    let from = |dot: usize| name.get(dot + 1..).unwrap_or(name);
    let tld = from(last);
    let second_label = name.get(second + 1..last).unwrap_or_default();
    if tld.len() == 2 && SECOND_LEVELS.contains(&second_label) {
        dots.next().map_or(name, from)
    } else {
        from(second)
    }
}

/// A burst, ready to become a `flag` event with a `dns` reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurstCandidate {
    pub category: Category,
    /// Blocked lookups in the window.
    pub lookups: usize,
    /// Distinct names among them.
    pub hosts: usize,
    /// Distinct registrable domains among them.
    pub domains: usize,
    /// From the first lookup in the window to the last, in seconds.
    pub span_secs: i64,
    /// Always true today: only lookups made with the screen on count.
    pub screen_on: bool,
    /// When the last lookup happened, in Unix milliseconds.
    pub at_ms: i64,
}

impl BurstCandidate {
    /// Minutes for the reason, rounded up, at least 1.
    fn minutes(&self) -> i64 {
        ((self.span_secs + 59) / 60).max(1)
    }

    /// The reason's label, to go with the `dns` source:
    /// `adult ×6, 4 hosts, 3 min, screen on`.
    pub fn label(&self) -> String {
        let screen = if self.screen_on {
            "screen on"
        } else {
            "screen off"
        };
        format!(
            "{} ×{}, {} hosts, {} min, {screen}",
            self.category,
            self.lookups,
            self.hosts,
            self.minutes()
        )
    }
}

impl fmt::Display for BurstCandidate {
    /// The whole reason: `dns:adult ×6, 4 hosts, 3 min, screen on`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dns:{}", self.label())
    }
}

#[derive(Debug, Clone)]
struct Lookup {
    at_ms: i64,
    host: String,
    /// Where the registrable domain starts in `host`.
    domain_at: usize,
}

impl Lookup {
    fn domain(&self) -> &str {
        self.host.get(self.domain_at..).unwrap_or_default()
    }
}

/// Watches blocked lookups for bursts. It only ever sees blocked lookups
/// of [`BURST_CATEGORY`], and holds at most [`MAX_BURST_EVENTS`] of them for
/// at most [`BURST_WINDOW_SECS`].
#[derive(Debug, Clone, Default)]
pub struct BurstDetector {
    window: VecDeque<Lookup>,
    quiet_until_ms: Option<i64>,
    thresholds: BurstThresholds,
}

impl BurstDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// A detector with other thresholds (development builds only; see
    /// [`crate::dev`]).
    pub fn with_thresholds(thresholds: BurstThresholds) -> Self {
        BurstDetector {
            thresholds,
            ..Self::default()
        }
    }

    pub fn thresholds(&self) -> BurstThresholds {
        self.thresholds
    }

    /// Note a blocked lookup of `host` at `now_ms` (Unix milliseconds).
    /// Returns a candidate when this lookup completes a burst.
    pub fn observe(
        &mut self,
        now_ms: i64,
        host: &str,
        category: BlockCategory,
        screen_on: bool,
    ) -> Option<BurstCandidate> {
        if category != BlockCategory::Bundle(BURST_CATEGORY) || !screen_on {
            return None;
        }
        let cooldown_ms = self.thresholds.cooldown_secs.saturating_mul(1000);
        if let Some(until) = self.quiet_until_ms {
            // A clock set back by more than the cooldown ends it too.
            if now_ms < until && until.saturating_sub(now_ms) <= cooldown_ms {
                return None;
            }
            self.quiet_until_ms = None;
        }
        // A clock that went backwards: what is held can't be compared.
        if self.window.back().is_some_and(|l| l.at_ms > now_ms) {
            self.window.clear();
        }
        let oldest = now_ms.saturating_sub(WINDOW_MS);
        while self.window.front().is_some_and(|l| l.at_ms < oldest) {
            self.window.pop_front();
        }
        let domain = registrable_domain(host);
        self.window.push_back(Lookup {
            at_ms: now_ms,
            host: host.to_owned(),
            domain_at: host.len() - domain.len(),
        });
        while self.window.len() > MAX_BURST_EVENTS {
            self.window.pop_front();
        }

        let lookups = self.window.len();
        if lookups < self.thresholds.min_lookups {
            return None;
        }
        let domains = self
            .window
            .iter()
            .map(Lookup::domain)
            .collect::<BTreeSet<_>>()
            .len();
        if domains < self.thresholds.min_domains {
            return None;
        }
        let hosts = self
            .window
            .iter()
            .map(|l| l.host.as_str())
            .collect::<BTreeSet<_>>()
            .len();
        let first = self.window.front().map_or(now_ms, |l| l.at_ms);
        let candidate = BurstCandidate {
            category: BURST_CATEGORY,
            lookups,
            hosts,
            domains,
            span_secs: now_ms.saturating_sub(first) / 1000,
            screen_on,
            at_ms: now_ms,
        };
        self.window.clear();
        self.quiet_until_ms = Some(now_ms.saturating_add(cooldown_ms));
        Some(candidate)
    }

    /// Lookups held in the window.
    pub fn held(&self) -> usize {
        self.window.len()
    }
}
