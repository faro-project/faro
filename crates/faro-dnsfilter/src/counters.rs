//! Counts of blocked lookups (IOS.md §7.5).
//!
//! Lookups are counted per category in 10-minute buckets, and per host for
//! `adult` and `gambling` only, the categories whose hosts allies see.
//! **Allowed lookups are never recorded:** the only way in is
//! [`Counters::record`], which takes a [`BlockCategory`], so there is no
//! value to pass for an allowed name.
//!
//! Memory is bounded. A bucket itemises at most [`MAX_HOSTS_PER_BUCKET`]
//! hosts, and all buckets together at most [`MAX_HOSTS_TOTAL`]. Lookups of
//! hosts past either limit still count in `by_category` and add to
//! `other_hosts`. At most [`MAX_BUCKETS`] buckets are kept, the oldest
//! dropped first, which takes a day without the tunnel handing them over.
//! At the limits that is about 1.3 MB of heap with the longest names (the
//! `dnsfilter-measure` example prints it).
//!
//! [`BlockedSummary`] is shaped to map one to one onto the `BlockedSummary`
//! event body of the protocol (issue #140). Until that type lands in
//! `faro-proto`, it is defined here.

use crate::filter::BlockCategory;
use faro_detect::Category;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Length of a bucket.
pub const BUCKET_SECS: u32 = 600;
/// Most hosts itemised in one bucket.
pub const MAX_HOSTS_PER_BUCKET: usize = 256;
/// Most hosts itemised in all buckets together.
pub const MAX_HOSTS_TOTAL: usize = 4096;
/// Most buckets kept: one day of 10-minute buckets.
pub const MAX_BUCKETS: usize = 144;

const BUCKET_MS: i64 = BUCKET_SECS as i64 * 1000;

/// Whether hosts of this category are itemised.
pub fn itemises_hosts(category: BlockCategory) -> bool {
    matches!(
        category,
        BlockCategory::Bundle(Category::Adult | Category::Gambling)
    )
}

/// One host's count in a bucket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCount {
    /// The name that was looked up, lowercased.
    pub host: String,
    /// `adult` or `gambling`.
    pub category: String,
    pub count: u32,
}

/// Blocked lookups in one bucket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedSummary {
    /// Start of the bucket, in Unix milliseconds (a multiple of
    /// `bucket_secs` × 1000).
    pub bucket_start: i64,
    pub bucket_secs: u32,
    /// Blocked lookups per category ([`BlockCategory`]'s string).
    pub by_category: BTreeMap<String, u32>,
    /// Itemised hosts, sorted by category, then host.
    pub hosts: Vec<HostCount>,
    /// Lookups of adult or gambling hosts that were not itemised because a
    /// limit was reached.
    pub other_hosts: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Bucket {
    by_category: BTreeMap<BlockCategory, u32>,
    /// Only `Adult` and `Gambling` keys.
    hosts: BTreeMap<Category, BTreeMap<String, u32>>,
    host_entries: usize,
    other_hosts: u32,
}

/// The blocked-lookup counters. Serialises as a list of
/// [`BlockedSummary`], oldest first, so the tunnel can persist them in the
/// app group and hand them over. Loading checks every bound again.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "Vec<BlockedSummary>", try_from = "Vec<BlockedSummary>")]
pub struct Counters {
    buckets: BTreeMap<i64, Bucket>,
    host_entries: usize,
}

/// The bucket `now_ms` falls in. A time before 1970 (a clock that was never
/// set) counts as 1970, which also keeps the arithmetic from overflowing.
fn bucket_start(now_ms: i64) -> i64 {
    let now = now_ms.max(0);
    now - now % BUCKET_MS
}

fn bump(n: &mut u32) {
    *n = n.saturating_add(1);
}

impl Counters {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one blocked lookup of `host` at `now_ms` (Unix milliseconds).
    pub fn record(&mut self, now_ms: i64, host: &str, category: BlockCategory) {
        let start = bucket_start(now_ms);
        if !self.buckets.contains_key(&start) && self.buckets.len() >= MAX_BUCKETS {
            match self.buckets.first_key_value() {
                // Older than everything kept: not worth evicting a newer one.
                Some((&oldest, _)) if start < oldest => return,
                Some(_) => {
                    if let Some((_, gone)) = self.buckets.pop_first() {
                        self.host_entries = self.host_entries.saturating_sub(gone.host_entries);
                    }
                }
                None => {}
            }
        }
        let bucket = self.buckets.entry(start).or_default();
        bump(bucket.by_category.entry(category).or_insert(0));
        let Some(cat) = category.bundle().filter(|_| itemises_hosts(category)) else {
            return;
        };
        let hosts = bucket.hosts.entry(cat).or_default();
        if let Some(n) = hosts.get_mut(host) {
            bump(n);
        } else if bucket.host_entries < MAX_HOSTS_PER_BUCKET && self.host_entries < MAX_HOSTS_TOTAL
        {
            hosts.insert(host.to_owned(), 1);
            bucket.host_entries += 1;
            self.host_entries += 1;
        } else {
            bump(&mut bucket.other_hosts);
        }
    }

    /// Remove and return the buckets that have ended by `now_ms`, oldest
    /// first. The current bucket stays.
    pub fn take_closed(&mut self, now_ms: i64) -> Vec<BlockedSummary> {
        let open = self.buckets.split_off(&bucket_start(now_ms));
        let closed = std::mem::replace(&mut self.buckets, open);
        for b in closed.values() {
            self.host_entries = self.host_entries.saturating_sub(b.host_entries);
        }
        closed.into_iter().map(summary).collect()
    }

    /// Every bucket, oldest first, without removing them.
    pub fn summaries(&self) -> Vec<BlockedSummary> {
        self.buckets
            .iter()
            .map(|(s, b)| summary((*s, b.clone())))
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Number of buckets held.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }
}

fn summary((start, b): (i64, Bucket)) -> BlockedSummary {
    BlockedSummary {
        bucket_start: start,
        bucket_secs: BUCKET_SECS,
        by_category: b
            .by_category
            .into_iter()
            .map(|(c, n)| (c.to_string(), n))
            .collect(),
        hosts: b
            .hosts
            .into_iter()
            .flat_map(|(c, hosts)| {
                hosts.into_iter().map(move |(host, count)| HostCount {
                    host,
                    category: c.to_string(),
                    count,
                })
            })
            .collect(),
        other_hosts: b.other_hosts,
    }
}

impl From<Counters> for Vec<BlockedSummary> {
    fn from(c: Counters) -> Self {
        c.buckets.into_iter().map(summary).collect()
    }
}

/// Why saved counters were refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CountersError {
    #[error("more than {MAX_BUCKETS} buckets")]
    TooManyBuckets,
    #[error("bucket {0} is not a {BUCKET_SECS}-second bucket")]
    BadBucket(i64),
    #[error("bucket {0} appears twice")]
    DuplicateBucket(i64),
    #[error("more hosts than a bucket or the counters may hold")]
    TooManyHosts,
    #[error("bucket {0} has a bad host or category")]
    BadEntry(i64),
}

impl TryFrom<Vec<BlockedSummary>> for Counters {
    type Error = CountersError;

    fn try_from(list: Vec<BlockedSummary>) -> Result<Self, Self::Error> {
        if list.len() > MAX_BUCKETS {
            return Err(CountersError::TooManyBuckets);
        }
        let mut counters = Counters::default();
        for s in list {
            let start = s.bucket_start;
            if s.bucket_secs != BUCKET_SECS || bucket_start(start) != start {
                return Err(CountersError::BadBucket(start));
            }
            if s.hosts.len() > MAX_HOSTS_PER_BUCKET
                || counters.host_entries + s.hosts.len() > MAX_HOSTS_TOTAL
            {
                return Err(CountersError::TooManyHosts);
            }
            let mut bucket = Bucket {
                other_hosts: s.other_hosts,
                ..Bucket::default()
            };
            for (c, n) in s.by_category {
                let c = c.parse().map_err(|_| CountersError::BadEntry(start))?;
                bucket.by_category.insert(c, n);
            }
            for h in s.hosts {
                let cat = h
                    .category
                    .parse::<BlockCategory>()
                    .ok()
                    .filter(|c| itemises_hosts(*c))
                    .and_then(BlockCategory::bundle);
                let host_ok =
                    crate::filter::normalize_entry(&h.host).as_deref() == Some(h.host.as_str());
                let (Some(cat), true) = (cat, host_ok) else {
                    return Err(CountersError::BadEntry(start));
                };
                if bucket
                    .hosts
                    .entry(cat)
                    .or_default()
                    .insert(h.host, h.count)
                    .is_some()
                {
                    return Err(CountersError::BadEntry(start));
                }
                bucket.host_entries += 1;
            }
            counters.host_entries += bucket.host_entries;
            if counters.buckets.insert(start, bucket).is_some() {
                return Err(CountersError::DuplicateBucket(start));
            }
        }
        Ok(counters)
    }
}
