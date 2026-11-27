//! A small in-memory token-bucket rate limiter for unauthenticated endpoints
//! (setup, magic links, device enrollment).
//!
//! In-memory is deliberate: the default deployment is one process on small
//! hardware, and limits only need to blunt online guessing of enroll codes and
//! mail-bombing via magic links, not to be globally exact. A multi-process
//! Postgres deployment gets per-process limits, which is still a meaningful
//! bound (documented for stage B).
//!
//! **Keys.** Clients are keyed by IPv4 address or IPv6 **/64** (one host
//! usually holds a whole /64, so per-/128 buckets would hand an attacker
//! unlimited fresh buckets). Per-address buckets (`email:…`) live in a
//! separate table, so a flood of client addresses can never evict the one
//! bucket that protects an inbox from mail-bombing.
//!
//! **Bounded work.** Each table holds at most `HARD_CAP` buckets. Idle
//! (refilled) buckets are pruned at most once per `PRUNE_INTERVAL_MS`,
//! so no request does more than O(1) work most of the time. When a table is
//! full of buckets that are all in use, new keys are refused (fail closed)
//! rather than resetting everyone's limits.

use crate::error::AppError;
use crate::state::AppState;
use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;

/// Above this many tracked keys, idle (full) buckets are pruned.
const PRUNE_THRESHOLD: usize = 10_000;
/// At most one prune per table this often.
const PRUNE_INTERVAL_MS: i64 = 10_000;
/// Hard cap on tracked keys per table; a new key beyond it is refused.
const HARD_CAP: usize = 100_000;
/// What a refused new key is told to wait while the table is full.
const FULL_RETRY_SECS: u64 = 60;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    updated_ms: i64,
}

/// A bucket policy: `capacity` requests, refilled evenly over `period_ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    pub capacity: u32,
    pub period_ms: i64,
}

impl Limit {
    pub fn per_minute(n: u32) -> Self {
        Limit {
            capacity: n,
            period_ms: 60_000,
        }
    }

    pub fn per_hour(n: u32) -> Self {
        Limit {
            capacity: n,
            period_ms: 3_600_000,
        }
    }

    fn refill_per_ms(self) -> f64 {
        f64::from(self.capacity) / self.period_ms.max(1) as f64
    }
}

#[derive(Debug, Default)]
struct Table {
    buckets: HashMap<String, Bucket>,
    last_prune_ms: Option<i64>,
}

impl Table {
    fn check(&mut self, key: &str, limit: Limit, now_ms: i64) -> Result<(), u64> {
        self.check_cost(key, limit, 1, now_ms)
    }

    /// Take `cost` tokens at once (clamped to the bucket's capacity, so a
    /// limit smaller than one request's cost still lets a full bucket through).
    fn check_cost(&mut self, key: &str, limit: Limit, cost: u32, now_ms: i64) -> Result<(), u64> {
        let rate = limit.refill_per_ms();
        let cap = f64::from(limit.capacity);
        if !self.buckets.contains_key(key) && self.buckets.len() >= PRUNE_THRESHOLD {
            let due = self
                .last_prune_ms
                .is_none_or(|t| now_ms.saturating_sub(t) >= PRUNE_INTERVAL_MS);
            if due {
                self.last_prune_ms = Some(now_ms);
                self.buckets
                    .retain(|_, b| b.tokens + (now_ms - b.updated_ms).max(0) as f64 * rate < cap);
            }
            if self.buckets.len() >= HARD_CAP {
                return Err(FULL_RETRY_SECS);
            }
        }
        let b = self.buckets.entry(key.to_owned()).or_insert(Bucket {
            tokens: cap,
            updated_ms: now_ms,
        });
        let elapsed = (now_ms - b.updated_ms).max(0) as f64;
        b.tokens = (b.tokens + elapsed * rate).min(cap);
        b.updated_ms = now_ms.max(b.updated_ms);
        let need = f64::from(cost.max(1)).min(cap);
        if b.tokens >= need {
            b.tokens -= need;
            Ok(())
        } else {
            let wait_ms = ((need - b.tokens) / rate).ceil();
            Err(((wait_ms / 1000.0).ceil() as u64).max(1))
        }
    }
}

#[derive(Debug, Default)]
pub struct RateLimiter {
    /// Per client address (and route).
    clients: Mutex<Table>,
    /// Per account or email address: never pressured by client floods.
    accounts: Mutex<Table>,
    /// Per authenticated device or member (ingest and alert limits). Separate
    /// so a flood of unauthenticated addresses cannot evict them, and the
    /// reverse. Keys are server-issued ids, so the table is bounded by the
    /// number of devices and members.
    devices: Mutex<Table>,
}

fn with_table<T>(m: &Mutex<Table>, f: impl FnOnce(&mut Table) -> T) -> Option<T> {
    // A poisoned lock means a panic elsewhere while holding it; callers fail
    // open rather than taking the auth endpoints down with it.
    m.lock().ok().map(|mut t| f(&mut t))
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take one token from a client's bucket (key from [`client_key`]). On
    /// refusal returns the number of seconds until a token will be
    /// available.
    pub fn check_client(&self, key: &str, limit: Limit, now_ms: i64) -> Result<(), u64> {
        with_table(&self.clients, |t| t.check(key, limit, now_ms)).unwrap_or(Ok(()))
    }

    /// Take one token from a per-account / per-address bucket.
    pub fn check_account(&self, key: &str, limit: Limit, now_ms: i64) -> Result<(), u64> {
        with_table(&self.accounts, |t| t.check(key, limit, now_ms)).unwrap_or(Ok(()))
    }

    /// Take `cost` tokens from an authenticated device's or member's bucket
    /// (`cost` is clamped to the limit's capacity). On refusal returns the
    /// seconds until enough tokens will be available.
    pub fn check_device(&self, key: &str, limit: Limit, cost: u32, now_ms: i64) -> Result<(), u64> {
        with_table(&self.devices, |t| t.check_cost(key, limit, cost, now_ms)).unwrap_or(Ok(()))
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        with_table(&self.clients, |t| t.buckets.len()).unwrap_or(0)
    }
}

/// The rate-limit identity of a client address: an IPv4 address, or the /64
/// an IPv6 address is in (IPv4-mapped IPv6 counts as IPv4).
pub fn client_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let net = u128::from(v6) & !((1u128 << 64) - 1);
                format!("{}/64", std::net::Ipv6Addr::from(net))
            }
        },
    }
}

/// The client address used for rate limiting.
///
/// Behind a reverse proxy the TCP peer is the proxy, so the **rightmost**
/// `X-Forwarded-For` entry is used: it is the address the (trusted) proxy saw,
/// whereas entries further left are client-controlled. Without
/// `behind_proxy` the header is ignored entirely, since anyone could set it.
pub fn client_ip(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    behind_proxy: bool,
) -> Option<IpAddr> {
    if behind_proxy {
        // Take the rightmost *raw* entry and parse only that: skipping an
        // unparseable entry would fall back to a client-controlled one.
        let forwarded = headers
            .get_all("x-forwarded-for")
            .iter()
            .next_back()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|s| s.trim().parse::<IpAddr>().ok());
        if forwarded.is_some() {
            return forwarded;
        }
    }
    peer.map(|p| p.ip())
}

/// Middleware for unauthenticated routes: one bucket per (client IP, route).
pub async fn limit_unauthenticated(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let ip = client_ip(req.headers(), peer, state.config().behind_proxy)
        .map(client_key)
        .unwrap_or_else(|| "unknown".to_owned());
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| req.uri().path().to_owned());
    let limit = Limit::per_minute(state.config().rate_limit.unauthenticated_per_minute);
    state
        .rate_limiter()
        .check_client(&format!("ip:{ip}:{route}"), limit, state.now_ms())
        .map_err(|retry_after_secs| AppError::TooManyRequests { retry_after_secs })?;
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_burst_then_refills() {
        let rl = RateLimiter::new();
        let lim = Limit::per_minute(3);
        for _ in 0..3 {
            rl.check_client("k", lim, 0).unwrap();
        }
        let wait = rl.check_client("k", lim, 0).unwrap_err();
        assert_eq!(wait, 20);
        // Other keys are independent.
        rl.check_client("other", lim, 0).unwrap();
        // One token per 20 s.
        assert!(rl.check_client("k", lim, 19_000).is_err());
        rl.check_client("k", lim, 20_000).unwrap();
        assert!(rl.check_client("k", lim, 20_000).is_err());
        // Never more than capacity, however long the idle period.
        for _ in 0..3 {
            rl.check_client("k", lim, 10_000_000).unwrap();
        }
        assert!(rl.check_client("k", lim, 10_000_000).is_err());
    }

    #[test]
    fn a_costly_request_takes_several_tokens_and_waits_for_them() {
        let rl = RateLimiter::new();
        let lim = Limit::per_hour(100);
        rl.check_device("d", lim, 60, 0).unwrap();
        assert!(rl.check_device("d", lim, 60, 0).is_err());
        rl.check_device("d", lim, 40, 0).unwrap();
        // 60 tokens come back after 36 minutes.
        assert_eq!(rl.check_device("d", lim, 60, 0), Err(2160));
        rl.check_device("d", lim, 60, 2_160_000).unwrap();
        // A cost above capacity is clamped, so a full bucket still passes.
        rl.check_device("e", lim, 5_000, 0).unwrap();
        assert!(rl.check_device("e", lim, 1, 0).is_err());
    }

    #[test]
    fn clock_going_backwards_does_not_mint_tokens() {
        let rl = RateLimiter::new();
        let lim = Limit::per_minute(1);
        rl.check_client("k", lim, 100_000).unwrap();
        assert!(rl.check_client("k", lim, 0).is_err());
        assert!(rl.check_client("k", lim, 100_000).is_err());
    }

    #[test]
    fn prunes_idle_buckets() {
        let rl = RateLimiter::new();
        let lim = Limit::per_minute(5);
        for i in 0..PRUNE_THRESHOLD {
            rl.check_client(&format!("k{i}"), lim, 0).unwrap();
        }
        assert_eq!(rl.len(), PRUNE_THRESHOLD);
        // A minute later all buckets are full again and get pruned.
        rl.check_client("new", lim, 60_000).unwrap();
        assert_eq!(rl.len(), 1);
    }

    #[test]
    fn a_full_table_refuses_new_keys_without_resetting_anyone() {
        let rl = RateLimiter::new();
        let per_hour = Limit::per_hour(1);
        rl.check_account("email:victim", per_hour, 0).unwrap();
        assert!(rl.check_account("email:victim", per_hour, 0).is_err());
        // A flood of distinct client keys, all in use (never refilled).
        let lim = Limit::per_hour(5);
        for i in 0..HARD_CAP {
            rl.check_client(&format!("ip:{i}"), lim, 1).unwrap();
        }
        assert_eq!(rl.len(), HARD_CAP);
        // A new key is refused rather than the table being cleared ...
        assert_eq!(rl.check_client("ip:new", lim, 2), Err(FULL_RETRY_SECS));
        // ... existing clients keep their (used) buckets ...
        for _ in 0..4 {
            rl.check_client("ip:0", lim, 2).unwrap();
        }
        assert!(rl.check_client("ip:0", lim, 2).is_err());
        // ... and the per-address limit is untouched by any of it.
        assert!(rl.check_account("email:victim", per_hour, 3).is_err());
    }

    #[test]
    fn prunes_at_most_once_per_interval() {
        let rl = RateLimiter::new();
        // Five per second: a used bucket is full again after 200 ms.
        let lim = Limit {
            capacity: 5,
            period_ms: 1000,
        };
        for i in 0..PRUNE_THRESHOLD {
            rl.check_client(&format!("k{i}"), lim, 0).unwrap();
        }
        // Nothing is idle yet: the prune keeps everything ...
        rl.check_client("a", lim, 1).unwrap();
        assert_eq!(rl.len(), PRUNE_THRESHOLD + 1);
        // ... and does not run again within the interval, idle or not.
        rl.check_client("b", lim, 5_000).unwrap();
        assert_eq!(rl.len(), PRUNE_THRESHOLD + 2);
        rl.check_client("c", lim, 1 + PRUNE_INTERVAL_MS).unwrap();
        assert_eq!(rl.len(), 1);
    }

    #[test]
    fn ipv6_clients_share_a_bucket_per_64() {
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(client_key(a), client_key(b));
        assert_ne!(client_key(a), client_key(c));
        assert_eq!(client_key(a), "2001:db8:1:2::/64");
        assert_eq!(client_key("10.1.2.3".parse().unwrap()), "10.1.2.3");
        assert_eq!(client_key("::ffff:10.1.2.3".parse().unwrap()), "10.1.2.3");
    }

    #[test]
    fn forwarded_for_only_trusted_behind_proxy() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "6.6.6.6, 10.0.0.9".parse().unwrap());
        let peer = Some(SocketAddr::from(([127, 0, 0, 1], 5000)));
        assert_eq!(
            client_ip(&h, peer, false),
            Some(IpAddr::from([127, 0, 0, 1]))
        );
        assert_eq!(client_ip(&h, peer, true), Some(IpAddr::from([10, 0, 0, 9])));
        // A garbage rightmost entry never falls back to a client-chosen one.
        let mut h2 = HeaderMap::new();
        h2.insert("x-forwarded-for", "6.6.6.6, not-an-ip".parse().unwrap());
        assert_eq!(
            client_ip(&h2, peer, true),
            Some(IpAddr::from([127, 0, 0, 1]))
        );
        assert_eq!(
            client_ip(&HeaderMap::new(), peer, true),
            Some(IpAddr::from([127, 0, 0, 1]))
        );
        assert_eq!(client_ip(&HeaderMap::new(), None, false), None);
    }
}
