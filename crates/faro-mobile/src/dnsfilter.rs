//! [`DnsFilter`]: the packet tunnel's DNS filter (docs/IOS.md §7), which
//! is `faro_dnsfilter::Session` behind UniFFI.
//!
//! The tunnel hands every packet it reads to [`DnsFilter::handle_packet`]
//! and does what the [`DnsStep`] says: write packets back, or send a query
//! to the network's resolver over UDP (or TCP, for a truncated answer) and
//! hand the answer to [`DnsFilter::handle_answer`]. Everything else is
//! here: the block decision, the alias check on answers, ids, timeouts,
//! failover, fragments and the counters.
//!
//! * **The domain list** is the one packaged in the app, loaded with
//!   `faro_detect::load_domains`, until a newer verified one is installed in
//!   the app group ([`DnsFilter::refresh_domains`]). Without a usable list
//!   the filter still runs, blocking the always-blocked names and the
//!   member's list, and [`DnsFilterStatus::domains_error`] says why, as
//!   the desktop service does with its `integrity_failure`.
//! * **It never needs the app group or the keys to filter,** so it works
//!   before the first unlock: the member's choices and the saved counters
//!   are passed in when they can be read, and the defaults (adult and the
//!   always-blocked names) apply until then.
//! * **Upstreams** are the network's own resolvers, which the tunnel reads
//!   from the system ([`DnsFilter::set_upstreams`]). There is no fallback:
//!   without one, allowed names get `SERVFAIL`.

use crate::core::{lock, FaroCore};
use crate::error::FaroError;
use crate::types::{BlockedHostRecord, BlockedSummaryRecord, MAX_SUMMARY_HOSTS};
use faro_detect::{load_domains, DomainCategorizer, DomainCategorizerBuilder};
use faro_dnsfilter::dev::{self, DevBurstThresholds, DevThresholdsUse};
use faro_dnsfilter::session::Step;
use faro_dnsfilter::{tunnel, BlockedSummary, Counters, Engine, Filter, FilterConfig, Session};
use faro_update::Version;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::{Arc, Mutex};

/// What the tunnel does next.
#[derive(Clone, PartialEq, Eq, uniffi::Enum)]
pub enum DnsStep {
    /// Write these packets to the packet flow, in order.
    Reply { packets: Vec<Vec<u8>> },
    /// Send `payload` over UDP to the upstream `server` (a key from
    /// [`DnsFilter::set_upstreams`]), and the answer to
    /// [`DnsFilter::handle_answer`].
    Send { server: String, payload: Vec<u8> },
    /// Send `payload` over TCP to `server`, with its length as two bytes in
    /// front, and the answer (without its length) to
    /// [`DnsFilter::handle_answer`] with `tcp` set; if that fails, call
    /// [`DnsFilter::upstream_failed`] with `id`.
    SendTcp {
        server: String,
        id: u16,
        payload: Vec<u8>,
    },
    /// Nothing to do.
    Nothing,
}

impl std::fmt::Debug for DnsStep {
    /// Sizes only: a forwarded payload holds an allowed name.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsStep::Reply { packets } => write!(f, "Reply({} packets)", packets.len()),
            DnsStep::Send { server, payload } => {
                write!(f, "Send({server}, {} bytes)", payload.len())
            }
            DnsStep::SendTcp {
                server,
                id,
                payload,
            } => write!(f, "SendTcp({server}, {id}, {} bytes)", payload.len()),
            DnsStep::Nothing => f.write_str("Nothing"),
        }
    }
}

impl From<Step> for DnsStep {
    fn from(s: Step) -> Self {
        match s {
            Step::Reply(packets) => DnsStep::Reply { packets },
            Step::Send { server, payload } => DnsStep::Send {
                server: server.to_string(),
                payload,
            },
            Step::SendTcp {
                server,
                id,
                payload,
            } => DnsStep::SendTcp {
                server: server.to_string(),
                id,
                payload,
            },
            Step::Nothing(_) => DnsStep::Nothing,
        }
    }
}

/// An upstream resolver the filter accepted.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UpstreamServer {
    /// How [`DnsStep`] names it, and what [`DnsFilter::handle_answer`]
    /// takes back: `192.168.1.1:53`, `[fe80::1%4]:53`.
    pub key: String,
    /// The address without the scope: `192.168.1.1`, `fe80::1`.
    pub host: String,
    pub port: u16,
    /// The interface index of a link-local IPv6 address, else 0.
    pub scope_id: u32,
}

/// The tunnel's network settings (docs/IOS.md §7.1).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TunnelNetwork {
    pub ipv4_address: String,
    pub ipv4_dns: String,
    pub ipv6_address: String,
    pub ipv6_dns: String,
    pub mtu: u32,
    /// Host routes (mask 255.255.255.255): the DNS address and the
    /// resolver addresses whose encrypted DNS is dropped. Nothing else.
    pub ipv4_routes: Vec<String>,
    /// Host routes (prefix length 128), likewise.
    pub ipv6_routes: Vec<String>,
}

/// The tunnel's network settings, the same on every run.
#[uniffi::export]
pub fn tunnel_network() -> TunnelNetwork {
    TunnelNetwork {
        ipv4_address: tunnel::TUNNEL_V4.to_string(),
        ipv4_dns: tunnel::DNS_V4.to_string(),
        ipv6_address: tunnel::TUNNEL_V6.to_string(),
        ipv6_dns: tunnel::DNS_V6.to_string(),
        mtu: tunnel::MTU as u32,
        ipv4_routes: tunnel::routes_v4()
            .iter()
            .map(ToString::to_string)
            .collect(),
        ipv6_routes: tunnel::routes_v6()
            .iter()
            .map(ToString::to_string)
            .collect(),
    }
}

/// Where the filter stands, for the tunnel's log. Holds no name.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DnsFilterStatus {
    /// The domain list in use, if any.
    pub domains_version: Option<String>,
    /// `packaged`, `installed` or `none`.
    pub domains_source: String,
    /// Why there is no domain list, or why the packaged one didn't load.
    pub domains_error: Option<String>,
    /// Why the member's choices were not applied, if they weren't.
    pub config_error: Option<String>,
    pub blocked_categories: Vec<String>,
    pub upstreams: u32,
    pub pending: u32,
    pub counter_buckets: u32,
    /// What the burst thresholds are: `default`, `LOWERED FOR TESTING (...)`
    /// (a development build with a `dev_thresholds.json`) or `ignored
    /// (release build)`.
    pub thresholds: String,
}

struct Inner {
    session: Session,
    categorizer: Arc<DomainCategorizer>,
    config: FilterConfig,
    instance_host: Option<String>,
    version: Option<String>,
    source: &'static str,
    domains_error: Option<String>,
    config_error: Option<String>,
    thresholds: DevThresholdsUse,
}

impl Inner {
    /// Rebuild the filter from the categorizer, the member's config and
    /// the instance host. A config the filter refuses falls back to the
    /// defaults, which still block adult and the always-blocked names.
    fn rebuild(&mut self) {
        let mut config = self.config.clone();
        config.instance_host = self.instance_host.clone();
        let filter = match Filter::new(self.categorizer.clone(), &config) {
            Ok(f) => {
                self.config_error = None;
                f
            }
            Err(e) => {
                self.config_error = Some(e.to_string());
                let fallback = FilterConfig {
                    instance_host: self.instance_host.clone(),
                    ..FilterConfig::default()
                };
                match Filter::new(self.categorizer.clone(), &fallback) {
                    Ok(f) => f,
                    Err(_) => return,
                }
            }
        };
        self.session.engine_mut().set_filter(filter);
    }
}

/// The DNS filter for one packet tunnel. Every method is quick and takes
/// a lock briefly; call them from the tunnel's packet queue.
#[derive(uniffi::Object)]
pub struct DnsFilter {
    inner: Mutex<Inner>,
}

fn empty_categorizer() -> Result<DomainCategorizer, FaroError> {
    DomainCategorizerBuilder::new()
        .build()
        .map_err(FaroError::storage)
}

fn parse_config(json: Option<&str>) -> Result<FilterConfig, String> {
    match json {
        None => Ok(FilterConfig::default()),
        Some(j) => serde_json::from_str(j).map_err(|e| format!("filter config: {e}")),
    }
}

/// An upstream address as the system reports it: `192.168.1.1`,
/// `2001:db8::1`, `fe80::1%4` (a numeric scope), or a socket address with
/// a port. Port 53 unless one is given.
fn parse_upstream(s: &str) -> Option<SocketAddr> {
    let s = s.trim();
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Some(a);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 53));
    }
    let (ip, scope) = s.split_once('%')?;
    let ip: Ipv6Addr = ip.parse().ok()?;
    Some(SocketAddr::V6(SocketAddrV6::new(
        ip,
        53,
        0,
        scope.parse().ok()?,
    )))
}

fn server_record(a: &SocketAddr) -> UpstreamServer {
    let scope_id = match a {
        SocketAddr::V6(v6) => v6.scope_id(),
        SocketAddr::V4(_) => 0,
    };
    UpstreamServer {
        key: a.to_string(),
        host: a.ip().to_string(),
        port: a.port(),
        scope_id,
    }
}

#[uniffi::export]
impl DnsFilter {
    /// A filter over the packaged domain list (`packaged_manifest`, the
    /// `domains.manifest.json` shipped in the app), with the member's
    /// choices (`config_json`, a `FilterConfig`) and the counters saved by
    /// an earlier run (`saved_counters_json`), when they can be read. A
    /// list, config or counters that don't load are left out and reported
    /// in [`DnsFilter::status`]; the filter runs regardless.
    #[uniffi::constructor]
    pub fn new(
        packaged_manifest: Option<String>,
        config_json: Option<String>,
        saved_counters_json: Option<String>,
    ) -> Result<Arc<Self>, FaroError> {
        let (categorizer, version, source, domains_error) = match packaged_manifest {
            Some(path) => match load_domains(&path) {
                Ok(l) => (l.categorizer, Some(l.manifest.version), "packaged", None),
                Err(e) => (
                    empty_categorizer()?,
                    None,
                    "none",
                    Some(format!("the packaged domain list didn't load: {e}")),
                ),
            },
            None => (
                empty_categorizer()?,
                None,
                "none",
                Some("no packaged domain list".to_owned()),
            ),
        };
        let (config, mut config_error) = match parse_config(config_json.as_deref()) {
            Ok(c) => (c, None),
            Err(e) => (FilterConfig::default(), Some(e)),
        };
        let counters = saved_counters_json
            .and_then(|j| serde_json::from_str::<Counters>(&j).ok())
            .unwrap_or_default();
        let categorizer = Arc::new(categorizer);
        let filter = Filter::new(categorizer.clone(), &FilterConfig::default())
            .map_err(FaroError::storage)?;
        let seed = u64::from_le_bytes(faro_crypto::random_bytes::<8>());
        let session = Session::new(Engine::with_counters(filter, counters), seed);
        let mut inner = Inner {
            session,
            categorizer,
            config,
            instance_host: None,
            version,
            source,
            domains_error,
            config_error: None,
            thresholds: DevThresholdsUse::Default,
        };
        inner.rebuild();
        if inner.config_error.is_none() {
            inner.config_error = config_error.take();
        }
        Ok(Arc::new(DnsFilter {
            inner: Mutex::new(inner),
        }))
    }

    /// One packet read from the tunnel. `now_ms` is the wall clock (Unix
    /// ms), `screen_on` whether the phone is awake.
    pub fn handle_packet(&self, packet: Vec<u8>, now_ms: i64, screen_on: bool) -> DnsStep {
        lock(&self.inner)
            .session
            .packet(&packet, now_ms, screen_on)
            .into()
    }

    /// An answer from upstream `server` (a [`UpstreamServer::key`]), over
    /// UDP, or over TCP (`tcp`, without the length in front).
    pub fn handle_answer(
        &self,
        server: String,
        answer: Vec<u8>,
        tcp: bool,
        now_ms: i64,
        screen_on: bool,
    ) -> DnsStep {
        let Ok(server) = server.parse::<SocketAddr>() else {
            return DnsStep::Nothing;
        };
        lock(&self.inner)
            .session
            .answer(server, &answer, tcp, now_ms, screen_on)
            .into()
    }

    /// Sending the query `id` upstream failed: the client gets `SERVFAIL`.
    pub fn upstream_failed(&self, id: u16, now_ms: i64) -> DnsStep {
        lock(&self.inner).session.failed(id, now_ms).into()
    }

    /// Use these resolvers, the network's own, as the system reports them
    /// (see `parse_upstream`), in order of preference. Unparseable and
    /// unusable ones (the tunnel's own address among them) are left out.
    /// Returns the ones kept.
    pub fn set_upstreams(&self, servers: Vec<String>) -> Vec<UpstreamServer> {
        let parsed = servers.iter().filter_map(|s| parse_upstream(s));
        lock(&self.inner)
            .session
            .set_upstreams(parsed)
            .iter()
            .map(server_record)
            .collect()
    }

    /// The resolvers in use.
    pub fn upstreams(&self) -> Vec<UpstreamServer> {
        lock(&self.inner)
            .session
            .upstreams()
            .iter()
            .map(server_record)
            .collect()
    }

    /// Apply the member's choices (a `FilterConfig` as JSON). Refused, and
    /// the current ones kept, if it doesn't parse or the filter refuses it.
    pub fn set_config(&self, config_json: String) -> Result<(), FaroError> {
        let config = parse_config(Some(&config_json)).map_err(FaroError::invalid)?;
        let mut inner = lock(&self.inner);
        let mut check = config.clone();
        check.instance_host = inner.instance_host.clone();
        Filter::new(inner.categorizer.clone(), &check)
            .map_err(|e| FaroError::invalid(e.to_string()))?;
        inner.config = config;
        inner.rebuild();
        Ok(())
    }

    /// The instance's host name, always allowed, or `None`.
    pub fn set_instance_host(&self, host: Option<String>) {
        let mut inner = lock(&self.inner);
        if inner.instance_host != host {
            inner.instance_host = host;
            inner.rebuild();
        }
    }

    /// Switch to the domain list installed in the app group if it is newer
    /// than the one in use. Returns its version if it switched. Reads the
    /// list (and checks it again) only when its recorded version is newer,
    /// so calling this often is cheap.
    pub fn refresh_domains(&self, core: Arc<FaroCore>) -> Result<Option<String>, FaroError> {
        let current = lock(&self.inner).version.clone();
        let newer = |v: &str| match (Version::parse(v), current.as_deref().map(Version::parse)) {
            (Ok(v), Some(Ok(c))) => v > c,
            (Ok(_), None | Some(Err(_))) => true,
            (Err(_), _) => false,
        };
        let Some(recorded) = core.installed_domains_version()? else {
            return Ok(None);
        };
        if !newer(&recorded) {
            return Ok(None);
        }
        let Some((loaded, _)) = core.load_installed_domains()? else {
            return Ok(None);
        };
        let version = loaded.manifest.version.clone();
        if !newer(&version) {
            return Ok(None);
        }
        let mut inner = lock(&self.inner);
        inner.categorizer = Arc::new(loaded.categorizer);
        inner.version = Some(version.clone());
        inner.source = "installed";
        inner.domains_error = None;
        inner.rebuild();
        Ok(Some(version))
    }

    /// The counters, as JSON (a list of `faro_dnsfilter::BlockedSummary`),
    /// for the tunnel to save in the app group. Blocked lookups only.
    pub fn counters_json(&self) -> String {
        serde_json::to_string(lock(&self.inner).session.engine().counters())
            .unwrap_or_else(|_| "[]".to_owned())
    }

    /// Record the bursts seen so far as `flag` events (rated `medium`, one
    /// `dns` reason; see [`FaroCore::record_burst_flag`]). Call it about
    /// once a minute from the core's queue, so an alert is not held for the
    /// ten-minute flush. A burst is dropped from the filter only after its
    /// event is in the chain, so a locked key store (`KeysLocked`) loses
    /// nothing. Returns how many were recorded.
    pub fn flush_bursts(&self, core: Arc<FaroCore>) -> Result<u32, FaroError> {
        let mut recorded = 0;
        loop {
            // The filter's lock is not held across the database.
            let next = lock(&self.inner).session.bursts().first().cloned();
            let Some(burst) = next else {
                return Ok(recorded);
            };
            core.record_burst_flag(&burst)?;
            lock(&self.inner).session.discard_bursts(1);
            recorded += 1;
        }
    }

    /// Record the counter buckets that have ended as `blocked_summary`
    /// events, each once (see [`FaroCore::record_blocked_summary_once`]),
    /// and drop them from the counters. The tunnel saves the counters again
    /// afterwards; if it dies before, the next run offers the same buckets
    /// and the core skips them. A bucket the event can't carry is dropped
    /// rather than retried for ever. Returns how many were recorded.
    pub fn flush_summaries(&self, core: Arc<FaroCore>, now_ms: i64) -> Result<u32, FaroError> {
        let closed = lock(&self.inner).session.engine().closed(now_ms);
        let mut recorded = 0;
        for bucket in closed {
            let start = bucket.bucket_start;
            match core.record_blocked_summary_once(BlockedSummaryRecord::from(bucket)) {
                Ok(Some(_)) => recorded += 1,
                Ok(None) | Err(FaroError::InvalidArgument { .. }) => {}
                Err(e) => return Err(e),
            }
            lock(&self.inner).session.engine_mut().forget_through(start);
        }
        Ok(recorded)
    }

    /// Apply a `dev_thresholds.json` (docs/DEVELOPMENT.md, "lower only"),
    /// or none (`None`). Only a build with the `dev` feature lowers the
    /// burst thresholds; a release build ignores the file. A file that
    /// doesn't parse or would raise a threshold is refused and the
    /// defaults stay. Returns what the filter does now, as
    /// [`DnsFilterStatus::thresholds`] says it.
    pub fn set_dev_thresholds(&self, json: Option<String>) -> Result<String, FaroError> {
        let section = match json.as_deref() {
            None => None,
            Some(j) => {
                let t: DevBurstThresholds = serde_json::from_str(j)
                    .map_err(|e| FaroError::invalid(format!("dev_thresholds.json: {e}")))?;
                t.validate().map_err(FaroError::invalid)?;
                Some(t)
            }
        };
        let using = dev::build_use(section.as_ref());
        let mut inner = lock(&self.inner);
        inner
            .session
            .engine_mut()
            .set_burst_thresholds(dev::burst_thresholds(&using));
        inner.thresholds = using;
        Ok(using.to_string())
    }

    pub fn status(&self) -> DnsFilterStatus {
        let inner = lock(&self.inner);
        let engine = inner.session.engine();
        DnsFilterStatus {
            domains_version: inner.version.clone(),
            domains_source: inner.source.to_owned(),
            domains_error: inner.domains_error.clone(),
            config_error: inner.config_error.clone(),
            blocked_categories: engine
                .filter()
                .blocked_categories()
                .iter()
                .map(ToString::to_string)
                .collect(),
            upstreams: inner.session.upstreams().len() as u32,
            pending: inner.session.pending() as u32,
            counter_buckets: engine.counters().len() as u32,
            thresholds: inner.thresholds.to_string(),
        }
    }
}

/// Rust-only API.
impl DnsFilter {
    /// Remove and return the counter buckets that ended by `now_ms`, as
    /// records for [`FaroCore::record_blocked_summary`].
    pub fn take_closed_summaries(&self, now_ms: i64) -> Vec<BlockedSummaryRecord> {
        lock(&self.inner)
            .session
            .engine_mut()
            .take_closed(now_ms)
            .into_iter()
            .map(BlockedSummaryRecord::from)
            .collect()
    }
}

impl From<BlockedSummary> for BlockedSummaryRecord {
    /// The counters' bucket as the event body takes it. Both use Unix ms
    /// for the bucket's start. Hosts the event can't carry (more than
    /// [`MAX_SUMMARY_HOSTS`], or names with `_`, which a DNS name may have
    /// but the event's host field refuses) are counted in `other_hosts`.
    fn from(s: BlockedSummary) -> Self {
        let mut other = s.other_hosts;
        let mut hosts = Vec::new();
        for h in s.hosts {
            let fits = hosts.len() < MAX_SUMMARY_HOSTS && !h.host.contains('_');
            if fits {
                hosts.push(BlockedHostRecord {
                    host: h.host,
                    category: h.category,
                    count: h.count,
                });
            } else {
                other = other.saturating_add(h.count);
            }
        }
        BlockedSummaryRecord {
            bucket_start_ms: s.bucket_start,
            bucket_secs: u64::from(s.bucket_secs),
            by_category: s.by_category.into_iter().collect(),
            hosts,
            other_hosts: other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_detect::Category;
    use faro_dnsfilter::BlockCategory;
    use faro_proto::body::EventBody;

    #[test]
    fn closed_buckets_become_event_bodies_with_the_same_start() {
        let f = DnsFilter::new(None, None, None).unwrap();
        let t0: i64 = 1_800_000_000_000; // a bucket boundary
        {
            let mut inner = lock(&f.inner);
            let adult = BlockCategory::Bundle(Category::Adult);
            let mut c = Counters::new();
            for i in 0..(MAX_SUMMARY_HOSTS + 5) {
                c.record(t0 + 1, &format!("h{i}.porn.test"), adult);
            }
            c.record(t0 + 2, "_svc.porn.test", adult);
            c.record(t0 + 3, "dns.google", BlockCategory::EncryptedDns);
            let filter = inner.session.engine().filter().clone();
            *inner.session.engine_mut() = Engine::with_counters(filter, c);
        }
        assert!(f.take_closed_summaries(t0 + 1).is_empty(), "still open");
        let closed = f.take_closed_summaries(t0 + 600_000);
        assert_eq!(closed.len(), 1);
        let r = &closed[0];
        assert_eq!(r.bucket_start_ms, t0);
        assert_eq!(r.bucket_secs, 600);
        assert_eq!(r.hosts.len(), MAX_SUMMARY_HOSTS);
        assert_eq!(r.other_hosts, 6, "5 over the cap and the one with '_'");
        assert_eq!(r.by_category["adult"], MAX_SUMMARY_HOSTS as u32 + 6);
        assert_eq!(r.by_category["encrypted_dns"], 1);
        let EventBody::BlockedSummary { bucket_start, .. } = r.clone().into_body().unwrap() else {
            panic!("not a blocked summary");
        };
        assert_eq!(bucket_start, t0);
    }
}
