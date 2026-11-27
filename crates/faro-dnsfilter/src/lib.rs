//! # faro-dnsfilter
//!
//! The on-device DNS filter engine for iOS (IOS.md §7): everything the
//! packet tunnel extension does with a DNS packet except the I/O. The
//! extension reads packets from `NEPacketTunnelFlow`, hands each to
//! [`Engine::handle_packet`] and does what the [`Action`] says:
//!
//! ```text
//! packet ─▶ parse (IP, UDP, DNS question) ─▶ Filter::decide ─┬▶ Block: NXDOMAIN packet, counted
//!                │                                          └▶ Allow: DNS payload to send upstream,
//!                └▶ anything else: drop                               then ReplyTo::wrap the answer
//! ```
//!
//! No I/O, no threads and no clock: the caller passes the time and whether
//! the screen is on. The crate has no unsafe code.
//!
//! [`Session`] puts the pieces together the way the tunnel runs them: it
//! forwards allowed queries under ids of its own, checks every answer with
//! [`Engine::check_answer`] before it goes back, and says when an answer
//! needs fetching again over TCP. The tunnel only moves bytes.
//!
//! ## What gets an answer
//!
//! Only UDP to port 53 is handled. Everything else that enters the tunnel
//! is dropped without an answer ([`Action::Drop`]):
//!
//! * **TCP**, including DNS over TCP to the tunnel's DNS address. Clients
//!   retry over UDP. Faro's own `NXDOMAIN` replies are small and never
//!   truncated, so a blocked name never needs TCP. An upstream answer that
//!   comes back truncated (`TC` set) would make the client retry over TCP,
//!   so the client never sees one: [`Session`] has the tunnel fetch the
//!   whole answer from the same resolver over TCP, checks it like any
//!   other, and sends it back over UDP, in IP fragments if it is larger
//!   than the tunnel's MTU ([`packet::build_udp_fragments`]).
//! * **Traffic to the routed resolver addresses** ([`resolvers`]) other than
//!   UDP 53: DNS over HTTPS, TLS or QUIC. Clients fall back to system DNS.
//! * **Malformed packets** of any kind ([`Reject`]), without panicking.
//!   Every read is bounds-checked and nothing is allocated before a packet
//!   has parsed.
//!
//! ## Privacy (IOS.md §4)
//!
//! * The decision is made here, from the signed bundle and the member's
//!   lists. Nothing is looked up anywhere else.
//! * **Allowed names are never recorded.** The [`Counters`] and the
//!   [`BurstDetector`] only take a [`BlockCategory`], which only a blocked
//!   verdict has. The tests check it, as `faro-detect`'s privacy tests do
//!   for frames. A forwarded query is held in memory only until its answer
//!   comes back or it times out ([`session`]).
//!
//! ## Aliases
//!
//! A name is not only what it is called: `innocent.example CNAME
//! blocked.example` would resolve a blocked name under an allowed one. So
//! every answer to an allowed name is checked before it goes back
//! ([`Engine::check_answer`]): each CNAME and DNAME target, and the target
//! of each SVCB and HTTPS record ([`dns::answer_targets`]), goes through
//! [`Filter::decide`]. If any is blocked, the client gets the same
//! `NXDOMAIN` as for a blocked name, and the lookup is counted as a block
//! of the target (never of the allowed name it was asked under). An answer
//! that can't be read that far gets `SERVFAIL`: one the filter can't check
//! never reaches the client. Answers for the instance host are not
//! checked, so the phone can always reach its instance.

#![forbid(unsafe_code)]

pub mod burst;
pub mod counters;
pub mod dns;
pub mod filter;
pub mod packet;
pub mod resolvers;
pub mod session;
pub mod tunnel;

#[cfg(test)]
mod answer_tests;
#[cfg(test)]
mod privacy_tests;
#[cfg(test)]
mod tests;

pub use burst::{BurstCandidate, BurstDetector};
pub use counters::{BlockedSummary, Counters, HostCount};
pub use dns::{DnsError, DnsName, DnsQuery};
pub use filter::{
    BlockCategory, BlockReason, ConfigError, Filter, FilterConfig, Verdict, ALWAYS_BLOCKED,
    ALWAYS_BLOCKED_VERSION,
};
pub use packet::{BuildError, PacketError};
pub use resolvers::{is_resolver_addr, RESOLVER_ADDRS, RESOLVER_LIST_VERSION};
pub use session::{Session, Skipped, Step};

use std::net::SocketAddr;

/// The DNS port.
pub const DNS_PORT: u16 = 53;

/// Why a packet was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Reject {
    #[error("packet: {0}")]
    Packet(#[from] PacketError),
    #[error("UDP to port {0}, not 53")]
    NotDnsPort(u16),
    #[error("DNS: {0}")]
    Dns(#[from] DnsError),
    #[error("reply: {0}")]
    Build(#[from] BuildError),
}

/// A DNS query read from a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Query<'a> {
    /// The app or system resolver that asked.
    pub client: SocketAddr,
    /// The address it asked (the tunnel's DNS address, or a routed resolver).
    pub server: SocketAddr,
    pub dns: DnsQuery<'a>,
}

/// Parse a raw IP packet as a DNS query.
pub fn parse_packet(packet: &[u8]) -> Result<Query<'_>, Reject> {
    let d = packet::parse_udp(packet)?;
    if d.dst.port() != DNS_PORT {
        return Err(Reject::NotDnsPort(d.dst.port()));
    }
    let dns = dns::parse_query(d.payload)?;
    Ok(Query {
        client: d.src,
        server: d.dst,
        dns,
    })
}

impl<'a> Query<'a> {
    /// The `NXDOMAIN` reply as a packet from the server back to the client.
    pub fn nxdomain_packet(&self) -> Result<Vec<u8>, BuildError> {
        packet::build_udp(self.server, self.client, &self.dns.nxdomain())
    }

    /// The DNS message to send upstream, unchanged.
    pub fn upstream_payload(&self) -> &'a [u8] {
        self.dns.message()
    }

    /// Where the upstream answer goes.
    pub fn reply_to(&self) -> ReplyTo {
        ReplyTo {
            client: self.client,
            server: self.server,
            id: self.dns.id,
        }
    }
}

/// Why an upstream answer could not be wrapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WrapError {
    #[error("not a DNS response to this query's id")]
    NotTheResponse,
    #[error(transparent)]
    Build(#[from] BuildError),
}

/// The addresses of a forwarded query, kept until its answer comes back.
/// Holds no name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReplyTo {
    client: SocketAddr,
    server: SocketAddr,
    id: u16,
}

impl ReplyTo {
    /// The query's DNS id, to match the upstream answer by.
    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn client(&self) -> SocketAddr {
        self.client
    }

    pub fn server(&self) -> SocketAddr {
        self.server
    }

    /// Wrap the upstream answer, unchanged, into a packet from the address
    /// the client asked back to the client. Refuses anything that is not a
    /// DNS response with the query's id.
    pub fn wrap(&self, response: &[u8]) -> Result<Vec<u8>, WrapError> {
        if !dns::is_response_to(response, self.id) {
            return Err(WrapError::NotTheResponse);
        }
        Ok(packet::build_udp(self.server, self.client, response)?)
    }
}

/// What to do with a packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action<'a> {
    /// Write this packet back to the tunnel: the `NXDOMAIN` for a blocked
    /// name.
    Reply(Vec<u8>),
    /// Send `payload` to the upstream resolver, and the answer back through
    /// [`ReplyTo::wrap`].
    Forward {
        payload: &'a [u8],
        reply_to: ReplyTo,
    },
    /// Write nothing back.
    Drop(Reject),
}

/// The result of [`Engine::handle_packet`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handled<'a> {
    pub action: Action<'a>,
    /// Set when this lookup completed a burst.
    pub burst: Option<BurstCandidate>,
}

/// What [`Engine::check_answer`] found in an upstream answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnswerCheck {
    /// Nothing it points to is blocked: send it back.
    Pass,
    /// It points to a blocked name: answer `NXDOMAIN` instead. Counted.
    Blocked {
        category: BlockCategory,
        /// Set when this lookup completed a burst.
        burst: Option<BurstCandidate>,
    },
    /// It can't be read far enough to check: answer `SERVFAIL` instead.
    Unreadable(DnsError),
}

/// The filter, the counters and the burst detector, for one tunnel.
#[derive(Debug, Clone)]
pub struct Engine {
    filter: Filter,
    counters: Counters,
    burst: BurstDetector,
}

impl Engine {
    pub fn new(filter: Filter) -> Self {
        Engine {
            filter,
            counters: Counters::new(),
            burst: BurstDetector::new(),
        }
    }

    /// Start from counters saved by an earlier run.
    pub fn with_counters(filter: Filter, counters: Counters) -> Self {
        Engine {
            counters,
            ..Engine::new(filter)
        }
    }

    /// Swap in a new filter (the member changed their choices, or a newer
    /// bundle arrived). The counters are kept.
    pub fn set_filter(&mut self, filter: Filter) {
        self.filter = filter;
    }

    pub fn filter(&self) -> &Filter {
        &self.filter
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    /// Remove and return the counter buckets that ended by `now_ms`.
    pub fn take_closed(&mut self, now_ms: i64) -> Vec<BlockedSummary> {
        self.counters.take_closed(now_ms)
    }

    /// Decide about one packet from the tunnel. `now_ms` is the wall clock
    /// in Unix milliseconds, `screen_on` whether the screen is on.
    pub fn handle_packet<'a>(
        &mut self,
        packet: &'a [u8],
        now_ms: i64,
        screen_on: bool,
    ) -> Handled<'a> {
        let query = match parse_packet(packet) {
            Ok(q) => q,
            Err(e) => {
                return Handled {
                    action: Action::Drop(e),
                    burst: None,
                }
            }
        };
        match self.filter.decide(query.dns.name.as_str(), query.dns.qtype) {
            Verdict::Allow => Handled {
                action: Action::Forward {
                    payload: query.upstream_payload(),
                    reply_to: query.reply_to(),
                },
                burst: None,
            },
            Verdict::Block { category, .. } => {
                let name = query.dns.name.as_str();
                self.counters.record(now_ms, name, category);
                let burst = self.burst.observe(now_ms, name, category, screen_on);
                let action = match query.nxdomain_packet() {
                    Ok(p) => Action::Reply(p),
                    Err(e) => Action::Drop(Reject::Build(e)),
                };
                Handled { action, burst }
            }
        }
    }

    /// Check an upstream answer to an allowed query for `question` (the
    /// name that was asked) before it goes back to the client: every name
    /// it points to must be allowed too (see "Aliases" in the crate
    /// documentation). The first blocked target is counted, under its own
    /// name. Answers for the instance host pass unchecked.
    pub fn check_answer(
        &mut self,
        question: &DnsName,
        answer: &[u8],
        now_ms: i64,
        screen_on: bool,
    ) -> AnswerCheck {
        if self.filter.is_instance_host(question.as_str()) {
            return AnswerCheck::Pass;
        }
        let filter = &self.filter;
        let found = dns::answer_targets(answer, |target| {
            match filter.decide(target.as_str(), dns::qtype::CNAME) {
                Verdict::Block { category, .. } => Some((*target, category)),
                Verdict::Allow => None,
            }
        });
        match found {
            Ok(None) => AnswerCheck::Pass,
            Ok(Some((target, category))) => {
                let name = target.as_str();
                self.counters.record(now_ms, name, category);
                let burst = self.burst.observe(now_ms, name, category, screen_on);
                AnswerCheck::Blocked { category, burst }
            }
            Err(e) => AnswerCheck::Unreadable(e),
        }
    }
}
