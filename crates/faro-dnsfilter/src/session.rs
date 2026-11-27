//! Forwarding, as the tunnel runs it: [`Session`] wraps the [`Engine`]
//! with the queries in flight, so the tunnel only moves bytes between the
//! packet flow and its sockets.
//!
//! ```text
//! packet ─▶ Session::packet ─┬▶ Reply: write the packets back (NXDOMAIN, or SERVFAIL without an upstream)
//!                            └▶ Send: UDP to the upstream resolver ─▶ Session::answer ─┬▶ Reply: the checked answer
//!                                                                                      ├▶ SendTcp: fetch it again over TCP
//!                                                                                      └▶ Nothing
//! ```
//!
//! * **Ids.** Each forwarded query gets a random id of the session's own,
//!   unused by any other query in flight, so two clients that picked the
//!   same id can't get each other's answers. The client's id is put back
//!   in the answer. An answer must come from the server its query went to,
//!   carry exactly the query's question, and arrive within
//!   [`UDP_TIMEOUT_MS`] (or [`TCP_TIMEOUT_MS`] once fetched over TCP).
//!   Anything else is ignored.
//! * **Truncated answers.** One with `TC` set is never passed on, because
//!   the client would retry over TCP and the tunnel answers no TCP. The
//!   session asks for the whole answer from the same resolver over TCP
//!   ([`Step::SendTcp`]) and sends that back over UDP, in fragments when it
//!   is larger than [`tunnel::MTU`].
//! * **Every answer is checked** ([`Engine::check_answer`]) before it goes
//!   back: a blocked alias target gets `NXDOMAIN`, an answer that can't be
//!   read gets `SERVFAIL`.
//! * **No resolver.** With no upstream known (none found, or none usable),
//!   an allowed name gets `SERVFAIL` at once: the filter fails closed, and
//!   apps fail fast rather than wait. Faro never falls back to a resolver of
//!   its own choosing.
//! * **Failover.** When a query sent to the preferred resolver times out,
//!   the next one becomes preferred. The client retries on its own.
//!
//! **Privacy.** The session holds a forwarded query (and so its name) only
//! while it is in flight: until its answer comes back, it fails, or it
//! times out. At most [`MAX_PENDING`] are held, each at most
//! [`MAX_QUERY`] bytes, so an app flooding the tunnel can't make it hold
//! more than 2 MiB of them. Its `Debug` output never shows one.

use crate::dns::{self, DnsQuery};
use crate::packet::build_udp_fragments;
use crate::{tunnel, Action, AnswerCheck, BurstCandidate, Engine, Reject, ReplyTo};
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;

/// Most queries in flight. When full, the oldest is given up.
pub const MAX_PENDING: usize = 512;
/// Largest query forwarded. Real ones are a few hundred bytes, EDNS
/// padding included; a larger one gets `SERVFAIL`.
pub const MAX_QUERY: usize = 4096;
/// How long an answer over UDP may take.
pub const UDP_TIMEOUT_MS: i64 = 4_000;
/// How long an answer fetched again over TCP may take.
pub const TCP_TIMEOUT_MS: i64 = 10_000;
/// Most upstream resolvers kept.
pub const MAX_UPSTREAMS: usize = 8;
/// Most burst candidates held until [`Session::take_bursts`].
pub const MAX_BURSTS: usize = 16;

/// Why a step does nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skipped {
    /// The packet was dropped ([`Action::Drop`]).
    Dropped(Reject),
    /// An answer to no query in flight: late, a duplicate, or forged.
    NotPending,
    /// From another server than the one its query went to.
    WrongServer,
    /// Its question is not the query's.
    WrongQuestion,
    /// A UDP answer to a query that is being fetched over TCP.
    AwaitingTcp,
    /// The reply could not be built (an answer too large for a datagram).
    Unbuildable,
}

/// What the tunnel should do next.
#[derive(Clone, PartialEq, Eq)]
pub enum Step {
    /// Write these packets back to the tunnel, in order.
    Reply(Vec<Vec<u8>>),
    /// Send `payload` to `server` over UDP, and the answer to
    /// [`Session::answer`].
    Send {
        server: SocketAddr,
        payload: Vec<u8>,
    },
    /// Send `payload` to `server` over TCP (with the two-byte length in
    /// front), and the answer, without its length, to [`Session::answer`]
    /// with `tcp` set. If that fails, call [`Session::failed`] with `id`.
    SendTcp {
        server: SocketAddr,
        id: u16,
        payload: Vec<u8>,
    },
    /// Nothing to do.
    Nothing(Skipped),
}

impl fmt::Debug for Step {
    /// Sizes only: a forwarded payload holds an allowed name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Step::Reply(p) => write!(f, "Reply({} packets)", p.len()),
            Step::Send { server, payload } => {
                write!(f, "Send({server}, {} bytes)", payload.len())
            }
            Step::SendTcp {
                server,
                id,
                payload,
            } => write!(f, "SendTcp({server}, id {id}, {} bytes)", payload.len()),
            Step::Nothing(why) => write!(f, "Nothing({why:?})"),
        }
    }
}

/// A query in flight.
struct Pending {
    reply_to: ReplyTo,
    /// The client's query, with the client's id.
    query: Vec<u8>,
    server: SocketAddr,
    sent_ms: i64,
    tcp: bool,
}

impl Pending {
    fn expired(&self, now_ms: i64) -> bool {
        let limit = if self.tcp {
            TCP_TIMEOUT_MS
        } else {
            UDP_TIMEOUT_MS
        };
        // A clock that jumped back counts as time passing.
        now_ms.saturating_sub(self.sent_ms).unsigned_abs() > limit.unsigned_abs()
    }

    /// The parsed query. It parsed when it was stored, so this always
    /// succeeds.
    fn parsed(&self) -> Option<DnsQuery<'_>> {
        dns::parse_query(&self.query).ok()
    }

    /// The query as it goes upstream: the session's id in front.
    fn upstream(&self, id: u16) -> Vec<u8> {
        let mut q = self.query.clone();
        if let Some(head) = q.get_mut(..2) {
            head.copy_from_slice(&id.to_be_bytes());
        }
        q
    }
}

impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pending")
            .field("reply_to", &self.reply_to)
            .field("query_bytes", &self.query.len())
            .field("server", &self.server)
            .field("sent_ms", &self.sent_ms)
            .field("tcp", &self.tcp)
            .finish()
    }
}

/// The engine with the queries in flight, for one tunnel.
pub struct Session {
    engine: Engine,
    upstreams: Vec<SocketAddr>,
    preferred: usize,
    pending: HashMap<u16, Pending>,
    rng: u64,
    frag_ident: u32,
    bursts: Vec<BurstCandidate>,
}

impl fmt::Debug for Session {
    /// Leaves out the id generator's state, from which the next ids could
    /// be guessed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("engine", &self.engine)
            .field("upstreams", &self.upstreams)
            .field("preferred", &self.preferred)
            .field("pending", &self.pending)
            .field("bursts", &self.bursts)
            .finish()
    }
}

impl Session {
    /// A session over `engine`. `seed` seeds the query ids: pass random
    /// bytes from the OS, so an off-path attacker can't guess them.
    pub fn new(engine: Engine, seed: u64) -> Self {
        let mut s = Session {
            engine,
            upstreams: Vec::new(),
            preferred: 0,
            pending: HashMap::new(),
            rng: seed,
            frag_ident: 0,
            bursts: Vec::new(),
        };
        s.frag_ident = s.next_random() as u32;
        s
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn engine_mut(&mut self) -> &mut Engine {
        &mut self.engine
    }

    /// Use these resolvers, the network's own, in order of preference.
    /// Unusable addresses ([`tunnel::upstream_addr`]) and duplicates are left
    /// out, and at most [`MAX_UPSTREAMS`] kept. Returns the ones kept.
    pub fn set_upstreams(
        &mut self,
        servers: impl IntoIterator<Item = SocketAddr>,
    ) -> &[SocketAddr] {
        let mut kept: Vec<SocketAddr> = Vec::new();
        for s in servers.into_iter().filter_map(tunnel::upstream_addr) {
            if !kept.contains(&s) && kept.len() < MAX_UPSTREAMS {
                kept.push(s);
            }
        }
        if kept != self.upstreams {
            self.upstreams = kept;
            self.preferred = 0;
        }
        &self.upstreams
    }

    /// The resolvers in use, in order of preference.
    pub fn upstreams(&self) -> &[SocketAddr] {
        &self.upstreams
    }

    /// The resolver new queries go to.
    pub fn preferred_upstream(&self) -> Option<SocketAddr> {
        self.upstreams.get(self.preferred).copied()
    }

    /// Queries in flight.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Bursts seen and not yet taken or discarded, oldest first.
    pub fn bursts(&self) -> &[BurstCandidate] {
        &self.bursts
    }

    /// Drop the first `n` bursts, once they have been recorded.
    pub fn discard_bursts(&mut self, n: usize) {
        self.bursts.drain(..n.min(self.bursts.len()));
    }

    /// Bursts seen since the last call, oldest first.
    pub fn take_bursts(&mut self) -> Vec<BurstCandidate> {
        std::mem::take(&mut self.bursts)
    }

    /// One packet from the tunnel.
    pub fn packet(&mut self, packet: &[u8], now_ms: i64, screen_on: bool) -> Step {
        self.expire(now_ms);
        let h = self.engine.handle_packet(packet, now_ms, screen_on);
        self.note_burst(h.burst);
        match h.action {
            Action::Reply(p) => Step::Reply(vec![p]),
            Action::Drop(r) => Step::Nothing(Skipped::Dropped(r)),
            Action::Forward { payload, reply_to } => self.forward(payload, reply_to, now_ms),
        }
    }

    fn forward(&mut self, payload: &[u8], reply_to: ReplyTo, now_ms: i64) -> Step {
        let server = match self.preferred_upstream() {
            Some(s) if payload.len() <= MAX_QUERY => s,
            _ => return error_reply(&reply_to, payload, Rcode::ServFail),
        };
        let pending = Pending {
            reply_to,
            query: payload.to_vec(),
            server,
            sent_ms: now_ms,
            tcp: false,
        };
        if self.pending.len() >= MAX_PENDING {
            let oldest = self
                .pending
                .iter()
                .min_by_key(|(_, p)| p.sent_ms)
                .map(|(id, _)| *id);
            if let Some(id) = oldest {
                self.pending.remove(&id);
            }
        }
        let id = self.free_id();
        let step = Step::Send {
            server: pending.server,
            payload: pending.upstream(id),
        };
        self.pending.insert(id, pending);
        step
    }

    /// An answer from `server` over UDP, or over TCP (`tcp`, without the
    /// length in front) after [`Step::SendTcp`].
    pub fn answer(
        &mut self,
        server: SocketAddr,
        answer: &[u8],
        tcp: bool,
        now_ms: i64,
        screen_on: bool,
    ) -> Step {
        self.expire(now_ms);
        let Some(&[hi, lo]) = answer.get(..2) else {
            return Step::Nothing(Skipped::NotPending);
        };
        let id = u16::from_be_bytes([hi, lo]);
        let Some(p) = self.pending.get_mut(&id) else {
            return Step::Nothing(Skipped::NotPending);
        };
        if p.server != server {
            return Step::Nothing(Skipped::WrongServer);
        }
        if !dns::is_response_to(answer, id) {
            return Step::Nothing(Skipped::NotPending);
        }
        if p.tcp && !tcp {
            return Step::Nothing(Skipped::AwaitingTcp);
        }
        let question = p.parsed().map(|q| q.question_bytes().to_vec());
        let one_question = answer.get(4..6) == Some(&[0u8, 1][..]);
        let same = question
            .as_deref()
            .is_some_and(|q| one_question && answer.get(12..12 + q.len()) == Some(q));
        if !same {
            return Step::Nothing(Skipped::WrongQuestion);
        }
        if !tcp && dns::is_truncated(answer) {
            p.tcp = true;
            p.sent_ms = now_ms;
            return Step::SendTcp {
                server,
                id,
                payload: p.upstream(id),
            };
        }
        let Some(p) = self.pending.remove(&id) else {
            return Step::Nothing(Skipped::NotPending);
        };
        let Some(q) = p.parsed() else {
            return Step::Nothing(Skipped::NotPending);
        };
        match self.engine.check_answer(&q.name, answer, now_ms, screen_on) {
            AnswerCheck::Pass => {
                let mut out = answer.to_vec();
                if let Some(head) = out.get_mut(..2) {
                    head.copy_from_slice(&p.reply_to.id().to_be_bytes());
                }
                self.frag_ident = self.frag_ident.wrapping_add(1);
                match build_udp_fragments(
                    p.reply_to.server(),
                    p.reply_to.client(),
                    &out,
                    tunnel::MTU,
                    self.frag_ident,
                ) {
                    Ok(packets) => Step::Reply(packets),
                    Err(_) => error_reply(&p.reply_to, &p.query, Rcode::ServFail),
                }
            }
            AnswerCheck::Blocked { burst, .. } => {
                self.note_burst(burst);
                error_reply(&p.reply_to, &p.query, Rcode::NxDomain)
            }
            AnswerCheck::Unreadable(_) => error_reply(&p.reply_to, &p.query, Rcode::ServFail),
        }
    }

    /// Sending the query with `id` failed (the TCP fetch, or the socket):
    /// the client gets `SERVFAIL` now rather than waiting.
    pub fn failed(&mut self, id: u16, now_ms: i64) -> Step {
        self.expire(now_ms);
        match self.pending.remove(&id) {
            Some(p) => error_reply(&p.reply_to, &p.query, Rcode::ServFail),
            None => Step::Nothing(Skipped::NotPending),
        }
    }

    /// Give up on queries whose answer is overdue, and move on from the
    /// preferred resolver if one of them went there. Every other call does
    /// this first; the tunnel needs no timer for it. Returns how many were
    /// given up.
    pub fn expire(&mut self, now_ms: i64) -> usize {
        let before = self.pending.len();
        let preferred = self.preferred_upstream();
        let mut rotate = false;
        self.pending.retain(|_, p| {
            let keep = !p.expired(now_ms);
            rotate |= !keep && Some(p.server) == preferred;
            keep
        });
        if rotate && self.upstreams.len() > 1 {
            self.preferred = (self.preferred + 1) % self.upstreams.len();
        }
        before - self.pending.len()
    }

    fn note_burst(&mut self, burst: Option<BurstCandidate>) {
        if let Some(b) = burst {
            if self.bursts.len() >= MAX_BURSTS {
                self.bursts.remove(0);
            }
            self.bursts.push(b);
        }
    }

    /// splitmix64.
    fn next_random(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A random id no query in flight uses. There are at most
    /// [`MAX_PENDING`] of 65536 in use, so a few tries always find one.
    fn free_id(&mut self) -> u16 {
        loop {
            let r = self.next_random();
            for shift in [0, 16, 32, 48] {
                let id = (r >> shift) as u16;
                if !self.pending.contains_key(&id) {
                    return id;
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Rcode {
    NxDomain,
    ServFail,
}

/// An `NXDOMAIN` or `SERVFAIL` for the client's query, to the client.
fn error_reply(reply_to: &ReplyTo, query: &[u8], rcode: Rcode) -> Step {
    let Ok(q) = dns::parse_query(query) else {
        return Step::Nothing(Skipped::Unbuildable);
    };
    let msg = match rcode {
        Rcode::NxDomain => q.nxdomain(),
        Rcode::ServFail => q.servfail(),
    };
    match reply_to.wrap(&msg) {
        Ok(p) => Step::Reply(vec![p]),
        Err(_) => Step::Nothing(Skipped::Unbuildable),
    }
}
