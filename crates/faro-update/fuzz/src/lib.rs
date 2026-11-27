//! Shared by the fuzz targets and `examples/seed_corpus.rs`: the toy project
//! every target trusts, the release history it signs, the encoding of
//! multi-document inputs, and the checks every target applies to the
//! verifier's state.
//!
//! The project's keys are derived from a fixed seed
//! ([`ToyProject::from_seed`]), so the seed corpus written by one process
//! verifies against the root a target trusts in another.

use faro_proto::Hash32;
use faro_update::metadata::{is_valid_target_name, RoleMetadata, MAX_ROOT_BYTES};
use faro_update::testing::{Artifact, Release, ToyProject, DAY_MS};
use faro_update::{
    verify_target_stream, Channel, Envelope, Role, Selection, StreamError, TargetKind,
    TrustedState, Updater, VerifiedTargets, Version,
};
use std::collections::BTreeSet;

/// The fuzzing clock. Every step's `now` is this plus or minus some hours.
pub const NOW_MS: i64 = 1_800_000_000_000;
const HOUR_MS: i64 = 3_600_000;

const SEED: [u8; 32] = *b"faro-update fuzzing toy project!";

/// The toy project every target trusts.
pub fn project() -> ToyProject {
    ToyProject::from_seed(SEED, NOW_MS + 365 * DAY_MS)
}

/// Everything the project signs for the fuzzers, in publishing order.
pub struct History {
    pub project: ToyProject,
    /// Root 1, the one every target trusts.
    pub first_root: Vec<u8>,
    /// Roots 2 and 3.
    pub rotations: Vec<Vec<u8>>,
    /// Releases and timestamp refreshes, oldest first.
    pub releases: Vec<Release>,
}

impl History {
    pub fn new() -> Self {
        let mut p = project();
        let first_root = p.first_root();
        let rotations = vec![p.rotate_root().1, p.rotate_root().1];

        let mut macos = Artifact::new(
            "client/macos/aarch64/faro-1.0.0.pkg",
            TargetKind::Client,
            "macos",
            "aarch64",
            "1.0.0",
            b"",
        );
        macos.min_os = Some("13.0".into());
        let model = Artifact::new(
            "model/detect-3.onnx",
            TargetKind::Model,
            "any",
            "any",
            "3.0.0",
            b"model",
        );
        let r1 = p.release_expiring(
            &[macos.clone(), model.clone()],
            NOW_MS + 30 * DAY_MS,
            NOW_MS + DAY_MS,
        );
        let r1b = p.refresh_timestamp(&r1, NOW_MS + 2 * DAY_MS);

        let beta = Artifact::new(
            "client/macos/aarch64/faro-1.2.0-beta.1.pkg",
            TargetKind::Client,
            "macos",
            "aarch64",
            "1.2.0-beta.1",
            b"beta",
        )
        .channels(&["beta"]);
        let next = Artifact::new(
            "client/macos/aarch64/faro-1.1.0.pkg",
            TargetKind::Client,
            "macos",
            "aarch64",
            "1.1.0",
            b"next",
        )
        .channels(&["stable", "beta"]);
        let windows = Artifact::new(
            "client/windows/x86_64/faro-1.1.0.msi",
            TargetKind::Client,
            "windows",
            "x86_64",
            "1.1.0",
            b"windows",
        );
        let server = Artifact::new(
            "server/linux/aarch64/faro-server-1.1.0",
            TargetKind::Server,
            "linux",
            "aarch64",
            "1.1.0",
            b"server",
        );
        let r2 = p.release_expiring(
            &[macos, next, beta, windows, server, model],
            NOW_MS + 30 * DAY_MS,
            NOW_MS + DAY_MS,
        );
        // A fresh timestamp for targets that have already expired.
        let r3 = p.release_expiring(&[], NOW_MS - HOUR_MS, NOW_MS + DAY_MS);

        History {
            project: p,
            first_root,
            rotations,
            releases: vec![r1, r1b, r2, r3],
        }
    }

    /// Every envelope, as served.
    pub fn envelopes(&self) -> Vec<(Role, &[u8])> {
        let mut out = vec![(Role::Root, self.first_root.as_slice())];
        out.extend(self.rotations.iter().map(|r| (Role::Root, r.as_slice())));
        for r in &self.releases {
            out.push((Role::Timestamp, r.timestamp.as_slice()));
            out.push((Role::Targets, r.targets.as_slice()));
        }
        out
    }

    /// BLAKE3 of every payload the project signed: the only payloads a
    /// verifier may ever trust when the mirror is the attacker.
    pub fn signed_payloads(&self) -> BTreeSet<Hash32> {
        self.envelopes()
            .into_iter()
            .map(|(role, bytes)| Hash32::of(&payload(role, bytes)))
            .collect()
    }
}

impl Default for History {
    fn default() -> Self {
        History::new()
    }
}

/// A named sequence of `(op, hours from NOW_MS, document)` steps.
pub type Flow<'a> = (&'static str, Vec<(Op, i64, &'a [u8])>);

/// Whole update checks as a mirror serves them: the seeds of `client_flow`
/// (and, as payloads, of `signed_flow`).
pub fn seed_flows(h: &History) -> Vec<Flow<'_>> {
    let [r1, r1b, r2, r3] = &h.releases[..] else {
        unreachable!("History has four releases")
    };
    let (root2, root3) = (&h.rotations[0], &h.rotations[1]);
    vec![
        (
            "rotate-then-release",
            vec![
                (Op::Root, 0, root2),
                (Op::Root, 0, root3),
                (Op::Timestamp, 0, &r1.timestamp),
                (Op::Targets, 0, &r1.targets),
                (Op::Persist, 1, &[]),
                (Op::Timestamp, 2, &r2.timestamp),
                (Op::Targets, 2, &r2.targets),
            ],
        ),
        (
            "refresh-and-replay",
            vec![
                (Op::Timestamp, 0, &r1.timestamp),
                (Op::Targets, 0, &r1.targets),
                (Op::Timestamp, 30, &r1b.timestamp),
                (Op::Targets, 30, &r1b.targets),
                (Op::Timestamp, 30, &r1.timestamp),
                (Op::Persist, 40, &[]),
                (Op::Timestamp, -10, &r1.timestamp),
            ],
        ),
        (
            "mix-and-expire",
            vec![
                (Op::Timestamp, 0, &r2.timestamp),
                (Op::Targets, 0, &r1.targets),
                (Op::Targets, 0, &r2.targets),
                (Op::Timestamp, 0, &r3.timestamp),
                (Op::Targets, 0, &r3.targets),
                (Op::Timestamp, 47, &r2.timestamp),
            ],
        ),
    ]
}

/// The (unverified) payload of one of the project's own envelopes.
pub fn payload(role: Role, envelope: &[u8]) -> Vec<u8> {
    Envelope::parse(role, envelope)
        .and_then(|e| e.unverified_payload())
        .expect("the project's own envelope")
}

/// One call on the [`Updater`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `update_root`
    Root,
    /// `verify_timestamp`
    Timestamp,
    /// `verify_targets`
    Targets,
    /// Persist the state and resume from it, as a client does between checks.
    Persist,
}

/// One step of a multi-document input.
#[derive(Debug, Clone, Copy)]
pub struct Step<'a> {
    pub op: Op,
    pub now_ms: i64,
    pub bytes: &'a [u8],
}

/// Most steps decoded from one input.
pub const MAX_STEPS: usize = 16;

/// Decode an input as steps. Each is a header byte (bits 0-1: the [`Op`];
/// bits 2-7: the clock, `NOW_MS` - 16 h + that many hours), a little-endian
/// `u32` length (cut to what is left) and that many bytes.
pub fn steps(mut data: &[u8]) -> Vec<Step<'_>> {
    let mut out = Vec::new();
    while out.len() < MAX_STEPS {
        let Some((&head, rest)) = data.split_first() else {
            break;
        };
        let (len, rest) = match rest.split_first_chunk::<4>() {
            Some((len, rest)) => (u32::from_le_bytes(*len) as usize, rest),
            None => (rest.len(), rest),
        };
        let (bytes, rest) = rest.split_at(len.min(rest.len()));
        data = rest;
        let op = match head & 3 {
            0 => Op::Root,
            1 => Op::Timestamp,
            2 => Op::Targets,
            _ => Op::Persist,
        };
        let now_ms = NOW_MS + (i64::from(head >> 2) - 16) * HOUR_MS;
        out.push(Step { op, now_ms, bytes });
    }
    out
}

/// Inverse of [`steps`], for writing seeds. `hours` is relative to
/// `NOW_MS` and must be in -16..=47.
pub fn encode_steps(steps: &[(Op, i64, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(op, hours, bytes) in steps {
        assert!((-16..=47).contains(&hours));
        let op = match op {
            Op::Root => 0,
            Op::Timestamp => 1,
            Op::Targets => 2,
            Op::Persist => 3,
        };
        out.push(op | (((hours + 16) as u8) << 2));
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
    }
    out
}

/// A persisted state must load back unchanged.
pub fn persist_roundtrip(state: &TrustedState) -> TrustedState {
    let json = serde_json::to_vec(state).expect("TrustedState serializes");
    let back: TrustedState = serde_json::from_slice(&json).expect("TrustedState loads back");
    assert_eq!(&back, state, "TrustedState changed through persistence");
    back
}

/// [`persist_roundtrip`], and the state the verifier built stays small
/// whatever it was fed: the client writes it after every call.
pub fn check_persist(state: &TrustedState) -> TrustedState {
    let size = serde_json::to_vec(state)
        .expect("TrustedState serializes")
        .len();
    assert!(
        size <= MAX_ROOT_BYTES,
        "persisted state grew to {size} bytes"
    );
    persist_roundtrip(state)
}

/// The rules every call must keep, given the state before and after it and
/// whether it succeeded (crate docs, "Client state machine").
pub fn check_transition(before: &TrustedState, after: &TrustedState, op: Op, ok: bool) {
    assert!(
        after.max_observed_ms() >= before.max_observed_ms(),
        "observed time went backwards"
    );
    assert!(after.root().validate().is_ok(), "trusted an invalid root");
    let unchanged = after.root() == before.root()
        && after.root_payload_hash() == before.root_payload_hash()
        && after.timestamp() == before.timestamp()
        && after.targets() == before.targets();
    if !ok || op == Op::Persist {
        assert!(unchanged, "{op:?} failed but changed the trusted state");
        return;
    }
    match op {
        Op::Root => {
            assert_eq!(after.root().version, before.root().version + 1);
        }
        Op::Timestamp => {
            assert_eq!(after.root(), before.root());
            let new = after.timestamp().expect("a trusted timestamp");
            if let Some(old) = before.timestamp() {
                assert!(new.version >= old.version, "timestamp rolled back");
                assert!(
                    new.targets_meta.version >= old.targets_meta.version,
                    "committed targets version rolled back"
                );
                if new.version == old.version {
                    assert_eq!(new, old, "timestamp equivocation accepted");
                }
            }
            if let Some(t) = before.targets() {
                assert!(new.targets_meta.version >= t.version);
            }
            assert!(new.expires_ms > NOW_MS - 16 * HOUR_MS);
        }
        Op::Targets => {
            assert_eq!(after.root(), before.root());
            assert_eq!(after.timestamp(), before.timestamp());
            let new = after.targets().expect("trusted targets");
            let ts = after.timestamp().expect("targets need a timestamp");
            assert_eq!(new.version, ts.targets_meta.version);
            if let Some(old) = before.targets() {
                assert!(new.version >= old.version, "targets rolled back");
                if new.version == old.version {
                    assert_eq!(new.payload_hash, old.payload_hash, "targets equivocation");
                }
            }
        }
        Op::Persist => unreachable!(),
    }
}

/// Run one step against `u`, check the transition, and return whether it
/// succeeded.
pub fn run_step(u: &mut Updater, step: &Step<'_>) -> bool {
    let before = u.state().clone();
    let ok = match step.op {
        Op::Root => u.update_root(step.bytes).is_ok(),
        Op::Timestamp => u.verify_timestamp(step.bytes, step.now_ms).is_ok(),
        Op::Targets => match u.verify_targets(step.bytes, step.now_ms) {
            Ok(t) => {
                exercise_targets(&t);
                true
            }
            Err(_) => false,
        },
        Op::Persist => {
            *u = Updater::from_state(check_persist(u.state()));
            true
        }
    };
    check_transition(&before, u.state(), step.op, ok);
    check_persist(u.state());
    ok
}

/// Use a verified listing the way the client and the mirror do: look
/// targets up, select updates, and verify a download.
pub fn exercise_targets(t: &VerifiedTargets) {
    let channels = [
        Channel::stable(),
        Channel::Named("beta".into()),
        Channel::StableMinusOne,
    ];
    let os = Version::new(14, 0, 0);
    for info in t.iter().take(8) {
        assert!(is_valid_target_name(&info.name));
        assert_eq!(t.get(&info.name).as_ref(), Some(&info));
        let c = &info.custom;
        for channel in &channels {
            for (current, allow_downgrade) in [(None, false), (Some(&c.version), false)] {
                let q = Selection {
                    channel,
                    kind: c.kind,
                    platform: &c.platform,
                    arch: &c.arch,
                    current_version: current,
                    os_version: Some(&os),
                    allow_downgrade,
                };
                let Some(sel) = t.select_with(&q) else {
                    continue;
                };
                assert_eq!(sel.custom.kind, c.kind);
                assert!(sel.custom.platform == c.platform || sel.custom.platform == "any");
                assert!(sel.custom.arch == c.arch || sel.custom.arch == "any");
                if let Some(cur) = current {
                    assert!(sel.custom.version > *cur, "selected a downgrade");
                }
                if let Channel::Named(n) = channel {
                    assert!(sel.custom.channels.contains(n));
                }
            }
        }
        // Download it: zeros of the signed length, under a small cap.
        const CAP: u64 = 4096;
        if info.length <= CAP {
            let body = vec![0u8; info.length as usize];
            let r = verify_target_stream(body.as_slice(), &info, CAP);
            assert_eq!(r.is_ok(), Hash32::of(&body) == info.blake3);
        } else {
            let r = verify_target_stream(std::io::empty(), &info, CAP);
            assert!(matches!(r, Err(StreamError::ExceedsCap { .. })));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(flow: &[(Op, i64, &[u8])], first_root: &[u8]) -> (Updater, Vec<bool>) {
        let mut u = Updater::bootstrap(first_root).unwrap();
        let encoded = encode_steps(flow);
        let decoded = steps(&encoded);
        assert_eq!(decoded.len(), flow.len());
        let oks = decoded.iter().map(|s| run_step(&mut u, s)).collect();
        (u, oks)
    }

    /// The seeds must reach deep into the verifier, or the fuzzers start
    /// from rejections.
    #[test]
    fn seed_flows_do_what_they_say() {
        let h = History::new();
        let expect: [&[bool]; 3] = [
            &[true; 7],
            &[true, true, true, true, false, true, false],
            &[true, false, true, true, false, false],
        ];
        for ((name, flow), expect) in seed_flows(&h).iter().zip(expect) {
            let (u, oks) = run(flow, &h.first_root);
            assert_eq!(oks, expect, "{name}");
            check_persist(u.state());
        }
    }

    #[test]
    fn the_project_is_deterministic() {
        assert_eq!(History::new().envelopes(), History::new().envelopes());
    }
}
