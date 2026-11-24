//! The client's persisted trust state and the verification state machine.

use crate::envelope::{parse_payload, Envelope};
use crate::error::UpdateError;
use crate::metadata::{Role, RoleMetadata, Root, Targets, TargetsMeta, Timestamp};
use crate::select::VerifiedTargets;
use faro_proto::Hash32;
use serde::{Deserialize, Serialize};

/// What we remember about the newest timestamp we accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimestampRecord {
    pub version: u64,
    /// BLAKE3 of the signed payload bytes (not the envelope, so a mirror
    /// re-ordering or adding signatures is not mistaken for equivocation).
    pub payload_hash: Hash32,
    pub expires_ms: i64,
    pub targets_meta: TargetsMeta,
}

/// What we remember about the newest targets document we accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetsRecord {
    pub version: u64,
    /// BLAKE3 of the signed payload bytes.
    pub payload_hash: Hash32,
    pub expires_ms: i64,
}

/// Everything a client must persist between update checks.
///
/// Callers serialize this (it is `serde`) after **every** [`Updater`] call
/// that changed it — including calls that returned `Err`, because a
/// rejected-as-expired document still raises the observed-time mark, and
/// dropping that raise would let a rolled-back clock revive frozen metadata
/// after a restart. The simplest correct rule is "persist after every call";
/// a caller that wants to avoid redundant writes can compare against the last
/// persisted copy (the type is `PartialEq`). Load it at startup with
/// [`Updater::from_state`]. It contains only
/// public data; it does not need to be secret, but it must be stored where
/// an unprivileged user can't rewrite it (the service's state directory),
/// since resetting it would re-open the rollback window back to the
/// installer's embedded root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedState {
    root: Root,
    root_payload_hash: Hash32,
    timestamp: Option<TimestampRecord>,
    targets: Option<TargetsRecord>,
    /// Observed-time high-water mark (Unix ms). Expiry is judged against
    /// `max(now, max_observed_ms)`. Only raised by authentic metadata and
    /// never past the earliest expiry that metadata carries (see
    /// [`Updater::effective_now`]), so it is bounded by project-signed data.
    max_observed_ms: i64,
}

impl TrustedState {
    /// The currently trusted root.
    pub fn root(&self) -> &Root {
        &self.root
    }

    /// BLAKE3 of the trusted root's signed payload.
    pub fn root_payload_hash(&self) -> Hash32 {
        self.root_payload_hash
    }

    pub fn timestamp(&self) -> Option<&TimestampRecord> {
        self.timestamp.as_ref()
    }

    pub fn targets(&self) -> Option<&TargetsRecord> {
        self.targets.as_ref()
    }

    pub fn max_observed_ms(&self) -> i64 {
        self.max_observed_ms
    }

    /// Forget the observed-time high-water mark.
    ///
    /// Not needed for recovery from a clock that once ran far into the
    /// future: the mark is capped at the earliest expiry of the metadata that
    /// raised it, so it self-heals as soon as the project publishes a
    /// timestamp expiring later than that. This exists for operators who must
    /// recover *immediately* (e.g. while the project's timestamp signer is
    /// down). Only call it from an authenticated administrative action; it
    /// re-opens the freeze window that the high-water mark closes.
    pub fn clear_observed_time(&mut self) {
        self.max_observed_ms = i64::MIN;
    }
}

/// Verifies update metadata against a [`TrustedState`].
///
/// Expected call sequence on every check (see the crate docs):
/// 1. loop [`update_root`](Self::update_root) with `root/{v+1}.json` until
///    the mirror has no newer root;
/// 2. [`verify_timestamp`](Self::verify_timestamp);
/// 3. fetch the targets document with a length cap of
///    `timestamp.targets_meta.length` and
///    [`verify_targets`](Self::verify_targets);
/// 4. select and download a target, verifying it with
///    [`verify_target_stream`](crate::verify_target_stream).
///
/// Every operation is all-or-nothing on the state, except that the observed
/// time is raised as soon as a document's signatures verify and its payload
/// parses, even if the document is then rejected (see
/// [`effective_now`](Self::effective_now)). Persist [`state`](Self::state)
/// after **every** call, `Ok` or `Err`; see [`TrustedState`].
#[derive(Debug, Clone)]
pub struct Updater {
    state: TrustedState,
}

impl Updater {
    /// Start from a root obtained out of band (embedded in the installer).
    ///
    /// The root must be signed by a threshold of *its own* root keys. This
    /// is a consistency check, not the source of trust: the trust comes from
    /// the bytes having shipped inside a project-signed installer, which is
    /// why the payload is parsed before its signatures are checked here and
    /// nowhere else. Expiry is deliberately *not* checked: an installer may
    /// sit on a shelf past its root's expiry and must still be able to walk
    /// the rotation chain forward to a fresh root.
    pub fn bootstrap(root_envelope: &[u8]) -> Result<Self, UpdateError> {
        let env = Envelope::parse(Role::Root, root_envelope)?;
        let unverified = env.unverified_payload()?;
        let root: Root = parse_payload(&unverified)?;
        let payload = env.verify_role(Role::Root, &root.keys, root.role_keys(Role::Root))?;
        Ok(Updater {
            state: TrustedState {
                root,
                root_payload_hash: Hash32::of(&payload),
                timestamp: None,
                targets: None,
                max_observed_ms: i64::MIN,
            },
        })
    }

    /// Resume from persisted state.
    pub fn from_state(state: TrustedState) -> Self {
        Updater { state }
    }

    pub fn state(&self) -> &TrustedState {
        &self.state
    }

    pub fn into_state(self) -> TrustedState {
        self.state
    }

    /// The clock used for expiry: `max(now_ms, max_observed_ms)`.
    ///
    /// Whenever a call has authenticated and parsed its documents, the mark
    /// is raised to `min(now_ms, earliest expiry among the documents that
    /// call checks)` — never to `now_ms` alone. Both halves matter:
    ///
    /// * **Rollback-proof.** If any checked document was expired at `now_ms`
    ///   (`now_ms >= e` for its expiry `e`), the mark becomes at least the
    ///   earliest expiry `e_min <= e`, so the earliest-expiring document of
    ///   that set stays expired (`effective >= e_min`) however far the clock
    ///   is wound back, and the set as a whole stays dead.
    /// * **Bounded by signed data.** A wildly wrong future clock (the
    ///   monitored user changing the system time once during a check) can
    ///   push the mark no further than an expiry the project itself signed.
    ///   With timestamps expiring in about a day, a corrected clock recovers
    ///   on the next fresh timestamp, instead of every document looking
    ///   expired until the far-future date really arrives (which would turn
    ///   one clock tamper into a permanent update block).
    pub fn effective_now(&self, now_ms: i64) -> i64 {
        now_ms.max(self.state.max_observed_ms)
    }

    /// Raise the observed-time mark to `min(now_ms, min(expiries))`; see
    /// [`effective_now`](Self::effective_now). Call only after the
    /// documents carrying `expiries` have been authenticated.
    fn observe(&mut self, now_ms: i64, expiries: &[i64]) {
        let cap = expiries.iter().copied().fold(now_ms, i64::min);
        self.state.max_observed_ms = self.state.max_observed_ms.max(cap);
    }

    fn check_fresh(role: Role, expires_ms: i64, now_ms: i64) -> Result<(), UpdateError> {
        if now_ms >= expires_ms {
            return Err(UpdateError::Expired {
                role,
                expires_ms,
                now_ms,
            });
        }
        Ok(())
    }

    /// Advance the trusted root by exactly one version.
    ///
    /// The new root must be signed by a threshold of the **old** root's root
    /// keys (so the current key holders authorised the change) **and** a
    /// threshold of the **new** root's root keys (so the new key set is
    /// actually held by someone — a typo can't brick every client).
    /// Intermediate roots may be expired; freshness is enforced on the final
    /// root when the timestamp is verified.
    ///
    /// If a key was **removed** from the targets or timestamp role (or an id
    /// now points at a different public key), the corresponding rollback
    /// records are discarded. This is the recovery path from an online-key
    /// compromise: an attacker holding the old timestamp key may have pushed
    /// clients to an absurdly high version, which must not lock out the
    /// legitimate new key. Recovering from a compromise always means revoking
    /// the compromised key, so pure additions and threshold changes keep the
    /// records: otherwise a routine "add a second timestamp key" rotation
    /// would let a mirror replay any older, still-unexpired timestamp.
    pub fn update_root(&mut self, new_root_envelope: &[u8]) -> Result<(), UpdateError> {
        let env = Envelope::parse(Role::Root, new_root_envelope)?;
        let old = &self.state.root;
        let payload = env.verify_role(Role::Root, &old.keys, old.role_keys(Role::Root))?;
        let new: Root = parse_payload(&payload)?;

        let expected = old.version.saturating_add(1);
        if new.version <= old.version {
            return Err(UpdateError::Rollback {
                role: Role::Root,
                trusted: old.version,
                offered: new.version,
            });
        }
        if new.version != expected {
            return Err(UpdateError::RootVersionSkip {
                expected,
                offered: new.version,
            });
        }
        env.verify_role(Role::Root, &new.keys, new.role_keys(Role::Root))?;

        let targets_rotated = role_key_revoked(old, &new, Role::Targets);
        let timestamp_rotated = role_key_revoked(old, &new, Role::Timestamp);

        if targets_rotated {
            // The timestamp record pins a targets version too, so it goes as well.
            self.state.targets = None;
            self.state.timestamp = None;
        }
        if timestamp_rotated {
            self.state.timestamp = None;
        }
        self.state.root = new;
        self.state.root_payload_hash = Hash32::of(&payload);
        Ok(())
    }

    /// Verify a timestamp and, on success, make it the trusted one.
    pub fn verify_timestamp(
        &mut self,
        bytes: &[u8],
        now_ms: i64,
    ) -> Result<Timestamp, UpdateError> {
        let env = Envelope::parse(Role::Timestamp, bytes)?;
        let root = &self.state.root;
        let payload =
            env.verify_role(Role::Timestamp, &root.keys, root.role_keys(Role::Timestamp))?;
        let ts: Timestamp = parse_payload(&payload)?;
        let root_expires = self.state.root.expires_ms;
        self.observe(now_ms, &[root_expires, ts.expires_ms]);
        let now = self.effective_now(now_ms);
        Self::check_fresh(Role::Root, root_expires, now)?;

        let payload_hash = Hash32::of(&payload);

        if let Some(prev) = &self.state.timestamp {
            if ts.version < prev.version {
                return Err(UpdateError::Rollback {
                    role: Role::Timestamp,
                    trusted: prev.version,
                    offered: ts.version,
                });
            }
            if ts.version == prev.version && payload_hash != prev.payload_hash {
                return Err(UpdateError::Equivocation {
                    role: Role::Timestamp,
                    version: ts.version,
                });
            }
            let (pm, nm) = (&prev.targets_meta, &ts.targets_meta);
            if nm.version < pm.version {
                return Err(UpdateError::Rollback {
                    role: Role::Targets,
                    trusted: pm.version,
                    offered: nm.version,
                });
            }
            if nm.version == pm.version && nm != pm {
                return Err(UpdateError::Equivocation {
                    role: Role::Targets,
                    version: nm.version,
                });
            }
        }
        if let Some(t) = &self.state.targets {
            if ts.targets_meta.version < t.version {
                return Err(UpdateError::Rollback {
                    role: Role::Targets,
                    trusted: t.version,
                    offered: ts.targets_meta.version,
                });
            }
        }
        Self::check_fresh(Role::Timestamp, ts.expires_ms, now)?;

        self.state.timestamp = Some(TimestampRecord {
            version: ts.version,
            payload_hash,
            expires_ms: ts.expires_ms,
            targets_meta: ts.targets_meta,
        });
        Ok(ts)
    }

    /// Verify the targets document the trusted timestamp commits to.
    ///
    /// The length and BLAKE3 of the raw bytes are checked against the
    /// timestamp *before* anything is parsed, so a mirror mixing a stale (but
    /// validly signed) targets file with a fresh timestamp is rejected
    /// cheaply. Re-verifying the same document is allowed (idempotent), which
    /// lets callers cache the targets bytes and re-check them at startup.
    pub fn verify_targets(
        &mut self,
        bytes: &[u8],
        now_ms: i64,
    ) -> Result<VerifiedTargets, UpdateError> {
        let ts = self
            .state
            .timestamp
            .clone()
            .ok_or(UpdateError::NoTrustedTimestamp)?;
        let meta = ts.targets_meta;
        if bytes.len() as u64 != meta.length {
            return Err(UpdateError::TimestampMismatch(format!(
                "length {} != committed {}",
                bytes.len(),
                meta.length
            )));
        }
        if Hash32::of(bytes) != meta.blake3 {
            return Err(UpdateError::TimestampMismatch("BLAKE3 differs".into()));
        }

        let env = Envelope::parse(Role::Targets, bytes)?;
        let root = &self.state.root;
        let payload = env.verify_role(Role::Targets, &root.keys, root.role_keys(Role::Targets))?;
        let targets: Targets = parse_payload(&payload)?;
        let root_expires = self.state.root.expires_ms;
        // The timestamp's (short) expiry is part of the cap, so a far-future
        // clock here can't pin the mark at the targets' weeks-long expiry.
        self.observe(now_ms, &[root_expires, ts.expires_ms, targets.expires_ms]);
        let now = self.effective_now(now_ms);
        Self::check_fresh(Role::Root, root_expires, now)?;
        Self::check_fresh(Role::Timestamp, ts.expires_ms, now)?;

        if targets.version != meta.version {
            return Err(UpdateError::TimestampMismatch(format!(
                "version {} != committed {}",
                targets.version, meta.version
            )));
        }
        let payload_hash = Hash32::of(&payload);
        if let Some(prev) = &self.state.targets {
            if targets.version < prev.version {
                return Err(UpdateError::Rollback {
                    role: Role::Targets,
                    trusted: prev.version,
                    offered: targets.version,
                });
            }
            if targets.version == prev.version && payload_hash != prev.payload_hash {
                return Err(UpdateError::Equivocation {
                    role: Role::Targets,
                    version: targets.version,
                });
            }
        }
        Self::check_fresh(Role::Targets, targets.expires_ms(), now)?;

        self.state.targets = Some(TargetsRecord {
            version: targets.version,
            payload_hash,
            expires_ms: targets.expires_ms,
        });
        Ok(VerifiedTargets::new(targets))
    }
}

/// Whether the rotation from `old` to `new` revoked any key of `role`: some
/// key id authorised in `old` is no longer authorised in `new`, or now maps
/// to a different public key. (Key ids are bound to keys by root validation,
/// so the second check is belt-and-braces.)
fn role_key_revoked(old: &Root, new: &Root, role: Role) -> bool {
    let still_authorised = new.role_keys(role).keyid_set();
    old.role_keys(role)
        .keyids
        .iter()
        .any(|id| !still_authorised.contains(id.as_str()) || old.keys.get(id) != new.keys.get(id))
}
