//! # faro-update
//!
//! TUF-inspired signed update verification, shared by the client service
//! (which installs updates) and `faro-server`'s update mirror (which fetches
//! and re-serves them). ARCHITECTURE.md §3.8, §4.1(7), §9 threat #4.
//!
//! ## The principle
//!
//! Every Faro instance mirrors releases for its members, so the party
//! serving update bytes to a client is an instance operator the project does
//! not trust. Clients therefore verify the **project's** signatures
//! themselves. A malicious or compromised instance can *delay* updates (stop
//! serving, or keep serving the last good metadata until it expires) but can
//! never make a client install code the project didn't sign, and can never
//! roll a client back to older, validly signed metadata or artifacts.
//!
//! ## Roles
//!
//! | Role | Key custody | Signs | Expiry |
//! |---|---|---|---|
//! | `root` | offline, threshold (e.g. 2-of-3 hardware keys) | the key ids and thresholds of every role, including itself | long (≈1 year) |
//! | `targets` | offline-ish release key | the artifact list: name → length, BLAKE3, selection hints | weeks |
//! | `timestamp` | online | the current targets document's version, length and BLAKE3 | short (≈1 day) |
//!
//! TUF's *snapshot* role is folded into `timestamp`: Faro has exactly one
//! targets document and no delegations, so pinning that one document's
//! version, length and hash is all a snapshot would add. The timestamp key
//! is online (it must re-sign daily to prove freshness), so compromising it
//! buys an attacker only freeze/mix-and-match capabilities that the version
//! checks below shut down — it cannot add or change any artifact.
//!
//! Keys are Ed25519 via `faro-crypto` (strict verification). Key ids are
//! [`faro_proto::keys::key_id`] of the public key, and a root is invalid if
//! any id in its key table doesn't match its key, so an id can never be
//! silently re-pointed.
//!
//! ## Envelope
//!
//! Every document travels in a DSSE-style [`Envelope`]:
//! `{"payload_type", "payload": base64url(bytes), "signatures": [{"keyid","sig"}]}`.
//! Signatures cover [`pae`]`(payload_type, payload)` built with
//! [`faro_proto::encoding::Canonical`] under the tag
//! `faro/update-envelope/v1`, so the role (`application/vnd.faro.<role>+json`)
//! is bound into every signature and a targets document can never be
//! presented as a timestamp. The payload is parsed **only after** its
//! signatures verify (the one exception is the installer-embedded root, see
//! [`Updater::bootstrap`]), so the JSON parser only ever sees attacker bytes
//! after the attacker has been authenticated as a project key. Envelopes are
//! size-capped per role before parsing.
//!
//! ## Threshold rules
//!
//! For a role with `threshold = t`: at least `t` **distinct** key ids that
//! are **listed for that role** must carry a valid signature. Unknown key
//! ids and keys belonging to another role are ignored; repeated entries for
//! one key count once; malformed entries (bad base64, wrong length, invalid
//! signature) are skipped rather than fatal, so a mirror appending garbage
//! can't invalidate good metadata — but they can't count either. At most
//! [`MAX_SIGNATURES`] entries are examined.
//!
//! ## Client state machine
//!
//! The caller persists a [`TrustedState`] (current root, newest accepted
//! timestamp and targets versions with payload hashes, and the highest time
//! observed) and drives an [`Updater`]:
//!
//! 1. **Root rotation** — [`Updater::update_root`] with `root/{v+1}.json`,
//!    repeated until the mirror has none newer. Each new root must have
//!    version exactly `old + 1` and be signed by a threshold of the old
//!    root's root keys *and* of its own root keys. If a targets or timestamp
//!    key was revoked (removed from the role), the stored versions for that
//!    role are reset so a fast-forward attack by a compromised online key
//!    can be recovered from by rotating that key out. Pure key additions and
//!    threshold changes keep them, so they can't re-open replay.
//! 2. **Timestamp** — [`Updater::verify_timestamp`]: signed by the timestamp
//!    role; version never decreases; the same version with different content
//!    is equivocation; the committed targets version never decreases; not
//!    expired; the trusted root not expired.
//! 3. **Targets** — [`Updater::verify_targets`]: the raw bytes must have
//!    exactly the length and BLAKE3 the trusted timestamp committed to
//!    (checked before parsing); signed by the targets role; payload version
//!    equals the committed version; never decreases; not expired. Returns
//!    [`VerifiedTargets`], the only type selection works on.
//! 4. **Select & download** — [`VerifiedTargets::select`] picks an artifact;
//!    [`verify_target_stream`] / [`copy_verified_target`] check it with a
//!    streaming BLAKE3 against the *signed* length, never the mirror's
//!    `Content-Length`.
//!
//! **Rollback protection**: versions never decrease, and an equal version
//! with different signed content is an error ([`UpdateError::Equivocation`]).
//! Re-presenting the *same* document is fine, which keeps retries and
//! cached copies idempotent.
//!
//! **Freeze protection**: expiry is judged against
//! `max(now, max_observed_ms)`. The high-water mark is raised whenever a
//! document authenticates and parses, even if it is then rejected (e.g. as
//! expired), so rolling the system clock back after the client has seen a
//! later time cannot revive expired metadata that a mirror keeps replaying.
//! It is raised to `min(now, earliest expiry of the documents checked)`,
//! never to `now` alone: only authentic metadata raises it, and never past a
//! project-signed expiry, so neither an unauthenticated party nor a single
//! far-future clock tamper can freeze updates beyond the next fresh
//! timestamp (see [`Updater::effective_now`]). Because a rejection can raise
//! the mark, callers persist the [`TrustedState`] after **every** call, `Ok`
//! or `Err`. Expiry is `now >= expires_ms`.
//!
//! ## Target selection
//!
//! Targets carry `custom = {kind, platform, arch, version (semver),
//! channels, min_os?, min_client?}`. A channel is either a name (`stable`, `beta`, ...),
//! selecting the highest semver listed in it, or the instance-admin pin
//! `stable-1`, selecting the newest release on the `major.minor` line
//! immediately below the newest stable line (precisely specified on
//! [`VerifiedTargets::select_with`]). A version equal to or below the
//! installed one is never selected unless the caller sets
//! [`Selection::allow_downgrade`]. Platform/arch `any` matches everything.
//! A client also skips targets whose `min_client` is above its own version
//! ([`VerifiedTargets::select_for`]).
//!
//! Models and blocklists are two files each (a manifest and what it
//! describes), joined into one target as a [`bundle`].
//!
//! ## Signing
//!
//! [`MetadataSigner`] turns role structs into envelopes (validating them
//! first); [`Envelope::add_signature`] lets offline root holders co-sign one
//! at a time. `examples/faro-release.rs` wraps both as a small release CLI.
//!
//! ## Not covered here
//!
//! Transport (HTTP fetching, retries) and installation are the caller's job;
//! this crate is pure verification over bytes and is `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

pub mod bundle;
mod envelope;
mod error;
pub mod metadata;
mod select;
mod signer;
mod stream;
#[cfg(feature = "testing")]
pub mod testing;
mod trust;

pub use envelope::{pae, Envelope, EnvelopeSignature, ENVELOPE_TAG, MAX_SIGNATURES};
pub use error::{StreamError, UpdateError};
pub use metadata::{
    Role, RoleKeys, RoleMetadata, Root, RootRoles, TargetCustom, TargetFile, TargetKind, Targets,
    TargetsMeta, Timestamp, STABLE_CHANNEL,
};
pub use select::{Channel, InvalidChannel, Selection, TargetInfo, VerifiedTargets};
pub use semver::Version;
pub use signer::MetadataSigner;
pub use stream::{copy_verified_target, verify_target_stream, TargetVerifier};
pub use trust::{TargetsRecord, TimestampRecord, TrustedState, Updater};
