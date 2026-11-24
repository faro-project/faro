//! Passkeys (WebAuthn): **not implemented yet.** This module only records the
//! intended design so the next implementer starts from the same assumptions.
//! No routes are registered for it, and nothing pretends to support it.
//!
//! # Plan
//!
//! * Passkeys are the primary login for every role (§4.5, §9 "admin passkey");
//!   magic links remain the fallback and the recovery path.
//! * Use `webauthn-rs` (MPL-2.0 is *not* Apache-compatible for vendoring, but
//!   linking an unmodified crate is fine; confirm with `cargo-deny` policy) or
//!   a minimal in-tree verifier restricted to ES256/EdDSA, `none` attestation.
//! * Relying-party id = the host of `public_url`; origin must equal
//!   `public_url` exactly (no subdomains), checked server-side.
//! * Tables (new migration): `passkeys(id, user_id, credential_id UNIQUE,
//!   public_key_cose, sign_count, transports, created_at, last_used_at)` and
//!   short-lived `webauthn_challenges(id_hash, user_id NULL, kind, challenge,
//!   expires_at)` stored hashed like every other bearer secret.
//! * Endpoints: `POST /v1/auth/passkey/register/{start,finish}` (session
//!   required), `POST /v1/auth/passkey/login/{start,finish}` (discoverable
//!   credentials, rate-limited like magic links), `DELETE /v1/me/passkeys/{id}`.
//! * Login finishes by creating a normal session via
//!   [`super::session::create`], so everything downstream is unchanged.
//! * The PRF extension can later unwrap the ally's private key in the browser
//!   (§6, "unlock with a passphrase or a passkey PRF"); the server only stores
//!   another opaque wrapped blob for that.
