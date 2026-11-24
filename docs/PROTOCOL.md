# Faro wire protocol, v1

**Status:** Draft, matches `crates/faro-proto` and `crates/faro-crypto` at protocol version 1.
**Audience:** anyone re-implementing Faro's signing, hashing or encryption (the TypeScript ally web app, alternative clients) and security reviewers.

The Rust crates are the reference implementation. If this document and the code disagree, the code is right and this document has a bug.

---

## 1. Principles

- **JSON is transport only.** Nothing is signed or hashed as JSON. Every signed or hashed structure has a *canonical byte encoding* (§2), built field by field.
- **Every canonical encoding starts with a domain-separation tag**, so a signature over one structure can never be replayed as a signature over another.
- **The instance sees headers, never bodies.** Headers carry only what the instance needs for routing, liveness, chain verification and notification timing. Everything else is in an encrypted body.

## 2. Canonical encoding

A canonical byte string is built by appending, in order:

| Item | Encoding |
|---|---|
| Tag | ASCII bytes of the tag, then a single `0x00` byte |
| `u16`, `u64`, `i64` | Big-endian, fixed width |
| String / byte string | `u32` big-endian length, then the bytes (strings are UTF-8) |
| Fixed-size value (hash, key) | Raw bytes, no length prefix |
| `Option<u64>` | `u64`: `0` for none, `n + 1` for `Some(n)` |

Tags in use:

| Tag | Structure |
|---|---|
| `faro/event-header/v1` | Event header (§3) |
| `faro/genesis/v1` | Genesis `prev_hash` |
| `faro/event-body/v1` | Event body AAD |
| `faro/report-header/v1` | Report header |
| `faro/report-body/v1` | Report body AAD |
| `faro/heartbeat/v1` | Heartbeat |
| `faro/request/v1` | Device request signature |
| `faro/ally-endorsement/v1` | Member-signed ally key |
| `faro/device-endorsement/v1` | Member-signed device key |
| `faro/member-enc-key/v1` | Member's own encryption key binding |
| `faro/key-id/v1` | Key identifier |
| `faro/safety-code/v1` | Safety code |
| `faro/wrapped-secret/v1` | AAD for passphrase-wrapped secrets |

## 3. Events and the hash chain

### 3.1 Header

| Field | Type | Notes |
|---|---|---|
| `v` | u16 | `1` |
| `instance_id` | string | `inst_…` |
| `device_id` | string | `dev_…` |
| `seq` | u64 | Strictly increasing per device, starting at `0` |
| `prev_hash` | 32 bytes | Chain hash of the previous event, or the genesis hash for `seq = 0` |
| `ts_ms` | i64 | Wall clock, Unix milliseconds |
| `mono_ms` | u64 | Monotonic milliseconds since boot |
| `boot_id` | string | Opaque, per boot |
| `kind` | string | `capture`, `flag`, `tamper`, `settings_change`, `agent_restarted`, `paused`, `resumed`, `goodbye`, `boot`, `shutdown` |
| `urgency` | string | `none`, `normal`, `urgent` |
| `body_hash` | 32 bytes | `BLAKE3(nonce ‖ ciphertext)` of the encrypted body, or 32 zero bytes if there is none |
| `body_len` | u64 | Ciphertext length, or `0` |

`signing_bytes` encodes these fields in table order under the tag `faro/event-header/v1`. `kind` and `urgency` are encoded as their strings.

- **Signature:** Ed25519 (strict verification) by the device key over `signing_bytes`.
- **Chain hash:** `BLAKE3(signing_bytes)`. The next event's `prev_hash` must equal it.
- **Genesis hash:** `BLAKE3(Canonical("faro/genesis/v1").str(instance_id).str(device_id))`.

Because the header commits to the body through `body_hash`, the instance can verify the whole chain from headers alone, even after retention has deleted the body blobs.

### 3.2 Verification outcomes

`faro_crypto::chain::verify_next` checks a header against the stored chain head:

| Situation | Result | Instance action |
|---|---|---|
| `seq == next_seq` and `prev_hash` matches | `Contiguous` | Store |
| `seq > next_seq` | `Gap` | Store, raise an urgent `chain_gap` alert |
| `seq == next_seq` but `prev_hash` differs | `Fork` | Reject, raise an urgent alert (history was rewritten) |
| `seq < next_seq` | `Behind` | `duplicate` if the header hash matches what is stored, otherwise reject and raise an alert |
| Bad signature | `BadSignature` | Reject, raise an urgent `invalid_signature` alert |

### 3.3 Urgency floor

The member controls the device, so a modified client could sign a tamper event as `none`. The instance stores the signed header verbatim but computes `effective_urgency = max(header.urgency, kind.min_urgency())`:

| Kind | Floor |
|---|---|
| `tamper`, `goodbye` | `urgent` |
| `settings_change`, `paused`, `resumed` | `normal` |
| everything else | `none` |

Context-only signals (VPN, VM, remote desktop, browser without the extension, an unmonitored user session) are **not** sent as `tamper` events. They appear in the daily report's `health.context`.

## 4. Encryption

### 4.1 Items

Every encrypted item (an event body or a report) uses the same layout:

1. Generate a random 32-byte content key (CK) and a 24-byte nonce.
2. `ciphertext = XChaCha20-Poly1305(CK, nonce, plaintext, aad)`.
3. For each recipient, `wrapped_key = crypto_box_seal(CK, recipient_x25519_pubkey)` (libsodium sealed box).

```json
{
  "alg": "xchacha20poly1305",
  "nonce": "<base64url>",
  "ciphertext": "<base64url>",
  "envelopes": [{ "recipient": "usr_…", "key_id": "<16 hex>", "wrapped_key": "<base64url>" }]
}
```

The recipients are every active ally **and the member** (§5.1 transparency).

The AAD binds a ciphertext to its context, so the instance cannot swap bodies between events:

| Item | AAD |
|---|---|
| Event body | `Canonical("faro/event-body/v1").str(instance_id).str(device_id).u64(seq)` |
| Report body | `Canonical("faro/report-body/v1").str(instance_id).str(device_id).i64(period_start_ms).i64(period_end_ms)` |

The plaintext is UTF-8 JSON of `EventBody` (tagged by `"type"`) or `DailyReport`. The only image type that can appear in it is `BlurredThumbnail`, a PNG that was blurred before encryption.

### 4.2 Key identifiers and safety codes

- `key_id(pk)` is the first 8 bytes of `BLAKE3(Canonical("faro/key-id/v1").bytes(pk))`, as lowercase hex.
- `safety_code(a, b)`: sort the two keys bytewise, compute `h = BLAKE3(Canonical("faro/safety-code/v1").bytes(lo).bytes(hi))`, then take 60 bytes of BLAKE3 XOF output from `h`. Map each byte `b` to the digit `b mod 10` and print the result as 12 groups of 5 digits.

### 4.3 Passphrase wrapping

The member and ally private keys are wrapped in the browser and stored on the instance as an opaque `WrappedSecret`:

```json
{ "v": 1, "kdf": "argon2id13", "params": { "m_cost_kib": 65536, "t_cost": 3, "p_cost": 1 },
  "salt": "<16 bytes b64url>", "nonce": "<24 bytes b64url>", "ciphertext": "<b64url>" }
```

- The key is derived with Argon2id v1.3 and `p = 1`, which matches libsodium's `crypto_pwhash_ALG_ARGON2ID13`. The cipher is XChaCha20-Poly1305 with AAD `faro/wrapped-secret/v1`.
- Recovery codes are 160 random bits written as 8 groups of 4 Crockford-base32 characters. They are used as a second passphrase that wraps the same secret.

## 5. Trust: endorsements

The member's Ed25519 signing key is the root of trust for their key directory. The instance stores endorsements but cannot forge them.

- `DeviceEndorsement {instance_id, member_id, device_id, device_sign_pubkey, endorsed_at_ms}`: the member vouches for a device key.
- `AllyEndorsement {instance_id, member_id, ally_id, ally_enc_pubkey, endorsed_at_ms}`: the member approves an ally's encryption key.
- `MemberEncKeyBinding {instance_id, member_id, member_enc_pubkey, endorsed_at_ms}`: the member binds their own encryption key.

On the wire, each one is the struct's JSON fields flattened together with `"sig"`.

A device **pins the member's signing key at enrollment**. It only encrypts to ally keys whose endorsements verify against that pinned key and name the same `instance_id` and `member_id`. Endorsements that fail are ignored, so a curious or compromised instance cannot add an eavesdropping key.

## 6. Device request authentication

Every device request carries:

```
Authorization: Bearer <device_token>
faro-device: dev_…
faro-timestamp: <unix ms>
faro-signature: <base64url Ed25519 over request_signing_bytes>
```

`request_signing_bytes = Canonical("faro/request/v1").str(METHOD).str(path_and_query).str(device_id).i64(ts_ms).fixed(BLAKE3(body))`

The instance rejects requests whose timestamp is more than 5 minutes off its own clock.

## 7. Heartbeats

Heartbeats are **not** chain events, so 288 pings a day don't grow the chain. A `Heartbeat` carries `{instance_id, device_id, ts_ms, mono_ms, boot_id, state, last_seq?, last_hash?}` and is signed under `faro/heartbeat/v1`. `state` is one of `active`, `idle`, `locked`, `paused`, `sleeping` or `shutting_down`.

The instance uses these fields for liveness and to tell the device which `seq` it holds (`acked_through`). It also returns `server_time_ms`, which the device compares with its own clock to detect clock tampering.

## 8. Deviations from ARCHITECTURE.md v0.2

| Topic | ARCHITECTURE.md | Protocol v1 | Why |
|---|---|---|---|
| Timestamp | RFC 3339 `ts` | `ts_ms` (Unix ms) | Unambiguous canonical encoding, trivial in TS |
| Hash chain input | header + ciphertext | header only, which commits to `body_hash` | Chain stays verifiable after body blobs expire |
| `heartbeat` kind | An event kind | A separate signed message | Keeps the chain small, and liveness doesn't depend on upload order |
| Context signals | Listed in the tamper table | Daily report only | The `tamper` kind is floored to `urgent` |
