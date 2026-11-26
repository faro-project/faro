# Faro wire protocol, v1

**Status:** Draft, matches `crates/faro-proto` and `crates/faro-crypto` at protocol version 1.
**Audience:** anyone re-implementing Faro's signing, hashing or encryption (the web app's TypeScript port in `web/src/lib/crypto`, alternative clients) and security reviewers.

The Rust crates are the reference implementation. If this document and the code disagree, the code is right and this document has a bug.

Cross-implementation test vectors live in `crates/faro-crypto/tests/data/web-vectors.json`. The Rust test `web_vectors` and the web app's `npm test` both check them, and its `from_web` section holds what the TypeScript code wrapped and signed, which Rust must open and verify.

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
| `faro/device-endorsement/v2` | Member-signed device key, with the `min_manifest` anchor |
| `faro/member-enc-key/v1` | Member's own encryption key binding |
| `faro/recipient-manifest/v1` | Member-signed, versioned recipient list (§5.1) |
| `faro/key-id/v1` | Key identifier |
| `faro/safety-code/v1` | Safety code |
| `faro/wrapped-secret/v1` | AAD for passphrase-wrapped secrets |
| `faro/key-rewrap/v1` | Member-signed replacement of their wrapped keys (§4.3) |
| `faro/ally-key-rewrap/v1` | Challenge-proven replacement of an ally's wrapped key (§4.3) |

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

Context-only signals (VPN, VM, remote desktop, browser without the extension) are **not** sent as `tamper` events. They appear in the daily report's `health.context`.

An interactive session of any OS account with no connected agent for 90 s **is** a `tamper` event (urgent floor), `unmonitored_user_session` with the account's short name: every account on the computer is monitored (ARCHITECTURE §3.1).

A window hidden from screen capture is a `tamper` event (urgent floor), `window_hidden_from_capture` with `app`: the app's display name (or its bundle id when it has none), at most 64 characters, never a window title (ARCHITECTURE §3.7). It is appended to the agent ↔ service IPC's positional `TamperSignal` mirror, so older variants keep their positions; an agent and service of different versions that don't both know it can't exchange it, which the package avoids by shipping them together.

A `capture_failing` tamper event is raised for repeated failed captures, and also when the session at the screen has a connected agent that nothing is captured from: no capture attempt for the longest regular interval plus two mean intervals of awake time, while no member pause, lock, idle or sleep explains it. `consecutive_failures` then counts the captures missed at the mean interval.

When the failures are because Screen Recording is off, the event is `permission_revoked` (`permission: "screen_recording"`) instead, and no `capture_failing` follows for the same run of failures. Its optional `never_granted` (boolean, default `false`, left out when `false`) is `true` when the device never saw the permission granted to that account on this enrollment, rather than saw it turned off. Readers must accept bodies without it, and readers that predate it read the event as a permission turned off. The agent ↔ service IPC doesn't carry the field: only the service decides it.

`flag` and `tamper` bodies carry an optional `account` field: the short name of the OS account the event came from, when it concerns one session (ARCHITECTURE §3.6). Report flagged moments, tamper records and timeline spans carry it too. It is inside the encrypted body, so the instance never sees it. Readers must accept bodies without it.

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
- Recovery codes are 160 random bits written as 8 groups of 4 Crockford-base32 characters. They are used as a second passphrase that wraps the same secret. The passphrase bytes are the code in its canonical form: uppercase, groups joined by `-` (`7K2M-…`). Clients normalize what a person types first: case, spaces and dashes don't matter, `I` and `L` read as `1`, and `O` as `0`.
- Readers must ignore fields they don't know, and must refuse parameters they can't afford. The web app accepts `m_cost_kib` up to 1 GiB (Rust: 4 GiB).

**What the instance stores.** The wrapped secrets are opaque to the server, which only checks that each one is a JSON object of at most 8 KiB. The web app writes them like this:

| Field | Contents |
|---|---|
| `PUT /v1/me/keys` `wrapped_sign_key` | The member's Ed25519 seed (32 bytes) under the passphrase |
| `PUT /v1/me/keys` `wrapped_enc_key` | The member's X25519 secret (32 bytes) under the passphrase, with the **same salt and parameters** as `wrapped_sign_key` (its own random nonce), so unlocking costs one Argon2id run |
| `PUT /v1/me/keys` `recovery_wrapped` | `{"sign": WrappedSecret, "enc": WrappedSecret}`: the same two secrets under the recovery code, sharing one derivation likewise |
| `POST /v1/invites/{token}/accept` `wrapped_privkey` | The ally's X25519 secret under the passphrase, as a `WrappedSecret`, plus a `"recovery"` field: the same secret under the recovery code. A reader that knows only `WrappedSecret` ignores `recovery` and still opens it with the passphrase |

After unlocking, clients check the secrets against the public keys stored next to them (and the member's `enc_binding` signature), so a modified blob can't substitute other keys.

**Changing the passphrase.** The keys never change, only their wrapped copies: `PUT /v1/me/keys/wrapped` takes a member-signed `KeyRewrap`, flattened with `sig` like an endorsement:

| Field | Type | Notes |
|---|---|---|
| `instance_id` | string | |
| `member_id` | string | |
| `sign_pubkey` | 32 bytes | The member's signing key, which must be the stored one |
| `issued_at_ms` | i64 | Within 5 minutes of the instance's clock, and later than the last change |
| `wrapped_sign_key`, `wrapped_enc_key`, `recovery_wrapped` | string | The **JSON text** of each new value, exactly as signed; the instance verifies, then parses and stores it |

`signing_bytes = Canonical("faro/key-rewrap/v1").str(instance_id).str(member_id).fixed(sign_pubkey).i64(issued_at_ms).str(wrapped_sign_key).str(wrapped_enc_key).str(recovery_wrapped)`.

The instance can't tell a good wrapped key from garbage, so the signature is what stops a stolen session from overwriting a member's keys and locking them out. Carrying the values as signed text means nobody has to canonicalize JSON. The freshness rules stop an old request from being replayed to restore an old passphrase.

**Changing an ally's passphrase.** The ally key is X25519 and can't sign, so possession is proven with a challenge instead. The stored format doesn't change (the `wrapped_privkey` row above), and neither does the key, so members see the same safety code and devices the same endorsement.

1. `POST /v1/me/ally-key/challenge` returns `{enc_pubkey, issued_at_ms, sealed_challenge}`: 32 bytes sealed to the ally's key (`crypto_box_seal`, base64url). The instance computes the challenge as a keyed hash (with its token-hashing key) over the ally's id, their key, `issued_at_ms` and the stored `wrapped_privkey`, so it keeps no state, and once the wrapping changes, every earlier challenge stops matching.
2. The browser opens it and sends `PUT /v1/me/ally-key/wrapped`: an `AllyKeyRewrap`, flattened with `proof`:

| Field | Type | Notes |
|---|---|---|
| `instance_id` | string | |
| `ally_id` | string | The signed-in account |
| `enc_pubkey` | 32 bytes | Must be the stored ally key: it can be re-wrapped, never replaced |
| `issued_at_ms` | i64 | From the challenge; refused once more than 5 minutes old |
| `wrapped_privkey` | string | The **JSON text** of the new value, exactly as proven; the instance checks it, then parses and stores it |
| `proof` | `b3:<hex>` | `BLAKE3-keyed(challenge, proof_bytes)` |

`proof_bytes = Canonical("faro/ally-key-rewrap/v1").str(instance_id).str(ally_id).fixed(enc_pubkey).i64(issued_at_ms).str(wrapped_privkey)`.

The browser never sends the opened challenge itself, only a MAC keyed with it. Otherwise a hostile instance could pass off an item's sealed key as a "challenge" and have the ally's browser open it. Before uploading, the browser opens each new copy it made, from the exact text it will send, and checks that the secret inside has the stored public key, because a bad copy would lock the ally out of every member they support. Members' browsers do the same check before `PUT /v1/me/keys/wrapped`. Neither change notifies anyone.

## 5. Trust: endorsements

The member's Ed25519 signing key is the root of trust for their key directory. The instance stores endorsements but cannot forge them.

- `DeviceEndorsement {instance_id, member_id, device_id, device_sign_pubkey, endorsed_at_ms}`: the member vouches for a device key.
- `AllyEndorsement {instance_id, member_id, ally_id, ally_enc_pubkey, endorsed_at_ms}`: the member approves an ally's encryption key.
- `MemberEncKeyBinding {instance_id, member_id, member_enc_pubkey, endorsed_at_ms}`: the member binds their own encryption key.

On the wire, each one is the struct's JSON fields flattened together with `"sig"`.

A device **pins the member's signing key at enrollment**, and everything it trusts must be signed by that key. Endorsements record individual approvals, but they **cannot express removal**: a removed ally's old endorsement still verifies. So devices do not pick recipients from endorsements. They use the recipient manifest (§5.1).

### 5.1 Recipient manifest

`RecipientManifest` is a single member-signed, versioned list of everyone a device may encrypt to:

| Field | Type | Notes |
|---|---|---|
| `instance_id` | string | |
| `member_id` | string | |
| `version` | u64 | Starts at 1 and goes up by exactly 1 with every change |
| `issued_at_ms` | i64 | |
| `member_enc_pubkey` | 32 bytes | The member's own X25519 key |
| `allies` | list | `{ally_id, enc_pubkey}` entries, at most 32, sorted strictly ascending by `ally_id` |

- **Encoding:** `signing_bytes = Canonical("faro/recipient-manifest/v1").str(instance_id).str(member_id).u64(version).i64(issued_at_ms).fixed(member_enc_pubkey).u64(len(allies))`, followed by `.str(ally_id).fixed(enc_pubkey)` for each ally in order.
- **Identity:** a manifest's identity is `hash = BLAKE3(signing_bytes)`. A `ManifestRef` is `{version, hash}`.
- **Uploads:** the member signs a new version whenever they approve or remove an ally, an ally's key rotates, or their own encryption key rotates. The instance stores the latest version and serves it at `GET /v1/members/{id}/recipient-manifest`.

**Device rules.** The device keeps a persisted checkpoint: the highest `ManifestRef` it has accepted, **together with that signed manifest itself**. Both are stored atomically in the outbox database. Storing the document, not just its ref, is what lets a device that restarts while offline, or whose instance withholds manifests, keep using its last accepted manifest.

**Bootstrapping (first manifest).** Version checks only protect a device that already has a checkpoint. A freshly enrolled or reinstalled device must not trust whatever the instance serves first, which could be a pre-removal manifest. So the member-signed `DeviceEndorsement` carries `min_manifest: ManifestRef`, the manifest current when the member approved the device. A device accepts its first manifest only if it is at or above that version, and, at exactly that version, has that hash. The device stays `pending` (it seals nothing) until it holds its endorsement. A client that has no anchor must opt into trust-on-first-use explicitly; it never falls into it by default.

A fetched manifest is accepted only if all of the following hold:

1. It passes `validate()`: version ≥ 1, at most 32 allies, ids well formed, sorted and unique, and the member not listed as their own ally. This check runs **before** the signature, because it needs no keys and bounds the encoding and hashing work a hostile document can cause. The result for a bad document is the same rejection either way.
2. Its signature verifies against the **pinned** member signing key.
3. `instance_id` and `member_id` match the enrollment.
4. No key in it is a small-order X25519 point.
5. Against the checkpoint (or, for the first manifest, against the `min_manifest` anchor):
   - a lower `version` is **rollback**: reject it;
   - the same `version` with a different `hash` is **equivocation**: reject it;
   - the same `version` and `hash` means nothing changed;
   - a higher `version` is accepted, and the checkpoint advances.

On any rejection the device keeps using its last accepted manifest and surfaces a warning to the member. It **never** falls back to endorsements.

**Recipients:** for every new item, the recipients are the member plus exactly the allies in the accepted manifest. The device refuses to queue anything sealed to a manifest other than its current checkpoint, so a stale recipient set held in memory can't keep encrypting to a removed ally.

**Fetch limits:** clients cap the response body of `GET /v1/members/{id}/recipient-manifest` at 64 KiB before JSON parsing. A maximal manifest (32 allies, bounded ids) is a few KiB.

**Limits** (documented, not solved by v1):

- **Removal is forward-only.** A removed ally can still decrypt items sealed to them before the device accepted the new manifest. No scheme can take back a key that was already shared. The instance limits the damage: it serves an ally a blob only if the item was received while that ally held an active link. Being approved again later never opens items from the gap.
- **Withholding.** A malicious instance can delay delivering a newer manifest, though it can't forge one or roll one back. The planned mitigations:
  - the tray UI and the monthly consent notice show the ally list the device is actually using;
  - the member's own client can hand a newly signed manifest to the device locally;
  - reports will carry the `ManifestRef` used, so the ally web app can flag a device still encrypting to an outdated list.

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

Refusals a device can act on (every other credential failure is a plain `401 unauthorized`):

| Response | Meaning |
|---|---|
| `403 device_pending_endorsement` | Enrolled, but the member hasn't approved it yet. Only heartbeats and key and status fetches are allowed. |
| `403 device_removed` | The member removed this device. Sent only when the token **and** the signature check out. |
| `403 account_deleted` | The account this device reported to was deleted. Sent on the token alone, because the device's key was deleted with the account. The instance keeps the token's keyed hash for 365 days. |

The last two are final. Allies were told when each happened (`device_removed`, `account_deleted`), so `faro-service goodbye` writes nothing and lets an uninstall go ahead.

## 7. Heartbeats

Heartbeats are **not** chain events, so 288 pings a day don't grow the chain. A `Heartbeat` carries `{instance_id, device_id, ts_ms, mono_ms, boot_id, state, last_seq?, last_hash?}` and is signed under `faro/heartbeat/v1`. `state` is one of `active`, `idle`, `locked`, `paused`, `sleeping` or `shutting_down`.

The instance uses these fields for liveness and to tell the device which `seq` it holds (`acked_through`). It also returns `server_time_ms`, which the device compares with its own clock to detect clock tampering.

`last_seq` and `last_hash` are checked against what the instance holds:

- **Upload stall.** If `last_seq` stays ahead of the highest event the instance has verified for longer than the liveness grace period, the device is alive but not uploading what it records. The instance raises one urgent `upload_stalled` alert per stall.
- **Fork.** If `last_seq` names an event the instance holds but `last_hash` differs from that event's chain hash, the device's history differs from what it uploaded. The instance raises an urgent `chain_gap` alert. So `last_hash` must be the `chain_hash` of the event at `last_seq`.

Both alerts are tamper-class: allies can move them to the digest but not turn them off.

## 8. Updates

Releases are signed by the project with TUF-style metadata (`faro-update`; the roles, threshold, rollback and freeze rules are documented in `crates/faro-update/src/lib.rs`, and the keys are made and rotated as in [KEY-CEREMONY.md](KEY-CEREMONY.md)). Every document is a DSSE-style envelope whose signatures cover `PAE(payload_type, payload)` under the tag `faro/update-envelope/v1`, with payload types `application/vnd.faro.{root,targets,timestamp}+json`.

### 8.1 Layout

The project's publishing location, a release directory for an air-gapped import, and an instance's mirror all use the same layout. An instance serves it under `/v1/updates`:

| Path | Content |
|---|---|
| `roots/<n>.json` | Root version `n`, for `n >= 2`. Root 1 ships with every client and server. |
| `timestamp.json` | The current timestamp: commits to the exact length and BLAKE3 of `targets.json`. |
| `targets.json` | The artifact list: target name → length, BLAKE3, `{kind, platform, arch, version, channels, min_os?, min_client?}`. |
| `targets/<name>` | An artifact, under its target name. |

`kind` is `client`, `model`, `blocklist` or `server`. `min_client` (semver, optional) is the oldest client that may install the target. Clients skip targets above their own version and take the newest one they can use; it is meant for models and blocklists that need a newer client than the oldest one that fetches them.

**Models and blocklists.** A model or a domain list is two files: a JSON manifest (a model's `faro_detect::ModelInfo`, or the `faro-domains-manifest/1` that `domains-compile` writes) and the file it names. One target carries both, as a *data bundle* (`faro_update::bundle`):

| Offset | Size | Content |
|---|---|---|
| 0 | 8 | `FARODATA` |
| 8 | 1 | format version, `1` |
| 9 | 4 | manifest length `m`, big-endian, 1 to 1 MiB |
| 13 | `m` | the manifest, byte for byte |
| 13 + `m` | rest | the file the manifest names (the model, or the domain bundle) |

The target's BLAKE3 covers the whole bundle, and the manifest pins the file's BLAKE3. Such targets have platform and arch `any`, and their `version` is the manifest's `version` (semver), not a client release's. The release workflow names them `<kind>/any/<name>-<version>-<first channel>.data` (`+` in the version becomes `_`), for example `model/any/opennsfw-1.0.0_int8-stable.data`: a version listed for `beta` and later for `stable` is two entries with the same bytes.

`GET /v1/updates` returns `{"available": bool, "channel": "<channel>"}`: whether the instance has verified metadata to serve, and the channel its admin chose (`stable`, `beta`, … or the pin `stable-1`). Every path under `/v1/updates` is public: the content is project-signed, and a member's browser may download the installer from it.

### 8.2 Client rules

A client trusts the root it shipped with, never the instance. On each check it:

1. fetches `roots/<v+1>.json` until a 404, verifying each rotation against the previous root;
2. fetches and verifies `timestamp.json`, then `targets.json`, which must match the timestamp's commitment byte for byte (a mirror that switches release between the two requests is retried later);
3. selects for its platform, arch and OS version in the instance's channel, never below its installed version;
4. downloads the artifact, reading at most the signed length plus one byte, and keeps it only if length and BLAKE3 match;
5. on macOS, checks the package's own signature before installing it: a Developer ID Installer certificate that chains to Apple's Developer ID CA, from the Team ID the installed client was built with, and notarized (Gatekeeper accepts it as "Notarized Developer ID");
6. on macOS, reads the version inside the package and installs it only if that version equals the target's `version` and is above the installed version (semver precedence, so `0.1.0-beta.1 < 0.1.0`).

It persists its trust state after every step, including failed ones. The instance chooses the channel, so it can hold clients back or move them between channels, but it can't make them install anything the project didn't sign or go back to an older release.

**Models and blocklists** use the same steps 1 to 4, the same trust state and the same channel, after the client package (not while a client install has just started). A client checks for models only if it can run them (ONNX Runtime), and for blocklists always. It selects kind `model` or `blocklist` with `min_client` against its own version, and installs the target only if its version is above the copy its package ships, above the one it installed before, and not below the highest it ever installed: a model or a blocklist never goes back. Then, instead of steps 5 and 6:

1. it unpacks the bundle into a new directory in its state directory (`artifacts/<kind>/`), taking the file name from the manifest (a plain file name only);
2. it checks it exactly as the packaged copy is checked: a model with `load_model` (the licence allowlist, the attribution and licence text the licence asks for, the weights' BLAKE3), a manifest `version` equal to the target's, at least one label the client's policy reads as explicit, and ONNX Runtime loading it; a blocklist with `load_domains` (approved sources only, allowlisted licences, their attribution and texts, the bundle's length, BLAKE3 and domain count) and the same version check;
3. only then it moves the directory into place, writes the notice next to the packaged ones, and records it (`update-artifacts.json`, with the manifest's BLAKE3);
4. it hands the model or list to the detector, which switches between two captures without a restart. No frame is involved.

A bundle that fails step 2 was signed but can't be used: it is not installed, it is recorded by BLAKE3 and never downloaded again, and nothing else changes. It is not tamper (nothing on the computer changed), so it is logged, not reported. At each start the service uses the installed copy if it is newer than the packaged one and its manifest still has the recorded BLAKE3 and passes step 2 again; otherwise it uses the packaged copy. An installed copy that no longer matches is reported as an urgent `integrity_failure` (`image model update (changed)`, `domain list update (changed)`) and removed, and the next check installs it again. One that is no newer than the packaged copy (the client was updated since) is removed quietly.

There is no second layer like steps 5 and 6 for models: the metadata alone decides. ONNX Runtime parses the model, so a model signed with leaked targets and timestamp keys reaches a parser that is not built for hostile input (KEY-CEREMONY.md §4.2).

**Steps 5 and 6 are a second layer.** The metadata (steps 1 to 4) decides what to install. The package signature only stops a package the metadata approved but Faro's Apple identity didn't sign, for example if the targets and timestamp keys leak (KEY-CEREMONY.md §4.2). The Team ID is compiled into the client (`FARO_TEAM_ID`, the value `ipc.agent_requirement` is built from), never read from the update, its metadata or the mirror. The checks are `pkgutil --check-signature` and `spctl --assess --type install` (`crates/faro-service/src/update/signature.rs`):

- **Rejected** (unsigned, another team, not a Developer ID Installer certificate): not installed and never retried. The service reports it as a tamper-class `integrity_failure` (ARCHITECTURE.md §3.7), once each time it starts while the metadata still offers that package.
- **Unconfirmed** (a tool failed, Gatekeeper didn't confirm notarization, or the client has no Team ID): not installed, and tried again at the next check.
- **Offline:** release packages carry a stapled notarization ticket, so the check needs no connection to Apple. Without a ticket Gatekeeper asks Apple; offline that is unconfirmed, never a pass.
- **Development builds** (the `dev` feature, no Team ID) skip step 5. A build without the `dev` feature never does: without a Team ID it installs nothing.

**Step 6 stops a signed package listed under another version.** Without it, someone holding the targets and timestamp keys could list an old release Faro really signed, say `0.1.0-beta.1`'s package, as `99.0.0`. Its signature passes, so the client would go back to that release while it thinks it upgraded. Rollback protection in the metadata doesn't help, because the metadata is what lies. The version comes from the package itself:

- **Where.** `build-pkg.sh` passes the full semver version to `pkgbuild --version`, which writes it into the component's `PackageInfo` (`<pkg-info identifier="org.faro.pkg" version="…">`), and puts it in the Distribution's `pkg-ref`. Both must agree. The app bundle's version can't serve: bundle versions are plain integers (`0.1.0` for `0.1.0-beta.1`). `check-pkg.sh` checks both, and that the packaged `faro-service --version` reports the same version.
- **How.** The client reads the xar archive itself (`crates/faro-service/src/update/package_version.rs`). It runs nothing from the package and unpacks nothing to disk. It reads only the table of contents, `Distribution`, and the `PackageInfo` of the one component the Distribution installs. The table of contents must match the checksum the package signature covers, and both files their archived and extracted checksums in it. So the version read is in the bytes Faro signed.
- **Rejected:** the version isn't the target's or isn't above the installed one, the component isn't `org.faro.pkg`, or a checksum doesn't match. As in step 5: not installed, never retried, and reported as `integrity_failure`.
- **Unconfirmed:** the archive is in a form the reader doesn't know: an unsupported checksum or encoding, an entry missing or given twice, a version that isn't semver, or a `Distribution` and `PackageInfo` that disagree. Not installed, and tried again at the next check.
- **Development builds** run step 6 too.

### 8.3 What the mirror does

The mirror is configured with the same root of trust (`updates.root`) and runs the same verification before it stores anything. It serves exactly the bytes it verified. Artifacts are cached by BLAKE3. For each kind, platform and arch, an online mirror prefetches what its channel selects (models and blocklists included, the newest whatever its `min_client`) and fetches other listed artifacts on first request. `kind = server` artifacts are never fetched or served. A root older than the mirror's own (when the mirror started from a newer root file than a client) is passed through from upstream unverified, because the client verifies it.

## 9. Deviations from ARCHITECTURE.md v0.2

| Topic | ARCHITECTURE.md | Protocol v1 | Why |
|---|---|---|---|
| Timestamp | RFC 3339 `ts` | `ts_ms` (Unix ms) | Unambiguous canonical encoding, trivial in TS |
| Hash chain input | header + ciphertext | header only, which commits to `body_hash` | Chain stays verifiable after body blobs expire |
| `heartbeat` kind | An event kind | A separate signed message | Keeps the chain small, and liveness doesn't depend on upload order |
| Context signals | Listed in the tamper table | Daily report only | The `tamper` kind is floored to `urgent` |
