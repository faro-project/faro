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
| `faro/recipient-manifest/v1` | Member-signed, versioned recipient list, format 1 (§5.1) |
| `faro/recipient-manifest/v2` | The same list in format 2, with the allies' names (§5.1) |
| `faro/recipient-manifest/v3` | The same list in format 3, with the names and the hash of the previous version (§5.1) |
| `faro/key-id/v1` | Key identifier |
| `faro/safety-code/v1` | Safety code |
| `faro/wrapped-secret/v1` | AAD for passphrase-wrapped secrets |
| `faro/key-rewrap/v1` | Member-signed replacement of their wrapped keys (§4.3) |
| `faro/ally-key-rewrap/v1` | Challenge-proven replacement of an ally's wrapped key (§4.3) |
| `faro/group-roster/v1` | Facilitator-signed group roster entry (§10.2) |
| `faro/group-roster-genesis/v1` | `prev_hash` of a group's first roster entry (§10.2) |
| `faro/group-roster-snapshot/v1` | Facilitator-signed roster snapshot (§10.5) |
| `faro/group-epoch-key/v1` | Commitment to a group epoch key (§10.3) |
| `faro/group-safety-code/v1` | Group safety code (§10.8) |
| `faro/group-message/v1` | Author-signed group message: a reach out, a note, a check-in or a reply (§11) |
| `faro/group-message-epoch/v1` | AAD under which an epoch key wraps a whole-group message's content key (§11.2) |
| `faro/group-message-body/v1` | Group message body AAD (§11) |

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

### 3.4 iPhone additions

An iPhone enrolls with `platform: "ios"` (`POST /v1/devices/enroll`). It blocks rather than watches (docs/IOS.md), so it sends no thumbnails. Everything below is additive: readers must accept bodies without the new fields, and no signed or hashed encoding changes, so `PROTOCOL_VERSION` stays 1. Every new body is inside the encrypted body; the instance sees only the usual header.

**Tamper signals.** Three new `tamper` signals, all active tamper and so floored at `urgent` like every `tamper` event, and tamper-class (`notify::policy::is_tamper_class` picks them out by kind):

| `signal` | Fields | Meaning |
|---|---|---|
| `screen_time_revoked` | none | Screen Time authorization is no longer approved, so Faro can be deleted. |
| `filter_off` | `cause`: `vpn_disconnected`, `on_demand_off`, `other_vpn`, `profile_removed` or `unknown` | The DNS filter is off, and how the phone could tell. |
| `settings_cleared` | none | Faro's Screen Time settings were found cleared or changed while authorization stands. |

Three new context-only signals, `doh_dropped`, `other_vpn` and `jailbreak_suspected` (no fields), are not sent as `tamper` events. They appear in the daily report's `health.context` like the desktop ones. The agent to service IPC mirror does not carry any of the six: only an iPhone produces them.

**Android.** An Android phone enrolls with `platform: "android"` and watches like a computer (docs/ANDROID.md), so it reuses the desktop's signals (`permission_revoked` with `permission` `accessibility_service` or `device_admin`; `accessibility` stays the Mac's window-title permission, `window_hidden_from_capture`, `capture_failing`). It adds two context-only signals with no fields, `battery_optimization_on` and `usb_debugging_on`, which appear in `health.context` only. The IPC mirror doesn't carry them: the Android app runs the service in its own process.

**Blocked lookups and shields.** Two new body types, both `capture`-class: the header `kind` is `capture` and the urgency is `none`.

- `blocked_summary`: `bucket_start` (ms since the epoch), `bucket_secs`, `by_category` (category to count), `hosts` (a list of `{host, category, count}`, the host only, never a path or query) and `other_hosts` (blocked lookups of hosts not listed).
- `shield_summary`: `bucket_start`, `bucket_secs`, `shown` and `closed`. Counts only, never app names.

**Flags from DNS bursts.** A burst of blocked lookups is an ordinary `flag`. Its reason has source `dns`, and the label carries the explanation, for example `dns:adult ×6, 4 hosts, 3 min, screen on`.

**Pending loosening.** A `settings_change` body gains optional `requested_at`, `takes_effect_at` and `cancelled_at` (ms since the epoch) and `delay_secs`. They are left out when not set. A change that blocks more carries none of them. A loosening is sent when it is asked for (`requested_at`, `takes_effect_at`, `delay_secs`), again when it takes effect (the same fields) and, if the member cancels it, with `cancelled_at`.

**iPhone setting keys.** An iPhone's `settings_change` entries (`key`, `old`, `new`) use this vocabulary, which the web app renders in words ("Gambling sites will be unblocked on iPhone-X tomorrow at 21:04"). The code is `apps/ios/FaroKit/Sources/FaroKit/Choices.swift` and `web/src/lib/feed/ios-settings.ts`.

| Key | Values |
|---|---|
| `ios.category.<name>` (`gambling`, `violence`, `proxy_vpn`) | `blocked` or `allowed` |
| `ios.site` | `old` is the domain when it was unblocked, `new` when it was blocked |
| `ios.apps`, `ios.app_categories`, `ios.web_domains`, `ios.web_domain_categories` | how many are blocked, as a number. Which ones is never sent: Screen Time hides them |
| `ios.explicit_media`, `ios.app_removal_protection`, `ios.automatic_time` | `on` or `off` |
| `ios.app_rating` | `4`, `9`, `12`, `17` or `off` |
| `ios.delay_hours` | the loosening delay in hours, `0` to `72` |

A reader that doesn't know a key shows it as `key: old → new`.

**Allies see** these in the web app and reports, which render them from the decrypted body: "Screen Time protection is off on iPhone-X", "Faro's web filter is off on iPhone-X", "Faro's Screen Time settings were changed on iPhone-X". Alert emails stay content-free (the instance cannot tell which signal it was).

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
| `format` | u16 | `1`, `2` or `3`. Left out of format 1 JSON, and a missing `format` reads as `1` |
| `instance_id` | string | |
| `member_id` | string | |
| `version` | u64 | Starts at 1 and goes up by exactly 1 with every change, whatever the format |
| `prev_hash` | hash | Format 3 only: the `hash` of version `version - 1`, the list this one was built on. Present in every format 3 document above version 1; absent at version 1 and in formats 1 and 2 |
| `issued_at_ms` | i64 | |
| `member_enc_pubkey` | 32 bytes | The member's own X25519 key |
| `allies` | list | `{ally_id, enc_pubkey}` entries in format 1, `{ally_id, enc_pubkey, name}` in formats 2 and 3. At most 32, sorted strictly ascending by `ally_id` |

- **Encoding, format 1:** `signing_bytes = Canonical("faro/recipient-manifest/v1").str(instance_id).str(member_id).u64(version).i64(issued_at_ms).fixed(member_enc_pubkey).u64(len(allies))`, followed by `.str(ally_id).fixed(enc_pubkey)` for each ally in order.
- **Encoding, format 2:** the same fields under the tag `faro/recipient-manifest/v2`, followed by `.str(ally_id).fixed(enc_pubkey).str(name)` for each ally in order. `format` itself isn't encoded: the tag carries it.
- **Encoding, format 3:** as format 2 under the tag `faro/recipient-manifest/v3`, with `.fixed(prev_hash)` right after `.u64(version)`: `Canonical("faro/recipient-manifest/v3").str(instance_id).str(member_id).u64(version).fixed(prev_hash).i64(issued_at_ms).fixed(member_enc_pubkey).u64(len(allies))`, then `.str(ally_id).fixed(enc_pubkey).str(name)` for each ally. At version 1, which has no `prev_hash`, the 32 bytes are zero.
- **Identity:** a manifest's identity is `hash = BLAKE3(signing_bytes)`. A `ManifestRef` is `{version, hash}`.
- **Uploads:** the member signs a new version whenever they approve or remove an ally, an ally's key rotates, or their own encryption key rotates. The instance stores the latest version and serves it at `GET /v1/members/{id}/recipient-manifest`.

**Ally names (formats 2 and 3).** Devices show the allies by name (the monthly notice, ARCHITECTURE.md §12), and the only ally list a device trusts is this one. So the names are inside the member's signature: an instance can't put a false name next to a real key, swap two names, or name anyone the member didn't sign.

- **Where they come from.** The member's web app signs a new ally's display name as the instance gives it to that page, which shows it (the member approves "*name*"). Every other ally keeps the name the list it builds on signed, so an instance can't rename or swap allies by changing what it shows. The web app signs every new version in format 3.
- **Renames** don't force a new version: the instance never compares the names with its own. When the member signs a new version for any reason, the page shows each ally whose name on the instance differs from the signed one, and signs the new name only if the member ticks it.
- **Sanitizing.** Names are text people typed, so `sanitize_ally_name` (Rust, `faro_proto::keys`) and `sanitizeAllyName` (the web app) make them safe, the same way byte for byte. The web app applies it before signing, and devices apply it again before showing a name. In order:
  1. remove C0 controls (other than the ones in the next item), `DEL`, C1 controls (other than `NEL`), `U+061C`, `U+200E`, `U+200F`, `U+202A` to `U+202E`, `U+2066` to `U+2069`, `U+FEFF` and `U+FFF9` to `U+FFFB`; turn tab, line feed, vertical tab, form feed, carriage return, `NEL` (`U+0085`), `U+2028` and `U+2029` into a space;
  2. normalize to NFC;
  3. collapse runs of spaces (`U+0020`) into one, and trim them from both ends;
  4. keep at most 64 code points, then trim a trailing space again.

  The removed characters are an explicit list, not a Unicode property, so implementations agree whatever their Unicode version. The joiners (`U+200C`, `U+200D`) stay, because emoji and some scripts need them. The test vectors' `ally_names` section has inputs and outputs, and `from_web.manifest_v2` is a manifest the web app signed from raw names.
- **Verifying.** `validate()` refuses a format 1 manifest whose allies carry a `name` (it isn't signed), a format 2 or 3 manifest with an ally without one, a name longer than 256 bytes, a format 3 manifest above version 1 without a `prev_hash`, a `prev_hash` anywhere else, and any other `format`. It doesn't refuse a name that isn't in sanitized form: a device sanitizes it before showing it. Refusing would make every recipient change, removals included, depend on two Unicode implementations agreeing. An empty name (after sanitizing) is no name: the device shows that ally by safety code only.
- **The instance** stores and serves formats 2 and 3 like format 1. It checks names for length only (`validate()`), and compares ally sets by id and key, never by name. It also refuses a format 3 upload whose `prev_hash` isn't the hash of the latest version it stores (`manifest_prev_mismatch`).

**Fork links (format 3).** A version number alone can't tell a successor from a fork: if an instance serves the member's page an older list N-1 (which still names an ally removed at N) and the page signs a version N on it, a device at N refuses that as equivocation, but would accept the version N+1 signed on top of it. In format 3, each version names the hash of the one it was built on, so a device holding version N refuses an N+1 built on anything else (a **fork**, rule 5). The web app also refuses to build on an older list in the first place (below).

**Compatibility.** Format 1 and 2 manifests keep their exact JSON, bytes and hashes, and still verify everywhere, so a `min_manifest` anchor or a checkpoint that names one stays valid. A device holding a format 1 manifest shows its allies by count and safety code, as before. A version may change format either way; documents of two formats at the same version are different documents (equivocation). The first format 3 version after a format 1 or 2 one names that version's hash like any other. A client built before format 2 can't verify a format 2 manifest (it rejects it as a bad signature), and one built before format 3 refuses a format 3 manifest as an unknown format. Either way it keeps its last accepted list (the device rules below), so clients must understand a format before the member's web app signs it. **The web app signs format 3 since #180, so every enrolled client must accept format 3.**

**Device rules.** The device keeps a persisted checkpoint: the highest `ManifestRef` it has accepted, **together with that signed manifest itself**. Both are stored atomically in the outbox database. Storing the document, not just its ref, is what lets a device that restarts while offline, or whose instance withholds manifests, keep using its last accepted manifest.

**Bootstrapping (first manifest).** Version checks only protect a device that already has a checkpoint. A freshly enrolled or reinstalled device must not trust whatever the instance serves first, which could be a pre-removal manifest. So the member-signed `DeviceEndorsement` carries `min_manifest: ManifestRef`, the manifest current when the member approved the device. A device accepts its first manifest only if it is at or above that version, and, at exactly that version, has that hash. The device stays `pending` (it seals nothing) until it holds its endorsement. A client that has no anchor must opt into trust-on-first-use explicitly; it never falls into it by default.

A fetched manifest is accepted only if all of the following hold:

1. It passes `validate()`: a known format, version ≥ 1, at most 32 allies, ids well formed, sorted and unique, the member not listed as their own ally, names only in formats 2 and 3, at most 256 bytes each, and a `prev_hash` exactly in format 3 above version 1. This check runs **before** the signature, because it needs no keys and bounds the encoding and hashing work a hostile document can cause. The result for a bad document is the same rejection either way.
2. Its signature verifies against the **pinned** member signing key.
3. `instance_id` and `member_id` match the enrollment.
4. No key in it is a small-order X25519 point.
5. Against the checkpoint (or, for the first manifest, against the `min_manifest` anchor):
   - a lower `version` is **rollback**: reject it;
   - the same `version` with a different `hash` is **equivocation**: reject it;
   - the same `version` and `hash` means nothing changed;
   - exactly the next `version`, in format 3, with a `prev_hash` other than the checkpoint's `hash` is a **fork**: reject it;
   - a higher `version` is accepted, and the checkpoint advances. Further ahead than the next version, or in format 1 or 2, there is no link to check: the versions in between were never seen.

On any rejection the device keeps using its last accepted manifest and surfaces a warning to the member. It **never** falls back to endorsements.

**The member's web app** builds every new version on the latest one and anchors every new computer to it, so it holds the list it is given to the same rules as a device (`web/src/lib/keys/manifest-trust.ts`):

- it keeps a checkpoint per member in the browser's `localStorage`: the highest `ManifestRef` it has signed (once the instance accepted the upload) or seen;
- it refuses a served list that is older than the checkpoint (rollback), a different list at the checkpoint's version, or the next version with another `prev_hash` (fork), and a 404 once it has a checkpoint (rollback: the member already has a list). It then signs nothing and anchors nothing, and says why;
- the first list, signed when the instance answers 404 to a browser with no checkpoint, names only the member. Allies are added only by approving them (ARCHITECTURE.md §5.2), so nothing the instance lists as an active ally is ever signed without the member's approval;
- before signing a new version, or approving a computer (whose `min_manifest` is that list), it shows the list: each person's signed name and key id, who is added and who is removed, and any name changes for the member to tick.

`localStorage` is per browser and can be cleared, so a browser that has never seen the member's list trusts the first one it is served. A device that already holds a newer version still refuses what is signed on top of an older one (the fork rule), and the anchor of a computer approved in that browser is checked when the computer bootstraps.

**Recipients:** for every new item, the recipients are the member plus exactly the allies in the accepted manifest. The device refuses to queue anything sealed to a manifest other than its current checkpoint, so a stale recipient set held in memory can't keep encrypting to a removed ally.

**Fetch limits:** clients cap the response body of `GET /v1/members/{id}/recipient-manifest` at 64 KiB before JSON parsing. A maximal manifest (32 allies, bounded ids and names) is under 20 KiB.

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

The target's BLAKE3 covers the whole bundle, and the manifest pins the file's BLAKE3. Such targets have platform and arch `any`, and their `version` is the manifest's `version` (semver), not a client release's. The release workflow names them `<kind>/any/<name>-<version>-<first channel>.data` (`+` in the version becomes `_`), for example `model/any/opennsfw-1.0.0_int8-stable.data`: a version listed for `beta` and later for `stable` is two entries with the same bytes. An iPhone (`platform: "ios"`) takes only these `any` data bundles (the domain bundle), never packages: the App Store updates the app.

`GET /v1/updates` returns `{"available": bool, "channel": "<channel>"}`: whether the instance has verified metadata to serve, and the channel its admin chose (`stable`, `beta`, … or the pin `stable-1`). Every path under `/v1/updates` is public: the content is project-signed, and a member's browser may download the installer from it.

### 8.2 Client rules

A client trusts the root it shipped with, never the instance. On each check it:

1. fetches `roots/<v+1>.json` until a 404, verifying each rotation against the previous root;
2. fetches and verifies `timestamp.json`, then `targets.json`, which must match the timestamp's commitment byte for byte (a mirror that switches release between the two requests is retried later);
3. selects for its platform, arch and OS version in the instance's channel, never below its installed version;
4. downloads the artifact, reading at most the signed length plus one byte, and keeps it only if length and BLAKE3 match;
5. on macOS, checks the package's own signature before installing it: a Developer ID Installer certificate that chains to Apple's Developer ID CA, from the Team ID the installed client was built with, and notarized (Gatekeeper accepts it as "Notarized Developer ID");
6. on macOS, reads the version inside the package and installs it only if that version equals the target's `version` and is above the installed version (semver precedence, so `0.1.0-beta.1 < 0.1.0`).

On Windows, steps 5 and 6 check the MSI instead, before `msiexec` runs: its Authenticode signature must chain to a trusted root, and its signer must meet the requirement the installed service was built with (a certificate subject plus a pinned leaf or issuing-CA thumbprint, never taken from the update, the mirror or the config); its `UpgradeCode` must be Faro's; and its `FaroVersion` property must equal the target's `version` and be above the installed version, with `ProductVersion` its numeric part. The signature covers the `Property` table, and it is checked first, so the version read is the signed one.

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

## 10. Group roster log

**Status:** Phase C of [GROUPS.md](GROUPS.md) (§10.3, §10.5). Needs maintainer sign-off before it reaches `main`. Reference implementation: `faro_proto::roster` (structure) and `faro_crypto::roster` (signatures and epoch keys); the web app's port is `web/src/lib/crypto/roster.ts`, and both check the `roster` sections of the shared vectors.

Sending to "the whole group" means sealing to keys the instance hands out, and an instance could slip in a key of its own. The roster log closes that the way recipient manifests do for devices (§5.1): the instance stores and serves a signed, versioned record of who may read, but can't add a reader, roll it back or fork it without clients noticing.

### 10.1 Keys

Every participant needs an X25519 encryption key, and every facilitator an Ed25519 signing key:

| Who | Encryption key | Signing key |
|---|---|---|
| Member | Their member encryption key | Their member signing key |
| Ally (no member keys) | Their ally key | Made when they become a facilitator (`PUT /v1/me/group-sign-key`) |
| Neither | Made when they first open a group (`PUT /v1/me/ally-key`), stored as an ally key in the §4.3 format: passphrase copy plus `recovery` | As for an ally |

An ally-only person's signing key is a fresh Ed25519 seed, sealed (`crypto_box_seal`) to their own encryption key and stored with its public half and the encryption key it is sealed to. Their passphrase or recovery code unlocks the encryption key, which opens the seed, so a passphrase change (§4.3) keeps it working. The browser checks that the opened seed has the stored public key, and signs only once the roster lists that key for them.

### 10.2 Entries

A `RosterEntry` is one facilitator-signed change set:

| Field | Type | Notes |
|---|---|---|
| `instance_id` | string | |
| `group_id` | string | 1 to 64 of `[A-Za-z0-9_-]` |
| `seq` | u64 | 0 for the first entry, then +1 each |
| `prev_hash` | 32 bytes | The previous entry's hash, or the genesis hash for `seq = 0` |
| `at_ms` | i64 | The signer's clock; informational, not checked for order |
| `signer` | string | `usr_…` |
| `changes` | list | At most 256, sorted strictly by `user_id` (one change per person per entry) |
| `epoch` | `{epoch, key_check}` or null | A new epoch key (§10.3) |

A change is one of:

| `kind` | Fields | Encoding after `.str(kind).str(user_id)` |
|---|---|---|
| `join` | `role`, `enc_pubkey`, `sign_pubkey` (or null) | `.str(role).fixed(enc_pubkey).bytes(sign_pubkey or empty)` |
| `leave` | | (nothing) |
| `remove` | | (nothing); also used when the person's account was deleted |
| `role` | `role` | `.str(role)` |
| `keys` | `enc_pubkey`, `sign_pubkey` (or null) | `.fixed(enc_pubkey).bytes(sign_pubkey or empty)` |

`role` is `facilitator` or `participant`. An optional key is a length-prefixed byte string of 0 or 32 bytes.

- **Encoding:** `signing_bytes = Canonical("faro/group-roster/v1").str(instance_id).str(group_id).u64(seq).fixed(prev_hash).i64(at_ms).str(signer).u64(len(changes))`, then each change, then the epoch as an `Option<u64>` (`0`, or `epoch + 1` followed by `.fixed(key_check)`).
- **Identity:** `hash = BLAKE3(signing_bytes)`. The next entry's `prev_hash` must equal it. A `RosterHead` is `{seq, hash}`.
- **Genesis hash:** `BLAKE3(Canonical("faro/group-roster-genesis/v1").str(instance_id).str(group_id))`.
- **On the wire:** the entry's JSON fields flattened with `sig` (base64url Ed25519), like an endorsement.

**Structure** (`validate()`, before any key work): well-formed ids, at most 256 changes, sorted and unique by user, not empty unless it starts an epoch, and **every `join`, `leave`, `remove` and `keys` change comes with a new epoch** in the same entry. A `role` change alone doesn't rotate.

**Against the roster as of the previous entry** (`RosterState::check`):

1. same instance and group;
2. `seq` is the next one (lower: **rollback**; higher: an entry is **missing**) and `prev_hash` is the head (otherwise a **fork**);
3. the signer was a **facilitator with a signing key** in that roster, and the signature verifies with that key. For the first entry, the signer joins in it as a facilitator with the signing key it is signed with, and the entry may only add people;
4. a `join` names someone not in the roster; every other change someone who is; a `role` or `keys` change changes something;
5. a new epoch is the current epoch + 1 (the first entry starts epoch 1);
6. no key is a small-order X25519 point or an unusable Ed25519 key.

Applying it adds, removes and updates the people it names, sets the epoch, and moves the head.

### 10.3 Epoch keys

Whole-group content is sealed with the group's current **epoch key**, a random 32 bytes, so each item costs one envelope whatever the group's size (GROUPS.md §10.5).

- The entry that starts epoch `e` carries `key_check = BLAKE3(Canonical("faro/group-epoch-key/v1").str(instance_id).str(group_id).u64(e).fixed(key))`, never the key.
- The facilitator's browser seals the key (`crypto_box_seal`, 80 bytes) to the encryption key of **everyone in the roster after the entry**, the facilitator included, and uploads the sealed copies with the entry.
- A participant opens their copy and **checks it against `key_check`** from the entry they verified. A key the instance made up, or one moved from another epoch or group, fails.
- Joiners get a copy of the new epoch only, so they can't read what came before. Someone who leaves gets no copy of the epoch their departure starts.

### 10.4 Client rules

Each browser persists a checkpoint per user and group: the head it last accepted, with the roster as of that entry (in `localStorage`; if the roster doesn't fit, the head alone, and the roster is rebuilt from the latest snapshot at or below it and replayed up to the head, which must match exactly).

On every visit it fetches `GET /v1/groups/{id}/roster?after_seq=<checkpoint seq>`:

- a reported head below the checkpoint is a **rollback**, and one at the checkpoint's `seq` with another hash a **fork**;
- each entry is checked as in §10.2, in order;
- entries that end before the reported head mean the instance is **withholding** some.

On any refusal the browser keeps every entry it accepted before it, keeps using that roster, stops, and shows a warning. It never moves its checkpoint back or sideways. Page bodies and snapshots are capped at 8 MiB before parsing.

**Bootstrapping.** A browser with no checkpoint (a first visit, another browser) has nothing to compare with. It starts from the latest facilitator-signed snapshot (or from the first entry when there is none) and checks everything after it. That is trust on first use, as for a device without an anchor (§5.1): an instance could serve a whole parallel log signed by a facilitator key of its own. The group safety code (§10.8) is how people find out.

### 10.5 Snapshots

A `RosterSnapshot` is the full roster at one entry: `{instance_id, group_id, seq, head, at_ms, signer, epoch, epoch_key_check, members}`, members sorted strictly by `user_id`, each `{user_id, role, enc_pubkey, sign_pubkey}`, at most 100,000. `signing_bytes = Canonical("faro/group-roster-snapshot/v1").str(instance_id).str(group_id).u64(seq).fixed(head).i64(at_ms).str(signer).u64(epoch).fixed(epoch_key_check).u64(len(members))`, then `.str(user_id).str(role).fixed(enc_pubkey).bytes(sign_pubkey or empty)` for each. It is signed by a facilitator with a signing key **listed in it**.

A facilitator's browser signs one at the head whenever the head is 256 or more entries past the last one. A browser with a checkpoint never jumps to a snapshot above it; it replays entries.

### 10.6 What the instance stores and checks

| Route | |
|---|---|
| `GET /v1/groups/{id}/roster?after_seq=` | `{head, epoch, latest_snapshot_seq, entries, more}`, 100 entries per page |
| `GET /v1/groups/{id}/roster/snapshot?max_seq=` | The latest snapshot at or below `max_seq`, byte for byte |
| `GET /v1/groups/{id}/roster/pending` | `{head, epoch, changes, waiting_for_keys, posting_paused, snapshot_due, latest_snapshot_seq}` |
| `POST /v1/groups/{id}/roster` | `{entry, epoch_keys: [{user_id, sealed_key}]}`, facilitators |
| `POST /v1/groups/{id}/roster/snapshot` | A signed snapshot, facilitators |
| `GET /v1/groups/{id}/epoch-key?epoch=` | `{epoch, seq, key_check, sealed_key}`: the caller's copy |
| `PUT /v1/me/ally-key` | `{enc_pubkey, wrapped_privkey}`: an encryption key for someone with none |
| `GET`, `PUT /v1/me/group-sign-key` | `{sign_pubkey, enc_pubkey, sealed_seed}` |

The instance runs the §10.2 checks on uploads against its own copy of the roster, but only to keep garbage out: clients don't rely on it. It also ties the roster to the group: a `join` or `keys` change must carry the keys the instance holds for that person and their current role, a `leave` or `remove` must name someone no longer active, and a new epoch must come with exactly one sealed copy for each person in the roster after the entry, **all of them active participants**. Everything here answers `404` to anyone who isn't an active participant, from the moment they leave or are removed, before any facilitator has signed anything.

### 10.7 Facilitators' pending work

`/roster/pending` compares the roster with who is in the group and lists the changes to sign. A facilitator's browser checks them against the roster it verified, and when it opens the group with the facilitator's keys unlocked:

- **signs on its own** other people's leaves and removals, and changes to the facilitator's own keys (checked against the keys it holds), departures in the first entries so no new epoch is ever sealed to someone who left. A removal only takes a reader away; an instance proposing one nobody asked for gains nothing it couldn't by not serving that person;
- **asks first** before joins and other people's key changes, showing names and key ids: they add a reader, with a key the instance supplied. It also asks before role changes and the facilitator's own leave or removal: they change who may sign the roster, on the instance's word. An approval covers that exact change only;
- never signs a change that gives the facilitator keys that aren't theirs.

While `posting_paused` (someone who left is still in the roster, or someone's keys changed), clients pause whole-group posting: "Waiting for a facilitator to update the group". Nothing is escalated to admins (GROUPS.md decision 9).

### 10.8 Group safety code

`h = BLAKE3(Canonical("faro/group-safety-code/v1").str(instance_id).str(group_id).u64(seq).fixed(hash))` of the roster head, printed like a safety code (§4.2): 60 bytes of BLAKE3 XOF output from `h`, each byte mod 10, in 12 groups of 5 digits. Two people whose browsers show the same code hold the same roster history. The web app shows it on the group page, computed from the head of the roster the browser itself verified (never from a head the instance reports), for comparison with any facilitator.

### 10.9 Limits

- **Facilitators choose who reads.** A facilitator can add anyone; every addition is in the signed log, which every participant's browser holds.
- **Keys come from the instance the first time.** A facilitator adds someone with the key the instance holds for them, and a new browser starts from whatever signed history it is served. Approving joins in the browser and comparing the group safety code are the checks; neither is automatic.
- **Withholding.** The instance can delay entries (clients report a short log) or stop serving the group, but can't forge, reorder or roll back entries for a browser that has a checkpoint.
- **Removal is forward-only.** Someone who leaves keeps the epoch keys they already had. The instance stops serving them group items at once; the next epoch is never sealed to them.
- **Checkpoints are per browser.** Clearing site data or using another browser starts again from §10.4's bootstrapping.

## 11. Group messages: reach outs, notes, check-ins and replies

Reach outs, the notes on alliance proposals and join requests, check-ins and replies to them (GROUPS.md §8.3, §8.6, §10.2) are written by one person for specific people, or for a whole group. The instance stores and routes them but can neither read nor forge them. They are made and read only by the web app (`web/src/lib/crypto/group.ts`); the Rust reference is `faro_proto::group` and `faro_crypto::{seal,verify,open}_group_message`.

**Status: new in this version, awaiting maintainer sign-off** before it reaches `main`.

### 11.1 Header

`GroupMessage`, signed by the author's **member signing key** and flattened with `sig` like an endorsement:

| Field | Type | Notes |
|---|---|---|
| `instance_id` | string | |
| `group_id` | string or null | 32 lowercase hex. `null` only for a reach out outside any group; notes always name their group |
| `item_id` | string | 32 lowercase hex, chosen at random by the author's browser. The instance files the message under it |
| `kind` | string | `reach_out`, `proposal_note`, `join_request_note`, `check_in` or `check_in_reply`. A check-in names its group like a note does |
| `author_id` | string | |
| `issued_at_ms` | i64 | Within 5 minutes of the instance's clock on upload |
| `recipients` | list | `{user_id, enc_pubkey}`: 1 to 32 entries, sorted strictly ascending by `user_id`, never the author. A proposal note and a reply have exactly one. **Empty** in whole-group mode (`epoch` set) |
| `body_hash` | 32 bytes | `BLAKE3(nonce ‖ ciphertext)` of the body, or 32 zero bytes when there is none (a signed, content-free reach out) |
| `epoch` | u64, optional | **Whole-group mode:** the group epoch (§10.3) whose key seals the body. Only a `reach_out` or a `check_in`, with a group, no recipients, and an epoch of at least 1. Omitted from the JSON otherwise |
| `parent_id` | string, optional | 32 lowercase hex: the check-in a `check_in_reply` answers. Required for a reply, and for nothing else; not the reply's own id. Omitted from the JSON otherwise |

`signing_bytes = Canonical("faro/group-message/v1").str(instance_id).str(group_id or "").str(item_id).str(kind).str(author_id).i64(issued_at_ms).u64(len(recipients))`, then `.str(user_id).fixed(enc_pubkey)` for each recipient in order, then `.fixed(body_hash)`, then, **only when present**, `.str("epoch").u64(epoch)` and then `.str("parent").str(parent_id)`. A message without them signs exactly the bytes it always did (the vectors for reach outs and notes are unchanged), and the tags keep the optional parts apart. The empty string is never a valid group id, so "no group" can't collide with one.

The signature covers who it is for and the exact keys it was sealed to, so the instance can't add a reader, drop one, move a message to another group or item, or pass off one kind as another. `author_id` and `issued_at_ms` go beyond GROUPS.md §10.2's list: the first binds the message to its author independently of which key verifies it, the second lets readers show a time the instance can't change.

### 11.2 Body

The item construction of §4.1, with:

- `aad = Canonical("faro/group-message-body/v1").str(instance_id).str(item_id)`;
- plaintext: UTF-8 JSON, at most 500 characters per text (Unicode scalar values), not blank. Readers ignore other fields. A reach out, a note and a reply: `{"text": "…"}`. A **check-in**: `{"scale": 1..5, "went_well"?: "…", "was_hard"?: "…", "ask"?: "…"}`, the three texts optional ("What went well", "What was hard", "What I'd like from the group"), each not blank when present;
- envelopes: exactly one per recipient, with `key_id` of the signed `enc_pubkey`, and exactly one for the author, sealed to the author's own member encryption key so they can read what they sent. At most 33, inside the instance's 64;
- ciphertext at most 4096 bytes (8192 for a check-in, which has three texts).

**Whole-group mode** (`epoch` set). The content key `CK` is wrapped once with the epoch key `EK` (32 bytes, §10.3) instead of being sealed to each person, so the item costs one envelope whatever the group's size. The body has **exactly one envelope**: `recipient` is the author, `key_id` is `"epoch:<epoch>"`, and `wrapped_key = wrap_nonce(24) ‖ XChaCha20-Poly1305(EK, wrap_nonce, CK, aad = Canonical("faro/group-message-epoch/v1").str(instance_id).str(group_id).str(item_id).u64(epoch))`, 72 bytes. The author needs no copy of their own: they hold `EK` like every participant. Whoever has the epoch key can read the message; the instance serves it only to people who are active participants now and were when it arrived (GROUPS.md §10.5). A reach out in whole-group mode is offered only in groups of 32 or fewer, but the format has no such limit; a check-in has none.

On the wire, upload and download alike: `{"message": Signed<GroupMessage>, "body": EncryptedItem | null}`.

### 11.3 Readers

A browser shows a message only after all of these, in order:

1. The structure checks above (`validate`), before any signature: they bound the work a hostile document causes.
2. The body against the header: present exactly when `body_hash` isn't zero, hashing to it, and with the envelope set above.
3. Strict Ed25519 verification against the author's member signing key.
4. The context: `item_id` is the message asked for, `author_id` is the author the instance names, `instance_id` is this instance, and the reader is the author or a recipient. In whole-group mode there are no recipients: the reader opens it with the epoch key (§10.3) of `epoch`, which they checked against the signed roster, and the group is the one they asked for. A reply also names the check-in it answers: the reader checks the parent the instance reports against the signed `parent_id`.

A message that fails any of these is not shown at all, with a warning. The signing key is served by the instance, so how far a reader can trust it depends on what they checked themselves: an ally who compared safety codes with the author (the safety code covers the member signing key) sees the message as **verified**. Anyone else sees it marked *not yet verified*. For a message in a group (other than a join request's note, whose author isn't in the group yet), the reader also requires the served signing key to be the author's in the roster it verified (§10.4), once that roster has an entry; an author who isn't in it is refused.

Senders check the other way round before sealing: each key the instance serves for a recipient must be the one in the sender's own manifest (for their allies) or in the roster the sender's browser verified (for anyone else in a group), and each recipient must be someone the sender chose. Otherwise nothing is sealed. The keys of people outside a group who aren't the sender's allies, and of the facilitators of a group the sender asks to join, can't be checked; they are marked *not yet verified* (GROUPS.md §10.2).

### 11.4 What the instance checks

On upload the instance runs steps 1 to 3 with the author's stored key, and also checks the kind and group for the route, the author's own copy (sealed to their member key), that every recipient is someone this message may go to, and that each signed key is one it knows for that person. It gains nothing by skipping these, since every reader checks again, but they keep junk out of the database.

For a check-in or a reply, the instance also checks the group: the author is an active participant, the group isn't archived, and a whole-group post names the group's **current** epoch and is refused while whole-group posting is paused (`posting_paused`, §10.7). A reply goes only to the author of a check-in the replier can read, once each. A check-in to "my allies in this group" goes to the author's active allies who are also participants. Check-ins are filed in the group's feed (`POST` and `GET /v1/groups/{id}/posts`), never notify anyone, and follow blob retention (GROUPS.md §18).

People without a member signing key (ally-only participants) can't write messages. They can still send a **content-free reach out**, which is not a group message at all: no signature and no body. Readers mark it *"Sent through the server. Can't be verified."* A member who hasn't unlocked their keys can send the same kind.

## 12. Format changes

Signed structures change by getting a new format and a new domain-separation tag, never by changing an existing encoding.

| Structure | Change | Old format |
|---|---|---|
| Recipient manifest (§5.1) | Format 2 (`faro/recipient-manifest/v2`) adds each ally's display name inside the signed bytes, so devices can name allies without trusting the instance | Format 1 (`faro/recipient-manifest/v1`) still verifies and is still accepted everywhere |
| Recipient manifest (§5.1) | Format 3 (`faro/recipient-manifest/v3`) adds `prev_hash`, the hash of the version it was built on, so devices can refuse a fork | Formats 1 and 2 still verify and are still accepted everywhere; the web app signs format 3 |
