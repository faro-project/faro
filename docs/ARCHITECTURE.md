# Faro: Architecture

**Status:** Draft v0.1 (2026-11-23)
**Scope:** A free, open-source screen-accountability service, comparable to Covenant Eyes. The first release covers desktop only: macOS, Windows and Linux.

---

## 1. What we are building

Faro is an **accountability** tool, not a parental-control or surveillance tool. A person (the **member**) chooses to install Faro on their own computers and invites one or more trusted people (**allies**). Faro watches what is on the member's screen, detects explicit or otherwise flagged content *on the device*, and sends allies an end-to-end-encrypted report: a summary, a timeline and blurred thumbnails of flagged moments. Allies are also told when monitoring stops, gets tampered with or has its settings changed.

### Goals

1. **Free to run at scale.** The cost per user has to round to zero. That rules out server-side image analysis, storing full screenshots on the server, and anything that needs GPUs we pay for.
2. **Private by construction.** The server only ever sees ciphertext and minimal metadata. A breach of the server exposes no screenshots, URLs or report contents.
3. **Tamper-evident, not tamper-proof.** Someone with admin rights on their own machine can always defeat local software. What we can promise is that **allies find out** when that happens: missed heartbeats, a broken event chain, permission revoked, the app uninstalled.
4. **Cross-platform from one core.** A single Rust core with thin per-OS layers, so detection, crypto and reporting behave the same everywhere.
5. **Consent-forward and abuse-resistant.** It must be hard to use Faro as stalkerware (see §11).

### Non-goals for v1

- Mobile (iOS and Android). The design keeps the door open; §13 says how.
- Content **blocking** or filtering. v1 does accountability (reporting) only. Blocking is a possible later phase.
- Real-time live viewing of the screen. That will never be built.
- Running ML on the server.

---

## 2. System overview

```
 ┌──────────────────────── Member's computer ────────────────────────┐
 │                                                                     │
 │  ┌──────────────┐  frames/   ┌──────────────────────────────────┐   │
 │  │ Session Agent │──signals──▶│        Faro Service (privileged) │   │
 │  │ (per user,    │  local IPC │                                  │   │
 │  │  unprivileged)│◀──control──│  scheduler · classifier (ONNX)   │   │
 │  │ capture, title│            │  policy engine · report builder  │   │
 │  │ URL, idle     │            │  crypto · hash-chained event log │   │
 │  └──────┬────────┘            │  encrypted outbox · uploader     │   │
 │         │                     │  watchdog (relaunches agent)     │   │
 │  ┌──────▼────────┐            └───────────────┬──────────────────┘   │
 │  │ Tray / Settings│ (Tauri UI, talks to service)│                     │
 │  └───────────────┘                             │                     │
 │  ┌───────────────┐  native messaging           │                     │
 │  │Browser ext.   │──────────────▶ Agent        │                     │
 │  │(optional, URLs)│                             │                     │
 │  └───────────────┘                             │ HTTPS (TLS 1.3)     │
 └────────────────────────────────────────────────┼─────────────────────┘
                                                  │ ciphertext + signed
                                                  ▼ metadata only
 ┌──────────────────────────── Faro Cloud ─────────────────────────────┐
 │  API (Rust/axum) ── Postgres (accounts, keys, envelopes, heartbeats)│
 │        │                                                             │
 │        ├── Object storage (R2/S3): encrypted report & thumb blobs    │
 │        ├── Heartbeat monitor worker → "device went silent" alerts     │
 │        └── Notifier worker → email / Web Push ("new report", no data)│
 └───────────────────────────────┬─────────────────────────────────────┘
                                 │
                                 ▼
 ┌──────────────── Ally's browser (static web app) ────────────────────┐
 │  Fetches ciphertext → decrypts locally with ally's private key      │
 │  (libsodium.js; key held in IndexedDB, wrapped by passphrase)       │
 └─────────────────────────────────────────────────────────────────────┘
```

The one principle everything else follows from: **intelligence lives on the edges** (the member's device and the ally's browser), and **the server is a dumb, cheap, encrypted mailbox plus a liveness monitor.**

---

## 3. Desktop client

### 3.1 Process model

Every OS runs the same three processes.

| Process | Privilege | Lifetime | Responsibilities |
|---|---|---|---|
| **Faro Service** | root / SYSTEM | Boot to shutdown | Owns state, keys, the classifier, the event log, the outbox and uploads. Watches over the agent. Sends heartbeats. |
| **Session Agent** | Logged-in user | One per interactive session | Screen capture, active window and app info, idle and lock state, browser-extension bridge. Holds as little state as possible. |
| **Tray UI** (Tauri) | Logged-in user | Optional | Status, pausing (which allies are told about), ally management, viewing your own reports. |

**Why split it:** screen capture *has* to happen inside the user's graphical session, since a service in Windows session 0 or a macOS LaunchDaemon cannot see the screen. Everything worth protecting (keys, the queue of unsent events, the classifier) lives in the privileged service, where a standard user cannot touch it. If the agent is killed, the service notices within seconds, relaunches it and logs an `agent_restarted` event. If the service itself is killed, the server sees heartbeats stop.

**Recommendation:** members run as a standard (non-admin) user day to day and an ally keeps the admin password. Faro works without this, but it is the single biggest real-world anti-tamper measure, and onboarding should suggest it.

**Local IPC**
- macOS and Linux: a Unix domain socket in a root-owned directory. The service checks the peer's credentials (`getpeereid` / `SO_PEERCRED`) and verifies the code signature of the connecting binary (macOS: `SecCodeCheckValidity` against the team ID).
- Windows: a named pipe with a DACL. The service checks the client PID's image path and Authenticode signature.
- Protocol: length-prefixed messages over `serde` with `postcard` or CBOR, versioned.
- Frame transfer: the agent downscales before sending (longest side 768 px, BGRA → JPEG at q85 or raw), so a frame is about 100–300 KB. At roughly one capture a minute a socket is plenty and shared memory isn't needed.

### 3.2 Code layout: one Rust core plus platform crates

```
faro/
├── crates/
│   ├── faro-core/          # platform-agnostic: scheduler, policy, event model,
│   │                       # hash chain, report builder, outbox, API client
│   ├── faro-crypto/        # libsodium (via `sodiumoxide`/`libsodium-sys` or
│   │                       # RustCrypto: x25519-dalek, ed25519-dalek, chacha20poly1305)
│   ├── faro-detect/        # ONNX Runtime (`ort` crate) inference, signal fusion
│   ├── faro-ipc/           # agent<->service protocol
│   ├── faro-platform/      # trait definitions (Capture, ActiveWindow, Idle, ...)
│   ├── faro-platform-macos/
│   ├── faro-platform-windows/
│   ├── faro-platform-linux/
│   ├── faro-service/       # bin: privileged service
│   ├── faro-agent/         # bin: session agent
│   └── faro-proto/         # wire types shared with server + web (serde + typeshare → TS)
├── apps/
│   ├── tray/               # Tauri v2 app (Rust + TS/Svelte front end)
│   └── extension/          # WebExtension MV3 (Chrome, Edge, Firefox, Brave)
├── server/                 # Rust axum API + workers
├── web/                    # Ally dashboard (static SPA, SvelteKit adapter-static)
├── models/                 # model cards, export scripts, eval harness (weights via release assets)
├── installers/             # pkg/notarization, MSI/WiX, deb/rpm/Flatpak notes
└── docs/
```

**Why Rust:** one language across the service, the agent, Tauri and the server. Memory safety matters in a privileged process that parses images. `ort` (ONNX Runtime) and `windows-rs` / `objc2` are mature, and the binaries are small and quick to start.

**Platform traits** that every OS crate implements:

```rust
trait ScreenCapture   { fn capture_all_displays(&mut self) -> Result<Vec<Frame>>; fn permission_state(&self) -> PermissionState; }
trait ForegroundInfo  { fn active_app(&self) -> Option<AppInfo>; fn window_title(&self) -> Option<String>; }
trait SessionState    { fn idle_secs(&self) -> u64; fn is_locked(&self) -> bool; fn on_session_change(&self, cb: ...); }
trait ServiceHost     { fn install(), fn spawn_agent_in_session(session_id), fn list_sessions() }
trait TamperSignals   { fn poll(&self) -> Vec<TamperSignal>; }  // permissions, clock jumps, binary integrity, VM/RDP, etc.
```

### 3.3 Per-platform details

#### macOS (13+)

| Concern | Approach |
|---|---|
| Capture | **ScreenCaptureKit** (`SCScreenshotManager.captureImage` on 14+, an `SCStream` single frame on 13). Captures every display. |
| Permission | Needs the Screen Recording (TCC) permission, which the user can revoke in System Settings at any time. The agent checks `CGPreflightScreenCaptureAccess()` on every tick. If access is revoked, a `permission_revoked` tamper event goes out right away. |
| ⚠ Risk | Recent macOS versions **periodically re-prompt** users to re-confirm screen-capture access for apps that aren't using the system picker. A **Phase 0 spike** needs to confirm the current behavior and whether any entitlement avoids it. Worst case: the re-prompt is a normal UX step, and declining it reports as tamper. |
| Service | A privileged **LaunchDaemon** registered via `SMAppService.daemon`, plus a per-user **LaunchAgent** (`SMAppService.agent`) for the session agent. `KeepAlive=true` on both. |
| Active window | `NSWorkspace.frontmostApplication`. Window titles go through the Accessibility API (`AXUIElement`), which needs the Accessibility permission. It's optional, and revoking it is reported. |
| Browser URL | The extension is the main source. A fallback reads the URL via AppleScript or Accessibility for Safari and Chrome. |
| Network signals (Phase 2) | A Network Extension (`NEDNSProxyProvider` or `NEFilterDataProvider`) as a **System Extension**. Needs an Apple entitlement and user approval. Gives a domain log covering every browser. |
| Distribution | Developer ID signed + **notarized** `.pkg` (the $99/yr Apple Developer Program is the only unavoidable cost). Updates via **Sparkle 2** with EdDSA-signed appcasts. |
| Uninstall detection | A signed `goodbye` event when uninstalled through the app. Otherwise the server notices missing heartbeats. |

#### Windows (10 22H2+, 11)

| Concern | Approach |
|---|---|
| Capture | **DXGI Desktop Duplication** (`IDXGIOutputDuplication`). It's fast, handles multiple monitors and shows no yellow capture border. Falls back to `Windows.Graphics.Capture` or GDI `BitBlt`. Protected (DRM) content shows up black, which is expected. |
| Service | A Windows Service running as **LocalSystem**, auto-start with recovery actions (restart on failure). It uses `WTSEnumerateSessions` and `WTSRegisterSessionNotification` to launch the agent into each interactive session with `CreateProcessAsUser` and the user token from `WTSQueryUserToken`. |
| Self-protection | The service DACL denies `SERVICE_STOP` and `DELETE` to non-admins. Program files live in `%ProgramFiles%` (admin-write only), state in `%ProgramData%\Faro` (SYSTEM-only ACL). |
| Active window | `GetForegroundWindow`, `GetWindowText` and `QueryFullProcessImageName`. |
| Browser URL | Extension first. Fallback: UI Automation on the browser address bar. |
| Network signals (Phase 2) | **ETW** `Microsoft-Windows-DNS-Client` provider, a passive DNS query log with **no kernel driver**. A WFP callout driver is deliberately avoided because of the EV certificate, attestation signing and BSOD risk. |
| Distribution | MSI (WiX v4) or MSIX. Code signing: apply to the **SignPath Foundation** (free for OSS) or use Azure Trusted Signing (~$10/mo). Updates: signed manifests checked by the service (see §3.7). |

#### Linux (Ubuntu 22.04+, Fedora 39+; X11 and Wayland)

| Concern | Approach |
|---|---|
| Capture (X11) | `xcb` + MIT-SHM `GetImage`. Simple and reliable. |
| Capture (Wayland) | **xdg-desktop-portal ScreenCast** + PipeWire, with `persist_mode=2` and a stored **restore token**, so the user consents once at setup and capture runs unattended from then on. Losing the token or the portal session is reported as tamper. Wlroots compositors can use `wlr-screencopy` directly. |
| ⚠ Risk | Wayland behavior varies between GNOME, KDE and wlroots, which makes this the platform with the most unknowns. That's why Linux ships in **Phase 2**, after a dedicated spike. |
| Service | A **systemd system unit** (root) for the service and a **systemd user unit** (`WantedBy=graphical-session.target`) for the agent. Session discovery goes through `logind` D-Bus. |
| Active window | X11: `_NET_ACTIVE_WINDOW`. Wayland has no general API, so it relies on the extension plus GNOME and KDE-specific D-Bus where available. Its absence degrades gracefully. |
| Network signals | `systemd-resolved` D-Bus monitoring, or a local DNS stub. |
| Distribution | `.deb` and `.rpm` from a signed apt/dnf repo. A Flatpak can't host a root service, so it isn't used for the client. |

### 3.4 Capture scheduling

- **Randomized interval**: an exponential (Poisson) distribution with a mean of about 60 s, bounded to 15–180 s, so captures can't be predicted and avoided. The mean is configurable per member (30–300 s).
- **Burst mode**: once something scores borderline or flagged, sample every 5–10 s for the next 2 minutes to confirm the result and capture context.
- **Skip work when nothing changes**: compute a perceptual hash (dHash) of each downscaled frame. If it matches the last one within a set Hamming distance, reuse the previous classification.
- **Pause automatically** while the screen is locked, the session is idle (no input for 5 minutes and the frame unchanged) or the display is asleep. These states are recorded so that gaps in the timeline are explained.
- **Event triggers** (alongside the timer): foreground-app change, new browser URL or tab, or a new DNS domain on a watch list causes a capture 1–3 s later.
- **Budget**: under 1% average CPU, under 150 MB RSS for the service including the model, and nothing on the GPU unless it's available and idle.

### 3.5 Detection pipeline (on-device)

```
frame ─▶ dHash dedupe ─▶ preprocess (resize 224/384, normalize)
      ─▶ [A] image classifier (ONNX, int8)        → p(explicit), p(suggestive), p(gore?)...
      ─▶ [B] context signals                       → URL/domain category, window title keywords,
                                                     app category, private/incognito window
      ─▶ fusion/policy engine ─▶ rating {clean, low, medium, high} + reasons
      ─▶ if rating ≥ threshold: blurred thumbnail + event
      ─▶ append to hash-chained event log ─▶ report builder / immediate alert
```

**Models.** The model is swappable, versioned and signed, so it can be improved without an app release.
- Baseline: an open NSFW image classifier exported to ONNX and quantized to int8. Candidates include OpenNSFW2, ViT-based `nsfw_image_detection` fine-tunes and NudeNet. **Check every license** before shipping, since some are AGPL or non-commercial.
- Preferred long term: **a small CLIP-style image encoder (for example MobileCLIP or OpenCLIP ViT-B/32) with lightweight linear heads** trained on our own labeled set. One embedding pass can feed several categories (explicit, suggestive, gambling, violence), new categories only need a new head (a few KB), and it holds up better on screenshots than photo-trained nudity detectors.
- Runtime: `ort` with execution providers CoreML (macOS), DirectML (Windows) and CPU (everywhere). Target under 80 ms per frame on CPU on a 2019-era laptop.
- **Screenshot domain gap.** Most open NSFW datasets are photos, but screens contain UI chrome, thumbnails grids, video players and text. The `models/` eval harness needs a screenshot-specific test set (synthetic composites of safe and unsafe images inside browser and app chrome) and tracks precision and recall for each release.
- **Text signals** (later): on-device OCR via Apple Vision on macOS and `Windows.Media.Ocr` on Windows, combined with keyword lists, to catch text-heavy explicit content.

**Context signals.**
- Domain categorization uses open blocklists compiled into a compact Bloom filter or FST that ships with signed model updates. Sources include StevenBlack/hosts porn extensions, OISD NSFW and the UT1 Toulouse categories. **Check each list's license.**
- Browser extension (MV3) reports `{url, title, incognito}` to the agent through native messaging. A missing extension in a detected browser is reported as a signal of its own ("Firefox used without Faro extension"), not hard-blocked.

**Fusion and policy.** v1 uses a simple, explainable rules engine, for example: `high` if image ≥ 0.9, or image ≥ 0.6 on an adult-category domain. Each event carries **reasons** (`image:explicit 0.93`, `domain:adult`) so allies see *why*, and members can dispute false positives in their own view. A false-positive feedback loop is opt-in, local-first and never uploads images.

**Thumbnails.** Flagged frames become a thumbnail roughly 320 px wide with a **strong blur** (Gaussian σ≈12 plus pixelation), enough to show the gist ("this is a video player with a person") without explicit detail. **Unblurred images never leave the device.** By default they're not kept locally either. Clean frames are discarded after classification and only counted in aggregates.

### 3.6 Event model and the tamper-evident log

Every observation becomes an **event**:

```jsonc
{
  "v": 1,
  "device_id": "dev_…",
  "seq": 18234,                      // strictly increasing per device
  "prev_hash": "b3:…",               // BLAKE3 of previous event's canonical bytes
  "ts": "2026-11-23T21:04:11Z",      // wall clock
  "mono": 9123311,                   // monotonic ms since boot (detects clock tampering)
  "boot_id": "…",
  "kind": "capture" | "flag" | "heartbeat" | "tamper" | "settings_change" |
          "agent_restarted" | "paused" | "resumed" | "goodbye" | "boot" | "shutdown",
  "body": { … }                      // kind-specific; encrypted (see §5)
}
```

- The **hash chain** with `seq` and `prev_hash` means that if events are deleted or reordered locally, for example by wiping the outbox while offline, the chain breaks when uploads resume. The server checks chain continuity **on headers only, without decrypting anything** and raises a `chain_gap` alert.
- Device signing: each event header is signed with the device's **Ed25519** key, which sits in the OS secure store wherever possible (macOS: Keychain, ideally Secure Enclave-backed with P-256 as a fallback; Windows: TPM-backed via CNG/NCrypt; Linux: a root-only 0600 file, optionally TPM2 via `tss-esapi`).
- **Outbox**: a SQLite database (WAL) in the service's protected directory. Event bodies are already encrypted for allies before they're queued, so a stolen disk image shows nothing either. It holds about 30 days of data while offline and is pruned oldest-clean-first.
- **Clock tampering**: comparing wall-clock against monotonic deltas and against the server's `Date` header turns large jumps into a `clock_skew` tamper event.

### 3.7 Tamper detection (what allies are told)

| Signal | Detected by | Ally sees |
|---|---|---|
| No heartbeat for longer than the grace period | **Server** heartbeat monitor | "Laptop-X hasn't checked in for 3h" (alongside a "last seen asleep or shut down" hint if a signed `shutdown` or `sleep` event came first) |
| Screen-recording / portal permission revoked | Agent | Immediate tamper alert |
| Agent repeatedly killed | Service | Tamper alert with a count |
| Chain gap or invalid signature | Server | Tamper alert |
| Settings changed, ally removed, pause | Service / server | Notification. **Removing an ally notifies that ally**, and changes to the capture rate or category thresholds notify all allies |
| Uninstall | Uninstaller sends `goodbye`; otherwise the heartbeat gap | "Faro was uninstalled from Laptop-X" |
| Binary or model integrity failure | Service checks its own signature and model signature at startup | Tamper alert |
| Clock manipulation | Service | Tamper alert |
| Unknown browser without extension, VPN/proxy change, VM or remote desktop session | Agent (informational) | Listed in the report as context, not alarms |
| A new OS user account with no agent running | Service (`list_sessions`) | Info or tamper, depending on configuration |

Heartbeats go out every 5 minutes while awake. They're tiny signed headers, and their body is optional.

**Updates**: the service polls a signed release manifest using a minimal **TUF**-style scheme: an offline root key signs a timestamp-and-targets key. It downloads the platform package, checks its signature and installs it in place. Models and blocklists use the same channel. This blocks malicious-update attacks even if the update host is compromised.

---

## 4. Backend ("Faro Cloud")

### 4.1 Responsibilities, kept deliberately small

1. Accounts and auth for members and allies.
2. The **public-key directory**: devices' signing keys and allies' encryption keys.
3. **Encrypted mailbox**: accept signed and encrypted events and reports, and store the blobs.
4. **Liveness monitor**: heartbeats → missed-check-in alerts.
5. **Notifications**: email or Web Push saying "you have a new report or alert for Sam". Never contents.
6. Invitations and relationship management.

It does **not** run ML, decrypt anything or build reports.

### 4.2 Stack

| Component | Choice | Why |
|---|---|---|
| API | Rust + **axum** + `sqlx` | Shares `faro-proto` types with the client and keeps the footprint small |
| DB | **Postgres 16** | Relational data with simple operations; heartbeats are partitioned by day |
| Blobs | S3-compatible: **Cloudflare R2** (no egress fees) or MinIO when self-hosted | Encrypted reports and thumbnails |
| Queue / jobs | Postgres-backed (`SKIP LOCKED`) | One less system to run |
| Email | Any SMTP (AWS SES at ~$0.10/1k, or Postmark/Resend free tiers) | Alert and digest notices |
| Push | **Web Push (VAPID)** to the ally PWA | Free, no vendor |
| Web app hosting | Static files on Cloudflare Pages / Netlify / the same box | Free |
| Deploy | Single binary + `docker-compose.yml` (api, worker, postgres, minio, caddy) | Easy to self-host. Churches and ministries can run their own |

### 4.3 Core tables (sketch)

```
users(id, email, created_at, auth...)                      -- members and allies are both users
devices(id, owner_user_id, platform, name, sign_pubkey, enrolled_at, last_seen_at, last_seq, last_hash, status)
ally_links(id, member_id, ally_id, state[pending|active|removed], created_at, removed_at)
ally_keys(user_id, enc_pubkey, created_at, revoked_at)     -- X25519, may have several (rotation)
events(device_id, seq, ts, kind, header_sig, blob_ref|inline_ct, received_at)   -- partitioned by month
envelopes(event_or_report_id, recipient_user_id, wrapped_key)                   -- per-ally key wrap
reports(id, device_id|member_id, period_start, period_end, blob_ref, created_at)
alerts(id, member_id, kind, severity, created_at, delivered_at)                -- server-generated (missed heartbeat, chain gap)
invites(token_hash, member_id, expires_at)
```

### 4.4 API surface (v1)

```
POST /v1/auth/...                 passkeys (WebAuthn) primary, email magic-link fallback
POST /v1/devices/enroll           {enroll_code, sign_pubkey, platform} → device_id, device token
GET  /v1/members/{id}/allies/keys current ally encryption pubkeys (device fetches/caches; signed by member)
POST /v1/events:batch             signed headers + ciphertext; server verifies sig + chain, stores
POST /v1/heartbeat                signed {seq, ts, state}
POST /v1/reports                  encrypted report blob + envelopes
GET  /v1/ally/feed                list of reports/alerts for this ally (metadata only)
GET  /v1/blobs/{id}               presigned R2 URL to ciphertext
POST /v1/invites / accept         ally invitation flow
```

Device auth: a device token issued at enrollment **plus** an Ed25519 signature on every request body, so a stolen token without the key is useless.

---

## 5. Cryptography and key management

Primitives (libsodium or the equivalent RustCrypto/`libsodium.js`):
- **Device signing:** Ed25519.
- **Ally encryption keys:** X25519.
- **Content encryption:** XChaCha20-Poly1305 with a random per-item 256-bit content key (CK).
- **Key wrapping:** `crypto_box_seal(CK, ally_pubkey)`, one envelope per active ally. The member's own **member key** gets an envelope too, so the member can always see exactly what their allies see (transparency, §11).

**Ally key lifecycle**
1. The ally accepts the invite in the browser. The web app generates an X25519 keypair and stores the private key in IndexedDB as a non-extractable wrap: the key is encrypted with a key derived from a **passphrase via Argon2id**, and that wrapped blob is also uploaded to the server for multi-device recovery. The server can't unwrap it.
2. Recovery: a printable **recovery code** (a random 128-bit value, BIP39-style words) can also unwrap the key. If both the passphrase and the code are lost, the ally re-keys and only sees reports from then on.
3. **Key authenticity:** the member's devices only encrypt to ally keys the **member has signed** (the member key signs `{ally_id, ally_pubkey}` when approving the link). This stops a malicious server from slipping in its own key. Both sides can compare an optional "safety code" (a fingerprint).

**Device ↔ member key:** at enrollment, the member approves the device from the tray UI or a QR code. The member key, held in the member's own account and passphrase-wrapped the same way, signs the device's public key.

**Metadata the server sees (and accepts seeing):** device IDs, event kinds (needed for alerts like tamper and heartbeat), timestamps, sizes, who is linked to whom. Severity ratings are **encrypted** by default. As an option the client can expose a coarse `severity≥high` bit, so the server can send an immediate "urgent" notification. That bit is a per-member opt-in trade-off between privacy and promptness.

---

## 6. Reports and the ally experience

- **Built on the device**: the service compiles a **daily** report (default; weekly is optional) with an activity timeline (hours active), counts by rating, flagged moments with reasons and blurred thumbnails, top domains and apps (optional, off by default for privacy), and a tamper/health summary. It's encrypted as a single blob.
- **Immediate alerts**: a `high` flag or a tamper event goes out within about a minute as a small encrypted event, and the server sends a content-free notification.
- **Ally web app** (PWA, static, SvelteKit):
  - Unlocks with a passphrase (or a passkey-derived PRF key on supporting browsers), and decrypts everything in the browser.
  - Shows a feed per member, report details, device health ("last seen") and a "start a conversation" prompt with suggested questions. Covenant Eyes's real product is the *conversation*, and the UX should push toward that rather than toward policing.
  - Offline caching of decrypted reports is off by default.
- **Member view**: the same app, opened with the member key, so they see precisely what allies see.

---

## 7. Onboarding flow (desktop)

1. The member signs up on the web (passkey) and creates a member key (passphrase + recovery code).
2. The member downloads the installer for their OS. The installer registers the service and asks for OS permissions with clear guidance screens (macOS Screen Recording + Accessibility; Wayland portal consent).
3. Device enrollment: the tray app shows a code, or opens the browser for approval. The member key signs the device key.
4. The member invites allies by email or link. Each ally accepts and creates a key, then the member approves (signs) the ally key.
5. Until at least one ally is active, events are still recorded and encrypted to the member key, and allies get the backlog of **reports** (not raw history) once they join. Configurable.
6. Optional prompts: install the browser extension, move to a standard user account, let the ally set the admin password.

---

## 8. Cost model (why "free" is sustainable)

Rough per-active-device load:
- Heartbeats: 288/day × ~300 B ≈ 90 KB/day
- Daily report: ~20–200 KB (mostly the blurred thumbnails, ~8 KB each)
- Immediate alerts: rare

So roughly **0.3 MB/day and ~300 requests/day per device**. At **10,000 devices**: about 3 GB/day of ingress, ~35 req/s average, and roughly 100 GB/month of storage at 30-day retention. That fits a **single ~$40–80/month VPS + R2 (~$1.50/month for 100 GB, no egress)**, plus about $10–30/month in email. Even at 100k devices it stays in the low hundreds of dollars a month, which donations can cover. Fixed costs: the Apple Developer Program ($99/yr) and Windows signing (free via SignPath for OSS, otherwise ~$120/yr).

Retention defaults: event headers 90 days, report blobs 30 days, then deleted. Members can choose shorter.

---

## 9. Security considerations

- **Threat model, in priority order**: (1) the member trying to evade monitoring on their own machine, (2) a server compromise or a curious operator, (3) a network attacker, (4) a malicious update.
  - (1) is limited by the privilege split, the hash chain, heartbeats and permission monitoring. We explicitly accept that a determined admin can evade capture, **but cannot do so silently**.
  - (2) is handled by E2EE and member-signed ally keys.
  - (3) TLS 1.3 everywhere plus pinned API key signing (request signatures), and no plaintext anywhere.
  - (4) TUF-style signed updates with an offline root key.
- The privileged service parses images, so decoding happens **in the agent**, which sends raw pixels, or in a sandboxed decoder. The service never parses untrusted formats from the network.
- Fuzzing (`cargo fuzz`) covers the IPC and wire decoders.
- Reproducible builds for the client, so the community can verify the binaries match the source.
- A third-party audit of the crypto design comes before 1.0.

---

## 10. Testing strategy

- `faro-core` and `faro-detect`: unit plus property tests. A detection eval suite runs in CI against the screenshot test set and fails on regressions beyond a set tolerance.
- Platform crates: CI matrix on GitHub Actions (`macos-14`, `windows-2022`, `ubuntu-24.04` with Xvfb, plus a headless Wayland compositor (`weston --backend=headless`) where possible).
- E2E: a docker-compose server plus a headless client in "synthetic capture" mode (it feeds fixture images through the real pipeline), checking that the ally web app decrypts the expected report (Playwright).
- Tamper tests: kill the agent, revoke permissions (scripted with `tccutil` on a CI-only VM), delete outbox rows → expect the matching alerts.

---

## 11. Ethics, consent and abuse resistance (an architectural requirement)

Screen-capture software that's hard to remove is exactly what stalkerware looks like. Faro has to be built so that it works badly as a covert tool:

- **Never invisible:** a persistent tray or menu-bar icon that can't be hidden, plus a first-run and periodic (monthly) on-device notice ("Faro is sharing screen reports with: Alex, Jordan").
- **The monitored person holds the account.** The member, not the ally, creates the account, owns the member key and approves allies. An ally can't enroll devices or change capture settings.
- **Full transparency:** the member sees everything allies see (§6).
- **Members can always leave.** Uninstalling is allowed; it just isn't silent.
- **Minors / family use**: out of scope for v1. If added later it needs its own design (age-appropriate consent, COPPA/GDPR-K) and must not reuse the adult "member owns the account" assumptions.
- **Legal review before launch**: privacy policy, GDPR (EU members: lawful basis is consent; data minimization is already the design), and the handling obligations if the classifier flags apparent CSAM. Because blurred thumbnails are E2EE we can't see content, but we need counsel on obligations and on a reporting path for allies.

---

## 12. Roadmap

**Phase 0: Spikes (2–4 weeks).** Each spike answers one risky question before committing.
1. macOS ScreenCaptureKit from a LaunchAgent: permission persistence and the re-prompt behavior on current macOS.
2. Windows: capture from an agent launched by the service into the user session; check multi-monitor, fast user switching and RDP.
3. Model benchmark: three candidate models on a 1k-image screenshot set (latency, precision, recall), plus license review.
4. Wayland portal restore tokens on GNOME and KDE.
5. End-to-end crypto prototype: Rust encrypt → browser decrypt.

**Phase 1: MVP on macOS and Windows.**
Service and agent, capture scheduler, classifier v1, hash-chained events, outbox, E2EE, heartbeats, server (auth, enroll, events, heartbeat monitor, email), ally web app (feed, reports, alerts), tray UI, signed installers and updates. Ships to a small closed beta.

**Phase 2: Hardening and Linux.**
Linux (X11 + Wayland), browser extension, DNS/ETW domain signals, the full tamper-signal table, CLIP-head model, OCR signal, Web Push, self-host docs, reproducible builds, crypto audit.

**Phase 3: Beyond.**
Optional blocking (DNS-level filter using the same blocklists), ChromeOS (extension-based), Android (MediaProjection + Accessibility, with heavy Play policy constraints), iOS (very limited: Screen Time API / NetworkExtension content filter only, so screenshots aren't feasible), and multiple ally tiers.

---

## 13. Open questions

1. **Licensing**: GPL-3.0 for the client and AGPL-3.0 for the server (so forks stay open), or Apache-2.0 for wider adoption? This interacts with model and blocklist licenses.
2. **Urgent-flag metadata bit**: on by default (faster alerts) or off (maximum privacy)?
3. **Funding / governance**: donations, a nonprofit, or a church/ministry partnership for hosting?
4. **Capture frequency default**: more frequent means more coverage but more CPU and privacy cost. Start at a 60 s mean?
5. **Image retention on device**: should members be able to keep unblurred flagged images locally, for their own review only? The default is no.
6. **Mobile timing**: many users' main risk is the phone. Desktop first is the right engineering order, but mobile shouldn't slip so far that the product isn't useful.
