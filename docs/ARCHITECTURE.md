# Faro: Architecture

**Status:** Draft v0.2 (2026-11-23)
**Scope:** A free, open-source, **self-hosted** screen-accountability service, comparable to Covenant Eyes. The first release covers desktop only: macOS, Windows and Linux.
**License:** Apache-2.0 (client, server, web app and tooling).

---

## 1. What we are building

Faro is an **accountability** tool, not a parental-control or surveillance tool. A person (the **member**) chooses to install Faro on their own computers and invites one or more trusted people (**allies**). Faro watches what is on the member's screen, detects explicit or otherwise flagged content *on the device*, and sends allies an end-to-end-encrypted report: a summary, a timeline and blurred thumbnails of flagged moments. Allies are also told when monitoring stops, gets tampered with or has its settings changed.

There is **no central Faro service.** A church, a college, a ministry, a small group or one individual runs their own **Faro instance**. The Faro project publishes the software (client apps, server and ally web app) and signed releases, and nothing else.

### Goals

1. **Easy to self-host.** One container or binary, a SQLite default, built-in HTTPS, and an admin who isn't an engineer can get it running in under 30 minutes. It should run on a $5 VPS or a Raspberry Pi.
2. **Private by construction, even from the instance operator.** The server, and so the church or college IT person running it, only ever sees ciphertext and minimal metadata. Running an instance must not give anyone the ability to look at members' screens.
3. **Tamper-evident, not tamper-proof.** Someone with admin rights on their own machine can always defeat local software. What we can promise is that **allies find out** when that happens.
4. **Cross-platform from one core.** A single Rust core with thin per-OS layers.
5. **Consent-forward and abuse-resistant.** It must be hard to use Faro as stalkerware (see §12), which matters even more when institutions run instances.
6. **Prompt alerts.** Urgent events (high-severity flags, tamper) reach allies within about a minute, through **urgency flags** the server can see and act on (§5.4).

### Non-goals for v1

- Mobile (iOS and Android). The iOS client is specified in [IOS.md](IOS.md).
- Content **blocking** or filtering. iOS blocks: an iPhone's client is the one exception, and [IOS.md](IOS.md#1-summary) (§1) says what it does. The desktop clients still don't block.
- Live viewing of the screen. That will never be built.
- Any ML on the server.
- **Storing unblurred images anywhere.** That includes the member's own device (§3.5).
- Federation between instances (§14).

---

## 2. System overview

```
 ┌──────────────────────── Member's computer ────────────────────────┐
 │  ┌──────────────┐  frames/   ┌──────────────────────────────────┐   │
 │  │ Session Agent │──signals──▶│        Faro Service (privileged) │   │
 │  │ (per user,    │  local IPC │  scheduler · classifier (ONNX)   │   │
 │  │  unprivileged)│◀──control──│  policy engine · report builder  │   │
 │  │ capture, title│            │  crypto · hash-chained event log │   │
 │  │ URL, idle     │            │  encrypted outbox · uploader     │   │
 │  └──────┬────────┘            │  watchdog · updater              │   │
 │  ┌──────▼────────┐            └───────────────┬──────────────────┘   │
 │  │ Tray / Settings│                            │                     │
 │  └───────────────┘   ┌──────────────┐          │                     │
 │                      │ Browser ext. │──▶ Agent │                     │
 │                      └──────────────┘          │ HTTPS               │
 └────────────────────────────────────────────────┼─────────────────────┘
                                                  │ ciphertext + signed headers
                                                  │ + urgency flag
                                                  ▼
 ┌────────── Faro Instance (self-hosted: church / college / person) ──────┐
 │  faro-server (single binary or container)                               │
 │   ├─ API + ally web app (static, embedded) + admin console              │
 │   ├─ DB: SQLite (default) or Postgres                                   │
 │   ├─ Blob store: local disk (default) or any S3-compatible bucket       │
 │   ├─ Liveness monitor → missed check-in alerts                          │
 │   ├─ Notifier → SMTP email / Web Push, timed by urgency                 │
 │   ├─ Built-in HTTPS (ACME / Let's Encrypt) or behind a reverse proxy    │
 │   └─ Update mirror (caches signed releases, models, blocklists)         │
 └───────────────────────────────┬────────────────────────────────────────┘
                                 ▼
 ┌──────────── Ally's browser / ally desktop app ─────────────┐
 │  Fetches ciphertext → decrypts locally with ally's key      │
 └─────────────────────────────────────────────────────────────┘

 ┌──── Faro project (upstream, not a service) ─────┐
 │  GitHub Releases: signed clients, server images, │
 │  model + blocklist bundles, TUF-style metadata   │
 └──────────────────────────────────────────────────┘
```

The guiding principle: **intelligence lives on the edges** (the member's device and the ally's browser). **The instance is a dumb encrypted mailbox plus a liveness monitor and notifier**, so it is cheap to run and safe to hand to a volunteer administrator.

---

## 3. Desktop client

### 3.1 Process model

Every OS runs the same three processes.

| Process | Privilege | Lifetime | Responsibilities |
|---|---|---|---|
| **Faro Service** | root / SYSTEM | Boot to shutdown | Owns state, keys, the classifier, the event log, the outbox, uploads and updates. Watches over the agent. Sends heartbeats. |
| **Session Agent** | Logged-in user | One per interactive session, for **every** OS account | Screen capture, active window and app info, idle and lock state, browser-extension bridge. Shows the tray icon and the login notice (§12). Holds as little state as possible. |
| **Tray UI** (Tauri) | Logged-in user | Optional | Status, pausing (which allies are told about), ally management, viewing your own reports. *Status ([#89](https://github.com/faro-project/faro/issues/89)): on macOS the status part lives in the session agent's menu-bar menu, not a separate app: what Faro is doing ("Monitoring", "Paused until …", "Not enrolled", "Waiting for approval in the web app", or a problem such as "Screen Recording is off" or "Can't reach *instance*") and what to do, with an item that opens the fix, plus "Open Faro" and "About Faro…". On Windows, the same menu is in the agent's tray icon (the notification area). It only shows state: nothing on it stops, pauses or hides monitoring. Pausing, ally management and reports stay in the web app.* |

**Why split it:** screen capture *has* to happen inside the user's graphical session. Keys, the queue of unsent events and the classifier live in the privileged service, which a standard user cannot touch. If the agent is killed, the service relaunches it and logs `agent_restarted`. If the service is killed, the instance sees heartbeats stop.

**Every OS account is monitored.** An installation covers the whole computer, not one account. The agent runs in every interactive session of every OS account: existing accounts, accounts created later, guest sessions and remote sessions. Otherwise, switching to (or creating) another account would be a way around Faro. The service supervises one agent per session and follows session changes (fast user switching, Windows multi-session, Linux logind seats). There is no per-account opt-out, because an exemption is itself a way around monitoring. Everyone who uses the computer is told (§12). *Status ([#9](https://github.com/faro-project/faro/issues/9)): implemented in the service for macOS, Windows and Linux. It serves one agent per session on per-account sockets, sends captures to the session at the screen, raises tamper for any session without an agent, labels events with the account and sends every session the login notice. On macOS the installer (`installers/macos`) puts the agent in a global LaunchAgent, so it starts in every account's session, including accounts created later. On macOS the agent also shows the tray icon and the notice (`faro_platform_macos::ui`). On Windows, the service starts the agent in every signed-in session of every account (console, fast user switching, Remote Desktop) and restarts it if it is killed. The agent connects over a per-account named pipe (`\\.\pipe\faro\agent.<SID>`), and shows the tray icon and the notice (`faro-platform-windows`). Not done yet: the Linux packages and agent UI.*

**Who decides that an agent left on purpose:** the service, by watching the OS session, never the agent. An agent's `Goodbye` counts as expected only when its session actually ends (logout or user switch). If someone is logged in and no agent is connected for that session for 90 s, the service raises an urgent tamper event (§3.7).

**Recommendation:** members run as a standard (non-admin) user day to day and an ally keeps the admin password. Onboarding should suggest this.

**Local IPC**
- macOS and Linux: Unix domain sockets in a root-owned directory, one per account (`agent.<uid>.sock`, owned by that account, mode 0600), with peer-credential checks and verification of the connecting binary's code signature. The agent's `Hello` names its session, which must be one the OS lists for that account.
- Windows: a named pipe with a DACL, plus an Authenticode check on the client's image. *Status: implemented. Per-account pipes `\\.\pipe\faro\agent.<SID>`, the enroll pipe `\\.\pipe\faro\enroll`, and the admin approval pipe `\\.\pipe\faro\enroll.S-1-5-32-544`.*
- Protocol: length-prefixed, versioned `serde` messages using `postcard` or CBOR.
- Status: the service sends each agent `ServiceMsg::Status`, a view of its status scoped to that agent's session and the computer (`faro_ipc::MemberStatus::for_session`), for the status menu. It never names another account or session, and nothing the agent sends changes it. Before the agent's socket exists (not enrolled, or waiting for approval), the agent asks the enroll socket's `Status` instead.
- Frame transfer: the agent downscales to a longest side of 768 px and sends **raw pixels**, so the service never decodes image formats it didn't produce.

### 3.2 Code layout: one Rust core plus platform crates

```
faro/
├── crates/
│   ├── faro-core/          # scheduler, policy, event model, hash chain,
│   │                       # report builder, outbox, instance API client
│   ├── faro-crypto/        # X25519, Ed25519, XChaCha20-Poly1305, Argon2id
│   ├── faro-detect/        # ONNX Runtime (`ort`) inference, signal fusion
│   ├── faro-ipc/           # agent<->service protocol
│   ├── faro-platform/      # trait definitions (Capture, ActiveWindow, Idle, ...)
│   ├── faro-platform-macos/
│   ├── faro-platform-windows/
│   ├── faro-platform-linux/
│   ├── faro-service/       # bin: privileged service
│   ├── faro-agent/         # bin: session agent
│   ├── faro-update/        # TUF-style signed update verification (shared w/ server mirror)
│   └── faro-proto/         # wire types shared with server + web (serde + typeshare → TS)
├── apps/
│   ├── tray/               # Tauri v2 app
│   └── extension/          # WebExtension MV3 (Chrome, Edge, Firefox, Brave)
├── server/                 # faro-server: axum API, workers, admin console, embedded web app
├── web/                    # Ally + member web app (SvelteKit, adapter-static)
├── deploy/                 # Dockerfile, docker-compose.yml, systemd unit, Helm chart (later)
├── models/                 # model cards, export scripts, eval harness
├── installers/             # pkg/notarization, MSI/WiX, deb/rpm
└── docs/
```

**Why Rust:** one language across the service, the agent, Tauri and the server. Memory safety matters in a privileged process. It produces small static binaries, which also matters for self-hosters on small hardware.

**Platform traits** that every OS crate implements:

```rust
trait ScreenCapture   { fn capture_all_displays(&mut self) -> Result<Vec<Frame>>; fn permission_state(&self) -> PermissionState; }
trait ForegroundInfo  { fn active_app(&self) -> Option<AppInfo>; fn window_title(&self) -> Option<String>; }
trait SessionState    { fn idle_secs(&self) -> u64; fn is_locked(&self) -> bool; fn on_session_change(&self, cb: ...); }
trait ServiceHost     { fn install(), fn spawn_agent_in_session(session_id), fn list_sessions() }
trait TamperSignals   { fn poll(&self) -> Vec<TamperSignal>; }
```

### 3.3 Per-platform details

#### macOS (13+)

| Concern | Approach |
|---|---|
| Capture | **ScreenCaptureKit** (`SCScreenshotManager` on 14+, an `SCStream` single frame on 13), all displays. |
| Permission | Needs Screen Recording (TCC). The agent checks `CGPreflightScreenCaptureAccess()` on every tick, and revocation sends an urgent `permission_revoked` event. |
| ⚠ Risk | Recent macOS versions periodically ask users to re-confirm screen-capture access. A Phase 0 spike needs to confirm the current behavior. Worst case: the re-prompt is a normal step, and declining it reports as tamper. |
| Service | A **LaunchDaemon** (`SMAppService.daemon`) plus a **global LaunchAgent** in `/Library/LaunchAgents`, so the agent starts in every account's session, including accounts created after install. `KeepAlive` on both. |
| Active window | `NSWorkspace` for the frontmost app. Window titles go through `AXUIElement` (Accessibility permission, optional; revoking it is reported). |
| Browser URL | Extension first. Fallback: Accessibility for Safari, Chrome, Edge, Brave and Arc (the page's `AXURL`, else the address field), with the same permission as window titles. Not AppleScript, which needs an Automation permission for each browser. Only `scheme://host/` leaves the agent, since domain categorization and the report use only the host. Private windows can't be told apart this way, so `incognito` is false until the extension reports it. |
| Network signals (Phase 2) | A Network Extension DNS proxy as a System Extension. |
| Distribution | A Developer ID signed + notarized `.pkg`, built and signed **once by the Faro project**. The installer is the same for every instance (§3.8). It installs `/Library/Faro/bin/faro-uninstall`, which sends the `goodbye` (§3.7) before removing anything. |

#### Windows (10 22H2+, 11)

| Concern | Approach |
|---|---|
| Capture | **DXGI Desktop Duplication** (no capture border, multiple monitors), falling back to GDI. DRM content shows up black. |
| Service | A **LocalSystem** service with recovery actions. It launches the agent into every interactive session of every account, console and remote (`WTSQueryUserToken` + `CreateProcessAsUser`), and follows session changes. |
| Self-protection | The service DACL denies stop and delete to non-admins. State lives in `%ProgramData%\Faro` with a SYSTEM-only ACL. |
| Active window | `GetForegroundWindow`, `GetWindowText` and `QueryFullProcessImageName`. |
| Browser URL | Extension first. Fallback: UI Automation. |
| Network signals (Phase 2) | **ETW** `Microsoft-Windows-DNS-Client`, which needs no kernel driver. |
| Distribution | MSI (WiX 5), signed by the project through the **SignPath Foundation** (free for OSS) or Azure Trusted Signing. |

*Status (Windows, `0.1.0-beta.1`): implemented for x64 only (arm64 later), on Windows 10 22H2 (build 19045) and Windows 11. Capture is DXGI Desktop Duplication, with GDI as the fallback (for example in some Remote Desktop sessions and VMs). Browser addresses come from UI Automation in Edge, Chrome, Brave, Firefox, LibreWolf, Waterfox, Zen and Floorp, since the browser extension isn't built yet. The service is a LocalSystem service (`FaroService`) that starts automatically and restarts after a failure (after 5 s, 10 s and 30 s). Standard users can't stop, change or delete it. State lives in `%ProgramData%\Faro`, which only SYSTEM and Administrators can access. The MSI is per-machine and built with WiX 5.0.2. No Windows release is published yet, because the signing provider (SignPath Foundation or Azure Trusted Signing) isn't chosen.*

#### Linux (Ubuntu 22.04+, Fedora 39+; X11 and Wayland)

| Concern | Approach |
|---|---|
| Capture (X11) | `xcb` + MIT-SHM. |
| Capture (Wayland) | **xdg-desktop-portal ScreenCast** + PipeWire with `persist_mode=2` and a restore token, so the user consents once. `wlr-screencopy` on wlroots compositors. Losing the token is reported as tamper. |
| ⚠ Risk | Wayland differs between GNOME, KDE and wlroots, so Linux ships in Phase 2, after a spike. |
| Service | A systemd system unit (the service) and a **global** user unit (`systemctl --global enable`) bound to `graphical-session.target` (the agent), so it starts for every account. Sessions are found through `logind`. |
| Active window | X11 `_NET_ACTIVE_WINDOW`. On Wayland: the extension plus desktop-specific D-Bus where available. |
| Distribution | `.deb` and `.rpm` from a project-signed apt/dnf repo. |

### 3.4 Capture scheduling

- **Randomized interval**: exponential distribution with a mean of about 60 s, bounded to 15–180 s. The mean is configurable per member (30–300 s), and changing it notifies allies.
- **Burst mode**: after a borderline or flagged result, sample every 5–10 s for 2 minutes.
- **Skip unchanged frames**: if the perceptual hash (dHash) matches the last frame, reuse the previous result.
- **Pause** while the screen is locked, the session is idle or the display is asleep, and record these states so gaps in the timeline are explained.
- **Event triggers**: a foreground-app change, a new URL or a watch-listed DNS domain causes a capture 1–3 s later.
- **Budget**: under 1% average CPU, under 150 MB RSS including the model.

### 3.5 Detection pipeline (on-device)

```
frame ─▶ dHash dedupe ─▶ preprocess
      ─▶ [A] image classifier (ONNX, int8)   → p(explicit), p(suggestive), ...
      ─▶ [B] context signals                  → domain category, title keywords,
                                                app category, incognito
      ─▶ fusion/policy engine ─▶ rating {clean, low, medium, high} + reasons
      ─▶ if rating ≥ threshold: produce BLURRED thumbnail in memory
      ─▶ zeroize the original frame buffer
      ─▶ append to hash-chained event log ─▶ report builder / urgent alert
```

**No unblurred images are kept, by anyone.** The full-resolution frame lives only in memory long enough to classify it and produce the blurred thumbnail. Then the buffer is zeroized (`zeroize` crate) and freed. Frames are never written to disk, and the outbox only ever holds the blurred, already-encrypted thumbnail. Nothing in the protocol or UI can request or show an unblurred image, and there is **no setting to turn this on**, for members, allies or instance admins. This also limits Faro's exposure if the classifier ever captures illegal content (§12).

**Thumbnail.** About 320 px wide with a strong Gaussian blur (σ≈12) followed by pixelation. It shows the gist ("a video player with a person") without explicit detail. The blur is applied before any encryption or persistence, so the output can't be reversed.

**Models.** Swappable, versioned and signed by the project, and distributed through the update channel (§3.8). The beta's model ships in the macOS package and the Windows MSI instead, built from the upstream's own files at package build time ([DEVELOPMENT.md "The image model"](DEVELOPMENT.md#the-image-model)); the Windows release job takes the macOS job's build, and the service loads it with Microsoft's `onnxruntime.dll`, installed next to it. Every model's manifest carries the attribution and licence text its licence asks for.
- **Weights must be permissively licensed** (§11): no GPL, AGPL or non-commercial weights. The candidates and their licences are compared in [research/model-licenses.md](research/model-licenses.md).
- **Training data:** no model trained on a dataset with documented child sexual abuse material. Today that means NudeNet's dataset and LAION-5B, and the list grows with any later finding. A model's training data must be disclosed well enough to check this.
- Baseline for the beta: **OpenNSFW** (Yahoo, BSD-2-Clause), converted by the project from Yahoo's original weights to ONNX and quantized to int8. It is ImageNet-pretrained, which is allowed for this baseline only. NudeNet is excluded: it is GPL or AGPL, and its dataset contained CSAM.
- Long term: **a permissively licensed OpenCLIP image encoder that isn't ImageNet-based, with Faro's own linear heads** for each category (explicit, suggestive, gambling, violence). Adding a category only means shipping a new head. MobileCLIP no longer qualifies: Apple relicensed its weights as research-only in 2025.
- Runtime: `ort` with CoreML, DirectML and CPU execution providers. Target under 80 ms per frame on CPU.
- **Screenshot domain gap**: a screenshot-specific eval set, curated by the maintainer and kept outside the repository because it contains explicit imagery. `models/eval-baseline.json` holds its metrics (never images), and CI fails on regressions (DEVELOPMENT.md "Model benchmark").
- Later: on-device OCR (Apple Vision, `Windows.Media.Ocr`) combined with keyword lists.

**Context signals.** Domain categorization uses open blocklists (check licenses: StevenBlack/hosts is MIT; review OISD and UT1 terms) compiled into an FST or Bloom filter and shipped as a signed bundle. The browser extension reports `{url, title, incognito}` over native messaging. A browser in use without the extension is reported as context.

**Fusion and policy.** An explainable rules engine. Every event carries its **reasons** (`image:explicit 0.93`, `domain:adult`). Members can mark a flag as a false positive in their own view, and allies see that note.

### 3.6 Event model and the tamper-evident log

```jsonc
{
  "v": 1,
  "instance_id": "inst_…",           // the instance this device is enrolled in
  "device_id": "dev_…",
  "seq": 18234,                      // strictly increasing per device
  "prev_hash": "b3:…",               // BLAKE3 of previous event's canonical header+ciphertext
  "ts": "2026-11-23T21:04:11Z",
  "mono": 9123311,                   // monotonic ms since boot
  "boot_id": "…",
  "kind": "capture" | "flag" | "heartbeat" | "tamper" | "settings_change" |
          "agent_restarted" | "paused" | "resumed" | "goodbye" | "boot" | "shutdown",
  "urgency": "none" | "normal" | "urgent",   // plaintext, signed: drives notification timing (§5.4)
  "body": { … }                      // encrypted (§5)
}
```

- **Hash chain**: if events are deleted or reordered locally, the chain breaks. The instance checks continuity on headers only and raises an urgent `chain_gap` alert.
- **Device signing**: Ed25519 over every header (so `urgency` can't be forged or downgraded in transit). Keys live in the Keychain / Secure Enclave on macOS, TPM via CNG on Windows, and a root-only file or TPM2 on Linux. *Status: the TPM and CNG keys are not done. On Windows the keys are files in the SYSTEM-only state directory, the same as on macOS today.*
- **Outbox**: SQLite in the service's protected directory. It only holds encrypted bodies, keeps about 30 days of data while offline and prunes oldest-clean-first.
- **Clock tampering**: wall-clock and monotonic deltas are compared with each other and with the server's `Date` header.
- **Which OS account**: flag and tamper bodies record the OS account the event came from, as a short local label (the account's short name). It lives inside the encrypted body only, so the instance never sees it, while allies and the member can tell accounts apart. Reports group the timeline by account.

### 3.7 Tamper detection

| Signal | Detected by | Urgency | Ally sees |
|---|---|---|---|
| No heartbeat for longer than the grace period | Instance liveness monitor | urgent (after the grace period) | "Laptop-X hasn't checked in for 3h" plus the last known state (asleep or shut down) |
| Screen-recording / portal permission revoked | Agent / service (`permission_revoked`) | urgent | Immediate alert: "Screen Recording is off on Laptop-X", with the steps that turn it back on |
| Captures keep failing because Screen Recording is off, but the service never saw it granted to this account on this enrollment (a new install, or a reinstall that dropped the grant) | Service (`permission_revoked`, `never_granted`) | urgent | "Screen Recording is off on Laptop-X": Faro doesn't have the permission, so it can't see the screen; with the same steps |
| Captures keep failing for any other reason (5 in a row by default) | Service (`capture_failing`) | urgent | "Faro couldn't see the screen 5 times in a row" |
| Agent repeatedly killed | Service | urgent | Alert with a count |
| An interactive session (any OS account) with no connected agent for 90 s | Service | urgent | "Faro isn't running in the account *alex* on Laptop-X" |
| The session at the screen has its agent connected, nothing pauses capture, and no capture is attempted for a few capture intervals (5 min at the default mean) | Service (`capture_failing`) | urgent | "Faro couldn't see the screen 5 times in a row", for that account |
| A large on-screen window is hidden from capture (macOS `NSWindow.sharingType = .none`, Windows `WDA_EXCLUDEFROMCAPTURE` or `WDA_MONITOR`), so captures show what is behind it | Agent (`window_hidden_from_capture`, with the app's name) | urgent | "A window was hidden from Faro on Laptop-X": "*Viewer* kept a window out of Faro's screen captures" |
| Chain gap or invalid signature | Instance | urgent | Alert |
| Heartbeats claim events the instance never received, for longer than the grace period | Instance (`upload_stalled`) | urgent | "Laptop-X isn't sending what it records" |
| An active computer removed by its member | Instance (`device_removed`) | urgent | "Laptop-X was removed" |
| Uninstall (`goodbye`) | Uninstaller | urgent | "Faro was uninstalled from Laptop-X" |
| Binary or model integrity failure | Service | urgent | Alert |
| Clock manipulation | Service | urgent | Alert |
| Settings change, ally removed, pause | Service / instance | normal | Notification. **Removing an ally notifies that ally** |
| Device moved to a different instance | Old instance (`goodbye` + reason) | urgent | Alert to the old instance's allies |
| Screen Time access revoked, web filter off or Screen Time settings cleared (iPhone: `screen_time_revoked`, `filter_off`, `settings_cleared`; docs/IOS.md §10.2) | iPhone app and tunnel | urgent | "Screen Time protection is off on iPhone-X", "Faro's web filter is off on iPhone-X", "Faro's Screen Time settings were changed" |
| Browser without extension, VPN, VM, RDP | Agent / service | none (context) | Listed in the report |

Every urgent signal in this table, and removing an ally, reaches people as a tamper-class alert: it can be moved to the digest but not switched off (§5.4). Settings changes and pauses can be switched off.

**One cause, one signal.** A run of failed captures is reported once. When Screen Recording is off (the agent reports it denied, or a capture fails with `permission denied: screen_recording`), it is `permission_revoked` rather than `capture_failing`: sent at once when the service sees it go from granted to off, or at the failure threshold otherwise, and never followed by `capture_failing` for the same run. The person at the screen is told too: the agent shows "Faro can't see the screen" with a button that opens System Settings → Privacy & Security → Screen & System Audio Recording, once per agent run and again after a capture has worked in between.

**Windows hidden from capture (macOS).** An app can keep a window out of screenshots and screen recordings, Faro's included, which then show whatever is behind it. While it has Screen Recording, the agent reads every on-screen window's `kCGWindowSharingState` (`CGWindowListCopyWindowInfo`) on each poll: never a title or anything drawn. An app is reported when its hidden windows add up to 200 × 200 points for two polls in a row, on any window layer. Thin strips (under 64 points: toolbars, call controls, screen-sharing borders) and fully transparent windows don't count. Each app is reported once, and again only after five minutes without a hidden window. The person at the screen sees a notice naming the app, as their allies do. Allowed: macOS's own processes (an executable on the sealed system volume, `/System/…` but not `/System/Volumes/…`, and `/usr/libexec/…`), which hide some of their own windows (the screenshot toolbar, password and Touch ID prompts, the lock screen); never browsers (Safari's executable lives in a system cryptex) or Apple apps that run the member's own code (Script Editor, Automator, Shortcuts). No third-party app is allowed: password managers, DRM video players and screen-sharing tools are reported by name for allies to judge, since a bundle id can be copied and an allowlist would need code-signature checks. Without Screen Recording every other app's window reads "not shared", so nothing is read then, and a poll in which normal windows of two or more other apps all read "not shared" is skipped as unreliable. Details: `faro-platform-macos`'s `hidden_windows` module.

**Windows hidden from capture (Windows).** `SetWindowDisplayAffinity` with `WDA_EXCLUDEFROMCAPTURE` removes a window from every capture, and `WDA_MONITOR` blacks it out; either keeps its content from Faro. On each poll the agent lists the top-level windows (`EnumWindows`) and reads each visible one's display affinity, owner and size: never a title or anything drawn. Minimized and cloaked windows (another virtual desktop, a suspended Store app) don't count. The thresholds are the macOS ones: windows at least 64 pixels on their shorter side, adding up to 200 × 200 for two polls in a row, reported once per app and again only after a quiet spell. Allowed: executables directly under `%SystemRoot%\System32` or `%SystemRoot%\SystemApps`, which use it for some of their own UI (credential prompts), except hosts that run the member's own code (`rundll32`, `mshta`, script hosts, PowerShell, `cmd`, `conhost`, `dllhost`, `regsvr32`). No third-party app is allowed. Unlike macOS, reading another process's affinity needs no permission, so there is no unreliable reading. Details: `faro-platform-windows`'s `tamper` module.

*Status (Windows): implemented for a stopped service (its heartbeats stop, so the instance raises a missed check-in alert), a killed agent, a clock change (Windows tells the service), and program files made writable by a non-administrator (`IntegrityFailure`). A VPN and a virtual machine are context only, as on a Mac (the "Browser without extension, VPN, VM, RDP" row in the table above).*

**Instance downtime vs. device tamper.** On a self-hosted instance, the server itself can go down (a power cut, a Pi reboot). The liveness monitor records its own uptime. After an instance restart it waits for the grace period before judging any device, and it never treats a gap that overlaps its own downtime as device silence. Devices queue events offline and upload them later, and the hash chain shows whether anything is missing.

### 3.8 Distribution and updates in a self-hosted world

- **One build for all instances.** The Faro project builds, signs and notarizes the installers. Instances do **not** rebuild or re-sign clients, because macOS notarization and Windows signing would be out of reach for most self-hosters.
- **Binding to an instance happens at enrollment, not at build time.** The installer is generic. The member enrolls with a link or QR code (`faro://enroll?i=https://faro.example.org&c=XXXX-XXXX`) or by pasting the instance URL and a code. The client fetches `/.well-known/faro` (the instance's ID, its identity public key and version), shows the instance name for confirmation and pins the instance identity key. On macOS the link opens the agent, which asks the root service to enroll; the service does so only after an administrator approves in the system's own password dialog (Authorization Services, right `org.faro.enroll`; DEVELOPMENT.md, "Enrolling from the agent").
- **Updates go through the instance.** The service asks *its instance* for update metadata, and the instance mirrors and caches signed releases from upstream. The **client verifies the project's signatures** (TUF-style: an offline root key, plus targets and timestamp keys) itself, so a compromised or malicious instance can delay updates but can't push code. Instance admins can **pin a version channel** (`stable`, `stable-1`) for managed fleets, such as a college lab. Air-gapped instances can load release bundles by hand.
- **Models and blocklists use the same signed channel.** Each is one target, a *data bundle* (a manifest and the file it describes, PROTOCOL.md §8.1), with its own version, platform and arch `any`, and an optional `min_client`. The service installs one only if it is newer than the copy the package ships and than any it installed before, and only after the same checks the packaged copy passes (licence allowlist, attribution, BLAKE3, §11). It switches the detector to it between two captures, without a restart and without touching a frame (§3.5). The packaged copy stays as the fallback, and the attribution is written next to the packaged notices.
- *Status: `faro-update` verifies the metadata, and `faro-server` has the mirror (`server/src/updates`, PROTOCOL.md §8). It verifies against the project root before storing anything, prefetches what the instance's channel selects, fetches other listed artifacts on demand, and has an air-gapped `updates import`. On macOS the service updates itself (`crates/faro-service/src/update`). Every few hours it checks its instance's mirror and verifies the release against the root shipped in the package (`/Library/Faro/update-root.json`). It never goes below its own version, downloads with streaming verification, checks the package's own Developer ID signature and notarization (a rejected package is reported as an integrity failure, §3.7), and installs through a one-shot launchd job (`org.faro.update`). That job also restarts the service and agents if an install fails. A package that fails three times is skipped. Releases are built, signed and published by `.github/workflows/release.yml` to `https://updates.faro-project.org/`, and `update-timestamp.yml` re-signs the timestamp every 8 hours (DEVELOPMENT.md, "Releasing"). Models and blocklists come through the same channel (`crates/faro-service/src/update/artifacts.rs`): the release lists the packaged image model and the packaged domain list (`/Library/Faro/domains`), and a service with ONNX Runtime installs a newer model; any service installs a newer domain list, and the packaged copies stay as the fallback. Windows: the service installs the MSI itself, with `msiexec`, started detached so that it outlives the service that the MSI stops. Before it does, the update metadata is verified against the project's signatures, as on a Mac, and it checks the Authenticode signer, Faro's UpgradeCode and the version inside the MSI (`crates/faro-service/src/update/msi.rs`). No Windows package is published until one is signed. Not done yet: the project's own root keys (the key ceremony, KEY-CEREMONY.md). Linux packages will come from the project's repository rather than self-update.*

---

## 4. Faro Instance (`faro-server`)

### 4.1 Responsibilities, kept deliberately small

1. Accounts and auth for members, allies and instance admins.
2. The public-key directory: device signing keys and ally encryption keys, both counter-signed by members.
3. **Encrypted mailbox**: accept signed and encrypted events and reports, and store the blobs.
4. **Liveness monitor**: heartbeats → missed-check-in alerts.
5. **Notifier**: email or Web Push, timed by urgency. Notifications carry no content.
6. Invites, relationships and instance administration.
7. Update mirror.

It does **not** run ML, decrypt anything, build reports or hold any unblurred image.

### 4.2 Packaging: optimized for non-expert admins

| Concern | Default | Scales to |
|---|---|---|
| Delivery | **Single static binary** (`faro-server`) and an official **container image** (multi-arch: amd64, arm64) | Helm chart (later) |
| Database | **SQLite** (WAL, `sqlx`), a single file | **Postgres** for colleges or large ministries (same code via `sqlx`, chosen by `DATABASE_URL`) |
| Blob storage | **Local disk** directory | Any S3-compatible store (MinIO, R2, B2, AWS) |
| HTTPS | **Built-in ACME** (`rustls-acme`) when given a domain | Behind an existing reverse proxy (Caddy, nginx, Traefik) with `--behind-proxy` |
| Email | Any **SMTP** server (church Google Workspace / Microsoft 365, Mailgun, SES) | n/a |
| Push | **Web Push (VAPID)**, keys generated on first run | n/a |
| Web app | Ally, member and admin UIs **embedded in the binary** and served from the same origin | n/a |
| Jobs | In-process workers (liveness, notifier, retention, update mirror) | Separate `faro-server worker` processes on Postgres |
| Backups | `faro-server backup` writes a consistent snapshot (DB + blobs) to a tarball or S3 | n/a |
| Config | A single `faro.toml` plus env-var overrides. A first-run web setup wizard creates the admin account and tests SMTP | n/a |

**Hosting options, documented for each kind of host:**
- **Individual / small group**: a $5 VPS, a Raspberry Pi 4/5 at home, or a home server. For a home server without a public IP, use **Cloudflare Tunnel or Tailscale Funnel**. Devices need to reach the instance from anywhere, so a LAN-only instance isn't supported.
- **Church / ministry**: a VPS or existing church IT server via `docker compose up -d`.
- **College**: their own infrastructure, with Postgres, S3, an internal SMTP relay and optional SSO (§4.5).

**Resource guide** (estimated; confirm in Phase 1):

| Instance size | Active devices | Hardware | Storage (30-day retention) |
|---|---|---|---|
| Individual / small group | ≤ 50 | Raspberry Pi 4 or a 1 vCPU / 1 GB VPS | ~1 GB |
| Church | ≤ 1,000 | 2 vCPU / 2 GB | ~10 GB |
| College | ≤ 10,000 | 4 vCPU / 8 GB + Postgres | ~100 GB (S3 recommended) |

Per device: about 288 heartbeats a day (~90 KB) plus a 20–200 KB daily report, so roughly 0.3 MB/day.

### 4.3 Roles within an instance

| Role | Can | Cannot |
|---|---|---|
| **Instance admin** | Configure the instance (SMTP, domain, retention, registration mode, update channel), invite people, disable or re-enable accounts, grant or revoke the admin role, ask for an account to be deleted (§12), see **operational metadata** (device counts, last-seen, storage use, delivery failures) | Read any report, thumbnail, URL or rating. Enroll devices for someone else. Add themselves as anyone's ally. Disable or delete an account or change a role silently, or do any of these to their own through the console |
| **Member** | Enroll their own devices, invite and approve allies, see everything their allies see, delete their account (§12) | Hide events from allies, delete sent reports early (retention is the same for everyone, and a deleted account's data stays for a 7-day hold) |
| **Ally** | Read reports and alerts for members who approved them, set notification preferences, delete their account (§12) | Change a member's settings or devices |

**Admins are users.** The admin role is an extra on an ordinary account, not a separate kind of account: an admin can be a member or an ally like anyone else, and one admin can disable another admin's account. Nobody can disable their own account, and the last enabled admin can't be disabled.

**Granting the admin role.** An admin can make another account an admin, or take the role away, under Admin → People (`PUT /admin/api/users/{id}/admin`). The rules match disabling: nobody changes their own role, and the instance keeps at least one enabled admin who isn't being deleted. A disabled account can't be granted the role, and an account being deleted can't be changed. Every change is written to the admin log (`admin_log`, shown on the People page) and emailed to the person and every other enabled admin, the one who made it included. These notices name who did it, are always sent at once, and aren't alerts: no member's feed shows them and no ally hears of them. They aren't tamper-class either, since the role changes nothing about monitoring. If nobody can sign in as an admin, an operator with access to the server runs `faro-server admin grant --email …`, which follows the same rules and sends the same notices ("someone with access to the server"). With `--create` (and an optional `--name`), it first creates the account if no account has that address: a member with no keys, as at setup, who signs in with an email link and sets up keys like anyone else, and is emailed how to sign in (`account_created` in the admin log). The admin log is kept: retention never prunes it, and an account's purge only takes the account's id out of its entries. The role still gives no access to content: the admin routes return configuration and account metadata only.

**Disabling or deleting an account is never silent.** Deleting is in §12. A disabled account can't sign in and its sessions end. Faro always tells, by email, the person themself and everyone in an accountability partnership with them: their allies (`account_disabled`), and each member they are an ally for, with that member's other allies (`ally_disabled`). These alerts are urgent and tamper-class, so they can't be switched off, only moved to the digest. Disabling stops sign-in, not monitoring: the account's devices keep reporting and alerting its allies. Re-enabling tells the same people (`account_enabled`, `ally_enabled`, normal urgency). Both are also written to the admin log (`account_disabled`, `account_enabled`: which account, which admin, from the console, and when) and emailed at once to every other enabled admin. The admin who did it isn't emailed, and neither is the person, who has the notice above. Like role changes, these log emails aren't alerts and aren't tamper-class: the tamper-class part is the notice to the person and their partners. Disabling and re-enabling are only done in the console; there is no command-line path.

**Registration modes** (admin setting): `invite-only` (default), `open` with an email-domain allowlist (for example `@college.edu`), or `closed`.

**Groups** are a place for people doing this together, such as "Men's group, Tuesday", run by one or more facilitators who invite and look after it. Being in a group, or facilitating one, gives no access to content: only an approved ally link does that. Groups can propose alliances, but a link becomes active only when the member approves it. See [GROUPS.md](GROUPS.md).

### 4.4 Core tables (sketch)

```
instance(id, name, identity_pubkey, settings_json)
users(id, email, display_name, roles, created_at, auth...)
devices(id, owner_user_id, platform, name, sign_pubkey, member_sig, enrolled_at,
        last_seen_at, last_seq, last_hash, status)
ally_links(id, member_id, ally_id, state[pending|active|removed], member_sig, created_at, removed_at, origin_group_id)
ally_keys(user_id, enc_pubkey, wrapped_privkey_blob, created_at, revoked_at)
events(device_id, seq, ts, kind, urgency, header_sig, blob_ref|inline_ct, received_at)
envelopes(item_id, recipient_user_id, wrapped_key)
reports(id, member_id, device_id, period_start, period_end, blob_ref, created_at)
alerts(id, member_id, kind, urgency, source[device|server], created_at)
notifications(id, alert_or_item_id, recipient_id, channel, urgency, status, sent_at)
notification_prefs(user_id, member_id, urgency, channel, mode[immediate|digest|off], quiet_hours)
instance_uptime(started_at, stopped_at)   -- for liveness-vs-downtime logic
invites(token_hash, member_id, expires_at)
accountability_groups(id, name, description, created_by, meeting_json, settings_json, listed, listing_json, max_participants, archived_at)
group_participants(id, group_id, user_id, role[facilitator|participant], state[active|left|removed], joined_via, joined_at, ended_at)
group_history(id, group_id, at, kind, subject_id, actor_id)   -- joins, leaves, role changes
group_invites(token_hash, group_id, inviter_id, email|user_id, expires_at, used_at, outcome)
group_join_requests(id, group_id, user_id, state[open|accepted|not_accepted|withdrawn|void], expires_at, cooldown_until)
group_meeting_prefs(group_id, user_id, reminders, email)
group_notices(id, kind, recipient_id, actor_id, detail, dedupe_key, created_at)   -- notifications.group_notice_id points here
alliance_proposals(id, group_id, from_id, to_id, kind[request|offer|partnership], state[open|accepted|not_accepted|withdrawn|void], expires_at, cooldown_until)
proposal_blocks(user_id, blocked_id, created_at)
```

### 4.5 API surface (v1)

```
GET  /.well-known/faro            instance id, name, identity pubkey, server version, min client version
POST /v1/auth/...                 passkeys (WebAuthn) primary, email magic link fallback
                                  (Phase 2: OIDC/SAML SSO for colleges, for login only; keys stay user-held)
POST /v1/devices/enroll           {enroll_code, sign_pubkey, platform}
GET  /v1/members/{id}/allies/keys member-signed ally pubkeys
POST /v1/events:batch             signed headers (incl. urgency) + ciphertext
POST /v1/heartbeat                signed {seq, ts, state}
POST /v1/reports                  encrypted report blob + envelopes
GET  /v1/ally/feed                metadata list of reports and alerts, and each device's platform
GET  /v1/blobs/{id}               ciphertext (served directly or via presigned S3 URL)
GET  /v1/updates/...              mirrored, project-signed update metadata + artifacts
POST /v1/invites, /accept         ally invitations
POST|GET /v1/groups               create a group; list your groups (GROUPS.md §16)
GET|PATCH|DELETE /v1/groups/{id}  read, edit (facilitators), or close a group
GET /v1/groups/{id}/participants  paged roster
GET /v1/groups/{id}/history       joins, leaves, removals and role changes
GET /v1/groups/{id}/me/allies     your allies who are in this group
GET /v1/groups/{id}/user-search   facilitators find existing users to invite
GET|POST /v1/groups/{id}/invites  list or send invitations
DELETE /v1/groups/{id}/me         leave a group (alliances stay)
DELETE /v1/groups/{id}/participants/{user_id}   remove someone (facilitators)
PUT /v1/groups/{id}/participants/{user_id}/role   make a facilitator or participant
POST /v1/groups/{id}/facilitator-offer/accept|decline   take on a vacant facilitator role
POST /v1/groups/{id}/proposals    propose a request, offer or partnership (GROUPS.md §7)
GET /v1/me/proposals              your incoming and outgoing proposals
DELETE /v1/proposals/{id}         withdraw a proposal you sent
POST /v1/proposals/{id}/accept|decline   answer a proposal (accept creates pending links only)
GET /v1/me/proposal-blocks        people you have stopped from proposing
PUT|DELETE /v1/me/proposal-blocks/{user_id}   stop or allow proposals from someone
GET /v1/group-directory           listed groups, for signed-in people (listing fields only)
GET|POST /v1/groups/{id}/join-requests   list or send join requests (GROUPS.md §8.8)
DELETE /v1/groups/{id}/join-requests/me  withdraw your join request
GET /v1/me/join-requests          your own join requests
POST /v1/join-requests/{id}/accept|decline   facilitators answer a join request
PUT /v1/groups/{id}/me/meeting-reminders     your meeting reminder choices
GET /v1/me/group-invites          group invitations waiting for you
GET /v1/group-invites/{token}     read an invitation
POST /v1/group-invites/{token}/accept|decline   answer an invitation
DELETE /v1/me                     ask for your account to be deleted (§12): recent sign-in + your address
POST /v1/me/deletion/cancel       cancel it during the 7-day hold, whoever asked
DELETE /admin/api/users/{id}     an admin asks for someone else's account to be deleted (§12)
POST /admin/api/users/{id}/deletion/cancel   an admin cancels a deletion an admin asked for
GET  /v1/branding                 instance logo id, welcome line, support contact (public; only what is switched on)
GET  /v1/branding/logo/{id}.png   the logo, re-encoded by the server; the id changes with the logo
GET /admin/api/groups             group names and counts, no rosters (admins only)
DELETE /admin/api/groups/{id}     close a group as an admin (logged)
PUT /admin/api/groups/{id}/listed unlist or relist a group (logged)
/admin/*                          admin console (instance admins only, metadata only)
```

Device auth uses a device token **plus** an Ed25519 signature on every request.

---

## 5. Cryptography, trust and urgency

### 5.1 Primitives

- Device signing: **Ed25519**. Ally and member encryption keys: **X25519**.
- Content: **XChaCha20-Poly1305** with a random per-item content key (CK).
- Key wrap: `crypto_box_seal(CK, pubkey)` for each active ally **and for the member's own key** (transparency).
- Passphrase wrapping: **Argon2id**.

### 5.2 Key lifecycle

1. The ally accepts an invite. Their browser generates an X25519 keypair, wraps the private key with a passphrase-derived key and uploads the wrapped blob, so they can use it on several devices. The ally also receives a **recovery code**.
2. The member approves the ally, and the member key **signs** `{instance_id, ally_id, ally_pubkey}`. Devices only encrypt to member-signed keys, so neither the instance operator nor someone who breaks into the server can add an eavesdropping key. The member-signed recipient list devices use also carries each ally's display name (PROTOCOL.md §5.1), so a device names allies without trusting the instance.
3. Device enrollment: the member key signs the device's public key.
4. An optional **safety code** (a key fingerprint) lets a member and ally compare keys in person, which suits a church small-group setting.

### 5.3 Trusting the instance operator

Self-hosting means many operators with varying security skills. The design assumes **the instance can be curious or compromised** and limits the damage:

| Operator / attacker could… | Mitigation |
|---|---|
| Read reports | E2EE. Only ciphertext is stored |
| Insert their own ally key | Ally keys must be member-signed |
| Forge or suppress urgent events | Headers are device-signed, and suppression shows up as a gap in the member's own view and the hash chain |
| Push a malicious client update | Clients verify **project** signatures, not instance signatures |
| **Serve malicious web-app JavaScript to steal ally keys** | The hardest risk, common to all web E2EE. Mitigations: (a) the embedded web app is a **project-signed, versioned bundle**, and the server refuses to start with an unsigned bundle unless run in `--dev`; (b) a **Faro Ally desktop app** (Tauri, project-signed, Phase 2) gives security-sensitive allies a client that doesn't load code from the instance; (c) Subresource Integrity plus a strict CSP; (d) document honestly that an ally using the web app trusts the instance operator not to modify the code |
| Make a page look like a Faro security message (instance branding) | Branding is plain text, one short line, labelled as the instance admins', and shown only in page chrome (header, footer, sign-in and setup pages), never in alerts, feeds, reports, safety codes, fingerprints, tamper warnings, enrollment or emails. The logo is decoded and re-encoded to PNG by the server (SVG refused) and always sits next to Faro's, never in place of it |
| See metadata | Accepted: who is linked to whom, device counts, timing, event kinds and **urgency levels** (§5.4). Documented in the operator privacy notice |

### 5.4 Urgency flags

Every event carries a **plaintext, device-signed `urgency`** so the instance can decide *when* and *how* to notify without decrypting anything.

| Urgency | Produced by | Default delivery |
|---|---|---|
| `urgent` | `high` rating flag, `medium` rating flag (by default), every tamper event, uninstall, chain gap, invalid signature, missed check-in past grace, upload stall, a computer removed by its member, an account disabled by an admin, a member asking for their account to be deleted | **Immediate** email + Web Push |
| `normal` | `medium` flag (if the member chooses), settings change, ally added or removed, pause or resume, an account re-enabled, an ally deleting their account, a deletion cancelled | Bundled into the **next hourly digest** |
| `none` | Clean captures, heartbeats, low-rated flags, context signals | Only in the daily report |

- Server-generated alerts (missed check-in, chain gap) set their own urgency.
- **Allies choose** per member and urgency level: immediate, digest or off, with quiet hours. The member makes the same choice for their own alerts. The exception is **tamper-class alerts** (listed below): they **can't be turned off, only moved to the digest**, so tamper can't be silenced quietly.
- **Tamper-class alerts** are the ones `notify::policy::is_tamper_class` picks out. If a recipient chose off for the alert's urgency, the server sends them in the hourly digest instead (`notify::policy::effective_mode`). Any other choice is kept. Quiet hours still hold them back, and the feed shows them at once. This applies to every recipient: the member and each ally. The list is:

  | Kind | Source | Urgency | Why it can't be switched off |
  |---|---|---|---|
  | `tamper` | device | urgent (floor) | Something interfered with Faro: a permission revoked, the agent killed repeatedly, an integrity failure, the clock changed, an account in use with no agent, a window hidden from capture, an iPhone's Screen Time access revoked, its web filter turned off or its Screen Time settings cleared, and the other §3.7 signals. Context-only signals (VPN, VM, remote desktop, browser without the extension) never become `tamper` events. |
  | `goodbye` | device | urgent (floor) | Faro was uninstalled or moved to another instance. |
  | `chain_gap` | server | urgent | Events are missing, were rewritten, or the device's history forked (§3.6, PROTOCOL.md §7). |
  | `invalid_signature` | server | urgent | An event or report arrived that the device's key didn't sign. |
  | `missed_checkin` | server | urgent only | The device went silent past the grace period. The normal-urgency "back online" alert of the same kind is not tamper-class. |
  | `upload_stalled` | server | urgent | The device is alive but not uploading what it records (PROTOCOL.md §7). |
  | `device_removed` | server | urgent | The member removed an active computer, which stops its monitoring. |
  | `ally_removed` | server | normal | The member removed an ally, or an ally left. That is the most direct way to stop being watched. A removed ally is told too. |
  | `account_disabled` | server | urgent | An admin disabled the account (§4.3). The person is told even though their account is disabled. |
  | `ally_disabled` | server | urgent | An admin disabled the account of one of the member's allies (§4.3). |
  | `account_deleted` | server | urgent | The member, or an admin, asked for the member's account to be deleted (§12). Sent to the member and their allies, and to a disabled member too. |
  | `ally_deleted` | server | normal | One of the member's allies asked for their account to be deleted, or an admin did (§12). |
  | `account_deletion_cancelled` | server | normal | A deletion was cancelled during its hold (§12). Sent to everyone who was told about it. |

  In the table, "urgent (floor)" means the instance raises the event to urgent with `EventKind::min_urgency()`, whatever the device signed. The source is the alert's source: a device kind never counts as a server kind, or the other way round. Everything else can be switched off, including flags of any rating, `settings_change`, `paused`, `resumed`, `agent_restarted`, `ally_added`, `member_settings_changed`, `account_enabled` and `ally_enabled`.
- The member chooses the threshold mapping within per-rating floors. The default and the floor are not always the same:

  | Rating | Default | Floor (lowest the member may choose) |
  |---|---|---|
  | `low` | `none` | `none` |
  | `medium` | `urgent` | `normal` |
  | `high` | `urgent` | `urgent` |

  Changing the mapping in either direction, including lowering `medium` flags to `normal`, is itself a `normal` event that allies are told about. The floors are enforced on the device: the instance can't see a flag's rating, so its own floor (`EventKind::min_urgency`) applies to event kinds, not ratings.
- A device keeps the mapping it last announced to allies. Devices that started before `medium` defaulted to `urgent` stay at `normal` until the member changes it; only new devices start at the new default, so allies never see a mapping change the member didn't make.
- **Group notices are not tamper-class.** Joins, leaves, removals, archiving, proposals and meeting reminders ([GROUPS.md §14](GROUPS.md#14-notifications)) are normal urgency, and each recipient's own choice for normal alerts applies. Existing kinds still fire for links formed in groups: removing an ally sends `ally_removed` whether the link began in a group or not. Leaving or being removed from a group ends no link.
- Notification text is content-free: *"Urgent: new alert for Sam on Laptop-X. Open Faro to view."* Details only appear after decryption in the app.
- **Privacy trade-off, accepted:** the operator can see *that* an urgent event happened and when, but not what it was. The operator privacy notice states this.

---

## 6. Reports and the ally experience

- **Daily reports are built on the device** (weekly is optional). Each contains an activity timeline, counts by rating, flagged moments with reasons and blurred thumbnails, optional top domains and apps (off by default), and a tamper and health summary.
- **Urgent and normal items** go out as small encrypted events and trigger notifications according to §5.4.
- **Ally web app** (served by the instance; desktop app in Phase 2): unlock with a passphrase or a passkey PRF, decrypt locally. Feed per member, urgency badges, device health, and conversation prompts. The product's real goal is honest conversation, not policing. *Status: the web app has the member and ally pages. Keys unlock with a passphrase or recovery code (passkey PRF not yet); the crypto is a pure-JS TypeScript port of `faro-crypto`, since the page CSP rules out WebAssembly, checked against shared test vectors.*
- **Member view**: exactly what allies see, plus the false-positive note.
- **An ally of members on several instances** has one account per instance in v1. The ally desktop app (Phase 2) can hold several instance accounts in one place.

---

## 7. Onboarding flows

**Instance admin**
1. `docker compose up -d` (or run the binary), point DNS at it, open `https://faro.example.org/setup`.
2. The setup wizard asks for the instance name, the admin account (passkey), SMTP settings (with a test email), the registration mode and the retention period.
3. The admin invites members, or shares the signup link.

**Member**
1. Accepts the invite, creates an account and a member key (passphrase + recovery code).
2. Downloads the official installer (linked from the instance), installs it and grants OS permissions with guided screens. The installer says plainly that **every account on this computer will be monitored** and suggests disabling the guest account. Enrolling the device (step 3) lists the existing accounts and warns if the guest account is on, before monitoring starts.
3. Enrolls the device using the instance link or QR code, confirms the instance name, and the member key signs the device key.
4. Invites allies, who might be on the same instance or people who only ever use that instance's ally login.
5. Optional: browser extension, a standard user account, and an ally who holds the admin password.

---

## 8. Data retention

- Configurable per instance by the admin. Members can choose **shorter** retention, never longer.
- Defaults: event headers 90 days, report and thumbnail blobs 30 days, alerts 90 days.
- A retention worker hard-deletes expired rows and blobs. Backups follow the same windows (the docs explain backup rotation).
- Deleting an account (§12) removes everything about the person through the same code path, after a 7-day hold. **Older backups still hold it until they are rotated out**, and restoring a backup taken before a deletion brings that account back, including its computers' tokens (SELF-HOSTING.md §9).
- Unblurred frames are never stored anywhere (§3.5), so retention only ever applies to ciphertext and metadata.

---

## 9. Security considerations

- **Threat model, in priority order**:
  1. The member evading monitoring on their own machine. Handled by the privilege split, the hash chain, heartbeats, permission monitoring and urgent tamper alerts. A determined admin can evade capture, **but not silently**.
  2. A curious or compromised instance operator (§5.3).
  3. A network attacker. TLS 1.3 everywhere, signed requests and a pinned instance identity key.
  4. A malicious update. Project-signed, TUF-style updates verified on the client.
- The service never decodes image formats from the network or from the agent; it gets raw pixels only.
- `cargo fuzz` covers the IPC, wire and update-metadata parsers.
- Reproducible builds for the client and server.
- **Secure defaults for operators**: invite-only registration, admin passkey, automatic HTTPS, security headers, rate limiting, and a `faro-server doctor` command that checks the configuration (TLS, SMTP, backups, disk space, update freshness).
- A third-party audit of the crypto and update design before 1.0.

---

## 10. Testing strategy

- Unit and property tests for `faro-core`, `faro-crypto` and `faro-update`. The detection eval suite runs in CI.
- Platform CI matrix: macOS (Apple Silicon and Intel), Windows (x64) and Linux (x64) on GitHub's hosted runners (DEVELOPMENT.md, CI runners). Linux display tests use Xvfb plus headless Weston.
- **A test that no unblurred frames are kept**: run the pipeline under an instrumented allocator or file-system watcher and assert that no frame-sized buffer is written to disk or IPC beyond the classifier, and that every persisted image is a blurred thumbnail.
- E2E: the server in both SQLite and Postgres modes, plus a headless client in synthetic-capture mode, with Playwright driving the ally app to check decryption, urgency routing and digest timing.
- Tamper tests: kill the agent, revoke permissions, delete outbox rows, take the instance down → expect the right alerts, with no false alarms from instance downtime.
- Self-host tests: the container image boots on arm64 (a Raspberry Pi in QEMU), the setup wizard completes, and backup → restore works.

---

## 11. Licensing

- All Faro code is **Apache-2.0**: client, server, web app and installers. Forks, including closed or commercial ones, are allowed.
- **Trademark**: Apache-2.0 doesn't grant trademark rights. Keep the "Faro" name and logo for official builds so that users can tell which installers are signed by the project. Forks distribute under their own name.
- Third-party components must be Apache-2.0 compatible. That rules out AGPL or non-commercial model weights and blocklists that don't allow redistribution. CI runs `cargo-deny` to enforce license policy.

---

## 12. Ethics, consent and abuse resistance

Institutions running instances (churches, colleges) make consent even more important. The architecture enforces it:

- **Never invisible**: a persistent tray icon that can't be hidden, plus a monthly on-device notice listing the current allies (by the names the member signed, PROTOCOL.md §5.1) and the instance name and operator. The icon and the notices belong to the session agent, not the optional tray app, because the agent is the process that is always running in every session (§3.1): if it is killed, launchd restarts it and the service raises tamper. *Status (macOS): a menu-bar icon with no Quit item that can't be dragged out of the menu bar. macOS 26 and later let the user turn menu-bar items off in System Settings, and the agent doesn't detect that yet.* *Status (Windows): a tray icon with no Exit item. The monitoring notice at sign-in is a window, not a notification, because Focus Assist and full-screen apps silently drop notifications. Hiding the icon in the notification area's overflow isn't detected: it is a display preference, and the agent and monitoring keep running.*
- **Everyone who uses the computer is told.** Monitoring covers every OS account (§3.1), so the tray icon and a login notice appear in every account's session: "This computer is monitored by Faro for *member*. Screenshots are blurred and shared with *allies*." Faro is meant for a computer the member controls. On a shared computer, everyone is monitored and everyone is told; the installer warns about this up front.
- **The monitored person holds the account and keys.** Instance admins **cannot** enroll devices for someone else, become someone's ally on their own, or read content. A college or church can host the service but can't use it to monitor people who haven't opted in themselves.
- **Full transparency**: the member sees everything allies see.
- **Members can always leave**: uninstalling is allowed but never silent. Members and allies can also delete their account, and that is never silent either:
  - **Asking.** Settings → "Delete your account" needs a sign-in within the last 10 minutes and the account's address typed out (`DELETE /v1/me`). The passphrase isn't used: the server can't check it, allies and admins may have none, and a forgotten passphrase must not stop anyone leaving. The instance's only admin can't delete their account.
  - **Telling.** At once, by email, with alerts that can't be switched off: the person and their allies (`account_deleted`), and each member they are an ally for, with that member's other allies (`ally_deleted`). The emails give the date.
  - **A 7-day hold, for every account.** Nothing else changes: their computers keep reporting and alerting allies, allies can still open what was sent, and the person can still sign in. Only what the purge would have to undo is refused: inviting allies, adding computers, approving new ones. Every page offers **Cancel deletion**. Cancelling tells the same people (`account_deletion_cancelled`, with both times), and a later request starts a new hold.
  - **The purge.** After the hold, and only once every notice has been delivered (an email outage makes it wait; the admin is told after a week), the instance stops accepting the person's computers (`403 account_deleted`; the uninstaller's `goodbye` then goes ahead, since allies were told), ends their links (members re-sign their ally list, as after a leave), and deletes their ciphertext, rows and keys through the retention code path, then the account.
  - **An admin can ask too**, under Admin → People (`DELETE /admin/api/users/{id}`): for an erasure request from someone who can no longer sign in, or to remove a disabled account. It is the same request, hold, notices and purge, with the same confirmation (a sign-in within 10 minutes, the account's address typed out). The notices say the account is "being deleted by the instance administrator", without naming the admin, and a disabled person is emailed too. The person keeps their sessions and the banner says who asked. During the hold the person or any admin can cancel, and a cancel tells the same people. A deletion the person asked for is theirs alone to cancel. The request and any cancel are written to the admin log and emailed to every admin. Admins can't delete their own account this way (they use Settings), and nobody can delete the last enabled admin. A disabled account stays disabled during the hold: re-enabling it means cancelling the deletion first.
  - **What remains** after a purge: the person's opaque user id and public keys inside *other* members' signed event headers and recipient-manifest history (signed data can't be edited), alert detail codes on other members' alerts that name the id (for example `ally=usr_…`), the keyed hashes of their computers' tokens for 365 days (so the computers get a clear refusal), server log lines with the id, and older backups until they are rotated out.
- **No unblurred images anywhere**, which limits harm if devices, outboxes or instances are compromised.
- **Operator privacy notice**: the setup wizard generates a plain-language notice of what the operator can and cannot see, and members are shown it at signup.
- **Minors**: out of scope for v1, and the docs say colleges should not enroll minors without a separate design and legal review.
- **Legal**: each operator is the data controller for their instance. The project ships template privacy text (GDPR/FERPA considerations for colleges) but gives no legal advice. Because images are always blurred and E2EE, operators can't see content, but the docs should still cover what to do if an ally reports seeing apparently illegal material.

---

## 13. Roadmap

**Phase 0: Spikes (2–4 weeks)**
1. macOS ScreenCaptureKit from a LaunchAgent: permission persistence and re-prompt behavior.
2. Windows: capture from an agent launched by the service into the user session; multi-monitor, user switching, RDP.
3. Model benchmark: OpenNSFW, exported to int8 ONNX, on the screenshot eval set. The license review is done ([research/model-licenses.md](research/model-licenses.md)).
4. Wayland portal restore tokens on GNOME and KDE.
5. Crypto round trip: Rust encrypt → browser decrypt, member-signed ally keys.
6. `faro-server` skeleton on SQLite with built-in ACME, running on a Raspberry Pi.

**Phase 1: MVP (macOS + Windows clients, self-hostable server)**
Service and agent, scheduler, classifier v1, in-memory blur and zeroize, hash chain, outbox, E2EE, urgency flags and notifier (SMTP, immediate and digest), liveness monitor with downtime awareness, `faro-server` (SQLite and Postgres, local disk and S3, ACME, setup wizard, admin console, backups, update mirror), ally and member web app, tray UI, project-signed installers and updates, docker-compose and self-hosting docs. Closed beta with 2–3 pilot instances (an individual, a church, a college). *Status of the tray UI: on macOS, the agent's menu-bar status menu ([#89](https://github.com/faro-project/faro/issues/89), §3.1); no separate tray app. On Windows the agent's tray icon has the same menu.*

**Phase 2: Hardening, Linux, institutions**
Linux client, browser extension, DNS/ETW signals, full tamper table, CLIP-head model, OCR, Web Push, Faro Ally desktop app, signed web bundles, OIDC/SAML SSO, groups ([GROUPS.md §20](GROUPS.md#20-rollout) for the phases), `faro-server doctor`, reproducible builds, crypto audit, an opt-in public list of instances for people who don't want to host their own (§14).

**Phase 3: Beyond**
Optional DNS-level blocking, ChromeOS, Android, a limited iOS client (Screen Time / content filter, specified in [IOS.md](IOS.md)), Helm chart, and possibly federation between instances.

---

## 14. Open questions and decisions

### Open

- **Funding and stewardship of the project**: signing certificates, the Apple Developer account and the release infrastructure have small fixed costs and need a responsible owner (a nonprofit? fiscal sponsorship?).
- **Mobile timing**: many users' main risk is the phone, so mobile shouldn't slip so far that the product isn't useful.

### Decisions

- **Cross-instance allies: one account per instance is enough for v1.** An ally who supports members on two instances has an account on each. Lightweight federation (an ally on instance A following a member on instance B) stays out of v1 (§1) and is at most a Phase 3 possibility (§13).
- **Capture frequency default: a 60 s mean** (§3.4), `MEAN_DEFAULT_SECS` in `faro-core`'s scheduler. Members can still choose 30–300 s, and allies are told when they do.
- **Default urgency mapping: `medium` flags are `urgent` by default.** The floor stays `normal`, so a member may lower them, and allies are told when they do (§5.4). Devices that started before this default keep the mapping they already announced; only new devices start at `urgent`.
- **Instance discovery: yes, an opt-in public list of instances, later.** It helps people who don't want to host their own (for example a ministry offering a free shared instance). It isn't needed for the beta and is on the Phase 2 roadmap (§13).
