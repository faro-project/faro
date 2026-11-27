# Faro: Android client

**Status:** Proposal, draft v0.1 (2026-11-26). Being built on the `android-client` branch.
**Replaces:** "Android" in [ARCHITECTURE.md §13](ARCHITECTURE.md#13-roadmap) Phase 3, and answers the "Mobile timing" open question (§14) for Android. The iOS half is [IOS.md](IOS.md).
**Changes a v1 non-goal, on Android only:** mobile ([ARCHITECTURE.md §1](ARCHITECTURE.md#non-goals-for-v1)). Unlike iOS, it doesn't change the "no blocking" non-goal: Android Faro watches.
**Depends on:** the desktop capture, blur and detection pipeline (§3.4 to §3.6), tamper detection (§3.7), enrollment and member approval (§3.8, §7), the hash chain and heartbeats ([PROTOCOL.md](PROTOCOL.md)), urgency flags and tamper-class alerts (§5.4), the signed update channel ([KEY-CEREMONY.md](KEY-CEREMONY.md)).

---

## 1. Summary

Android lets an app take screenshots of the whole screen, in the background, with one permission the member grants once: an **accessibility service** (§2). So Faro on Android does what Faro on a computer does, and does not do what Faro on iOS does. It **watches**: it captures the screen on the same random schedule, classifies each frame on the phone, keeps only a blurred thumbnail for frames that are flagged, and tells allies. It is tamper-evident in the same way. It does not block anything.

The shape of the app is simpler than on a computer, because Android has no privileged service and no per-user agent. **One app process** does both jobs:

- an **accessibility service** takes the screenshots and reads the foreground app and browser address;
- a **foreground service**, with a persistent notification, hosts the Rust core and the scheduler (the notification is Faro's tray icon and its "this device is monitored" notice, §13);
- a **device admin** receiver gives Faro one thing: it can warn allies before it is uninstalled (§5.2, §8).

The design is honest about the limit that shapes everything else: **the member owns the phone and can always uninstall Faro.** Android gives an app no way to prevent that, short of Device Owner mode, which Faro rejects (§5.2). What Faro guarantees is that allies find out: by an urgent alert when the member goes through Device Admin or the accessibility switch, and by a missed check-in when anything else happens (§8).

---

## 2. What Android allows, and what it doesn't

The constraints that shape this design. Several rows are behaviours that vary by Android version or maker. The ones we haven't confirmed are marked with a spike number (§15) and are questions, not facts.

| Constraint | Consequence for Faro |
|---|---|
| No root service, and no admin-versus-standard-user split like Windows or macOS. The member is the owner of the phone and can uninstall any app from Settings. | Faro can't prevent removal. It can only make removal loud (§5.2) and make silence visible (§8). The threat model says so in plain words (§14). |
| `MediaProjection` needs the member's consent for every capture session. Since Android 14 a granted token can't be reused for a second session. After a reboot, or after the session ends, Faro would need the member to tap through a consent dialog again. | Not the primary capture path (§5.1). Whether a session survives screen lock on Android 15 and 16 is spike S9. |
| `AccessibilityService.takeScreenshot` (API 30+) works from a bound accessibility service, with no per-session consent. Android restarts an enabled service after a reboot. It is rate limited by the system (one request per 333 ms or so; to be measured). | The chosen capture path (§5.1). `minSdk` is 30. |
| Google Play's policy limits the Accessibility API to apps that help users with disabilities, with narrow exceptions. A screen monitor is likely outside them. | No Play Store in the first release (§11). Phase C asks whether a Play listing is possible at all. |
| From Android 13, an app installed outside a store is under "restricted settings": its accessibility service can't be switched on until the member opens the app's info page, uses the overflow menu to allow restricted settings, and then enables the service. | Enrollment has a guided step for this (§10), and the flow differs by Android version and maker (spike S3). |
| Windows with `FLAG_SECURE` can't be screenshotted: `takeScreenshot` fails with `ERROR_TAKE_SCREENSHOT_SECURE_WINDOW`. Banking apps, Signal, Chrome Incognito, Firefox private tabs and DRM video set it. | Faro can't see these windows, and doesn't try to (§4). A sustained secure window is reported as `window_hidden_from_capture`, as on desktop (§8). Browsers are never exempt, so private browsing shows up as a hidden window. |
| An app is not told when it is being uninstalled, and a force-stopped app does not run again until the member opens it. | No "uninstalled" hook exists. Device Admin gives a warning one step earlier (§5.2). Force-stop, uninstall without admin, and a factory reset all look like a silent phone, which the instance reports as a missed check-in (§8). Whether an enabled accessibility service comes back after a force-stop is spike S4. |
| Doze, App Standby, battery savers and the makers' own background killers (Xiaomi, Samsung, OnePlus, Huawei and others) can stop background work and sometimes kill a foreground service. | Faro asks to be exempt from battery optimisation, and reports when it isn't (context, §8). The heartbeat doesn't depend on the member opening the app. How well this works on each maker's phones is spike S1. |
| A foreground service must show a persistent notification the member can see. | This fits §12 of ARCHITECTURE.md ("never invisible"). The notification has no stop, pause or hide action (§4). |
| More than one person can use a phone (multiple users, work profiles, and Private Space on Android 15). Each has its own app installs and its own accessibility settings. | Faro covers the user it is installed in. The documented limits are in §13. Whether capture reaches into a Private Space or a work profile is spike S6. |
| Google has announced that, in the coming years, apps installed on certified devices must come from a **registered developer**, including apps installed outside Play, with roll-out by region starting in 2026. | Something to confirm before the beta, not a fact this document can rely on. It could require the project to register, and it could change how a sideloaded APK is installed. Spike S8. |

---

## 3. Goals and non-goals

### Goals

1. **Watch the phone like a computer.** The same random schedule, the same classifier, the same blurred thumbnails, the same flags and reports.
2. **Tamper-evident, not tamper-proof, as on desktop.** The member owns the phone and can uninstall Faro. Allies always find out, quickly.
3. **Nothing leaves the phone except the end-to-end-encrypted report to allies.** Frames are never written to disk, and browser addresses are reduced to `scheme://host/`.
4. **Works on an ordinary phone.** No root, no ADB, no Device Owner provisioning, no computer needed.
5. **Same instance, same allies.** An Android phone enrolls in the member's existing instance like a computer, and allies see it next to the member's computers.

### Non-goals

- **Blocking or filtering** (ARCHITECTURE.md §1). Android Faro watches.
- **Device Owner or MDM mode** (§5.2). It would stop uninstalling, but only by giving whoever sets it up control of the device. Same stalkerware reasoning as in IOS.md §5.
- **The Google Play Store for the first release** (§11).
- **Minors.** Faro is for adults (ARCHITECTURE.md §12).
- **ChromeOS.** It runs Android apps, but Faro doesn't promise it works there.
- **Tablets as a special case.** An Android tablet runs the same app. Nothing is designed for it in the first release.
- **Wear OS and Android TV.**
- **Reading content Android hides from apps** (§4).

---

## 4. Principles (invariants)

The six invariants in [DEVELOPMENT.md](DEVELOPMENT.md#invariants-every-change-must-keep) hold unchanged: no unblurred image leaves memory, the instance sees only ciphertext and header metadata, devices encrypt only to member-endorsed keys, tamper can't be silenced, clients trust project signatures for updates and never the instance, and disabling or deleting an account is never silent. These add to them, and would join that list when Phase A ships.

1. **Frames never leave Kotlin except into the Rust core, and they are zeroed.** The screenshot's `HardwareBuffer` and `Bitmap` copies are recycled, and any `ByteArray` Kotlin kept is overwritten with zeros, as soon as the downscaled RGBA bytes have been handed to Rust. Kotlin never writes a frame to disk and never logs one. In Rust the bytes move straight into a `faro_platform::Frame`, which is zeroized on drop.
2. **Addresses are reduced to `scheme://host/` in Kotlin and checked again in Rust.** The accessibility tree gives Faro the whole address bar. Kotlin keeps only the scheme and host. The Rust core refuses anything with a path, a query or credentials, as the desktop does. A full address is never logged and never leaves Kotlin.
3. **Nothing in the app can stop, pause or hide monitoring.** No "stop" or "pause" action on the notification, no setting, no quick tile. Pausing is the same instance-side, ally-visible mechanism as on desktop, not a switch in the app.
4. **The notification is the notice.** The foreground notification is always present while Faro runs, and its text says that this phone is monitored and who sees the reports.
5. **Faro doesn't defeat Android's own protections.** No rooting or root detection tricks, no private or hidden APIs, no reading `FLAG_SECURE` content by any route, no grabbing credentials, no turning on a permission through the accessibility service on the member's behalf. A window Android hides from Faro is reported, not worked around.
6. **The member's own phone, the member's own choices.** Allies and instance administrators can't change Faro's settings on the phone (ARCHITECTURE.md §12).

---

## 5. The options, and which ones Faro uses

### 5.1 Capture

| Mechanism | Works on an ordinary phone? | Survives a reboot without the member? | Verdict |
|---|---|---|---|
| **Accessibility service, `takeScreenshot`** (API 30+) | Yes, after the member enables the service once. Sideloaded installs need the restricted-settings step (§2). | Yes: Android restarts an enabled service (confirm on each maker's phones: S1) | **Chosen** |
| `MediaProjection` through a foreground service | Yes, with a consent dialog per session | **No.** A fresh consent is needed after each reboot, and since Android 14 for each session | Rejected for v1. It could come back as a fallback when accessibility capture fails, but a nag that the member has to answer is a poor tamper signal. Spike S9 asks whether it survives screen lock. |
| Root or ADB-based capture (`screencap`, a shell user, wireless debugging) | Needs a rooted phone, or a computer or on-device pairing the member would have to keep alive | No | Rejected. Not an ordinary phone, and it needs developer settings that weaken the phone. |
| `FLAG_SECURE` bypasses (virtual displays, hidden APIs, reading the compositor) | n/a | n/a | Rejected (§4 principle 5). Not Faro's to defeat. |
| Reading the accessibility tree alone (text, no pixels) | Yes | Yes | Not a replacement. Detection works on pixels (§7.2), and the tree is unreliable for images. Kept for the foreground app and address bar only. |

### 5.2 Uninstall protection

| Mechanism | What it does | Can the member get around it? | Verdict |
|---|---|---|---|
| None | The member uninstalls from Settings or the launcher. Faro isn't told. The instance sees a missed check-in. | n/a | The baseline for everything not below |
| **Device Admin** (`DeviceAdminReceiver`) | While Faro is an active admin, Android won't uninstall it until the member deactivates it in Settings. Faro gets `onDisableRequested` first, and `onDisabled` after. | Yes. Deactivating takes a few taps. | **Chosen.** Faro reports deactivation (`PermissionRevoked { permission: "device_admin" }`, urgent) before the uninstall can happen (§8). It turns a silent removal into a loud one, which is the point. Device Admin is deprecated for new policy uses, but the plain "admin must be deactivated before uninstall" behaviour is what is needed here. Whether that holds on current releases and on each maker's phones is spike S1. |
| **Device Owner** (set up by ADB or QR provisioning on a factory-reset phone) | Can block uninstall, with no way around short of a factory reset | Only by wiping | Rejected for now. It needs a wipe and a provisioning step, and it hands control of the phone to whoever provisions it, which is the stalkerware risk §12 forbids. It may come back as an expert option. |
| Profile Owner (work profile) | Controls only a separate profile | n/a | Rejected. It doesn't cover the member's own apps. |

---

## 6. Process model and code layout

On a computer, a root service and a per-user agent are two processes (ARCHITECTURE.md §3.1). Android has neither. Faro on Android is **one app process**, with Kotlin owning everything Android-specific and Rust owning everything Faro-specific:

```
                  ┌──────────────────── one app process ────────────────────┐
                  │                                                           │
 member ──────►   │  Kotlin (apps/android)                                    │
 (enroll, status) │   • FaroAccessibilityService  takeScreenshot, window and  │
                  │       address-bar reads, secure-window detection          │
                  │   • FaroForegroundService     persistent notification,    │
                  │       owns the Rust object, restarts it                   │
                  │   • FaroDeviceAdminReceiver   onDisableRequested/Disabled │
                  │   • enrollment, status screen, monitoring notice          │
                  │            │  ▲                                           │
                  │   UniFFI   │  │  AndroidPlatform callbacks                │
                  │            ▼  │  (capture_screen, foreground_app, ...)    │
                  │  Rust (crates/faro-android, libfaro_android.so)           │
                  │   • faro-service's runtime: scheduler, classifier,        │
                  │     blur, chain, outbox, heartbeats, tamper               │
                  │   • InProcessFrameSource over an AgentPlatform whose      │
                  │     calls go to Kotlin                                    │
                  └───────────────────────────┬───────────────────────────────┘
                                              │ HTTPS, ciphertext only
                                              ▼
                                        Faro instance
```

- **`apps/android`** (Kotlin, Jetpack Compose for the screens): the accessibility service, the foreground service, the device admin receiver, enrollment, the status screen, the monitoring notice, and the glue to the Rust library. `minSdk` 30, `targetSdk` and `compileSdk` 35.
- **`crates/faro-android`**: the Rust half, built as a `cdylib` (`libfaro_android.so`) and a `lib`, with UniFFI 0.29 in proc-macro mode, the same as `faro-mobile`. Kotlin bindings are generated with `uniffi-bindgen` from the built library, into the package `org.faro.core`.
- **Reused, not copied:** `faro-service`'s runtime (scheduler, capture loop, tamper tracking, outbox and uploads), with `source::InProcessFrameSource` standing in for the desktop's agent connection; `faro-client` (enrollment, instance client, heartbeats), `faro-core` (writer, hash chain, outbox, urgency, reports), `faro-crypto`, `faro-proto`, `faro-detect` (image pipeline, domain bundle) and `faro-update` (verification).
- **The platform boundary** is the `AndroidPlatform` trait, which Kotlin implements and Rust calls from its own worker threads, never the main thread: `capture_screen`, `permission_state`, `foreground_app`, `browser`, `idle_secs`, `is_locked`, `display_asleep`, `poll_tamper` and `show_notice`. Kotlin calls `FaroAndroid` for `preview_enrollment`, `enroll`, `poll_approval`, `start`, `stop`, `status`, `report_tamper_now` and `session_changed`.

**Why this differs from iOS's `faro-mobile`.** `faro-mobile` is a set of calls the app and its extensions make one at a time: no runtime, no scheduler, no threads of its own. That fits iOS, where the long-running work is done by a Network Extension that the system owns, and several 6 MB processes share one database, so each one can only do a small thing and leave. Android has a single process that can stay alive under a foreground service, so the whole desktop runtime can run inside it. Embedding that runtime avoids writing the schedule, the capture loop, the heartbeat and the tamper logic a second time. The cost is that `faro-android` is a bigger library, and the runtime must be careful about Android's lifecycle (the process may be killed at any moment, §8).

---

## 7. Capture, scheduling and detection

### 7.1 Capture and scheduling

- **Schedule.** The same as on desktop (ARCHITECTURE.md §3.4): a randomised interval around the configured mean, with the same jitter and the same flag-triggered extra captures.
- **Paused while the phone is locked or the display is off.** There is nothing to capture, and `takeScreenshot` fails. `is_locked` and `display_asleep` are the inputs, and `session_changed` tells Rust about changes straight away. A phone that is awake with the lock screen up is treated as locked, not as a hidden window.
- **Downscale in Kotlin.** `takeScreenshot` returns a hardware-backed bitmap. Kotlin scales it so the longest side is at most **768 px**, copies it to tightly packed RGBA8888 rows, recycles the originals and zeroes its copy once Rust has taken the bytes. 768 is what the classifier needs and keeps memory small (§4 principle 1).
- **Rate limiting.** Android limits how often `takeScreenshot` may be called. At Faro's interval this should not matter, but an extra capture after a flag must respect it. A rate-limited call is an `Unavailable` error, not a tamper signal.
- **Battery budget.** To be measured, not assumed: the cost per capture (screenshot, downscale, inference, blur) and per day on typical phones. Spike S7. If a capture costs too much, the interval or the cadence while charging is the first thing to change.

### 7.2 Detection

- **Classifier.** The same OpenNSFW int8 model as the desktop clients, run by **ONNX Runtime for Android**. Status: the official AAR's `libonnxruntime.so` (1.22.0, pinned by digest) is linked dynamically by the `ort` crate and ships next to `libfaro_android.so`, and the model is packaged in the APK; no thin binding was needed (§18). The packaged model must load: a missing, changed or unloadable one is an urgent `integrity_failure`, as on desktop. Inference speed and the effect on battery on real phones are still spike S7.
- **Same flags and reasons.** Thresholds, explainable reasons and the blurred thumbnail for a flagged frame are the desktop's, unchanged.
- **Domain bundle.** The same domain category bundle as on desktop, used to classify the host of the foreground browser (§7.3), through `faro_detect::load_domains`.

### 7.3 Foreground app and browser address

The accessibility service already sees the foreground window. From it Kotlin reports `foreground_app` (package and label) and, for a known browser, `browser`:

- the address comes from the browser's address bar node, found by **view id** (for example Chrome's `url_bar`, Firefox's `url_bar_title`), kept in a small table of known browsers with the ids they use;
- Kotlin reduces it to `scheme://host/` before it goes anywhere (§4 principle 2), and never logs the full text;
- `incognito` is set when the browser's own private-mode marker is visible. Whether Chrome and Firefox expose their address bar in private mode at all is spike S2. If they don't, private browsing shows up as a hidden window (§8) with no address.

The view ids change between browser releases. A browser that isn't in the table, or whose id has changed, gives no address. It doesn't fail capture. A missing address only makes the report less specific.

---

## 8. Tamper and context

The same table as [ARCHITECTURE.md §3.7](ARCHITECTURE.md#37-tamper-detection), for Android. The Android signals reuse existing `TamperSignal` variants, so the wire format, the urgency flooring and `is_tamper_class` are unchanged, and the instance can't tell them apart from desktop tamper. The wording in "Ally sees" is rendered by the web app after decryption, never in emails.

| Signal | Detected by | Reported as | Urgency | Ally sees |
|---|---|---|---|---|
| No heartbeat for longer than the grace period | Instance | missed check-in | urgent | "Phone-X hasn't checked in for 3h", with the last known state |
| The accessibility service is turned off (or loses its connection) | The app: `permission_state` and the service's `onUnbind` / `onDestroy`, checked by the runtime | `PermissionRevoked { permission: "accessibility_service" }` (not `accessibility`, which on a Mac means the optional window-title permission) | urgent | "Accessibility is off on Phone-X, so Faro can't see the screen", with the steps that turn it back on |
| Captures keep failing for any other reason | Runtime | `CaptureFailing` | urgent | "Faro couldn't see the screen 5 times in a row" |
| A `FLAG_SECURE` window stays in front: `takeScreenshot` fails with the secure-window error on two polls in a row | Runtime, from `CaptureError::SecureWindow` and `poll_tamper` | `WindowHiddenFromCapture { app }` (the app's label, or the package) | urgent | "*Signal* kept a window out of Faro's screen captures on Phone-X" |
| The member asks to deactivate Faro as a device admin (`onDisableRequested`) | Device admin receiver, through `report_tamper_now` | `PermissionRevoked { permission: "device_admin" }` | urgent | "Faro's uninstall protection is being turned off on Phone-X. The app can now be removed" |
| Device admin deactivated (`onDisabled`) | Device admin receiver | The same signal, if the request wasn't seen | urgent | The same |
| Uninstalled without Device Admin, force-stopped, or the phone was factory reset | Instance (no heartbeat) | missed check-in | urgent after the grace period | "Phone-X hasn't checked in for 3h". Nothing more is known |
| Chain gap, invalid signature, upload stall, clock change | Instance, core | as on desktop | urgent | As on desktop |
| Leaving Faro on purpose (Settings → Leave Faro) | App | `goodbye` | urgent | "Faro was removed from Phone-X" |
| Battery optimisation is on for Faro (Faro can be stopped in the background) | App | context (`BatteryOptimizationOn`) | none | Listed in the report |
| USB debugging is on | App | context (`UsbDebuggingOn`) | none | Listed in the report |

**Allowed secure windows.** Android's own UI sets `FLAG_SECURE` for good reasons, and these are not reported: the system (`android`, `com.android.systemui`), the lock screen and keyguard, the permission controller, and the device's settings app while it is showing a credential prompt. **No third-party app is allowed, browsers least of all.** A password manager, a banking app or a messenger is reported by name, for allies to judge, because a package name can be copied and an allow-list would need code-signature checks. This is the same reasoning as the macOS and Windows rules in ARCHITECTURE.md §3.7. Whether to treat the system's own UI by package name alone is safe enough is spike S5.

**Pre-uninstall alert.** `onDisableRequested` runs in the app before Android lets the member deactivate Faro. The receiver calls `report_tamper_now`, which writes the signal to the outbox and tries to upload it within a budget of about five seconds. If the phone is offline, the event sits in the outbox until the next time it is. If the member also uninstalls while offline, allies get a missed check-in after the grace period instead, which is the same as unplugging a laptop's network on desktop.

**One cause, one signal.** As on desktop: when accessibility is off, captures fail because of it, so the report is `permission_revoked` and never also `capture_failing` for the same run.

**Known gaps.**

- A member who is offline, turns off accessibility, and uninstalls before the phone reconnects produces a missed check-in and no alert. That is §10.3 of IOS.md in different words.
- A phone that is switched off looks like a silent one, with the last state attached.
- A phone whose maker kills Faro's process aggressively produces false missed check-ins. That is why the grace period for phones needs checking (§12) and why spike S1 exists.

---

## 9. What allies see

An Android phone appears in the member's reports next to their computers, with the same thumbnails, flags, summaries and tamper history. Differences:

- the device name pattern is "Phone-X", and the device card says Android;
- the foreground app is a package label instead of an executable name;
- the browser address is `scheme://host/`, as on desktop;
- a **context** line lists "battery optimisation on" and "USB debugging on" when they are;
- the report states plainly what Faro can't see on a phone: apps that hide their window (§2, §8), and private browsing, which shows up as a hidden window rather than a page.

The instance's view is unchanged: ciphertext, signed headers with urgency, and heartbeats.

---

## 10. Enrollment, keys and state

### Enrollment

- **The link.** The same `faro://enroll?i=…&c=…` as on desktop, registered as an intent filter in the app. The member can tap it, or paste it into the app. **QR scanning comes later** (Phase B), because it needs a camera permission and a scanner for little gain at first.
- **Check the instance first.** `preview_enrollment` fetches `/.well-known/faro` and refuses an instance whose `server_version` is too old to know the `android` platform: an old instance would reject the request, and the member should be told why, not shown an error from the API. It shows the instance name for the member to confirm.
- **Confirm with the device credential.** Before creating a key, the app asks for the phone's screen lock (PIN, pattern, password or biometric) through the system prompt. It proves the person holding the phone is the one who owns it, and it keeps someone who picks up an unlocked phone from enrolling it for a stranger's instance. (If the phone has no screen lock, the app says so and continues. Spike S3 covers the prompt.)
- **Fingerprint.** `enroll` creates the device key, registers, and returns the device fingerprint. The member compares it with the one in the web app when approving the phone, as on desktop. The device is then `Pending` until the member approves it (`poll_approval`).
- **Setup steps, in order:** accessibility service (with the restricted-settings walk-through, §2), the notification permission (Android 13+), battery optimisation exemption, device admin. Each has a plain screen that says what it does and what the allies will be told if it is turned off. Faro asks for no permission it doesn't use.

### Keys and state

- **Keys** are files in the app's **no-backup** directory (`Context.getNoBackupFilesDir()`), like the desktop's state directory. They are excluded from Android's cloud backup and device-to-device transfer, so a restored phone has no keys and enrolls as a new device. The old one goes silent, which allies see as a missed check-in, and the new one needs member approval, as in IOS.md §10.2.
- **Keystore wrapping is later work** (Phase B). Android Keystore can wrap the key files with a hardware-backed key, so a copy of the app's private storage isn't enough on its own. Keystore doesn't hold Ed25519 on every supported version, so it can only wrap, not replace, the software keys. Until then the protection is Android's per-app sandbox and full-disk or file-based encryption, the same level as the desktop key files.
- **State** (the SQLite database, outbox and settings) is in the same app-private directory, written by the one process, so no cross-process locking is needed (unlike iOS).

---

## 11. Distribution and updates

### Distribution

A **project-signed APK**, not the Play Store, for the first release. It is served from the project's release channel and from the instance's update mirror, so a self-hosted member can install from their own instance's page. The member must allow "install unknown apps" for their browser or file manager once. The restricted-settings step (§2) follows.

### Updates

- **TUF verification, as on desktop.** The APK is a target in the signed metadata with `platform: "android"` and `arch: "aarch64"` or `x86_64` (PROTOCOL.md §8). The app checks the project-signed metadata, the length and the BLAKE3 hash against the root shipped in the app before it hands the file to Android. The instance can delay an update but can't forge one (invariant 5).
- **Android's own same-signer rule is a second check.** Android installs an update only if it is signed by the same key as the installed app. A tampered APK from a hostile mirror fails twice: once against the project root, once against the package signature.
- **Installing needs the member to confirm, unless Faro is the installer of record.** `PackageInstaller` sessions normally show a confirmation dialog. From Android 12, an app that installed a package can update it later without the dialog in some cases, if the platform allows it. Whether Faro can self-update with no tap, and on which versions and makers, is spike S8. Until it is answered the design assumes one tap: the app downloads and verifies the update, then asks the member.
- **The APK signing key is a permanent key.** It can't be rotated the way the TUF roles can, because Android's same-signer rule ties every future update to it (Android's key rotation through signature lineage may help, to be confirmed). It goes into [KEY-CEREMONY.md](KEY-CEREMONY.md) as its own entry, with its own storage and loss plan: losing it means every member reinstalls by hand.
- **Developer verification.** If Google's registration requirement applies to the project's APK, the sideload path may change (§2, spike S8). This needs checking before Phase A is announced.

### Later

- **F-Droid**, with reproducible builds and the project's upstream signature (F-Droid verifies that its build matches the upstream APK, and then ships the upstream signature). This is a good fit for a self-hosted, open-source tool, and keeps the same signing key. It adds a second update channel, which has to agree with the first.
- **Google Play**, in Phase C, only if the Accessibility API policy allows an app like Faro. It is a question, not a plan (§16, §18).

---

## 12. Server, protocol and web app changes

Small, and none of them gives the instance new visibility:

- **Device platform `android`** in enrollment and the device list (`Platform::Android` already exists in `faro-proto`), with its own name pattern ("Phone-X"). An instance older than this change rejects the platform, so the client checks `server_version` first (§10).
- **No new tamper variants.** The signals in §8 reuse `PermissionRevoked`, `WindowHiddenFromCapture`, `CaptureFailing` and the other variants, so `EventKind::min_urgency()` and `notify::policy::is_tamper_class` already treat them correctly. The two context-only signals (battery optimisation, USB debugging) are context-only variants if they aren't covered already. If a new variant is needed, it is added to `faro-proto` as context-only (`is_context_only` true).
- **Web app:** the Android device card, and the wording in §8 ("Accessibility is off on Phone-X"), shown in alerts and reports after decryption. The tamper wording otherwise reuses the desktop wording.
- **Update mirror:** `android` targets for `aarch64` and `x86_64`, like the desktop platforms, plus the same data bundles.
- **Liveness.** The grace period per device stays the instance's setting. Phones sleep and are killed more often than laptops, so Phase A measures how long real phones go without a heartbeat and decides whether Android needs a longer default (§18).

---

## 13. Consent, multiple users and never invisible

- **Visible on the phone:** the persistent notification while Faro runs, Faro in the accessibility and device admin lists in Settings, and the status screen. From Android 14 the member can swipe a foreground service's notification away; Faro posts it straight back (its delete intent restarts the running service), and the service's 30-second tick posts it again in any case.
- **The monthly notice** (ARCHITECTURE.md §12) is `show_notice`: a full-screen activity or a notification, listing the allies and the instance.
- **Setup explains the cost** in plain words: that Faro watches the screen, that allies see blurred thumbnails of flagged frames, that Faro can't be uninstalled quietly, and that apps which hide their window are reported.
- **Leaving is allowed and never silent.** Settings → **Leave Faro** sends `goodbye` (urgent), deactivates device admin, and tells the member they can now uninstall the app. Deactivating device admin by hand works too, and is reported (§8).

### Multiple users, work profiles and Private Space

| Situation | What Faro does | Limit |
|---|---|---|
| The member's own account on the phone | Covered | |
| Another Android user on the same phone (multiple users, guest) | Not covered. Faro is installed per user. It could be installed in each, enrolled as a separate device. | Allies see a separate device or nothing. Documented. |
| A work profile | Not covered by Faro installed in the personal profile. Whether `takeScreenshot` shows work-profile content is spike S6. | Documented. Faro doesn't install itself into a work profile. |
| Private Space (Android 15) | Same as a work profile for apps installed there. Whether captures include it while it is unlocked is spike S6. | Documented. |
| The phone is shared with someone else | Faro sees everything on the screen, including their content | Same as a shared computer. The monitoring notice is shown to whoever is using the phone (ARCHITECTURE.md §12). |

---

## 14. Threat model differences

Stated honestly, and the same in the ally guide:

- **The member can uninstall Faro.** Android allows it, and Faro doesn't use Device Owner mode to stop it (§5.2). Allies learn about it as follows: an urgent alert if the member deactivates device admin or accessibility through the normal route, and a missed check-in if the phone just goes silent (uninstall without admin, force-stop, a factory reset, or switching the phone off).
- **Device Admin turns removal into an alert first.** That is all it does. It is a speed bump the member must step over in front of their allies, not a lock.
- **Faro doesn't see everything.** Apps that set `FLAG_SECURE` (banking, messengers, private browsing) can't be captured. Faro reports that they hid the window, and doesn't try to see through it. A member who uses only such apps gives allies the alert and little else.
- **A second user, a work profile or a Private Space** may hold content Faro can't see (§13).
- **A maker's battery killer** can make an honest phone look silent. The grace period and the battery context line are the mitigation (§8, §12).
- **A rooted phone** can do anything, including stopping or faking Faro. Faro doesn't try to detect root beyond what it can do honestly, and doesn't claim to defend against it (§4 principle 5).
- **The instance still sees only ciphertext and headers**, as on desktop.

---

## 15. Spikes: what to confirm on a device first

These are facts the design depends on that platform documentation doesn't settle. Each must be checked on physical phones running current Android releases before Phase A starts.

| # | Question | If the answer is bad |
|---|---|---|
| S1 | Does capture survive reboot, lock, Doze and the makers' background killers on a Pixel, a Samsung and a Xiaomi phone? That covers: the accessibility service coming back after a reboot, the foreground service staying alive for a week of normal use, a heartbeat gap under battery savers, and whether Device Admin still blocks a plain uninstall on current releases. | Add per-maker setup steps for battery settings, lengthen the phone grace period (§12), and say in the report which makers are unreliable. |
| S2 | Can the accessibility service read the address bar in Chrome Incognito and Firefox private tabs, or are their windows hidden entirely? Which view ids does each current browser use? | No address in private mode. The hidden-window signal still shows it happened (§7.3, §8). |
| S3 | The restricted-settings flow for a sideloaded APK (Android 13 to 16, Pixel, Samsung, Xiaomi): where the member has to go, and can the app deep-link to it? Does the screen-lock confirmation work on phones with no lock? | Write the steps per version and maker in the member guide. Adjust §10. |
| S4 | What does force-stopping Faro do to an enabled accessibility service? Does Android keep it bound, restart it, or turn it off? Is accessibility being turned off after a force-stop reported by anything? | If it is turned off with no signal, force-stop is a missed check-in only (already assumed, §8). If it stays alive, the force-stop gap is smaller than assumed. **Emulator, Android 16 (2026-11-27):** a force-stop removes Faro from the enabled accessibility services (the setting is cleared), and it stays off until someone switches it on again. The next time Faro starts it sends an urgent `permission_revoked` (`accessibility_service`), since it had seen the service on. Still to check on Pixel, Samsung and Xiaomi. |
| S5 | Which packages and windows set `FLAG_SECURE` as part of normal Android (system UI, credential prompts, the permission controller, Settings), and is allowing them by package name safe enough? | Allow by package plus signature, or report them as context only. Adjust §8. |
| S6 | Does `takeScreenshot` include Private Space and work-profile content while they are unlocked? Does Faro in the main profile see an app running in a second user? | Document as a limit (§13). Possibly a note in the ally guide. |
| S7 | ONNX Runtime for Android: latency and battery per capture for the int8 model on a mid-range and a low-end phone, and a clean way to link the official AAR's libraries. | Lengthen the interval, or capture less while on battery. If the AAR doesn't link cleanly, use a different runtime or a thin binding (§18). |
| S8 | Can Faro update itself with no member action once installed (installer of record, `setRequireUserAction`)? Does Google's developer verification apply to the project's APK, and from when? Does Android's signature lineage allow the signing key to be rotated? | One tap per update. Register as a developer if required. Treat the signing key as permanent (§11). |
| S9 | Does a `MediaProjection` session survive screen lock on Android 15 and 16, and how does a session end in practice? | Stays rejected for v1 (§5.1). It would only matter if the accessibility route becomes unavailable. |

---

## 16. Rollout

| Phase | Contents | Exit |
|---|---|---|
| **0: Spikes** | S1 to S9 (§15), on real phones | Every spike answered and this doc updated to v0.2 |
| **A: Beta** | `crates/faro-android`, the app (accessibility and foreground services, device admin, enrollment by link or paste, status screen, notice), the signals in §8, a project-signed sideloaded APK on **one pilot instance** | One pilot instance with real phones (BETA.md) |
| **B: Hardening** | Keystore wrapping, QR enrollment, per-maker setup guidance, the measured battery and grace-period defaults, TUF self-update, an F-Droid build with reproducible builds | Wider beta |
| **C: Maybe** | A Google Play listing, if the Accessibility policy allows it. Tablets, ChromeOS. | Decision in §18 |

**CI.** The Android build needs the NDK. As far as we know, Google ships no NDK for Linux ARM64 hosts, so the existing ARM64 Linux runner can't build `libfaro_android.so`. The Android build runs on the **macOS ARM64 runner**, and the Rust unit tests for `faro-android` run on the host as they do for `faro-mobile`. An emulator or instrumented test needs its own setup and is not planned for Phase A.

---

## 17. Considered and left out

- **A Device Owner "maximum mode".** It can stop uninstalling, but needs a factory reset and gives whoever provisions the phone control of it (§5.2).
- **`MediaProjection` as the main capture path.** A consent dialog after each reboot or session leaves the phone unwatched until the member taps, and is a nag instead of a signal (§5.1).
- **Reading private-browsing or `FLAG_SECURE` content by any route.** Android hides it for the member's protection. Faro reports the hiding (§4 principle 5).
- **Blocking.** Android would allow an accessibility service to cover the screen or press Back. Faro doesn't: it is an accountability tool, and the desktop clients don't block either.
- **A stop or pause button on the notification.** It would be the easiest way to silence monitoring (§4 principle 3).
- **Push notifications to wake the phone.** FCM needs a key tied to the app, held by the project. The foreground service doesn't need to be woken, and a self-hosted instance couldn't send one anyway.

---

## 18. Decisions and open questions

### Decisions (2026-11-26)

- **Watch, don't block.** Accessibility `takeScreenshot` (API 30+) is the capture path. No `MediaProjection` in v1.
- **One app process**, with a foreground service hosting the Rust core, which embeds `faro-service`'s runtime through `InProcessFrameSource`.
- **`minSdk` 30, `targetSdk` and `compileSdk` 35.**
- **A project-signed APK**, not Play, for now.
- **Device Admin for uninstall protection.** No Device Owner.
- **UniFFI 0.29 in proc-macro mode**, in a new crate `faro-android`, package `org.faro.core`.
- **Tamper signals reuse the existing variants** (§8). Context-only additions if needed.
- **Keys in the no-backup directory**, Keystore wrapping later.
- **A dismissed notification comes straight back** (§13), so Faro stays visible on Android 14 and later.
- **`QUERY_ALL_PACKAGES` stays**, so reports can name the app behind a hidden window or in the foreground. Play restricts it, which doesn't matter while the APK is distributed outside Play; a Play listing would have to revisit it.

### Open

- **The APK signing key:** who holds it, where, and the loss plan. It can't be rotated like the TUF keys (§11). Needs an entry in KEY-CEREMONY.md before Phase A.
- **Google Play:** is a listing worth pursuing given the Accessibility policy, or should Faro stay with APK and F-Droid? (Phase C.)
- **Developer verification:** does the project register as a developer if Google's requirement applies to sideloaded APKs, and under whose name? (Ties to ARCHITECTURE.md §14 "Funding and stewardship".)
- **ONNX Runtime for Android:** settled for linking (the official AAR's libraries under the `ort` crate, §7.2); speed and battery on real phones are still open (S7).
- **The Android grace period:** the same as computers, or longer, once Phase A shows how long real phones go without a heartbeat.
- **The battery budget:** the capture interval or cadence on battery, set from S7 and beta data.
- **Support list:** which makers' phones the beta will say it supports, after S1.
