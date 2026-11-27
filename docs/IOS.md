# Faro: iOS client

**Status:** Proposal, draft v0.1 (2026-11-26). Being built on the `ios-client` branch (epic #138).
**Replaces:** "a limited iOS client (Screen Time / content filter)" in [ARCHITECTURE.md §13](ARCHITECTURE.md#13-roadmap) Phase 3, and answers the "Mobile timing" open question (§14) for iOS.
**Changes a v1 non-goal, on iOS only:** content **blocking** ([ARCHITECTURE.md §1](ARCHITECTURE.md#non-goals-for-v1)). The desktop clients still don't block.
**Depends on:** enrollment and member approval (§3.8, §7), the hash chain and heartbeats ([PROTOCOL.md](PROTOCOL.md)), urgency flags and tamper-class alerts (§5.4), the signed data-bundle channel and the domain category bundle ([DEVELOPMENT.md](DEVELOPMENT.md#the-domain-category-bundle)).

---

## 1. Summary

Faro on a computer **watches**: it captures the screen, classifies frames on the device, and tells allies. iOS doesn't allow that. No app can capture the screen in the background (§2). So Faro on an iPhone does the next best thing for accountability: it **blocks** explicit content, and it is **tamper-evident about the blocking**. Allies are told when protection is turned off, loosened or removed, and they see how often it had to step in.

The recommended enforcement uses two independent layers, both of which work on an adult's own, unsupervised iPhone:

1. **Screen Time** (FamilyControls with `.individual` authorization plus ManagedSettings). Apple's own adult-website filter for all WebKit browsing, apps and app categories the member picks, and **Faro can't be deleted** while it is authorized.
2. **An on-device DNS filter** (a Network Extension packet tunnel that carries DNS only). Faro's signed domain list, matched on the phone, for every app and every browser engine. It is also the long-running process that sends heartbeats and watches layer 1.

Each layer watches the other, so turning off either one raises an urgent alert, and turning off both makes the phone go silent, which raises a missed check-in. Nothing about browsing leaves the phone except the encrypted report to allies.

A third layer, Apple's new **URL filter** (iOS 26+), would match full URLs system-wide. It needs a project-run lookup server, so it is left for a later phase and a decision (§8, §19).

---

## 2. What iOS allows, and what it doesn't

The constraints that shape this design:

| Constraint | Consequence for Faro |
|---|---|
| No background screen capture. ReplayKit broadcast extensions need the user to start each session from Control Center, show a recording indicator, and end when the user stops them. | No screenshots, no classifier and no blurred thumbnails on iOS. `faro-detect`'s image pipeline isn't used. |
| No privileged service, no launchd, no long-running daemons. Apps are suspended in the background. | The only reliably long-running Faro code is a Network Extension provider (§7). Screen Time extensions run only when the system calls them, and they are throttled (§10). |
| A full content filter (`NEFilterDataProvider`) is "supported on supervised devices only" (WWDC25, session 234). | Not available to an adult on their own phone. Rejected (§5). |
| One build for everyone, from the App Store. Entitlements and some server URLs are fixed in the signed app. | A self-hosted instance can't supply its own server-side filtering service to iOS (§8). Everything that blocks has to run on the phone. |
| Screen Time hands apps **opaque tokens**. The app can't learn which apps or sites the member picked. | Reports can count "opened a blocked app", but can't name the app (§11). Faro doesn't work around this. |
| The Family Controls distribution entitlement is approved **per bundle ID**, for the app and for each extension. | The app and its four extensions each need Apple's approval before TestFlight (§14). |
| App Store guideline 5.4: VPN apps may be offered only by developers enrolled as an organization. | The DNS filter is a packet tunnel, so the Apple Developer account must belong to an organization. This depends on the funding and stewardship question (ARCHITECTURE.md §14). |

---

## 3. Goals and non-goals

### Goals

1. **Block explicit content across the whole phone.** That means Safari, other browsers (including non-WebKit engines where the EU allows them), in-app browsers, and apps.
2. **Tamper-evident, not tamper-proof, as on desktop.** The member owns the phone and can always turn Faro off. Allies always find out, quickly.
3. **Nothing about browsing leaves the phone** except the end-to-end-encrypted report to allies. No remote DNS resolver, no cloud filter, no lookups to any server.
4. **Works on an ordinary iPhone.** No wipe, no supervision, no MDM, no Mac needed.
5. **Same instance, same allies.** An iPhone enrolls in the member's existing instance like a computer, and allies see it next to the member's computers.

### Non-goals

- **Screen capture or image classification on iOS** (§2).
- **Supervised or MDM-managed phones**, for now (§5). They need a wipe and an MDM server, and they would give whoever runs the MDM control of the device.
- **Minors and Family Sharing child accounts.** Faro is for adults (ARCHITECTURE.md §12). That rules out `.child` authorization, even though it is harder to remove.
- **iPadOS and visionOS** in the first release. The same code should run on iPadOS later with little change.
- **Blocking on the desktop clients.** Out of scope here.
- **Android.** That needs a spec of its own.

---

## 4. Principles (invariants)

These add to the six invariants in [DEVELOPMENT.md](DEVELOPMENT.md#invariants-every-change-must-keep), and would join that list when Phase A ships.

1. **Filtering never leaves the phone.** Every block decision is made on the device from a project-signed list. No DNS query, URL or hostname is sent to the instance, the project or a third party in order to decide whether to block it.
2. **Every protection layer is watched by another.** A layer that can be switched off has at least one other Faro component that notices and raises an urgent tamper event. When nothing is left to notice, the heartbeats stop.
3. **Loosening is never silent.** Any change that blocks less (a category, an app, a layer turned off) is a `settings_change` that allies see. Turning a layer off is tamper-class.
4. **Faro doesn't defeat Apple's privacy boundaries.** No reading app identities out of Screen Time tokens, no capturing traffic other than DNS, no private APIs.
5. **The member chooses what is blocked.** Allies and instance admins can't change it (ARCHITECTURE.md §12).

---

## 5. The options, and which ones Faro uses

Every mechanism iOS offers for blocking, checked against the constraint that matters most: it must work on an adult's unsupervised phone.

| Mechanism | Works for an adult, unsupervised? | Covers | Can the member turn it off? | Verdict |
|---|---|---|---|---|
| **Screen Time**: FamilyControls `.individual` + ManagedSettings (iOS 16+) | Yes | WebKit browsing (Apple's adult filter), chosen apps and categories, Faro's own deletion | Yes, in Settings → Screen Time, after authenticating as the phone's owner | **Layer 1** (§6) |
| **On-device DNS filter**: `NEPacketTunnelProvider` carrying only DNS | Yes | Every DNS lookup from every app and engine | Yes: VPN switch, Control Center, another VPN app, or deleting the profile | **Layer 2** (§7) |
| **URL filter**: `NEURLFilterManager` (iOS 26+) | Yes ("managed and unmanaged devices") | Full URLs over WebKit and URLSession, system-wide; other engines only if they opt in | Yes, as a Settings switch (spike S7) | **Later, if decided** (§8) |
| Content filter: `NEFilterDataProvider` | **No**: supervised only | All flows | n/a | Rejected |
| Encrypted DNS settings (`NEDNSSettingsManager`) pointing at a filtering resolver | Yes | DNS | Yes | Rejected: every lookup goes to a server, which breaks principle 1, and a self-hosted resolver would show the operator the member's browsing |
| DNS proxy provider (`NEDNSProxyProvider`) | **No**: supervised only | DNS | n/a | Rejected |
| Safari content blocker extension | Yes | Safari only | Yes, silently, in Settings | Rejected: layer 1 already covers Safari, and nothing is notified when it is turned off |
| Supervision via Apple Configurator, plus MDM | Needs a wipe and a Mac | Everything, including filters that can't be removed | Only by wiping | Rejected for now: a heavy setup, and MDM gives the instance power over the device, which is the stalkerware risk §12 forbids |
| ReplayKit screen capture | Only while the user keeps a broadcast running | Screen | Yes, any time | Rejected (§2) |
| An ally holds the **Screen Time passcode** | Yes | Makes Screen Time settings harder to change | Only with the passcode | Not built into Faro. Documented as an optional practice (§12) |

**Why two layers and not one.** Neither is enough on its own:

- **Screen Time** uses Apple's classifier for adult sites, which is better than any domain list. It can stop Faro being deleted, and it can block apps, which DNS can't do reliably. But Faro can't see when its web filter steps in, its extensions are throttled and memory-starved (6 MB), and its callbacks are known to be dropped (§10). So it can't carry liveness.
- **The DNS filter** covers every browser engine and app, runs continuously, and can count what it blocks. But it only sees hostnames, apps with their own encrypted DNS can get around it (§7.4), and it takes the phone's single VPN slot.

Together they cover each other's gaps, and each notices when the other is turned off.

---

## 6. Layer 1: Screen Time

### 6.1 Authorization

At setup the app calls `AuthorizationCenter.shared.requestAuthorization(for: .individual)`. The member confirms with Face ID or their passcode. Faro then appears under Settings → Screen Time as an app with Screen Time access. Revoking that access clears every ManagedSettings store Faro wrote (spike S1 confirms this, and whether revoking needs authentication).

### 6.2 Settings Faro applies

Faro writes these to a single named `ManagedSettingsStore` ("faro"):

| Setting | Value | Why |
|---|---|---|
| `webContent.blockedByFilter` | `.auto(extra, except: allowed)` | Apple's adult-content filter, the same one as Content Restrictions → Limit Adult Websites, for all WebKit content: Safari, in-app browsers and web views. `extra` is a short member-chosen list. Apple caps hand-listed domains, so the full Faro list lives in layer 2 (spike S2). |
| `application.denyAppRemoval` | `true` | Faro can't be deleted, and neither can any other app, while authorization stands. To remove Faro, the member has to revoke Screen Time access first, and layer 2 reports that (§10). The member is told about the side effect at setup (spike S3: does this also block offloading?). |
| `shield.applications` / `shield.applicationCategories` | The member's picks from `FamilyActivityPicker` | Optional blocking of chosen apps or whole categories. Faro only sees opaque tokens. |
| `shield.webDomains` / `shield.webDomainCategories` | The member's picks | Optional. |
| `media.denyExplicitContent` | `true` (default, member can turn off) | Explicit music, podcasts, books and TV in Apple's stores and apps. |
| `dateAndTime.requireAutomaticDateAndTime` | `true` | Removes the easiest way to confuse liveness and chain timestamps. |
| `appStore.maximumRating` | Off by default; member's choice | Some members want it, most won't. |

Faro doesn't touch account, passcode, cellular, Siri or Game Center settings. They don't block content, and locking them would feel like a parental control rather than accountability.

### 6.3 Re-applying

A `DeviceActivityMonitor` extension is scheduled on a repeating 15-minute interval, the shortest Apple allows. On each `intervalDidStart` it re-writes the "faro" store from the settings file in the app group, in case anything was cleared. The app does the same each time it comes to the foreground. The monitor extension also does the cross-checks in §10.2. Its 6 MB memory limit means it does nothing else: no Rust core, no crypto, just file reads and ManagedSettings writes.

### 6.4 Shields

A `ShieldConfigurationDataSource` gives the block screen Faro's look and wording: "Blocked by Faro. You chose to block this." with one button, **Close**. A `ShieldActionDelegate` handles that button. Each one adds to a counter in the app group (`shield_shown`, `shield_closed`), which feeds the report (§11). Neither one records which app it was.

---

## 7. Layer 2: the on-device DNS filter

### 7.1 Shape

A `NEPacketTunnelProvider` that is a VPN in name only:

- **Tunnel network settings:** a private address for the tunnel interface, and DNS servers set to one tunnel-local address (`198.18.0.53` and `2001:2::53`, in the benchmarking ranges no real network uses) with `matchDomains = [""]`, so every lookup goes to it.
- **Included routes:** only that address, plus the known DNS-over-HTTPS and DNS-over-TLS resolver addresses (§7.4). **No other traffic enters the tunnel**, so Faro never sees page contents, connections or anything beyond DNS, and battery and latency costs stay small.
- **Resolution:** queries for allowed names are forwarded to the resolver the phone would otherwise use (read from the system before the tunnel's DNS settings apply, and again when the network changes) over a socket the provider opens outside the tunnel. There is no fallback: if no resolver can be found, allowed names fail at once (`SERVFAIL`) until one is, and blocked names are still blocked. Responses go back unchanged, unless they alias the name to a blocked one (`innocent.example CNAME blocked.example`, or a DNAME, SVCB or HTTPS target), which gets `NXDOMAIN` like the blocked name itself. A truncated response is fetched again over TCP by the provider, so clients never need DNS over TCP to the tunnel.
- **Blocking:** a blocked name gets a well-formed `NXDOMAIN` response. Safari's Screen Time page usually wins first for adult sites. Other browsers show their own "can't find the server" page.
- **On-demand:** an `NEOnDemandRuleConnect` for every interface, so iOS reconnects the tunnel after reboots, network changes and crashes without the app running.

### 7.2 What it matches against

The **domain category bundle** that the desktop clients already ship ([DEVELOPMENT.md](DEVELOPMENT.md#the-domain-category-bundle)): a project-signed FST of about 540 KB, loaded with `faro_detect::load_domains`, with the same licence and attribution checks. A name is blocked if it or any parent domain is in a category the member blocks (`adult` is always on, `gambling` is opt-in, more categories as the bundle gains them). Matching is a few FST lookups per query, well inside the packet tunnel's memory limit (spike S4).

The bundle ships in the app and updates through the instance's update mirror as a data bundle, verified against the project root shipped in the app, exactly as on desktop (§3.8). App Store updates replace the packaged copy. Updates delivered through the channel don't need an app update.

### 7.3 Always blocked, whatever the member picks

- **Encrypted-DNS bootstrap names** (for example `dns.google`, `cloudflare-dns.com`, `mozilla.cloudflare-dns.com`, `dns.quad9.net`). This pushes apps and browsers with their own DoH back to system DNS.
- **iCloud Private Relay** (`mask.icloud.com`, `mask-h2.icloud.com`). Returning `NXDOMAIN` for these is Apple's documented way for a network to turn Private Relay off. iOS then tells the member that Private Relay is off for the network. Without this, Private Relay would resolve Safari's lookups away from the filter (spike S5).

### 7.4 What gets around it, and what Faro does

| Bypass | Response |
|---|---|
| An app or browser using DoH or DoT to a hard-coded IP address | The known resolver addresses are routed into the tunnel and dropped, so clients fall back to system DNS. Unknown resolvers get through. Allies are told this is a limit of DNS filtering (§11). |
| Another VPN app (iOS runs one VPN at a time) | The Faro tunnel goes down. That is detected and reported (§10). Members who need a work VPN are told at setup that the two can't run together. |
| Turning the VPN off, or Connect On Demand off, in Settings | Detected and reported (§10). |
| IP-literal URLs, or sites on brand-new domains | Not covered by DNS. Layer 1 still covers them in WebKit. |
| Cached DNS answers from before the filter started | They expire within minutes. The tunnel starts at boot through on-demand. |
| Lookups while the tunnel re-reads the network's resolvers after a network change | iOS only reports the network's resolvers while the tunnel's own DNS settings are off, so the tunnel lifts them for a moment (well under a second) on each network change and puts them back. Lookups in that moment are not filtered. Layer 1 still covers WebKit. |

### 7.5 Recording what it blocks

The provider counts blocked lookups per category, and per host for adult and gambling, in 10-minute buckets in the app group. It never writes allowed lookups anywhere. Every few minutes it turns the counts into chain events (§11) through the Rust core.

---

## 8. Later: Apple's URL filter (iOS 26+)

`NEURLFilterManager` checks every HTTP and HTTPS request made through WebKit or URLSession against a developer's list, by full URL, system-wide, on unmanaged phones. It is privacy-preserving by design: a Bloom filter on the device, then a Private Information Retrieval (PIR) query, sent through Apple's Oblivious HTTP relay, to a server the developer runs. The app "does not execute in the filtering path and has no access to traffic."

It would add full-URL matching (`reddit.com/r/…`, not just `reddit.com`), which DNS can't do. But:

- **The server is fixed in the app.** The PIR service and Privacy Pass issuer URLs go in the app's Info.plist (enforced from iOS 27.3), are tied to the bundle ID by a DNS TXT record, and are validated by Apple before release. A self-hosted instance can't plug in its own, so **the Faro project would have to run one PIR service for every Faro user.** It would learn nothing about the queries (PIR plus OHTTP), but it would still be the first project-run service a client depends on, which ARCHITECTURE.md §1 says the project doesn't operate.
- It needs Apple's capability approval for the OHTTP relay and a separate `url-filter-provider` entitlement.
- Engines that don't use WebKit or URLSession are covered only if they opt in.

**Recommendation:** ship Phase A and B without it. Decide in §19 whether a content-blind, project-run PIR service is acceptable. If it is, add it as layer 3 in Phase C, watched by layer 2 like the others.

---

## 9. Choosing what is blocked

- **At setup**, the defaults are: adult (both layers), Faro protected from deletion, explicit media blocked, automatic time. Each optional extra is one screen: gambling, chosen apps or categories, chosen sites, App Store rating.
- **Tightening** takes effect at once and is a normal-urgency `settings_change`. Allies can switch these notifications off.
- **Loosening** (removing a category, app or site, or switching a default off) takes effect **after a delay**, 24 hours by default. Allies are told when it is asked for and again when it takes effect, and the member can cancel in between. The delay is the member's own setting (0 to 72 hours). Changing it is itself a loosening when it gets shorter. Desktop has no equivalent, because desktop doesn't block. On a phone, a short pause between the urge and the setting is most of what makes blocking work.
- **Allies can't change anything** (§4 principle 5). They can only see it.

---

## 10. Tamper evidence

### 10.1 Liveness without push

The instance's liveness monitor is the backstop, exactly as on desktop. iOS heartbeats come from the **packet tunnel provider**, the one process that runs continuously:

- every 5 minutes while the phone is awake, using the existing `Heartbeat` message, signed under `faro/heartbeat/v1`;
- `state: sleeping` from the provider's `sleep` callback, and a fresh heartbeat on `wake`;
- from the app too, whenever it runs (foreground or `BGAppRefreshTask`), so a phone whose tunnel is off still checks in and the tamper event from §10.2 gets uploaded.

**No push notifications.** APNs needs a key tied to the app's bundle ID, which only the project holds, so a self-hosted instance couldn't send them without a project relay. Nothing in this design needs the instance to wake the phone.

### 10.2 Signals

| Signal | Detected by | Urgency | Ally sees |
|---|---|---|---|
| No heartbeat for longer than the grace period | Instance | urgent | "iPhone-X hasn't checked in for 3h", with the last state |
| Screen Time access revoked (`authorizationStatus` no longer `.approved`) | Tunnel provider on each wake and every few minutes; the app on launch (spike S6: readable from the extension?) | urgent | "Screen Time protection is off on iPhone-X". Faro can now be deleted |
| DNS filter off: the VPN switched off, On Demand off, another VPN connected, or the profile deleted | Monitor extension: the tunnel's "alive" timestamp in the app group is older than 20 min while the phone is in use. The app: `NEVPNManager` status on launch | urgent | "Faro's web filter is off on iPhone-X" |
| The "faro" ManagedSettings store found cleared or changed while authorization stands | Monitor extension or app, when re-applying | urgent | "Faro's Screen Time settings were changed" |
| Protection loosened through Faro (§9) | App | normal (when asked for and when applied) | "Gambling sites will be unblocked on iPhone-X tomorrow at 21:04" |
| Leaving Faro on purpose (§12) | App | urgent (`goodbye`) | "Faro was removed from iPhone-X" |
| Chain gap, invalid signature, upload stall | Instance | urgent | As on desktop |
| Clock changed | Core (wall clock and monotonic deltas, server `Date`) | urgent | As on desktop. Rare with automatic time required |
| Restored from a backup onto another phone | Keys are `ThisDeviceOnly`, so the new phone has none and enrolls as a new device. The old one goes silent. | urgent (old device's missed check-in); member approval for the new one | "iPhone-X hasn't checked in"; "New device iPhone-Y is waiting for approval" |
| DoH resolver connections dropped, unknown VPNs, a jailbroken phone | Tunnel provider / app | none (context) | Listed in the report |

Each layer is watched by another (§4 principle 2): the tunnel watches Screen Time, the monitor extension and the app watch the tunnel, and the instance watches the phone as a whole. **Deleting Faro** takes revoking Screen Time first (because of `denyAppRemoval`), which the tunnel reports before it disappears with the app.

### 10.3 Known gaps

- **Throttled Screen Time callbacks.** Monitor callbacks can be late or dropped. The 20-minute staleness check tolerates one miss, and the instance's heartbeat check doesn't depend on it.
- **Revoking and deleting while offline.** If the member goes offline (airplane mode), revokes Screen Time, then deletes Faro, the tamper event never leaves the phone. Allies get a missed check-in after the grace period instead. Same as unplugging a laptop's network on desktop.
- **Power.** A switched-off phone looks like a silent one, with the last state attached.

---

## 11. What allies see

An iPhone appears in the member's reports next to their computers, marked as blocking rather than watching:

- **Protection status timeline:** when each layer was on, and every loosening and tamper event.
- **Blocked lookups by category per day**, from layer 2. Adult and gambling hosts are listed (only the host, like desktop's `scheme://host/`), grouped and counted.
- **Blocked apps opened:** a count from the shields, with no app names (§2).
- **Flags.** One blocked lookup isn't intent: link previews, ads and prefetching make lookups the member never saw. A **burst** is, so `blocked_burst` becomes a `flag` event with explainable reasons (`dns:adult ×6, 4 hosts, 3 min, screen on`), rated `medium`, which maps to `urgent` by default (ARCHITECTURE.md §14). The thresholds go next to the desktop ones and follow the same "lower only" rule for development builds.
- **Limits, stated plainly in the report:** "Faro on iPhone blocks; it doesn't see the screen. It can't block sites reached through some private DNS services or apps."
- **No thumbnails, ever.** There are none to send.

The instance's view is unchanged: ciphertext, signed headers with urgency, and heartbeats. The new event bodies are encrypted like the rest.

---

## 12. Consent and never invisible

- **Visible on the phone:** the VPN indicator in the status bar while the filter runs, Faro under Settings → Screen Time, and Faro's shield wording on every block.
- **The monthly notice** (ARCHITECTURE.md §12) is a local notification that opens a screen listing the allies and the instance. iOS has one user per phone, so there are no other accounts to tell.
- **Setup explains the cost** in plain words: other apps can't be deleted while Faro is protecting itself, the phone can't run another VPN at the same time, Private Relay is turned off.
- **Leaving is allowed and never silent.** Settings → **Leave Faro** sends `goodbye` (urgent, tamper-class), lifts `denyAppRemoval`, clears the store, removes the VPN profile and tells the member they can now delete the app. Revoking Screen Time in Settings works too, and gets reported (§10).
- **Optional: an ally holds the Screen Time passcode.** Some accountability partners do this. It makes Screen Time settings changes need the ally, and it may make revoking Faro's access need the ally too (spike S1). Faro doesn't set it up, ask for it or rely on it. It conflicts with "members can always leave", so it stays the member's and ally's own arrangement, and the ally guide describes it with that caveat.

---

## 13. Code layout

```
apps/ios/                  Xcode project (SwiftUI), the first thing in apps/
  Faro/                    the app: enrollment, setup, settings, status, Leave Faro
  FaroTunnel/              NEPacketTunnelProvider: DNS filter, heartbeats, Screen Time watch
  FaroMonitor/             DeviceActivityMonitor: re-apply settings, watch the tunnel (6 MB)
  FaroShield/              ShieldConfigurationDataSource
  FaroShieldAction/        ShieldActionDelegate
crates/faro-mobile/        UniFFI bindings over the Rust core, built as an XCFramework
```

- **Rust reused through `faro-mobile`:** `faro-proto` and `faro-crypto` unchanged; `faro-core`'s writer, hash chain, outbox, urgency and report builder; `faro-client`'s instance client, enrollment, uploads and heartbeats, which the desktop service uses too; `faro-update` for data bundles; `faro-detect`'s `domains` module only, behind a feature that leaves out the image pipeline and ONNX. `faro-platform` gets an iOS implementation of only the traits that make sense (clock, device identity). The capture traits stay unimplemented.
- **One chain, several processes.** The tunnel, the app and (indirectly) the extensions all produce events. The outbox and chain live in one SQLite database in the app group container. Each append is an exclusive transaction, so `seq` and `prev_hash` stay strict across processes. The 6 MB extensions never link Rust. They write counters and requests to small files, and the tunnel or app turns those into events.
- **Keys** live in the Keychain under a shared access group, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. The Secure Enclave can't hold Ed25519, so the keys are software keys, as on macOS today. Before the first unlock after a reboot the tunnel filters but can't sign, and it sends its first heartbeat after unlock.
- **Swift does the iOS parts:** FamilyControls, ManagedSettings, DeviceActivity, NetworkExtension, the UI, and DNS packet parsing in the tunnel (or in Rust, behind the same FFI, whichever spike S4 says is cheaper).

---

## 14. Enrollment, distribution and updates

- **Enrollment** uses the same link and QR code as desktop (`faro://enroll?i=…&c=…`). The app registers the `faro` URL scheme. A universal link isn't possible, since every instance has its own domain. The app fetches `/.well-known/faro`, shows the instance name, pins its key, and the member approves the new device as on desktop. Setup then walks through Screen Time authorization and the VPN permission prompt.
- **Distribution:** App Store and TestFlight only. One build for every instance (§3.8). The project's Apple Developer account must be an organization (§2).
- **Entitlements to request before the beta:** Family Controls distribution for the app and each of the four extensions, Network Extension `packet-tunnel-provider`, and App Groups. The App Review notes explain the self-hosted model and include a test instance.
- **Updates:** the App Store updates the app. The domain bundle updates through the instance mirror with project-signed metadata (§7.2), so invariant 5 holds: the instance can delay a list but can't forge one.

---

## 15. Server, protocol and web app changes

Small, and none of them gives the instance new visibility:

- **Device platform `ios`** in enrollment and the device list, with its own name pattern ("iPhone-X") and the "blocks, doesn't watch" label.
- **New tamper reasons**, all tamper-class (`notify::policy::is_tamper_class`, ARCHITECTURE.md §5.4): `screen_time_revoked`, `filter_off`, `settings_cleared`. They are `TamperSignal` variants inside the encrypted body of an ordinary `tamper` event, so `EventKind::min_urgency()` already floors them at `urgent` and the instance can't tell them apart. Its alert emails stay content-free, as for every tamper event. The iPhone wording in §10.2 ("Ally sees") is rendered by the web app after decryption. Documented in PROTOCOL.md §3.4.
- **New encrypted body types:** `blocked_summary` (category and host counts per bucket) and `shield_summary` (counts). They are ordinary `capture`-class events, so the header urgency is `none`.
- **`blocked_burst` flags** use the existing `flag` kind and urgency mapping.
- **`settings_change` bodies** gain the pending-loosening fields (requested, takes effect, cancelled).
- **Web app:** the iOS device card, the report sections in §11, and the iPhone wording for each tamper signal ("Faro's web filter is off on iPhone-X"), shown in alerts and reports after decryption, never in emails.
- **Liveness:** the grace period per device stays the instance's setting. Phase A measures real phones to see whether iOS needs its own default (§19).

---

## 16. Rollout

| Phase | Contents | Exit |
|---|---|---|
| **0: Spikes** | S1 to S8 (§17), on real phones (the Simulator can't run Screen Time authorization or the monitor extension) | Every spike answered and this doc updated to v0.2 |
| **A: Beta** | Layer 1 defaults, layer 2 with the packaged list, heartbeats, the tamper signals in §10.2, enrollment, Leave Faro, the status timeline in reports | TestFlight with the pilot instances (BETA.md) |
| **B** | Chosen apps, categories and sites; the loosening delay; blocked counts and `blocked_burst` flags; domain bundle updates over the channel; App Store release | Public release |
| **C** | Layer 3 (URL filter) if §19 approves it; iPadOS | |

---

## 17. Spikes: what to confirm on a device first

These are facts the design depends on that Apple's documentation doesn't settle. Each must be checked on a physical phone running the current iOS release before Phase A starts.

| # | Question | If the answer is bad |
|---|---|---|
| S1 | Revoking `.individual` authorization: does it need Face ID or the passcode, is it covered by a Screen Time passcode if one is set, and does it clear every store at once? | Adjust §6.1 and §12. The tamper signal still holds. |
| S2 | `webContent.blockedByFilter`: the cap on hand-listed domains in `.auto` and `.specific`, and whether it applies to non-WebKit engines in the EU and to in-app browsers. Does Limit Adult Websites still turn off Safari Private Browsing? | Layer 2 already covers these. Correct §6.2 and §11. |
| S3 | Does `denyAppRemoval` also stop offloading (Settings → General → iPhone Storage) and automatic offload? | If not, report an offload as `filter_off` (the tunnel goes with the app's binary). |
| S4 | Packet tunnel memory limit and steady-state use with the FST loaded. Battery cost of DNS-only routing over a day. | Shrink the bundle per platform, or parse DNS in Swift. |
| S5 | With Private Relay on, do the `mask.icloud.com` answers reliably turn it off for Safari lookups while the tunnel runs? | Ask the member to turn Private Relay off at setup and report it as context. |
| S6 | Can the tunnel extension read `AuthorizationCenter.shared.authorizationStatus` and the "faro" store? | Fall back to the app on launch plus a monitor-extension marker file. Detection gets slower. |
| S7 | `NEURLFilter`: can the member switch it off, and is that visible to the app? | Only matters for Phase C. |
| S8 | How reliably does the 15-minute DeviceActivity schedule fire on iOS 27 under normal use? | Lengthen the staleness threshold in §10.2. |

---

## 18. Considered and left out

- **A filtering DNS resolver on the instance.** Simple, and it works on every device, but the operator would see every hostname the member looks up. That breaks the core promise.
- **Requiring supervision for "maximum mode".** It needs a wipe and an MDM server, and the MDM operator controls the phone. It might come back as an expert option, without the instance as MDM, if members ask for it.
- **A Safari content blocker as a third layer.** It adds nothing over layer 1 and can be switched off without anyone knowing.
- **Silent pushes from the instance to wake the phone.** They need the project's APNs key, which means a project relay, and the tunnel's heartbeats already do the job.
- **Naming blocked apps in reports** by reading `localizedDisplayName` in the shield extension and passing it on. Possible, perhaps, but it works around Apple's privacy design (§4 principle 4).

---

## 19. Decisions and open questions

### Decisions (2026-11-26)

- **Two layers, Screen Time plus an on-device DNS filter**, with the URL filter deferred.
- **Adults only, `.individual` authorization.** No child accounts, no supervision.
- **No server-side filtering of any kind**, and no APNs.
- **Loosening waits 24 hours by default.** The member can set it from 0 to 72 hours, and allies see the setting.
- **Faro doesn't set up or rely on an ally-held Screen Time passcode.**
- **Setup can't be finished without both layers.** There is no skip for Screen Time access or the VPN configuration: a phone with only one layer would be enrolled and look protected while half of §5's design is missing. Turning a layer off later is allowed and reported (§10.2).

### Open

- **A project-run, content-blind PIR service for the URL filter (§8):** acceptable as an exception to "no central service", or not?
- **The Apple Developer organization** that will own the app and its VPN entitlement (ties to ARCHITECTURE.md §14 "Funding and stewardship").
- **The iOS grace period:** the same as computers, or longer, once Phase A shows how long real phones sleep without a wake.
- **Bursts:** the `blocked_burst` thresholds, set from beta data. They start conservative to avoid flagging prefetch noise.
