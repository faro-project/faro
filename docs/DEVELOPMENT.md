# Developing Faro

**Audience:** contributors working on the Rust workspace and the web app.

## Toolchain

- Rust stable, 1.94 or newer (`rust-version` in the root `Cargo.toml`; set by `sqlx` 0.9, which the server needs so it can share the patched SQLite that `rusqlite` 0.41 bundles). CI uses the latest stable.
- No nightly is needed, except for the optional `cargo fuzz` targets (see [Fuzzing](#fuzzing)).
- `cargo-deny` is used for license, ban and advisory checks: `cargo deny check`.
- `cargo-about` 0.9.3, only to make the third-party notices (`build-pkg.sh` and the container image need it): `cargo install --locked cargo-about --version 0.9.3 --features cli`, or `release/notices/third-party.sh --install-cargo-about`, which CI uses and which skips the install when 0.9.3 is already there. See [Third-party notices](#third-party-notices).
- Node.js 22.17 or newer (SvelteKit 3 needs it), only for the web app in `web/` (CI and the container image use Node 24). The Rust build never runs npm.

## Everyday commands

```sh
cargo test --workspace                                  # all tests
cargo clippy --workspace --all-targets -- -D warnings   # lints (CI fails on warnings)
cargo fmt --all                                         # formatting
cargo deny check                                        # licenses, bans, sources, advisories
```

## Crate map

| Crate | Role | Depends on |
|---|---|---|
| `faro-proto` | Wire types and canonical signing encoding (see [PROTOCOL.md](PROTOCOL.md)) | none (leaf) |
| `faro-crypto` | Signing, sealed boxes, item encryption, passphrase wrapping, chain verification | `faro-proto` |
| `faro-platform` | Zeroizing `Frame`, OS traits, synthetic implementations | `faro-proto` |
| `faro-platform-macos` | macOS implementation of the platform traits | `faro-platform` |
| `faro-platform-windows` | Windows implementation of the platform traits: capture, foreground window, browser, session, tamper, the service host and SCM, ACLs, Authenticode, tray UI | `faro-platform` |
| `faro-detect` | dHash, classifier, domain categories, fusion, blurred thumbnails | `faro-platform`, `faro-proto` |
| `faro-dnsfilter` | The iOS on-device DNS filter engine (IOS.md §7): parses DNS queries from raw IP packets, decides with the domain bundle, builds `NXDOMAIN` replies, counts blocked lookups and detects bursts. No I/O, no unsafe code | `faro-detect` |
| `faro-ipc` | Agent ↔ service protocol and transport (Unix sockets on macOS, named pipes on Windows) | `faro-platform`, `faro-proto` |
| `faro-core` | Scheduler, urgency, recipients, event writer, outbox, reports | `faro-proto`, `faro-crypto` |
| `faro-update` | TUF-style signed update verification | `faro-proto`, `faro-crypto` |
| `faro-client` | The device side of the instance API, shared by every client platform: the signed HTTP client, enrollment links, discovery, registration and endorsement checks, uploads and heartbeats, the update mirror's metadata walk, unpacking data bundles | `faro-proto`, `faro-crypto`, `faro-core`, `faro-update` |
| `faro-service` / `faro-agent` | Client binaries | most of the above |
| `faro-mobile` | The iOS core behind UniFFI (`lib` and `staticlib`): one database shared by the app and its extensions, the `KeyStore` the app implements over the Keychain, enrollment, events, heartbeats, uploads, the domain bundle ([The iOS core](#the-ios-core)) | `faro-client`, `faro-core`, `faro-crypto`, `faro-update`, `faro-detect` (domains only) |
| `faro-android` | The Android core behind UniFFI (`cdylib` and `lib`): `faro-service`'s runtime in the app process over an in-process source whose platform calls go to Kotlin, enrollment and approval, the status screen's words ([The Android core](#the-android-core)) | `faro-service`, `faro-client`, `faro-core`, `faro-platform` |
| `faro-server` (`server/`) | The self-hosted instance | `faro-proto`, `faro-crypto`, `faro-update` |

`faro-proto` and `faro-crypto` are the contract between the client, the server and the web app. Change them deliberately: any change to a `signing_bytes()` encoding or a domain-separation tag is a protocol change and needs a version bump and an update to `docs/PROTOCOL.md`.

## Invariants every change must keep

These come from ARCHITECTURE.md §3.5, §4.3, §5 and §12, and invariant 7 from GROUPS.md §4. Reviewers check them on every PR.

1. **No unblurred image leaves memory.** `faro_platform::Frame` has no `Clone`, `Serialize` or pixel-printing `Debug`, and it is zeroized on drop. The only image type in any wire or storage format is `BlurredThumbnail`.
2. **The instance only sees ciphertext and header metadata.** Nothing in `faro-server` can decrypt anything.
3. **Devices encrypt only to member-endorsed keys,** checked against the member key pinned at enrollment.
4. **Tamper can't be silenced.** The server floors urgency with `EventKind::min_urgency()`, and tamper-class alerts can only be moved to the digest, never turned off. `notify::policy::is_tamper_class` decides which alerts those are; ARCHITECTURE.md §5.4 lists them.
5. **Clients trust project signatures for updates, never the instance.**
6. **Disabling or deleting an account is never silent.** The person and every accountability partner are told, and the alerts can't be switched off: `account_disabled` and `ally_disabled` when an admin disables an account, `account_deleted` and `ally_deleted` when someone asks for theirs to be deleted (or an admin does: then the notices say "deleted by the instance administrator", and a disabled person is told too), and `account_deletion_cancelled` when it is cancelled. Disabling stops sign-in, never monitoring. Deleting stops monitoring only at the purge, after the 7-day hold and once every notice has been delivered. The purge removes every row that names the person: a migration that adds a reference to `users` must add it to `db::repo::deletion::USER_COLUMNS` too, or `every_reference_to_users_is_purged` fails.
7. **Groups never grant access or activate a link.** Group membership never shows anyone's reports or alerts, and leaving, being removed or a group closing never ends an alliance. Only the member's own `POST /v1/me/allies/{ally_id}/approve` activates an `ally_links` row, after the safety-code check. Facilitators never act for someone else, declined proposals stay private, emails never name a group, and group content is encrypted to its recipients. Nobody joins without a yes. The full list is GROUPS.md [§4](GROUPS.md#4-principles-invariants). `no_route_but_approve_activates_a_link` in `server/tests/proposals.rs` checks at runtime that only `approve` activates a link, and `only_approve_calls_the_one_statement_that_activates_a_link` checks the source.

## Dependency notes

- **The crypto stack is pinned to the `rand_core` 0.6 generation:** `ed25519-dalek` 2, `crypto_box` 0.9 (sealed boxes), `chacha20poly1305` 0.10 and `argon2` 0.5. Newer major versions exist (dalek 3, `rand_core` 0.10, `crypto_box` 0.10 is still a pre-release), but mixing generations means duplicated RNG traits and awkward glue. Upgrade the whole set together in one PR, and keep the libsodium interop properties (sealed boxes; Argon2id with `p = 1`) covered by tests.
- **Internal workspace dependencies carry `version = "0.1.0-beta.1"`** (the workspace version) next to `path`. `cargo-deny`'s wildcard ban requires it. A requirement without a pre-release suffix doesn't match a pre-release crate, so when the workspace version changes, change these with it (root `Cargo.toml` and `faro-server` in `crates/faro-service/Cargo.toml`).
- **UniFFI** (`faro-mobile`) is MPL-2.0, which `deny.toml` allows for unmodified dependencies only: use it from crates.io as it is, never patched or vendored with changes. It is pinned at 0.29 and used in proc-macro mode (no UDL, no build script). The `uniffi-bindgen` that generates the Swift bindings must be the same version, so upgrade the two together.
- **HTTP and TLS on every client** is `reqwest` 0.12 on rustls with the ring provider and the OS trust store (`rustls-tls-native-roots`), in `faro-client`. No OpenSSL or native-tls. All of it builds for `aarch64-apple-ios` as well as the desktop targets; on iOS and macOS the trust store is the Security framework's.
- **Versions are semver, and a pre-release sorts below its release:** `0.1.0-beta.1 < 0.1.0`. The updater never installs a lower version than the one running, so the workspace version must never be ahead of the release being built. `MIN_CLIENT_VERSION` in `server/src/api/well_known.rs` must not be above it either. The macOS app bundle gets the version without its suffix (`0.1.0`), because bundle versions must be plain integers.

## The web app

`web/` is the browser side of an instance: a SvelteKit app (Svelte 5, TypeScript, `adapter-static`). Every page is prerendered to static files, and `server/build.rs` compiles `web/build` into the `faro-server` binary, which serves it from the instance's own origin (`server/src/web.rs`). There is no Node server in production.

```sh
cd web
npm ci              # once, and after package-lock.json changes
npm run dev         # http://localhost:5173, API proxied to faro-server on :8080
npm run check       # svelte-check (types)
npm run lint        # prettier --check; `npm run format` fixes
npm run build       # web/build, which the next `cargo build -p faro-server` embeds
npm test            # the crypto port against the Rust test vectors, and key re-wrapping
npm run vectors     # rewrite the vectors' from_web part after changing web/src/lib/crypto
```

| Page | For | What it does |
|---|---|---|
| `/` | everyone | Landing page; signed in, a dashboard with next steps |
| `/setup` | the first admin | Setup token, admin account, test email, registration and retention |
| `/signin`, `/auth/verify` | everyone | Email sign-in; sign-in emails link to `/auth/verify` |
| `/invite` | invitees | Member invitations hand over to sign-in; ally invitations create (or unlock) the ally key and accept |
| `/keys` | members | Create member keys (passphrase and recovery code), sign the first recipient list |
| `/computers` | members | Enrollment codes and links (with `m`), approving and removing computers |
| `/allies` | members | Inviting allies, safety codes, approving and removing them, re-signing after one leaves |
| `/activity` | members | Their own feed, decrypted with their key: what their allies see |
| `/supporting`, `/supporting/member?id=` | allies | The members they support, each member's feed, notification settings, safety code, leaving |
| `/settings` | everyone | Name, key fingerprints, changing the passphrase or getting a new recovery code (member and ally keys), a member's retention and own notifications, deleting the account (every page then shows the hold, with Cancel deletion) |
| `/privacy` | everyone | The operator privacy notice |
| `/licenses` | everyone | The licences of the npm packages in the bundle (`/third-party-licenses.txt`, [Third-party notices](#third-party-notices)) |
| `/admin/…` | admins | Overview, people (with granting the admin role, deleting accounts or cancelling that, and the admin log), settings, branding, email |

**Keys in the browser.** Private keys are created, wrapped and unwrapped in the page (`web/src/lib/keys`), held in memory only (`keyring.svelte.ts`: forgotten on reload, sign-out, "Lock" or after 30 idle minutes) and never sent anywhere unwrapped. Everything the browser builds on is checked first: a recipient manifest the server returns must verify against the member's own key, enrollment links take the member key fingerprint from the unlocked key, and safety codes are computed from the viewer's own key, never the server's copy. A new passphrase or recovery code replaces only the wrapped copies (`web/src/lib/keys/wrapping.ts`): each new copy is opened again and checked against the stored public key before it is uploaded. The storage formats are in PROTOCOL.md §4.3.

**Crypto.** `web/src/lib/crypto` ports what browsers need from `faro-proto` and `faro-crypto` (canonical encoding, key ids, safety codes, Ed25519, opening sealed boxes and items, Argon2id wrapping, manifests and endorsements) on the audited, pure-JavaScript `@noble` libraries. WebAssembly libsodium isn't an option: the page CSP has no `'wasm-unsafe-eval'`. Argon2id at the default 64 MiB / 3 passes takes well under a second. Both implementations check `crates/faro-crypto/tests/data/web-vectors.json`, in both directions; change one side, run both tests.

**The logo** is imported from `assets/brand` (the `$brand` alias in `vite.config.ts`), never copied into `web/` or redrawn; the container build copies that directory into its web stage.

**Instance branding** (`/admin/branding`) is operator content, and the two logos follow different rules:

| | Faro's logo | The instance's logo |
|---|---|---|
| Comes from | `assets/brand`, through `$brand` | an admin's upload: PNG, JPEG or WebP, at most 1 MB and 4096 px a side; SVG refused |
| Changed by | nobody: never redrawn or recoloured | the server: decoded and re-encoded to a PNG of at most 512 px (`faro_server::branding::reencode_logo`) |
| Stored | in the binary (`web/build`) | in the database, table `branding` (migration 0007, base64 in `logo_png`), so backups include it |
| Served at | `/_app/immutable/…` | `GET /v1/branding/logo/{id}.png`, `id` a hash of the PNG: `image/png`, `nosniff`, a sandboxing CSP, cached a year |
| Shown | always | only next to Faro's (`lib/ui/BrandMark.svelte`), alt text the instance name |

The toggles and text are in the same row (`settings_json`). Pages read `GET /v1/branding` (public, only what is switched on); admins use `GET`/`PATCH /admin/api/branding` and `PUT`/`DELETE /admin/api/branding/logo` (raw image body, `Content-Type` `image/png`, `image/jpeg` or `image/webp`). Operator text is one plain line, length-limited, with no control or invisible characters, and a support contact is an email address or an `https://` URL. The server checks this (`faro_server::branding`) and the web app checks again (`web/src/lib/branding.ts`). Only the files in `BRANDING_FILES` there may show it, all page chrome. `npm test` fails if any other file does, if any file uses `{@html}`, or if operator text is styled like a Faro notice.

For `npm run dev`, start a server in another terminal with `cargo run -p faro-server -- serve --dev` (it prints a setup token; set `FARO_DEV_API` to proxy somewhere other than `127.0.0.1:8080`). To test the embedded build instead, run `npm run build` and rebuild the server: `/setup` is then served on :8080 itself. The server refuses cookie-bearing non-GET requests that are not same-origin (`Sec-Fetch-Site`, or `Origin` against `public_url`), which is why the dev proxy works but a page on another origin calling :8080 with the cookie does not; scripts such as `curl` send neither header and pass.

Without `web/build`, `faro-server` still builds and its API works; page requests get a plain-text note and the setup token message points at the `curl` instructions. Release builds set `FARO_REQUIRE_WEB=1`, which makes a missing bundle a build error. CI's `web` job runs lint, check, the crypto tests and build, then the server's web-serving tests against the real bundle.

**CSP.** Pages are served with a strict Content Security Policy built by `web::page_csp`. Scripts and stylesheets load from the instance only. The only inline script allowed is SvelteKit's per-page bootstrap, by hash (`build.rs` hashes it). Inline `style="…"` attributes are allowed only with a constant value, also by hash, and `<style>` blocks are never allowed. In components, use classes, and use Svelte's `style:` directive for dynamic values. Keep `inlineStyleThreshold` at 0, and never load anything from another origin.

**API types** are hand-written in `web/src/lib/types.ts` for now, mirroring the serde types in `server/src/api` and `faro-proto`. Change both sides together.

## Update metadata in tests

`faro-update`'s `testing` feature adds `faro_update::testing::ToyProject`, a project with its own keys. It signs releases (root, targets, timestamp, artifacts) and writes them in the upstream layout (PROTOCOL.md §8.1), so the mirror and client tests can publish whatever they need. `ToyProject::from_seed` derives the keys from a seed, so separate processes sign identical documents, and `sign_raw` signs any payload bytes without validating them. Enable it only in `[dev-dependencies]`, never in a shipped binary. `server/tests/updates.rs` serves such a directory over HTTP on localhost to exercise the online mirror. Models and blocklists are published as data bundles (`faro_update::bundle::bundle_bytes(manifest, file)`); `crates/faro-service/tests/update_artifacts.rs` runs them on a stand-in for ONNX Runtime (a `ModelRuntime` that records what it is handed), so no weights are needed.

## Fuzzing

The parsers that read untrusted input have `cargo fuzz` targets (ARCHITECTURE.md §9). Each fuzz crate has an empty `[workspace]` table, which keeps it out of the workspace: stable builds, `cargo clippy --workspace` and `cargo test --workspace` never build it. They need nightly Rust and `cargo-fuzz`; the default toolchain can stay stable.

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz
cd crates/faro-update/fuzz
cargo run --release --example seed_corpus               # seeds into corpus/<target>/
cargo +nightly fuzz run client_flow -- -max_total_time=600
cargo +nightly fuzz run client_flow artifacts/client_flow/crash-<hash>   # replay one input
cargo test --release --lib                              # the seeds still decode and verify
```

| Crate | Target | Input |
|---|---|---|
| `faro-update` | `envelope` | A served envelope of each role, and a root to bootstrap from (`Updater::bootstrap`, the one place a payload is parsed before its signatures are checked) |
| | `metadata` | Root, targets and timestamp payloads, a persisted `TrustedState`, target names, channels and OS versions |
| | `client_flow` | A whole update check from an untrusted mirror: root rotations, timestamps and targets fed to the `Updater` the way a client calls it, with the state persisted in between. Every document the state ends up trusting must be one the project signed |
| | `signed_flow` | The same check with payloads the harness signs with the project's keys (a buggy release tool or a compromised key), which reaches validation, the version and expiry rules, selection and download checks |
| `faro-proto` | `encoding` | `from_b64`, `from_slice`, `from_prefixed_hex`, the base64 serde adapters, the canonical writer, ids, enum names, key ids, safety codes |
| | `event` | Event uploads (`EventsBatchRequest`, `SignedEvent`) and decrypted `EventBody`s |
| | `report` | Report uploads (`ReportUpload`) and decrypted `DailyReport`s |
| | `api` | The HTTP API types the server reads from devices and browsers and the client reads from its instance; the first byte picks the type |
| `faro-ipc` | `decode_agent_msg`, `decode_service_msg`, `stream_decoder` | Agent ↔ service messages |
| `faro-dnsfilter` | `packet` | A raw IP packet from the tunnel through the engine. A reply must be a well-formed `NXDOMAIN` packet back to the sender, a forwarded query must be the payload unchanged, and an allowed name must never be counted. The packets are read back by the harness's own parser and checksum, not the crate's |
| | `response` | An upstream answer wrapped back to the client |
| | `answer` | An upstream answer to an allowed query through the `Session`: CNAME, DNAME, SVCB and HTTPS records and truncation. A blocked alias (by the harness's own parser) must never pass, an answer that passes must come back unchanged but for its id, a truncated one must be fetched again over TCP, and only blocked names are counted. Fragments are reassembled by the harness |
| | `state` | Saved counters and filter configs, as the tunnel loads them from the app group |

Every target fails on a panic. Beyond that, every faro-proto decoder must round-trip (decode, encode, decode to an equal value, encode to the same bytes), and the faro-update targets check the state machine's rules after every call: nothing trusted rolls back, a failed call changes nothing but the observed time, and the persisted state loads back unchanged and stays small.

- **Seeds.** `faro-update`'s seeds are documents signed by `ToyProject::from_seed`, a toy project with fixed keys whose first root every target trusts, so a seed written by one process verifies in another. `faro-proto`'s are sample values of each type. `faro-dnsfilter`'s are query packets (IPv4 and IPv6, blocked, allowed, malformed), answers and saved state. Each is written by the crate's `seed_corpus` example, and `corpus/` is not checked in. The `src/lib.rs` tests check that the seeds still decode and reach as far into the verifier as they should, so run them after changing a type. `faro-dnsfilter`'s also run the target checks on random mutations of the seeds, which needs no nightly (`FARO_FUZZ_ITERS=1000000 cargo test --release --lib` for a longer run).
- **A shared machine.** libFuzzer uses one process unless asked for more; keep it that way (`-jobs=1`) and fuzz one target at a time.
- **Findings.** Fix the bug with a regression test in the crate's normal test suite, not only in the corpus. A finding in `faro-update` is a security issue: describe it in the pull request that fixes it, never in a public issue.
- **CI.** `.github/workflows/fuzz.yml` runs every target nightly and on demand (`workflow_dispatch`, with the seconds per target as input; 300 by default) on `ubuntu-24.04`, and never on pull requests. Each run starts from the corpus the previous one grew (kept in the Actions cache), and a crashing input is uploaded as the `fuzz-crashes-<crate>-<run id>` artifact, kept for 30 days.

## The domain category bundle

`faro-detect`'s `DomainCategorizer` (§3.5 "Context signals") loads a compiled FST bundle. The `domains-compile` example builds it from the blocklists listed in `crates/faro-detect/domains/sources.toml`. Run it from the repository root:

```sh
cargo run -p faro-detect --example domains-compile -- fetch --config crates/faro-detect/domains/sources.toml
cargo run -p faro-detect --example domains-compile -- build --config crates/faro-detect/domains/sources.toml \
    --out target/domains/domains.bin
```

- **`fetch`** downloads each approved `url` source with `curl` into `target/domains/sources` (`--sources-dir` changes it) and keeps it only if its BLAKE3 matches the pin in `sources.toml`. Sources can also be local files (`path`, relative to the config).
- **`build`** reads only those files, refuses any that don't match their pin, and writes `domains.bin` and `domains.manifest.json` (`faro_detect::DomainsManifest`): the config's `bundle_version`, the sources, their licences, attribution and entry counts, the licence texts, and the bundle's size and BLAKE3. Nothing in either depends on the time or the machine, so the same config always gives byte-identical files. Clients load the pair with `faro_detect::load_domains`, which checks all of it again.
- **`bundle_version`** (`MAJOR.MINOR.PATCH`) names the bundle on the update channel. Bump it whenever a source or a pin changes: a release lists each version once, and refuses the same version with other bytes.
- **Approved, pending and refused (§11).** Every source records an SPDX licence and a state, and the maintainer decides it:
  - **Approved** (`approved = true`) sources are always fetched and compiled. Their licence must be on `faro_detect::ALLOWED_MODEL_LICENSES`, or the config is rejected.
  - **Pending** (`approved = false`) sources are left out. `--allow-unapproved` includes them for local experiments only: the manifest then says `"unapproved_included": true`, and such a bundle must never ship. Their `terms` field says what the upstream terms are.
  - **Refused** (`refused = "reason"`) sources stay in the config, so nobody proposes them again, but they are never fetched or compiled, even with `--allow-unapproved`.
- **Attribution travels with the bundle.** The manifest ships next to `domains.bin` and has to be enough to comply on its own. So an approved source whose licence asks for attribution (anything on the allowlist except CC0-1.0 and the Unlicense) needs a `[source.attribution]` table: `author`, the upstream's verbatim `copyright` lines, `source_url`, `license_url`, and `changes`, a note of what the conversion did. For licences whose text must accompany copies (MIT, BSD, ISC, Zlib, Apache-2.0), the `copyright` lines are required and the text goes once under `[license_texts]`. CC BY 4.0 only needs the link to the licence. Without any of these, `fetch` and `build` refuse the config. The manifest copies every source's attribution and the texts of the licences it uses.
- **Moving to a newer upstream revision:** change the commit in the URL, run `fetch` (it stops at a file whose hash changed and prints the new hash), review what changed upstream and that its licence and copyright notices didn't, then update the pin.
- **Never commit a downloaded list or a built bundle.** The tests use the hand-written fixtures in `crates/faro-detect/examples/domains-compile/fixtures` (`.gitattributes` there keeps their bytes, and so their pins, the same on Windows).
- `domains-compile hash FILE…` prints BLAKE3 hashes for pinning a new source.
- `domains-compile notice --manifest M --out F` loads a built bundle with `load_domains` and writes its plain-text notice (`DomainsManifest::notice_text`): each source with where it came from and its attribution, then the licence texts.

**In the package.** The macOS package ships the list, so category detection (adult and gambling sites) works from the first start, before the update channel has been reached. `build-pkg.sh` runs `fetch`, `build` and `notice` above, with the downloads kept in `target/domains/sources` and checked against their pins on every build. It installs `domains.bin` and `domains.manifest.json` in `/Library/Faro/domains` (`pkg_layout::DOMAINS_MANIFEST`) and the notice as `/Library/Faro/notices/domains.txt`. `check-pkg.sh` fails if any of them is missing, if the version isn't `sources.toml`'s `bundle_version`, if a refused source is named, if the notice lacks the MIT text, the CC BY 4.0 link or any source, or if this Mac's slice of `faro-service` can't load the list (`faro-service domains-check [--manifest PATH]`, which loads it as the service does and prints its version and sources) or it has no adult or no gambling source.

**In the service.** It loads the packaged list with `load_domains`. When the packaged service's list is missing or doesn't load, it runs without domain categories and reports an urgent `integrity_failure` (`domain list (missing)` or `(changed)`). Each release also compiles the bundle in the `blocklist` job of `release.yml` and lists it on the update channel ([Models and blocklists on the update channel](#models-and-blocklists-on-the-update-channel)). A newer list from the channel replaces the packaged one without a restart; the packaged one stays as the fallback. The release fails unless the package's manifest is byte for byte the one `blocklist` built, so the two copies of a version are always the same. Tests hand a list to the service with the `domains` builder method.

## The DNS filter

`faro-dnsfilter` is the engine of the iOS packet tunnel (IOS.md §7). The tunnel runs it through `Session` (behind `faro_mobile::DnsFilter`): it hands each packet to `Session::packet` and does what the returned `Step` says: write packets back to the tunnel, or send a query to the network's resolver and hand the answer to `Session::answer`. Underneath, `Engine::handle_packet` decides about a packet and `Engine::check_answer` about an answer. The crate documentation has the rules. In short:

- **Only UDP to port 53 is handled.** TCP gets no answer, so clients retry over UDP, and DNS over HTTPS, TLS or QUIC to the routed resolver addresses (`RESOLVER_ADDRS`) is dropped. Malformed queries are dropped too: several questions, compression pointers in the question, labels over 63 bytes, names over 255, bytes other than letters, digits, `-` and `_`.
- **The decision**, first match wins: the always-blocked list (`ALWAYS_BLOCKED`, encrypted-DNS bootstrap names and iCloud Private Relay), the instance host (always allowed), the member's block list, the member's allow list, then the bundle's categories (`adult` always on). Names match their parents on label boundaries. Both constant lists carry a version (`ALWAYS_BLOCKED_VERSION`, `RESOLVER_LIST_VERSION`): bump it when a list changes.
- **Answers are checked too.** Every CNAME and DNAME target, and the target of every SVCB and HTTPS record, in the answer to an allowed name goes through the same decision. If one is blocked, the client gets `NXDOMAIN` and the lookup is counted as a block of the target. An answer that can't be read that far gets `SERVFAIL`. Answers for the instance host are not checked.
- **Forwarding.** Each forwarded query gets a random id of the session's own, and the answer must come from the resolver it went to, with the query's exact question, within 4 seconds. A truncated answer (`TC` set) is never passed on: the session asks for the whole answer over TCP from the same resolver and sends it back over UDP, in IP fragments when it is larger than the tunnel's MTU (`packet::build_udp_fragments`). Without a resolver, allowed names get `SERVFAIL` at once. There is no fallback resolver.
- **Counters and bursts** only ever see blocked lookups. The thresholds are constants in `burst.rs`.
- **The tunnel's addresses** are in `tunnel.rs`: the DNS address `198.18.0.53` and `2001:2::53`, both in the benchmarking ranges no real network uses, and the host routes (that address and `RESOLVER_ADDRS`, nothing else).

`cargo test -p faro-dnsfilter` checks the packet fixtures against checksums computed outside the crate, reassembles fragments with its own code, and has privacy tests that check that no allowed name reaches the counters, the burst detector or the session's state, through answers and aliases too. To measure memory and time per query against a real bundle, build it ([The domain category bundle](#the-domain-category-bundle)), then:

```sh
cargo run --release -p faro-dnsfilter --example dnsfilter-measure -- \
    target/domains/domains.manifest.json target/domains/sources
```

## Testing without real hardware

`faro_platform::synthetic::Script` drives a fake screen, foreground app, session state and tamper signals. Use it for anything above the OS layer. Tests that need real OS permissions (for example macOS Screen Recording) are `#[ignore]`d and say so in their name or doc comment. Tests that need SYSTEM or elevation on Windows skip themselves.

On macOS the agent binary shows a menu-bar icon, the status menu and the service's notices, which needs a GUI session. `cargo run -p faro-platform-macos --example session_ui` shows that UI with a sample notice and a sample status ("Screen Recording is off"; `FARO_SAMPLE_STATUS=ok` for "Monitoring") and no service. A `dev` agent started outside a GUI session (over SSH, for example) can skip it with `--no-ui`. AppKit's main thread can't be driven from `cargo test`, so the UI has no automated tests.

Browser tab URLs (`faro_platform_macos::browser`) need Accessibility and a real browser, so their live path has no automated test either. `cargo run -p faro-platform-macos --example browser_probe` prints what the agent would send every 2 seconds: the frontmost app and the reduced URL (`scheme://host/`). Run it from a terminal that has Accessibility and switch between browsers. `--pid PID --as safari|chrome|…` reads one process instead, which works for any app with a web view.

Windows hidden from screen capture (`faro_platform_macos::hidden_windows`) have unit tests for the decision, but reading other apps' capture state needs Screen Recording. `cargo run -p faro-platform-macos --example hidden_window_probe` lists every on-screen window's sharing state, layer, size and owner (never its title), marks the macOS processes that are allowed, and prints the reading and the signal the agent would send. `--hide` first opens a window of its own with `sharingType = .none` and reads the probe's own windows without skipping them, which works without the permission (a process always reads its own windows' real state). To check other apps, run it from a terminal that has Screen Recording.

## The image model

The beta's image classifier is **OpenNSFW** (Yahoo, BSD-2-Clause; ARCHITECTURE.md §3.5, [research/model-licenses.md](research/model-licenses.md)). The project converts it from Yahoo's own Caffe files. Nothing in the repository holds weights: `crates/faro-detect/models/opennsfw/build.sh` makes the model every time a package is built.

```sh
crates/faro-detect/models/opennsfw/build.sh target/models            # the models, manifests and notice
crates/faro-detect/models/opennsfw/build.sh --parity target/models   # and check them against the original
```

- **Source.** `deploy.prototxt`, `resnet_50_1by2_nsfw.caffemodel` and `LICENSE.md` from [yahoo/open_nsfw](https://github.com/yahoo/open_nsfw) at commit `a4e1393` (the archived repository's last). `build.sh` pins each file's SHA-256 and BLAKE3 and refuses any other bytes.
- **Tools.** CPython 3.9 (the Command Line Tools' `/usr/bin/python3`, or `FARO_PYTHON`) and the versions in `requirements.txt`, installed with `pip --require-hashes` into a fresh virtual environment.
- **Conversion** (`convert.py`). It decodes Yahoo's two files itself (no Caffe, no third-party port), folds each BatchNorm and Scale layer into the convolution before it, and writes `opennsfw-fp32.onnx`. Max pooling uses `ceil_mode`, as Caffe does. The weights are not retrained or changed in any other way.
- **Quantization.** ONNX Runtime's static quantizer makes `opennsfw-int8.onnx`: QDQ format, int8 weights per channel, uint8 activations, calibrated on synthetic images the script draws (solid colours, gradients, UI-like windows). Stages 2 and 3 run in int8. The stem (the first convolution and stages 0 and 1) and the classifier head stay in float: quantizing them moves p(nsfw) by up to 0.25 on synthetic images, against about 0.06 this way, at the same speed. This is the model the package ships.
- **Versions.** `1.0.0+int8` and `1.0.0+fp32`: semver, so the service can compare the packaged model with one from the update channel. Change the version whenever the model's bytes change.
- **Pinned outputs.** `manifest.json` (int8) and `manifest-fp32.json` pin each model's BLAKE3, and `build.sh` refuses a conversion that doesn't match. The same tools give the same bytes on the same kind of Mac. The quantizer runs the fp32 model to calibrate, so another CPU or tool version can give different bytes: `build.sh` then stops and prints the new hash. Check that run with `--parity` before changing a pin.
- **Parity** (`parity.py`, with `--parity`). OpenCV's Caffe importer runs Yahoo's original files as the reference, and both models get the same tensors for 14 synthetic, non-explicit images (solid colours, gradients, UI windows with text). It fails if p(nsfw) differs by more than 1e-4 (fp32) or 0.05 (int8). `check-pkg.sh` repeats the three solid-colour cases with the packaged service, on each architecture it can run.
- **Licence and attribution.** The manifests carry `license_text` (Yahoo's `LICENSE.md`, word for word; `notice.py` checks) and `attribution` (author, copyright line, source and licence URLs, and the changes above). `load_model` refuses a manifest without what its licence asks for, with the same rules as the domain bundle compiler (`faro_detect::attribution`). The package installs `notices/opennsfw.txt` from them.
- **Labels.** `sfw` and `nsfw`. The default policy reads `nsfw` as explicit; `sfw` is ignored. There is no `suggestive` output.
- **Preprocessing.** The manifest's `resize` says how a frame becomes the 224×224 input. `"direct"` (also what a manifest without `resize` means, which includes both shipped manifests) resizes the whole frame to 224×224 and keeps a screenshot's edges. `{"resize_crop": {"side": 256}}` resizes it to 256×256 and takes the centre 224×224, dropping a 16-pixel border, as Yahoo's script does. Both resample by area averaging and ignore the aspect ratio (Yahoo's script resizes with PIL's bilinear filter and re-encodes the result as JPEG, so scores can still differ a little from its own). `preprocess` applies it, so the service and `model-bench` do the same thing. The package ships `direct`; whether to switch is for the maintainer's eval on the real set ([Comparing preprocessing](#comparing-preprocessing)).
- **Caches.** Downloads and models are cached by digest in `~/Library/Caches/faro-models` (`FARO_MODEL_CACHE`) and checked again on every use, so a repeat build only reinstalls the tools.
- **In the service.** `faro-service` built with `--features onnx` loads `/Library/Faro/models/opennsfw/manifest.json` (`pkg_layout::MODEL_MANIFEST`) with `load_model`'s checks and runs it on ONNX Runtime's CPU provider, one thread. Without a model it rates frames from context signals only. When the packaged service's model is missing, altered or can't be loaded, it does the same and reports an urgent `integrity_failure` (`image model (missing)`, `(changed)` or `(cannot load)`) once it runs. `faro-service model-check [--manifest PATH]` loads a model the same way and prints its scores for a few synthetic frames and its latency. A newer model from the update channel replaces the packaged one without a restart ([Models and blocklists on the update channel](#models-and-blocklists-on-the-update-channel)); the packaged one stays as the fallback.

## Model benchmark

`faro_detect::bench` and the `model-bench` example measure a candidate image classifier the way the service uses it, and gate regressions against a baseline (ARCHITECTURE.md §3.5). Build it with `--release`: an unoptimized build says so in its output, and its latency means nothing.

```sh
B="cargo run --release -p faro-detect --features onnx --example model-bench --"
$B --manifest m.json --set /Volumes/FaroEval/set --json results.json      # run
$B --manifest m.json --model candidate.onnx --set … --json results.json   # weights elsewhere
$B --manifest m.json --set … --baseline models/eval-baseline.json         # run and gate
$B --results results.json --baseline models/eval-baseline.json            # gate only
$B --write-synthetic-set /tmp/synthetic                                   # a set with no real image
$B --help                                                                 # every option
```

**Latency without the real set.** `--write-synthetic-set DIR` writes the 15 synthetic images the harness tests use (solid colours and UI-like windows, labelled by colour). Benchmark a model on it for its latency; its precision and recall mean nothing. For OpenNSFW:

```sh
crates/faro-detect/models/opennsfw/build.sh target/models
$B --write-synthetic-set target/synthetic
$B --manifest target/models/manifest.json --set target/synthetic        # int8, as shipped
$B --manifest target/models/manifest-fp32.json --set target/synthetic   # fp32
```

The manifest is the same `ModelInfo` JSON the update channel ships, and the same checks apply: the licence must be on `ALLOWED_MODEL_LICENSES` and `blake3` must match the weights (`b3sum candidate.onnx`). `--policy policy.json` benchmarks other thresholds (a partial `PolicyConfig`; the default is the built-in policy). `--resize MODE` benchmarks another preprocessing than the manifest's (`direct` or `resize_crop:SIDE`, see [The image model](#the-image-model)).

**Test-set layout.** One folder per true class, PNG files only:

```text
<set>/
  explicit/       *.png, subfolders allowed
  suggestive/
  neutral/
  gambling/ …     optional: any of the policy's other_labels (gambling, violence, gore)
```

Classes are the policy's kinds, not a model's labels, so one set measures models with different label sets (`porn`, `hentai` and `explicit` all count as `explicit`). Convert other formats first (`sips -s format png in.jpg --out out.png`). Hidden files are skipped and files at the top level are ignored; an unknown folder, an empty class or any other file is an error.

**What it reports**, as text on stdout and, with `--json`, as JSON:

- *Predicted class:* `neutral` if the policy rates the image clean, otherwise the kind of its top reason (`explicit`, `suggestive` or the other label). So "predicted explicit" means an explicit label crossed a policy threshold (`any_low` or above) and was the strongest reason: what allies would see.
- *Per-class precision and recall*, from the *confusion matrix* (true class × predicted class).
- *Ratings per class* (clean, low, medium, high): the operating point, e.g. how many explicit images reach `medium`, where thumbnails and alerts start.
- *Latency:* p50, p95, mean and max of `Classifier::classify` (preprocessing and inference on ONNX Runtime's CPU provider, one intra-op thread) per frame, after 3 untimed warm-up runs. Images are downscaled to 768 px first, as `Detector::process` does.

**The gate** exits 1 when recall on `explicit` drops by more than `--max-recall-drop` (absolute, default 0.02) or p95 latency rises by more than `--max-p95-increase` (relative, default 0.25). It exits 2 when the reports can't be compared: the set's digest differs (an image was added, removed, edited or moved to another class) or a report has no explicit images. A different model, preprocessing (`resize`), policy or machine is printed as a note. Latency only compares on the same machine and build, so the baseline comes from the CI runner.

**The baseline** is `models/eval-baseline.json`: a results file from the macOS runner, metrics only, so it is safe to commit. There is none until the maintainer picks a model and the set is on the runner; until then the CI job warns and passes. To create or update it, download the `model-eval-metrics-<sha>` artifact of the run you accept and commit its `results.json` as the baseline, in the same pull request that changes the model, the set or the policy (or accepts a regression), and say why.

**In CI.** The harness itself is tested on every pull request against a synthetic set the tests generate (solid colours and UI-like windows) and a tiny ONNX graph they encode by hand (`classifier/test_onnx.rs`), so no model or image is downloaded or committed: `cargo test -p faro-detect` on every runner uses a pure-Rust stand-in for the graph, and the macOS `test` job also runs `cargo test -p faro-detect --features onnx` (the `onnx` feature's build script downloads ONNX Runtime). The `model-eval` job runs the gate on the real set. It runs on `main` only (each push, or a manual run from the Actions tab), never on a pull request, so a change to the harness is reviewed before it touches the set. To gate a candidate model before merging, run the tool locally. The job also runs only when the runner's environment sets the variables below. GitHub's runners never have the set, so **the job is skipped on every run today**; it needs a runner of the project's own that holds the set.

| Variable | Value |
|---|---|
| `FARO_MODEL_EVAL_SET` | the set's directory; unset, the job is skipped |
| `FARO_MODEL_EVAL_MANIFEST` | the manifest of the model under test, with the model next to it |

It uploads `results.json` and nothing else.

**Handling the real set.** It contains explicit imagery, so:

- **Never commit it,** and never copy it into the repository, a worktree, `target/`, an issue, a pull request or a CI artifact. Keep it on an encrypted volume outside the repository, readable by no account but yours and the runner's.
- **Adults only, obtained lawfully.** Anything that might depict a minor stays out of the set, without exception.
- **The tool writes metrics only.** Images enter through `Frame`, one at a time, and are zeroized when dropped (`privacy_tests::benchmark_frames_are_zeroized`); no image, thumbnail or per-image result is written, and the set appears only as a digest. It deliberately doesn't list which images were missed. File names can appear in error messages, and so in CI logs: name files neutrally (`0001.png`).
- **The runner can read it.** Keeping `model-eval` off pull requests stops unreviewed harness changes from running on the set, but it is not a sandbox: anyone who can push a branch can run any code on a runner that holds the set, and so read it. Keep push access to maintainers, and remove `FARO_MODEL_EVAL_SET` (and the set itself) from the runner before the repository goes public or that changes.

### Comparing preprocessing

Whether OpenNSFW sees the whole screenshot (`direct`, what the package ships) or Yahoo's resize-and-crop (`resize_crop:256`) is the maintainer's choice, made on the real screenshot set during the release checklist's model evaluation (section 5). Yahoo's way scored one real photo 0.150 where Faro's scored 0.061, with the same weights; Faro's way keeps the screen's edges, where a small window or a thumbnail may sit. Only the real set says which matters more on screens. Run it on your own Mac, with the set on its encrypted volume and the rules above:

```sh
crates/faro-detect/models/opennsfw/build.sh target/models
B="cargo run --release -p faro-detect --features onnx --example model-bench --"
$B --manifest target/models/manifest.json --set /Volumes/FaroEval/set \
   --resize direct,resize_crop:256 --json target/resize.json           # int8, as shipped
$B --manifest target/models/manifest-fp32.json --set /Volumes/FaroEval/set \
   --resize direct,resize_crop:256                                     # fp32, to rule out quantization
```

- **What it does.** The same verified model runs once per mode over the same images, with the same policy (`--policy` applies to both). It prints each run's full report, then a comparison with one column per mode: precision, recall and ratings (clean/low/medium/high) for every class, and p95 latency. If the set's digest differs between the runs (a file changed meanwhile), it stops. `--json target/resize.json` writes `target/resize.direct.json` and `target/resize.resize_crop-256.json`, metrics only, like every report.
- **What to weigh.** Explicit recall, and how many explicit images reach `medium` (where thumbnails and alerts start), against neutral images rated `low` or above (false alarms). Look at precision and recall per class, not only explicit. `resize_crop` resamples to 256×256 rather than 224×224, so its preprocessing takes a little longer; inference is the same.
- **Gating one mode.** Each JSON gates on its own: `$B --results target/resize.resize_crop-256.json --baseline models/eval-baseline.json`. A baseline taken with the other mode is compared, with a note.

**To switch** (in a pull request that says why, with the comparison's numbers):

1. Add `"resize": {"resize_crop": {"side": 256}}` to `crates/faro-detect/models/opennsfw/manifest.json` and `manifest-fp32.json`, and bump both versions (`1.0.1+int8`, `1.0.1+fp32`): the weights' BLAKE3 stays the same, but the manifest's bytes change, and so do the update-channel bundle, its target hash and its signature at the next release.
2. Publish it with `min_client` set to the first release whose `faro-detect` reads `resize` (`release/build-layout.sh --data model:<version>=…`). Older clients reject any manifest field they don't know, so they would refuse the bundle, record it as rejected and keep their model; `min_client` keeps it from being offered to them at all.
3. Update the baseline from a run with the new manifest, as for any model change.

A manifest without `resize` keeps meaning `direct`, and a `direct` manifest is written without it, so switching back is the same steps with the field removed.

## The macOS installer

`installers/macos/build-pkg.sh` builds the `.pkg` and `installers/macos/check-pkg.sh` checks one without installing it. CI builds and checks the development package on every pull request and keeps it for 14 days as the `faro-dev-pkg-universal-<sha>` artifact of the `macos-pkg` job.

```sh
rustup target add aarch64-apple-darwin x86_64-apple-darwin  # once
installers/macos/build-pkg.sh --dev                         # unsigned, for testing only
installers/macos/check-pkg.sh target/pkg/Faro-*-dev.pkg
installers/macos/test-uninstall.sh                          # the uninstaller's decisions, on a fake /Library
```

- **The package is universal.** It runs on Apple Silicon and Intel Macs. `build-pkg.sh` builds `faro-service` and `faro-agent` once for `aarch64-apple-darwin` and once for `x86_64-apple-darwin`, then joins each pair with `lipo -create`. Apple's clang compiles the C code (the bundled SQLite, `ring`, `blake3`) for both, so no other toolchain is needed. `--arch arm64` or `--arch x86_64` builds one architecture only, which is faster; check such a package with `check-pkg.sh --arch arm64 …`.
- **Every slice targets macOS 13.** `build-pkg.sh` sets `MACOSX_DEPLOYMENT_TARGET` from the `os-version min` in `Distribution.xml.in`. `check-pkg.sh` fails if any Mach-O file in the payload lacks an architecture, if `hostArchitectures` is not `arm64,x86_64`, or if a slice's minimum macOS is not 13.0.
- **On Intel.** The `macos-pkg-intel` job runs on GitHub's Intel Mac runner (`macos-15-intel`) after `macos-pkg`. It checks the same universal package (so the x86_64 `faro-service` classifies with the packaged model, see below), expands it without installing it, and runs the x86_64 `faro-service` and `faro-agent` with `--version`. On an Apple Silicon Mac with Rosetta 2, `cargo test --target x86_64-apple-darwin` runs the x86_64 tests locally.
- **The image model and ONNX Runtime.** Every package's `faro-service` is built with `--features onnx`. `fetch-onnxruntime.sh` downloads ONNX Runtime 1.22.0's static library for each architecture (the builds `ort-sys` 2.0.0-rc.10 pins in its `dist.txt`; `build-pkg.sh` checks the pins are the same), checks its SHA-256, and `build-pkg.sh` links it with `ORT_LIB_LOCATION`, one cargo run per architecture, with pkg-config and dynamic linking turned off. So `faro-service` carries ONNX Runtime and there is no dylib to join. The static builds carry no licence files, so ONNX Runtime's MIT licence and `ThirdPartyNotices.txt` come from the same release's Python wheel on PyPI, also pinned by SHA-256. The model comes from `crates/faro-detect/models/opennsfw/build.sh` (see [The image model](#the-image-model)). The package installs it in `/Library/Faro/models/opennsfw` and the notices in `/Library/Faro/notices` (`opennsfw.txt`, `onnxruntime-LICENSE.txt`, `onnxruntime-ThirdPartyNotices.txt`, the domain list's `domains.txt`, and the Rust crates' `third-party.txt`, see [Third-party notices](#third-party-notices)). The domain list goes in `/Library/Faro/domains` (see [The domain category bundle](#the-domain-category-bundle)). Both scripts need network access on a first build, and the model needs `/usr/bin/python3`. Downloads are cached by digest (`~/Library/Caches/faro-models`, `~/Library/Caches/faro-onnxruntime`). `check-pkg.sh` fails if any of these files is missing, if a notice lacks its copyright line or licence text, if `faro-service` loads ONNX Runtime from a dylib, or if this Mac's slice of `faro-service` can't load the model or scores solid black, white or grey more than 0.05 from Yahoo's original.

- **A `--dev` package is not safe to use on anyone.** Its `faro-service` is built with the `dev` feature, so it accepts any program running as a logged-in user as the agent. Install it only on a test machine.
- **Every new `--dev` package drops the Screen Recording grant.** Its binaries are signed ad hoc, so each build is a new app to macOS, and the old grant no longer applies even where System Settings still shows Faro Agent switched on. After installing one, open System Settings → Privacy & Security → Screen & System Audio Recording, remove Faro Agent with −, and add it again (`/Library/Faro/Faro Agent.app`). Until then every capture fails with `permission denied: screen_recording`, the agent shows its "Faro can't see the screen" notice, and allies get "Screen Recording is off" (`permission_revoked`, with `never_granted` if the service never saw it granted on this enrollment).
- **A release package** needs `FARO_SIGN_IDENTITY` (Developer ID Application), `FARO_INSTALLER_IDENTITY` (Developer ID Installer) and `FARO_TEAM_ID`. The package's default `service.toml` sets `ipc.agent_requirement` from the team ID. `FARO_NOTARY_PROFILE` (a `notarytool` keychain profile) also notarizes and staples it.
- **The layout is fixed:** programs in `/Library/Faro` (the agent inside `Faro Agent.app`, bundle id `org.faro.agent`), the daemon in `/Library/LaunchDaemons` and the **global** LaunchAgent in `/Library/LaunchAgents`, which launchd starts in every account's session. The paths live in `faro_platform_macos::pkg_layout`.
- **The launchd plists are checked in** under `installers/macos/payload`, and a test keeps them equal to the generator. After changing `pkg_daemon_job` or `pkg_agent_job`, run `FARO_BLESS=1 cargo test -p faro-platform-macos --test installer_plists`.
- **After installing,** the service waits for enrollment. Members enroll from the agent: opening a `faro://enroll` link (the web app's **Open in Faro**, or **Enroll this computer…** in the menu-bar icon) shows the instance and the accounts to confirm, and an administrator approves in macOS's own password dialog ([Enrolling from the agent](#enrolling-from-the-agent)). `sudo /Library/Faro/bin/faro-service enroll --link '…'` still works: it lists the computer's accounts, enrolls it, and leaves activation to the running service.
- **Uninstalling:** `sudo /Library/Faro/bin/faro-uninstall` stops the service, runs `faro-service goodbye` so allies get an urgent "Faro was uninstalled" (§3.7), then stops every session's agent and removes the programs, the launchd jobs, the state directory, the logs and the package receipt. If the instance can't be reached, `goodbye` writes nothing, so the uninstaller restarts the service and removes nothing. If the instance has already retired the computer (`403 device_removed` or `403 account_deleted`), allies were told then: `goodbye` writes nothing, exits 0, and the uninstall goes ahead. `--force` removes Faro anyway, and allies then see a missed check-in instead. A goodbye that is written but not delivered (exit status 3) never backs out: a service running again after its own goodbye would contradict it.
- **Logs.** The packaged service logs to `/Library/Logs/Faro/faro-service.log` (root:admin, 0640, in a 0750 directory, so an administrator reads it without `sudo`), and each account's agent to `~/Library/Logs/Faro/faro-agent.log` (0600). Each is rotated at 5 MiB to `.1`, `.2` and `.3`, so it never takes more than 20 MiB. The paths and the policy are in `faro_platform_macos::pkg_layout` (`SERVICE_LOG`, `agent_log`, `LOG_MAX_BYTES`, `LOG_KEEP`); anything that reads the logs takes them from there. To follow them: `tail -F /Library/Logs/Faro/faro-service.log` and `tail -F ~/Library/Logs/Faro/faro-agent.log`.
  - *Why the programs write the files, not launchd.* The plists have no `StandardOutPath` or `StandardErrorPath`: the agent's plist is one global LaunchAgent for every account and launchd doesn't expand `~` in it, and a file launchd opens for a job stays open in the job's process, so `newsyslog` couldn't rotate it under a running service (it would need a pid file and a signal handler to reopen). So each program opens its own log (`faro_platform::logfile::RotatingFile`) when it runs from the package with no terminal on stderr (started by launchd), and logs to stderr otherwise: in Terminal, in development builds and for every other `faro-service` command. If the file can't be opened it logs to stderr and says why. Panics, and the error a failing `faro-service run` exits with, go to the log too. What is lost: output before `main` (a `dyld` error), which launchd discards. `faro-uninstall` removes the logs; there is no `newsyslog` rule to remove.
  - *Level.* `info` by default. For the service, `RUST_LOG` wins, then `-v`/`-vv`, then `log_level` in `service.toml` (a `RUST_LOG`-style filter, such as `debug` or `faro_service=debug,info`), then `info`; a new level needs a restart (`sudo launchctl kickstart -k system/org.faro.service`). For the agent, `FARO_LOG`: `launchctl setenv FARO_LOG debug`, then `launchctl kickstart -k gui/$(id -u)/org.faro.agent` (the service sees that as a killed agent, like any other; the setting lasts until logout).
  - *What is in them.* At `info` and above, never URLs, window titles, notice bodies, email addresses or anything from a frame: those go to `debug` and `trace` only. `crates/faro-platform/tests/log_privacy.rs` scans every client crate's `info!`, `warn!` and `error!` calls and fails on an identifier that names such data, unless its `ALLOWED` list says why that one is safe (a service notice's title, which the service writes; the instance's address). At `debug` and `trace`, private values go only in fields named for what they are (`title = ?t`, `app = …`, never `x = ?t` or `"{t}"` in the message), so that `faro-service diagnose` can take them out of a problem report by name; the same test checks that, with the word list in `faro_platform::logfile::PRIVATE_LOG_WORDS` ([Problem reports](#problem-reports)). Keep `debug` for chasing a problem, and turn it off after.
- **One writer per chain:** `run` and `goodbye` both hold an exclusive lock on `service.lock` in the state directory (`StateDir::try_lock`), so a second `faro-service run`, or a `goodbye` while the service runs, is refused instead of forking the event chain.
- **Updates:** `FARO_UPDATE_ROOT` (a signed root document, for example from `cargo run -p faro-update --example faro-release -- sign-root …`) is installed as `/Library/Faro/update-root.json`. A release package requires it; a `--dev` one may have it. With it, the service checks its instance's mirror about every 6 hours (`[updates] check_secs`) and installs newer client packages through the one-shot launchd job `org.faro.update` (`faro_platform_macos::update_job`). It runs as its own job because the package's preinstall stops the service, which would kill an `installer` running as its child. Only the packaged service, run as root from `/Library/Faro/bin/faro-service`, installs anything. A development build checks and logs, nothing more. Before installing, the service checks the package's own signature (PROTOCOL.md §8.2, step 5): Faro's Developer ID Installer certificate and notarization, with the Team ID compiled in from `FARO_TEAM_ID` (`build-pkg.sh` passes it to `cargo`). A `--dev` package's service has the `dev` feature and no Team ID, so it skips that check and dev packages can update each other. A service built without either refuses every package. Then it reads the full semver version inside the package (`PackageInfo` and the Distribution, step 6), and refuses the package unless it is the version the metadata names and above the running one. Development builds do this too, so keep `pkgbuild --version` and the Distribution's `@VERSION@` the full version. To run both checks by hand: `FARO_TEAM_ID=<team> cargo run -p faro-service --example check_package -- <pkg>` (it prints the version). The job's output goes to `update-install.log` in the state directory, and `update-attempts.json` there records the pending install and failed packages. Models and blocklists come through the same check ([Models and blocklists on the update channel](#models-and-blocklists-on-the-update-channel)); their notices go to `/Library/Faro/notices/update-model.txt` and `update-blocklist.txt`.
- **The status menu** (issue #89) is in the agent's menu-bar icon, not a separate tray app: see [The status menu](#the-status-menu). There is no tray app beyond it.

## The Windows client

The Windows client is `faro-platform-windows`, which holds the capture, foreground-window, browser, session, tamper, service host (SCM), ACL, Authenticode and tray UI code. The binaries are `faro-service` and `faro-agent`, and they talk over named pipes in `faro-ipc`. It supports Windows 10 22H2 (build 19045) and Windows 11, x64 only.

- **Pipes.** Each account's agent uses `\\.\pipe\faro\agent.<SID>`. Enrollment uses `\\.\pipe\faro\enroll`. Administrator approval uses `\\.\pipe\faro\enroll.S-1-5-32-544`, the Administrators group's SID.
- **Logs and state.** The service logs to `C:\ProgramData\Faro\logs\faro-service.log`, and each agent to `%LOCALAPPDATA%\Faro\Logs\faro-agent.log`. Both rotate at 5 MiB, with 3 old files kept. The state directory, `C:\ProgramData\Faro`, is readable by SYSTEM and Administrators only.
- **Commands.** `install-service` and `uninstall-service` are for development and need an elevated shell. `run-service` is the entry point the SCM starts; from a console it runs in the foreground.

```powershell
faro-service run                              # foreground
faro-service run-service                      # the SCM entry point; from a console, foreground
faro-service install-service                  # dev, elevated
faro-service uninstall-service                # dev, elevated
faro-service approve-enroll --request <hex>   # the UAC helper
faro-agent run
faro-agent open-url <link>
```

- **Probes.** `cargo run -p faro-platform-windows --example <name>` runs `capture_probe`, `browser_probe`, `hidden_window_probe`, `sessions_probe` or `session_ui`.
- **Capture cost.** Spike results on one 2400×1600 monitor: DXGI takes about 17 ms, and under 16 ms of CPU, per warm capture; the first capture takes about 400 ms. The D3D driver adds about 70–80 MiB of working set (GDI alone adds about 27 MiB), which is significant against the 150 MB budget in ARCHITECTURE.md §3.4.

## The Windows installer

`installers/windows/build-msi.ps1` builds a per-machine x64 MSI (WiX 5.0.2: `dotnet tool install --global wix --version 5.0.2`) and `installers/windows/check-msi.ps1` checks one. CI's `windows-msi` job builds the unsigned development MSI on every pull request, checks it, and keeps it for 14 days as `faro-dev-msi-<sha>`; in an elevated session `check-msi.ps1` also installs it, checks the service, its DACL, the `faro://` handler and the state directory's ACL, uninstalls it and checks nothing is left (the runner's account must be an administrator for that part; otherwise the static checks run and the install is skipped with a message). Everything about the package, including what it assumes of `faro-service` and `faro-agent`, is in [installers/windows/README.md](../installers/windows/README.md).

```powershell
installers\windows\build-msi.ps1 -Dev -NoOnnx           # unsigned, without the image classifier
installers\windows\build-msi.ps1 -Dev -ModelDir <dir>   # with it; <dir> is the macOS build's model output
installers\windows\check-msi.ps1 target\msi\Faro-*-dev-x64.msi
```

- **The image model** ships in release MSIs; the release job builds them with the macOS job's model (`-ModelDir`). CI has no model build, so its per-PR MSI is `-NoOnnx`, but the Windows `test` job lints and tests the classifier with `installers/windows/test-onnx.ps1`, which links Microsoft's `onnxruntime.dll` and copies it next to each test binary: Windows' own older copy in `System32` would otherwise load first and fail with "Failed to initialize ORT API". The installed service isn't affected, since the MSI puts the DLL in its own directory.

- **Signing** is behind `installers/windows/sign.ps1`, chosen by the Actions variable `FARO_WINDOWS_SIGNING`: `signpath` (SignPath Foundation) or `trusted-signing` (Azure Trusted Signing); the variables each needs are in the script's help. A release also needs `FARO_WINDOWS_SIGNER` (the signer requirement compiled into the service; see the README) and `release/update-root.json`. With no provider, `release.yml`'s `windows-msi` job warns "UNSIGNED BUILD" and a real release has no Windows package; a dry run builds the unsigned `-Dev` MSI. No signing provider is chosen yet.
- **Updates.** The service installs the MSI with `msiexec`, started detached so it outlives the service the MSI stops. Before installing, `crates/faro-service/src/update/msi.rs` checks the Authenticode signer, Faro's UpgradeCode and the version inside the MSI. `release/build-layout.sh` lists the MSI as the target `client/windows/Faro-<version>-x64.msi` (`client:windows:x86_64:10.0.19045`).
- **Runner.** The `windows-msi` job runs on `windows-2025`, an elevated, throwaway VM, so it sets `FARO_CHECK_MSI_INSTALL=1` and the install half always runs. It does not run for pull requests from forks. On your own machine, leave `FARO_CHECK_MSI_INSTALL` unset unless it is a disposable test machine.

## Testing the whole flag path

To see a flag go all the way through (the service flags a frame, the encrypted event reaches the instance, the ally's feed shows it with a blurred thumbnail, the email arrives), the model has to rate a screen at least `medium`. OpenNSFW rates an ordinary swimwear photo about 0.06–0.15, and the default `explicit_medium` is 0.60. So a development build can lower the thresholds in `service.toml`:

```toml
[dev_thresholds]
explicit_high = 0.5     # default 0.85
explicit_medium = 0.05  # default 0.60
any_low = 0.03          # default 0.40
```

- **Development builds only.** Only a `faro-service` built with the `dev` feature (a `--dev` package, or `cargo run -p faro-service --features dev`) acts on it. At start it logs a `DEVELOPMENT THRESHOLDS` warning with the values, and `faro-service status` prints `Thresholds: LOWERED FOR TESTING (…)`. Flags themselves aren't marked: the event format has no field for it, so check `status` before trusting a flag on a test machine.
- **A release build ignores it.** It still parses the section, so a leftover one doesn't stop the service, but it lowers nothing, logs that it ignores it and says so in `status`. The decision is fixed at compile time (`thresholds::BUILD_ALLOWS_DEV_THRESHOLDS`), and the code that applies the values checks the `dev` feature again. `a_release_build_never_lowers_the_thresholds` tests this in every workspace run, `a_dev_build_lowers_the_thresholds` in CI's macOS job with `--features dev`, and `check-pkg.sh` runs the packaged service's `status` with the section: a release package must ignore it, a `--dev` one must apply it.
- **Lower only.** Each value must be above 0 and at most its default, and the result must keep `any_low <= explicit_medium <= explicit_high`, or a dev service refuses the file. Unset values keep their defaults. Other thresholds (`suggestive_medium`, the domain rules) aren't settable; OpenNSFW has no suggestive label.
- **Expect noise.** At these values ordinary screens flag too: Yahoo's model gives solid grey 0.20 and solid black 0.07. Leave the section in only for the test, then remove it and restart the service.

**A recipe,** on a test Mac (never one you monitor anyone on):

1. Run a test instance, for example `cargo run -p faro-server -- serve --dev` on the same Mac (the service accepts `http://` for localhost only). Without SMTP settings, `--dev` prints every email in its terminal.
2. Install a `--dev` package (CI's `faro-dev-pkg-universal-<sha>` artifact, or `installers/macos/build-pkg.sh --dev`).
3. In the web app: set up a member key, invite a test ally (a second email address; with `--dev` the invitation is printed), accept it in another browser profile and approve the ally on **Allies**. Then enroll the Mac (**Computers**, **Open in Faro**) and approve it.
4. Add the section above to `/Library/Application Support/Faro/service.toml` (root-owned, not group- or world-writable), restart the service with `sudo launchctl kickstart -k system/org.faro.service`, and check `sudo /Library/Faro/bin/faro-service status` shows `LOWERED FOR TESTING`.
5. Open an ordinary swimwear photo full screen (Preview, View → Enter Full Screen) and leave it up for a few capture intervals.
6. Check:
   - the service log (`/Library/Logs/Faro/faro-service.log`) has the `DEVELOPMENT THRESHOLDS` warning and then a `medium` flag, with no classification errors;
   - the member's **Activity** and the ally's **Supporting** feed show the flag, with an `image:explicit` reason and a blurred thumbnail that shows no detail;
   - the ally's alert email arrived (`medium` is `urgent` by default), with no image in it;
   - after removing the section and restarting, the same photo is no longer flagged.

## Third-party notices

Most licences of the software Faro is built from (MIT, Apache-2.0, BSD, ISC, Zlib…) ask for their copyright and licence text to travel with copies. The notices are generated from the lockfiles when a component is built, never checked in, one file per component:

| Component | File | Made by | Lists |
|---|---|---|---|
| macOS package | `/Library/Faro/notices/third-party.txt` | `release/notices/third-party.sh macos`, from `build-pkg.sh` | the crates in `faro-service` (with `onnx`) and `faro-agent`, for the two macOS targets |
| `faro-server` image | `/usr/share/faro/notices/third-party.txt` | `release/notices/third-party.sh server`, in the Dockerfile's `notices` stage | the crates in `faro-server`, for the two Linux targets |
| `faro-server` binaries | `faro-server-<version>-linux-<arch>-third-party.txt`, next to each binary in the GitHub Release | the same file, copied out of the image by `release.yml` | |
| iOS app | `third-party.txt` and `domains.txt` in the app bundle, shown on the Licences screen | `apps/ios/build-notices.sh`: `release/notices/third-party.sh ios`, and the domain list's notice | the crates in `faro-mobile`, for the two iOS targets |
| Web app | `/third-party-licenses.txt`, shown at `/licenses` (footer, `/privacy`); in the image also as `/usr/share/faro/notices/third-party-web.txt` | `npm run build` (`web/scripts/third-party.ts`) | the npm packages whose code is in the browser bundle |

- **Rust.** `third-party.sh` runs `cargo-about`, pinned in the script (`CARGO_ABOUT_VERSION`, 0.9.3), with `--locked` and the template `release/notices/about.hbs`. Its config is written on the fly: the accepted licences are `deny.toml`'s `[licenses] allow` list, so there is only one allowlist. Build and dev dependencies are left out. Each licence is printed once with the crates that use it. For a crate whose package lacks its licence file, `cargo-about` fetches the file from the crate's repository at the packaged commit, so a first run needs network access. Faro's own crates appear under Apache-2.0.
- **npm.** A Vite plugin in the client build walks the bundle's chunks, maps each module under `node_modules` to its package and writes the package's name, version, `license` and licence files (`LICENSE*`, `LICENCE*`, `COPYING*`, `NOTICE*`). Build tools that don't end up in the bundle (Vite, TypeScript, Prettier) aren't listed. The `license` must be an SPDX expression satisfiable with `deny.toml`'s allowlist.
- **Failing.** A crate or package whose licence can't be read, has no licence text, or isn't on the allowlist fails the build: `third-party.sh` (`cargo about --fail`) and `npm run build`. CI runs both on every pull request (the `deny` and `web` jobs). To accept a new licence, add it to `deny.toml`; it applies to both.
- **Checks.** `check-pkg.sh` fails if the package's `third-party.txt` is missing or lacks either program's section; `FARO_REQUIRE_WEB=1` (release builds) fails if the bundle has no `third-party-licenses.txt` or `/licenses` page.
- **Other notices.** The model's, the domain list's (`domains.txt`), ONNX Runtime's and installed update artifacts' notices are separate files in the same directory (see [The macOS installer](#the-macos-installer)). Add a new component's notices as a file of its own next to these.

## Models and blocklists on the update channel

`crates/faro-service/src/update/artifacts.rs`, PROTOCOL.md §8.1 and §8.2. After each client update check, the service checks the same mirror, with the same trust state, for `model` and `blocklist` targets.

- **What is installed.** The newest target of each kind in the instance's channel that this client may install (`min_client`), if its version is above the packaged copy's, above the one installed before, and not below the highest ever installed. Models only if the build has ONNX Runtime (`--features onnx`, `model::default_runtime`).
- **Where.** `artifacts/model/<blake3>/` and `artifacts/blocklist/<blake3>/` in the state directory (`/Library/Application Support/Faro` on macOS, root only), next to the packaged copy in `/Library/Faro`, which is never changed. `update-artifacts.json` there records what is in use, the highest version ever installed, and rejected bundles. Downloads go to `artifacts/downloads/` and are removed after the install.
- **Checks.** The same as for the packaged copy (`load_model`, `load_domains`), plus: the manifest's version is the target's, and a model has a label the default policy reads as explicit. A bundle that fails them is recorded and never downloaded again; nothing else changes.
- **The switch.** The update task puts the new classifier or domain list in `Swaps`; the core takes it on its next tick or capture and calls `Detector::set_classifier` / `set_domains`. `ServiceStatus::model` and `blocklist` say what is in use, and the status report's `detection` says where it came from ([The service status](#the-service-status)). No frame is written or kept: the model is built from its files.
- **At start.** The installed copy is used if it is newer than the packaged one and its manifest still has the recorded BLAKE3 and passes the checks. One that no longer matches is reported as an urgent `integrity_failure` (`image model update (changed)`, `domain list update (changed)`) and removed; the next check installs it again.
- **Notices.** Each installed artifact's attribution and licence texts go to `update-model.txt` and `update-blocklist.txt` next to the packaged notices (`/Library/Faro/notices` for the packaged service; `notices/` in the state directory for any other build). They are removed when the artifact is no longer in use.
- **Publishing.** `release/build-layout.sh --data model=MANIFEST --data blocklist=MANIFEST` checks the file against its manifest (and that a domain list has no unapproved source), joins the two with `faro-release pack-data`, and lists the bundle under the manifest's version as `<kind>/any/<name>-<version>-<channel>.data`. `--data model:1.2.0=...` sets `min_client`. `release.yml` does this for the packaged model and the domain list in every release; a version already listed with the same bytes is simply listed again.

## The service status

`sudo /Library/Faro/bin/faro-service status` shows the enrollment and the outbox (read from the state directory) and what the running service is doing. `--json` prints the same data (`faro_service::status_view::StatusView`). It needs no network access, and on macOS no `launchctl debug`.

- **Where it comes from.** The service keeps a `ServiceStatus` (`crates/faro-service/src/runtime/status.rs`) up to date and writes it as a `faro_ipc::status::StatusReport` to `status.json` in the state directory: about a second after a change, and at least every 30 s (`STATUS_REFRESH_SECS`). The file is 0600, like every state file. `status` reads it with `runtime::status::read_status_file`, and calls the service not running when the report is older than three refresh periods, its process is gone, or it says `stopped` (the last report an orderly stop writes).
- **The report** (`crates/faro-ipc/src/status.rs`, where every field is documented). It lives in `faro-ipc` so that the agent can show part of it without depending on the service: agents never get the report itself, only their session's `MemberStatus` ([The status menu](#the-status-menu)). It serializes with JSON and postcard, its fields are append-only, and readers accept missing and unknown fields.

| Section | What it says |
|---|---|
| top level | `schema`, the service's version and pid, when it started, when the report was made, the `phase`, `log_file`, the log it writes (`pkg_layout::SERVICE_LOG` for the packaged service, `null` when it logs to stderr), and the enrolled instance's `instance_name` and `instance_url` |
| `sessions` | each interactive session: account, at the screen, agent connected and its version, capture target, unmonitored (an `unmonitored_user_session` was raised) |
| `capture` | `state` (`active`, `idle`, `locked`, `asleep`, `paused`, `login_window`, `no_agent`, `not_started`, `stopped`), the target's account, the last attempt and success, failures in a row and the last failure's reason (`permission denied: screen_recording`), and with `paused`, when the member's pause ends (`paused_until_ms`) |
| `permissions` | Screen Recording and Accessibility, as the capture target's agent last reported them, and for which account |
| `detection` | the image model and the domain list in use, each `packaged` or `update_channel`, or why there is none (`image model (missing)`, `no domain list installed`), and `thresholds`: `default`, `lowered` (with the values) or `ignored`, what the service did with `[dev_thresholds]` at start. `status` prints its `Thresholds:` line from the config file as it is now, and `--json` has that as the top-level `thresholds` |
| `updates` | whether updates are on (or why not), the channel the instance named, the last check's time and result |
| `health` | the last heartbeat state, counters since start, the newest event written and acknowledged, recipient and identity warnings, the last error, when the instance last answered a heartbeat (`last_contact_ms`) and since when it can't be reached (`unreachable_since_ms`: a network error or a 5xx; any other answer clears it) |

- **No content.** A report never holds a URL, a window title, an app name or anything from a frame: only states, times, counters, account short names, versions and short diagnostics (at most 200 characters).
- **Times** are the service clock's wall milliseconds. `status` shows them relative to now (`4 min ago`).

## The status menu

The agent's menu-bar menu says what Faro is doing, for the person at the screen (issue #89). Under "This computer is monitored by Faro" it shows **Status: …**, and clicking that explains it and what to do. When something fixes the problem, an item below opens it. Then **Open Faro** (the instance's web app), **Show the monitoring notice…**, **Enroll this computer…**, **Report a problem…** (how to make a report with `faro-service diagnose`, with a button that copies the command; see [Problem reports](#problem-reports)) and **About Faro…** (the agent's and the service's versions, the instance, and a button that opens the third-party notices in `/Library/Faro/notices`). Nothing on the menu stops monitoring, pauses it or hides anything; pausing stays in the existing flow that allies are told about.

On Windows the same menu is in the agent's tray icon; the tray UI is in `faro-platform-windows`.

```text
faro-service (root)                         agent (user session)
  ServiceStatus ─ feed_loop ─▶ IpcFrameSource
                               MemberStatus::for_session(report, session)
                               ServiceMsg::Status ───────────▶ Seen::Connected
  enroll socket (before the agent socket exists)
                               EnrollRequest::Status ◀─────── on every failed connect
                               EnrollResponse::Status ──────▶ Seen::NotConnected
                                                              status_menu::status_menu → AppKit
```

- **Connected.** The service hands its report to the IPC source (`runtime::status::feed_loop`, at most about once a second), and the source sends each agent `ServiceMsg::Status` after `Welcome` and whenever that agent's view changes. The view is `faro_ipc::MemberStatus::for_session` (`crates/faro-ipc/src/status.rs`): the phase, the instance's name and address, the capture state when it concerns this session (always for `not_started`, `paused`, `asleep` and `stopped`; the rest only while this session is the capture target), the pause's end, this account's Screen Recording and Accessibility while it is the target, its failed captures in a row, whether the instance can't be reached, an identity mismatch, and a failed update check. Never another account's name, session or permissions, and nothing from the screen. A full agent queue skips a status instead of counting against the agent.
- **Not connected.** The service only binds the agent's socket once the computer is enrolled and approved. Until then, and whenever the connection drops, the agent asks the enroll socket's `Status` (which changes nothing) after each failed connect, so with the reconnect backoff (settling at every 30 s): "Not enrolled", "Waiting for approval in the web app" (with an item that opens the web app's Computers page), "Connecting to the Faro service…" (approved, but no connection yet), or "The Faro service isn't running". The service logs these `Status` requests at `debug` only.
- **Read only.** `Status` is service-to-agent only; there is no agent message that asks for it or changes anything, and the agent never acts on it beyond showing it. The words are pure functions in `faro_agent::status_menu`, tested there; the menu is `faro_platform_macos::ui` (`UiHandle::set_status`). `crates/faro-agent/tests/agent_loop.rs` (`the_status_menu_follows_the_service`) drives the loop against a fake service and enroll socket, and `source::ipc`'s `each_agent_gets_its_own_status_view` checks the per-session views on the real source.
- **What it shows, first match wins.** Stopping; the instance's identity changed ("Faro stopped sending to …"); Screen Recording off (with **Open Screen Recording Settings…**); 3 or more failed captures in a row ("Faro can't take screenshots"); "Can't reach *instance*"; "Paused until 15:30" (24-hour local time, with the day if it isn't today); "Starting…"; otherwise "Monitoring", with a hint when Accessibility is off (and **Open Accessibility Settings…**) or the last update check failed.
- **By hand**, on a test Mac with a `--dev` package: before enrolling, the menu says "Not enrolled"; after enrolling, "Waiting for approval in the web app", and its item opens the Computers page; after approving, "Monitoring" within a few seconds. Turn Screen Recording off for Faro Agent and check "Screen Recording is off" and its item; take the Mac offline and check "Can't reach …" after the next heartbeat; check **Open Faro** and **About Faro…** (and its notices button). With two accounts logged in, the menu in the background account never names the other one.

## Problem reports

`sudo /Library/Faro/bin/faro-service diagnose` makes a report a member can send when Faro isn't working (`crates/faro-service/src/diagnose`). The member guide's [Reporting a problem](MEMBER-GUIDE.md#reporting-a-problem) is the member's side of it.

- **What the member sees.** It collects everything first and writes nothing. It prints the path the zip will have and each file in it with its size and what it is, says what was taken out, and asks: `y` writes it, `s` prints every file in full and asks again, anything else (or end of input) writes nothing. Without a terminal on stdin it writes nothing unless `--yes` is given. `--print` prints everything and writes nothing.
- **Where it lands.** `~/Desktop/faro-report-YYYYMMDD-HHMMSSZ.zip` (the time is UTC) on the Desktop of the account that ran `sudo` (`SUDO_UID`), or, run as root without `sudo`, of the account at the screen (the owner of `/dev/console`). The file is new (never written over an existing one or through a link), 0600, and owned by that account. `--output DIR` writes it to `DIR` instead. A Desktop that is a link or belongs to someone else is refused, with a pointer to `--output`. The zip is made with `/usr/bin/ditto -c -k` in a private temporary folder and copied out.
- **What is in it.** One folder, `faro-report-YYYYMMDD-HHMMSSZ/`, of plain-text files:

| File | What it holds |
|---|---|
| `README.txt` | what the report is, when it was made, what was taken out |
| `status.txt`, `status.json` | `faro-service status` and `status --json` ([The service status](#the-service-status)) |
| `permissions.txt` | Screen Recording and Accessibility, as the capture target's agent last reported them |
| `system.txt` | the versions of this `faro-service`, the running service, each connected agent and `Faro Agent.app`; `sw_vers`; the hardware model, architecture, processor, memory, Rosetta and boot time (`sysctl`); `df -h / /Library` |
| `launchd.txt` | `launchctl print` of `system/org.faro.service`, `system/org.faro.update` and `gui/<uid>/org.faro.agent`, cut to the job's state (`state`, `pid`, `runs`, `last exit code`, …, `LAUNCHD_KEYS`; never its environment), and whether any Faro job is disabled (`launchctl print-disabled`) |
| `package.txt` | `pkgutil --pkg-info org.faro.pkg` (the receipt), `codesign -dv` of `faro-service` and `Faro Agent.app`, and the two launchd plists |
| `files.txt` | the entries of the state directory, the socket directory (`/var/run/faro`), both log directories, `/Library/Faro`, its `bin`, the model and the domain list, and the config file: type, mode, owner, size and name, never contents |
| `config.txt` | `service.toml` as the service reads it (with defaults filled in) |
| `logs/faro-service.log` | the last `--lines` lines (2000) of `pkg_layout::SERVICE_LOG`, reading back into `.1` … `.3` when the current file is shorter |
| `logs/faro-agent.log` | the same from that account's `~/Library/Logs/Faro/faro-agent.log`, and from no other account's |
| `logs/update-install.log` | the last 300 lines of the update job's output, if there is one |

- **What is never in it.** Nothing reads the device key, the enrollment or endorsement records, the outbox (events, reports, thumbnails), `settings.json` or any other state file except `status.json` and `update-install.log`. No frame, screenshot or thumbnail is involved. Other accounts' agent logs are left out.
- **The redaction step** (`diagnose::Redactor`, tested in `redact.rs` and against `tracing_subscriber`'s own output in `diagnose/tests.rs`). Every file passes through it when it is made (`ReportFile` has no other constructor), so what the member is shown is exactly what is written. It replaces:
  - URLs with `[url]`, except the instance's own, which keeps its path but loses its query (`?[redacted]`); a URL with a user name or password always goes;
  - email addresses with `[email]`;
  - host names other than the instance's with `[host]` (anything shaped like `name.tld`: the last label all letters; Faro's `org.faro.*` names, file names with the extensions Faro uses and version numbers stay), and IPv4 addresses other than loopback with `[ip]`;
  - the value of any field whose name has a word from `PRIVATE_LOG_WORDS` or `EXTRA_PRIVATE_WORDS` (`title`, `app`, `url`, `body`, `name`, `token`, …) with `[redacted]`, both as `name=value` and inside a printed value (`Foreground { title: Some("…") }`). Window titles can't be recognized by their shape, so this is how they go, and why `debug!` calls must name private fields for what they are (`log_privacy.rs` checks it);
  - other libraries' `debug` and `trace` lines (a target not starting with `faro`), with the lines that continue them, with `[another library's debug output, left out]`, keeping only the time, level and target.

  At the default `info` level the logs hold none of this to begin with; the redaction is what keeps a report safe when someone turned `debug` on. It is a filter, not a proof: a new kind of private value that matches none of these rules would get through, so keep private values out of `info` and in named fields at `debug`.
- **Reading as root for an account.** The agent log is in the member's home, which they control. It is opened with `O_NOFOLLOW` and read only if it is a regular file the account owns, so a link from `~/Library/Logs/Faro/faro-agent.log` to the device key reads nothing; the service's log must be owned by root. At most the last 8 MiB of each file is read.
- **From the menu.** **Report a problem…** in the agent's menu ([The status menu](#the-status-menu)) only explains how to run `diagnose` in Terminal and offers to copy the command; it sends the service nothing. Not there yet: having the service collect the report for the agent and reveal the file, which needs an IPC request (and then the service should hand the report to the agent rather than write into the member's home itself).
- On Windows, `diagnose` runs from an administrator terminal as `& "C:\Program Files\Faro\faro-service.exe" diagnose`, and the report is saved to the Desktop as `faro-report-….zip` (or to `--output <folder>`). It holds the same kind of content as on macOS, with private details removed: status, versions, the service state, sessions and agents, and recent service and agent logs. The tray menu's **Report a problem…** copies the command. The file list above is for macOS.

## Releasing

A release is built, signed and published by `.github/workflows/release.yml`, from a `vX.Y.Z` or `vX.Y.Z-pre` tag on `main`. `.github/workflows/update-timestamp.yml` keeps the published metadata fresh after that. The scripts both use are in `release/`, and the signing tool is `faro-release` (`crates/faro-update/examples/faro-release.rs`). The keys come from the key ceremony ([KEY-CEREMONY.md](KEY-CEREMONY.md)). Root keys never touch CI.

### Where a release goes

- **The update layout** (PROTOCOL.md §8.1) goes to `https://updates.faro-project.org/`, as plain files: `timestamp.json`, `targets.json`, `roots/<n>.json` and `targets/<name>`. Instances mirror it from there (`updates.upstream`). It is served by GitHub Pages from the public repository `faro-project/updates`. `release/publish-layout.sh` is the only code that knows this: to move the layout, change that script.
- **The GitHub Release** (`vX.Y.Z` in this repository) is for people: release notes, the `.pkg`, the `faro-server` binaries and `SHA256SUMS`. While this repository is private, only its collaborators can download from it.
- **The container image** `ghcr.io/faro-project/faro-server` gets the tags `X.Y.Z`, plus `X.Y` and `latest` for a release that isn't a pre-release. `container.yml` no longer runs on tags.

Every publish only adds files. Older releases stay listed in `targets.json` (so `stable-1` has something to select) and their artifacts stay served. A published artifact name never gets new bytes.

#### Why GitHub Pages on a separate public repository

A GitHub Release is a flat list of files, so it can't serve the layout's paths. The options:

| | Pages on this repository | Public `faro-project/updates` with Pages (chosen) | Object storage behind a CDN (Cloudflare R2) |
|---|---|---|---|
| Works now | No: Pages on a private repository needs a paid plan | Yes | Yes |
| New accounts | None | None | Cloudflare, and the domain's DNS moves to it |
| Largest file | 100 MB (Git) | 100 MB (Git) | 5 GB |
| Total size | 1 GB site | 1 GB site | 10 GB free, then paid per GB |
| Traffic | about 100 GB a month (soft limit) | about 100 GB a month (soft limit) | no traffic fees |
| Credential in CI | | a deploy key for that one repository | an API token for that one bucket |

The numbers that matter: the universal `.pkg` with ONNX Runtime and the OpenNSFW model (#45: about 6 MB int8, 23 MB fp32) should be well under 100 MB, and each release adds it plus two `faro-server` binaries. An instance downloads each client release once, whatever its number of members, so 100 instances take about 100 times one package per release. `publish-layout.sh` refuses a file over 100 MB and warns above 50 MB. The site will fill 1 GB after a few dozen releases: then old releases must be pruned (not automated yet), or the layout moves to R2.

Pages caches files for about 10 minutes. That is fine: the timestamp is re-signed every 8 hours and lasts 24.

### What to set up before the first real release

1. **The keys** (KEY-CEREMONY.md). Commit root 1 as `release/update-root.json`, and also as `release/roots/1.json` (never published; it lets a release carry `targets.json` forward after the targets or timestamp key is replaced). Add the Actions secrets `FARO_TARGETS_KEY` and `FARO_TIMESTAMP_KEY`.
2. **The publishing location.**
   - Create the public repository `faro-project/updates`, empty. In its Settings → Pages, serve the `main` branch, root folder. Set the custom domain `updates.faro-project.org` and tick "Enforce HTTPS" once the certificate is ready. The first publish writes `CNAME` and `.nojekyll`.
   - DNS: a `CNAME` record `updates.faro-project.org` → `faro-project.github.io`. Verify `faro-project.org` for the org (org Settings → Pages), so nobody else can claim the name.
   - A deploy key: `ssh-keygen -t ed25519 -N '' -C faro-release -f updates-deploy`. Add `updates-deploy.pub` to `faro-project/updates` as a deploy key **with write access**, and `updates-deploy` as the Actions secret `FARO_UPDATES_DEPLOY_KEY` of this repository. Delete both files.
3. **Apple signing.** **Not working yet on GitHub's runners:** `macos-pkg` expects the certificates and the notary profile to already be in the runner's keychain, which was true of the old self-hosted Mac but not of a fresh `macos-15` VM. Before a real release, the job needs a step that imports them from secrets into a temporary keychain (and `notarytool store-credentials` from an App Store Connect API key). What it needs:
   - The Developer ID Application and Developer ID Installer certificates in a keychain, and a notary profile: `xcrun notarytool store-credentials faro-notary --apple-id … --team-id … --password <app-specific password>`.
   - The Actions variables (not secrets: they are names) `FARO_SIGN_IDENTITY` (`Developer ID Application: … (TEAMID)`), `FARO_INSTALLER_IDENTITY` (`Developer ID Installer: … (TEAMID)`), `FARO_TEAM_ID` and `FARO_NOTARY_PROFILE` (`faro-notary`).
   - The old self-hosted setup, for reference: the certificates in their own keychain, locked except while a release builds. Create it with `security create-keychain -p <password> faro-release.keychain-db`, import both certificates into it, allow `codesign` to use them without a prompt (`security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k <password> faro-release.keychain-db`), add it to the search list (`security list-keychains -d user -s login.keychain-db faro-release.keychain-db`) and lock it (`security lock-keychain faro-release.keychain-db`). Then set the variable `FARO_MACOS_KEYCHAIN` to its path and the secret `FARO_MACOS_KEYCHAIN_PASSWORD` to its password.
4. **Runners.** Every job runs on GitHub's runners ([CI runners](#ci-runners)), and the jobs that read a signing key on `ubuntu-24.04` (KEY-CEREMONY.md §4.2). **None can start while the org's Actions spending limit is reached**, so a release and the timestamp job are blocked until it is raised. The signing jobs build `faro-release` with a fresh `CARGO_HOME` and delete the key files.
5. **Tags.** Add a tag ruleset so only you can create `v*` tags: a tag push is what starts a release.
6. **Later, when the plan allows environments:** move the secrets into environments and set `FARO_RELEASE_ENVIRONMENT` (for example `release`, limited to `v*` tags and `main`, with your approval) and `FARO_TIMESTAMP_ENVIRONMENT` (for example `timestamp`, limited to `main`). The jobs that read each key then run in its environment. `main` must be allowed for the targets key, because the scheduled job renews `targets.json` from it (about once every three weeks).

| Secret | What it is | Read by |
|---|---|---|
| `FARO_TARGETS_KEY` | the targets key file (`faro-release keygen`) | `layout` in `release.yml`; `renew-targets` in `update-timestamp.yml` |
| `FARO_TIMESTAMP_KEY` | the timestamp key file | the same, and `timestamp` in `update-timestamp.yml` |
| `FARO_UPDATES_DEPLOY_KEY` | SSH key with write access to `faro-project/updates` | every job that publishes the layout |
| `FARO_MACOS_KEYCHAIN_PASSWORD` | (optional) the signing keychain's password | `macos-pkg` |

| Variable | Default |
|---|---|
| `FARO_SIGN_IDENTITY`, `FARO_INSTALLER_IDENTITY`, `FARO_TEAM_ID`, `FARO_NOTARY_PROFILE` | none: a real release fails without them |
| `FARO_WINDOWS_SIGNING`, `FARO_WINDOWS_SIGNER` | none: a real release builds no Windows package without them ([The Windows installer](#the-windows-installer)) |
| `FARO_MACOS_KEYCHAIN` | none (use the default keychains) |
| `FARO_SIGNING_RUNNER` | `"ubuntu-24.04"` |
| `FARO_LINUX_X64_RUNNER` | `"ubuntu-24.04"` ([CI runners](#ci-runners)) |
| `FARO_UPDATES_URL` | `https://updates.faro-project.org/` |
| `FARO_RELEASE_ENVIRONMENT`, `FARO_TIMESTAMP_ENVIRONMENT` | none |

A dry run needs none of this.

### A dry run

```sh
gh workflow run release.yml --ref main -f dry_run=true
```

It builds everything from `main`, but:

- the package is the unsigned development package (`--dev`, with a warning in the run): never install it on anyone;
- it signs with throwaway keys made in the job, never the real ones, and as if nothing were published yet;
- it publishes no layout and no image. It makes a **draft** GitHub Release named `dry-run-<version>-<run>` with the artifacts, `SHA256SUMS` and `update-layout.tar.gz` (the verified layout and its throwaway root, `dry-run-root.json`). It deletes the previous dry-run draft. Never publish it.

While GitHub's runners can't start, the amd64 build fails at once and the dry run goes on without that binary: the run passes, `server (x86_64)` shows as failed, `layout` warns, and the draft's notes say which binary is missing. A real release needs every architecture.

To try changes to `release.yml` or `release/` before merging them, run a dry run of their branch: `gh workflow run release.yml --ref <branch> -f dry_run=true`. Only a real release must come from a tag on `main`.

### Cutting a release

1. Set the version in the root `Cargo.toml` (the workspace version and the internal dependencies, see [Dependency notes](#dependency-notes)), and merge it to `main`.
2. Run a dry run of `main` and look at the draft.
3. Tag the commit on `main` and push the tag:

   ```sh
   git tag -s v0.1.0-beta.1 -m "Faro 0.1.0-beta.1" <commit>
   git push origin v0.1.0-beta.1
   ```

The workflow then:

1. **prepare:** checks that the tag is `v` plus the workspace version and that the commit is on `main`. A pre-release (`0.1.0-beta.1`) goes to the `beta` channel only. A release (`0.1.0`) goes to `stable` and `beta`.
2. **macos-pkg:** builds the universal `.pkg` with `FARO_UPDATE_ROOT=release/update-root.json`, signs and notarizes it, and checks it (`check-pkg.sh`, `pkgutil --check-signature`, `stapler validate`, `spctl`). It fails if an identity is missing: an unsigned package is never published. It also keeps the image model the package ships (`data-model`), for the update channel, and the SHA-256 of the domain list manifest it ships.
3. **blocklist:** fetches the approved, pinned sources and compiles the domain list (`data-blocklist`). `layout` fails unless its manifest is the one in the package.
4. **server:** builds the container image natively on each architecture, pushes it by digest only, and takes the `faro-server` binary out of it. Both architectures are required.
5. **layout:** fetches what is published, builds `targets.json` from it plus this release's artifacts (`release/build-layout.sh`; the model and the domain list as data bundles under their own versions), signs it and a timestamp, and checks the whole set with `faro-release verify` the way an up-to-date client would see it. Nothing is published before this passes.
6. **publish-layout:** checks the layout again against what is published at that moment, publishes it (`release/publish-layout.sh push`), then waits until `https://updates.faro-project.org/` serves it and verifies what is served (`release/check-served.sh`).
7. **publish:** tags the image, then creates the GitHub Release. The model and the domain list are not among its downloads: they are only on the update channel.

If a job fails, use **Re-run failed jobs**, which keeps the artifacts already built. A full re-run after the layout was published fails on purpose: the new build has different bytes, and a published name never changes. Then cut the next version instead.

**Channels.** An instance chooses its channel (`stable` by default). Until there is a `0.1.0`, only `beta` has anything, so pilot instances must choose `beta` to get `0.1.0-beta.1`.

### Re-signing (update-timestamp.yml)

- **Every 8 hours** it re-signs `timestamp.json`, which expires 24 hours after it is signed. It reads only `FARO_TIMESTAMP_KEY`.
- **When `targets.json` has under 21 days left** (it lasts 42), or when `release/update-root.json` names a targets key that didn't sign it, the `renew-targets` job re-signs `targets.json` with the same entries instead, and a timestamp for it.
- Either run also publishes any root added to `release/roots/`.

Before the first release it finds nothing published and stops. Run it by hand with `gh workflow run update-timestamp.yml`.

#### If the timestamp job fails

It opens an issue, "Update metadata re-signing failed" (or comments on the open one), and GitHub emails you about the failed run. A timestamp is good for 24 hours from the last good run, so there are usually two more tries before it expires.

1. Open the run linked in the issue and find the failed step.
   - **The job didn't start:** GitHub's runners are blocked (spending limit). Raise the limit, or set `FARO_SIGNING_RUNNER`.
   - **No timestamp key / no deploy key:** a secret is missing or was replaced. Set it again (KEY-CEREMONY.md §4.3).
   - **verify failed:** read its error. A timestamp version that went backwards means a runner clock is wrong. A threshold error right after a root rotation means the secret still holds the old key.
   - **check-served timed out:** the files were pushed, but the site doesn't serve them. Look at the Pages build in `faro-project/updates` and at the DNS record.
2. Fix it, run `gh workflow run update-timestamp.yml`, and close the issue once a run passes.

If the timestamp does expire, nothing breaks for good: instances and computers keep running, they just take no update until the next good run.

### Instances

An instance uses the published layout with (SELF-HOSTING.md, "Updates for members' computers"):

```sh
FARO_UPDATES_ROOT=/usr/share/faro/update-root.json   # in the official image
FARO_UPDATES_UPSTREAM=https://updates.faro-project.org/
```

The image copies `release/update-root.json` to `/usr/share/faro/update-root.json` once it exists. An instance without the image downloads that file and points `FARO_UPDATES_ROOT` at it.

### Testing the scripts

`release/test-release.sh` runs the scripts end to end with throwaway keys, fake artifacts and a local Git repository standing in for `faro-project/updates`: a first release, re-signing, renewal, a root rotation that replaces the online keys, a second release, and the refusals. CI runs it in the `release-scripts` job. Locally:

```sh
cargo build --release --locked -p faro-update --example faro-release
release/test-release.sh
```

## Enrolling from the agent

Enrolling changes a root service, so the agent can only ask: an administrator approves every enrollment (issue #62).

```text
agent (user session)                       faro-service (root)
  faro://enroll link or menu item
  Preview(link) ──── enroll.<uid>.sock ──▶ parse (link.rs), GET /.well-known/faro
  ◀── name, address, identity key, accounts
  person confirms
  empty AuthorizationRef, external form
  Enroll(link, confirmed identity, auth) ─▶ discover again, same identity?
                                          check the org.faro.enroll rule
                                          AuthorizationCopyRights ─▶ macOS admin dialog
                                          enroll::enroll (the CLI's code)
  ◀── device fingerprint, member key checked?
                                          wait_for_enrollment sees enrollment.json
```

- **The enroll socket** (`faro_service::enroll_server`) is up before the service waits for enrollment and for as long as it runs. A root service binds `enroll.<uid>.sock` next to the agent sockets for each account with a GUI session (owner that account, mode 0600); a non-root development service binds `enroll.sock`. Peers are checked like agents (`source::ipc::peer_policy`): the socket's uid, and the code signature when `ipc.agent_requirement` is set. One request per connection, one enrollment at a time. The messages are `faro_ipc::enroll`, separate from the agent's session protocol.
- **Approval** is Authorization Services (`faro_platform_macos::authorization`), as in Apple's EvenBetterAuthorizationSample: the agent sends the external form of an empty authorization, and the service asks for the right `org.faro.enroll` with `ExtendRights | InteractionAllowed` and a prompt it writes itself, naming the instance it discovered. Faro's rule is `class user, group admin, shared false, timeout 0, allow-root false, authenticate-user true, session-owner false`, so an administrator types their name and password every time. Before every prompt the service reads the rule and accepts only exactly that (`definition_ok`); a root service rewrites it otherwise and reads it back, a non-root service refuses. It also refuses if a more specific `config.*` right for it exists, or if the agent's authorization already carries the right.
- **Testing.** The approver is a trait (`enroll_server::Approver`) so `tests/enroll_gui.rs` can fake the administrator; the binary always uses `SystemApprover`, and nothing (no flag, no setting, not the `dev` feature) swaps it. The `dev` feature only changes who may connect. `authorization.rs` has the no-dialog checks of the real mechanism; the test that writes the rule is `#[ignore]`d (run it as root on a test Mac only). AppKit can't be driven from `cargo test`, so the screens are tested as text (`faro_agent::enroll`) and the flow against a fake service (`crates/faro-agent/tests/enroll_flow.rs`).
- **By hand,** on a test Mac with a `--dev` package installed: create a code on the web app's **Computers** page, click **Open in Faro**, and check the confirm window, the macOS password dialog (its text names the instance), and the result. Then try **Enroll this computer…** from the menu (paste the link, or the address and the code), Cancel at each step, a wrong password, and an already enrolled computer. `security authorizationdb read org.faro.enroll` shows the rule the service wrote.
- **Not covered:** if the agent isn't running when a link is opened, LaunchServices starts a second copy with no arguments, which exits. The member then uses the menu item, or logs out and in. A fake password dialog drawn by another app is outside what Faro can prevent.

**On Windows** the approval is the UAC prompt instead of the macOS dialog. The UAC helper is `faro-service approve-enroll --request <hex>`, and the service checks the approval itself. Cancelling the prompt cancels enrolling. See [The Windows client](#the-windows-client).

## The iOS core

`crates/faro-mobile` is the Rust half of the iOS client (IOS.md §13): Faro's event log, hash chain, outbox, signing, enrollment, heartbeats and domain bundles, behind a Swift interface generated by UniFFI. It reuses the desktop's code rather than copying it: the chain and outbox are `faro-core`'s, and everything that talks to the instance is `faro-client`'s, which `faro-service` uses too. It builds and tests on the host:

```sh
cargo test -p faro-mobile
```

The iOS targets, the XCFramework and the Swift bindings are built by `apps/ios/build-rust.sh` ([The iOS app](#the-ios-app)), which also builds the `uniffi-bindgen` of the same UniFFI version.

- **One object per process.** The app and the packet tunnel each make a `FaroCore` on the app group container. Every method blocks on the core's own Tokio runtime, so Swift calls it from a background queue.
- **One database, several processes.** Everything is in `faro_core`'s `outbox.sqlite3` in that directory, in WAL mode with a 30 second busy timeout, plus two tables of `faro-mobile`'s own (`mobile_state`, `mobile_context`; `faro_mobile::store`). Every chain append is `Outbox::append_exclusive`: one `BEGIN EXCLUSIVE` transaction reads the stored head and recipient checkpoint, seals and signs the event on them, checks it as `commit` does and stores it with the new head. No other process can write in between, so `seq` and `prev_hash` stay strict and an event is always sealed to the current recipients. Nothing about the chain is cached between calls, and no transaction is held across a call (iOS ends a suspended app that holds a lock on a file in a shared container).
- **Keys.** `KeyStore` is a foreign trait the app implements over the Keychain; it holds the device key's seed and the device token. Keys are generated in Rust with `faro-crypto`. Rust loads the key for each call that signs and wipes every copy it makes; the copies UniFFI makes to cross the boundary, and what Swift keeps, are outside its reach. `MemoryKeyStore` is for tests. A locked store (before the first unlock after a reboot) is `FaroError::KeysLocked`: nothing is signed, and nothing is lost.
- **Enrollment** is the desktop's (`faro_client::enroll`): `preview_enrollment` parses the link and shows the instance, `enroll` checks the instance still has the identity the member saw, registers, and pins the member key (checked against the link's `m` when there is one), and `poll_approval` verifies the endorsement and bootstraps the recipient manifest no lower than its anchor. The device enrolls with platform `ios`.
- **Events** are the protocol's types (PROTOCOL.md §3), the iPhone ones included: `record_tamper` (an urgent `tamper` event, such as `screen_time_revoked` or `filter_off`), `record_settings_change` (with the pending-loosening fields), `record_blocked_summary` and `record_shield_summary` (capture-class; a summary names DNS hosts only, never a path, port or URL, and only inside the sealed body), `record_context` (kept for the daily report, never an event), `heartbeat(state)` and `upload_pending()`, which also adopts a newer recipient manifest the member signed.
- **Leave Faro** is `goodbye(deliver_within_secs)` (IOS.md §12): it reaches the instance first (identity and the latest recipient manifest), and if it can't, returns the error with nothing written. Then it marks the phone as leaving in `mobile_state`, writes the urgent `goodbye` and uploads until the instance has it or the time is up (`GoodbyeOutcome::Queued`; calling it again retries and never writes a second one). From the leaving mark on, every other append, `record_context` and `heartbeat` is `FaroError::Left`: anything after a goodbye would tell the instance the phone is back. Delivered, it deletes the device key and token. A phone the instance already retired, or one never approved, has nobody to tell (`AlreadyRetired`, `NotActivated`). `status()` says `leaving` and `goodbye_delivered`, so the app picks up where it was after a relaunch.
- **Who it reports to** is `allies()`: the stored recipient manifest, verified again against the pinned member key, with each ally's id, the name the member signed into it (format 2; `None` for a format 1 manifest, which has no names; sanitized again by `ManifestAlly::display_name`) and the safety code of the member's key and theirs (the code the web app shows next to that ally's name), the instance's name and the manifest's version and signing time. No network.
- **The clock.** `heartbeat` compares the phone's wall clock with the instance's time in the answer, with `faro_core::ClockGuard`'s threshold, and `upload_pending` with the `Date` header offset `faro_client` learned. A skew is one urgent `clock_manipulation`, claimed in `mobile_state` (`clock_skew_reported`) so the app and the tunnel don't both record it, and armed again only by a heartbeat in range. Every client a core makes shares one clock offset (`InstanceClient::with_shared_clock_offset`): each call makes its own client, and without it a phone whose clock is off would sign every call with the wrong time.
- **Summaries, flags and the daily report** (`faro_mobile::reports`, IOS.md §7.5 and §11). `DnsFilter::flush_summaries(core, now)` records each ended counter bucket as a `blocked_summary` once: `record_blocked_summary_once` writes the bucket's start into a ledger (`blocked_reported` in `mobile_state`, an immediate transaction, so two processes can't both win) before it appends, and takes it out again if the append fails, so a locked key store loses nothing, and a crash can lose one bucket but never repeat one. The filter drops a bucket from its counters only after that. `record_shield_totals(shown, closed)` takes the totals of the two shield counter files, swaps the stored baseline for them in one transaction and records the difference as a `shield_summary` covering the time since the last call (a total below the baseline means the file started over, and counts whole). `DnsFilter::flush_bursts(core)` records each burst candidate as a `flag` event, rated `medium`, `burst: true`, with the one reason `dns:adult ×6, 4 hosts, 3 min, screen on` (counts, never hosts), with the header urgency the default policy gives `medium` (urgent). Every one of these also lands in a `mobile_report_log` table on the device, with the tunnel's protection samples (`record_protection_sample`), tamper events and loosenings, and `queue_daily_report(now_ms, utc_offset_secs)` builds the last complete local day from it with `faro_core::ReportBuilder` and `IosReportBuilder` (the report's `ios` section: protection spans, blocked lookups and shield counts per day, loosenings), seals it to the verified recipients and queues it for upload, once per day. The log is kept three days after its day. An iPhone report has no activity timeline, and states Screen Time as unknown (`null`) only when neither the tunnel, the app nor the monitor has read it.
- **Development thresholds** follow the "lower only" rule of [the service's `[dev_thresholds]`](#testing-the-whole-flag-path). `apps/ios/build-rust.sh` with `FARO_DEV=1` builds the core with the `dev` feature; only that core reads `dev_thresholds.json` from the app group, for example `{"min_lookups": 2, "min_domains": 1, "cooldown_secs": 30}`. Each value must be at least 1 and at most its default (6, 3, 600), `min_domains` can't exceed `min_lookups`, and the window isn't settable (shortening it would raise the bar). A release core parses the file and ignores it (`ignored (release build)`), the decision is made at compile time and `burst_thresholds` checks the feature again, and a file that would raise a value is refused whatever the build. The tunnel logs `DEVELOPMENT THRESHOLDS` at start and the status shows `LOWERED FOR TESTING (...)`; flags themselves aren't marked, so check the status before trusting one on a test phone. `faro-dnsfilter` and `faro-mobile` test both builds: `cargo test -p faro-mobile --features dev` as well as the default.
- **The report fixture** `crates/faro-core/tests/data/ios-reports.json` is the iPhone's report and event bodies as the device writes them. A Rust test fails if the code no longer writes it (`FARO_UPDATE_FIXTURES=1 cargo test -p faro-core ios_fixture` rewrites it), and the web app's `ios.test.ts` reads it, so the two sides can't drift.
- **Domain bundles.** `update_domains(root)` verifies the instance mirror's metadata against the root the app passes in, selects the newest `blocklist` target, checks the bundle with `load_domains` and installs it under `domains/<blake3>/`, with the same rules as the service ([Models and blocklists on the update channel](#models-and-blocklists-on-the-update-channel)). `installed_domains` checks it again on each load; one that changed is removed and reported as an urgent `integrity_failure`.
- **The DNS filter.** `DnsFilter` is `faro-dnsfilter`'s `Session` for the packet tunnel ([The DNS filter](#the-dns-filter)). It starts from the packaged domain list, the member's choices (`filter.json` in the app group) and the counters the last run saved, whichever of them can be read: it needs neither the keys nor the database, so it filters before the first unlock. Without a usable list it still blocks the always-blocked names and the member's list, and `status()` says why. `refresh_domains(core)` switches to a newer list installed by `update_domains`, reading it only when its recorded version is newer. `set_upstreams` takes the network's resolvers as the system reports them and leaves out the tunnel's own addresses. `tunnel_network()` gives the tunnel's addresses and routes, so Swift spells none of them.
- **Tests** run the real instance in-process, as faro-service's end-to-end tests do (`crates/faro-mobile/tests/support`). `tests/processes.rs` starts copies of its own test binary as child processes that append to one chain at once with the parent, then verifies the whole chain and uploads it.

## The iOS app

`apps/ios` is the Xcode project for the iPhone client (IOS.md §13). The Rust core is `crates/faro-mobile` ([The iOS core](#the-ios-core)); everything iOS-specific (FamilyControls, ManagedSettings, DeviceActivity, NetworkExtension, the UI) is Swift.

**Tools.** A Mac with Xcode (the full app, not only the Command Line Tools), [XcodeGen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`) and a Rust toolchain that has the iOS targets: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim`. `build-rust.sh` uses plain `cargo` when it has those targets. Otherwise it looks for rustup (on `PATH`, or Homebrew's keg-only one in `/opt/homebrew/opt/rustup/bin`) and runs `cargo +stable`, or the toolchain named in `FARO_RUST_TOOLCHAIN`. `cargo-about` is only needed for the licence notices.

**Building.**

```sh
apps/ios/build-rust.sh                  # FaroCore.xcframework and the Swift bindings
apps/ios/build-domains.sh               # the domain list the tunnel ships, and its notice (network, once)
apps/ios/build-update-root.sh            # the update root the app bundles (FARO_UPDATE_ROOT or release/update-root.json; build-rust.sh runs it)
apps/ios/build-notices.sh               # optional: the licences the app shows, and the above (needs cargo-about, network)
cd apps/ios && xcodegen generate        # Faro.xcodeproj (git-ignored)
xcodebuild build -project Faro.xcodeproj -scheme Faro \
    -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO
xcodebuild build -project Faro.xcodeproj -scheme Faro -configuration Release \
    -destination 'generic/platform=iOS' -derivedDataPath build/device CODE_SIGNING_ALLOWED=NO
check-extension-sizes.sh build/device/Build/Products/Release-iphoneos/Faro.app
```

Run `build-rust.sh` again after changing `faro-mobile`'s interface, and `xcodegen generate` after changing `project.yml` or adding a Swift file. The project is arm64 only (devices and Apple Silicon Simulators), with iOS 17.0 as the deployment target.

**What is where.**

| Target | Bundle ID | Links FaroCore | What it is |
|---|---|---|---|
| `Faro` | `org.faro.ios` | yes | The app (SwiftUI): enrollment, setup (Screen Time, the VPN configuration with Connect On Demand, the monthly notice) and the status screen. Embeds the four extensions. Registers the `faro` URL scheme |
| `FaroTunnel` | `org.faro.ios.tunnel` | yes | `NEPacketTunnelProvider`: the DNS filter and the heartbeats ([The packet tunnel](#the-packet-tunnel)) |
| `FaroMonitor` | `org.faro.ios.monitor` | no | `DeviceActivityMonitor`: re-applies the settings, and watches Screen Time, the store and the tunnel (IOS.md §6.3, §10.2) |
| `FaroShield` | `org.faro.ios.shield` | no | `ShieldConfigurationDataSource` (block screen wording; counts how often it is shown) |
| `FaroShieldAction` | `org.faro.ios.shieldaction` | no | `ShieldActionDelegate` (Close button; counts presses) |

The monitor and the two shield extensions run under a 6 MB memory limit, so they never link the Rust core (IOS.md §13): they link `FaroKit` and Apple frameworks only, and write counters and markers to the app group for the app or tunnel to turn into events. `check-extension-sizes.sh` fails if one of their Release binaries is over 704 KiB (`FARO_EXTENSION_BUDGET`, in bytes), contains the core's symbol names, or links `FaroKitApp`. They were about 150 KB each as stubs. The package is built into one prelinked object per library, and the linker keeps every public symbol of such an object, so dead stripping can't trim `FaroKit`: each extension carries all of it. Today the monitor is about 654 KB and the two shields about 595 KB. **The two-library rule:** `FaroKit` holds only what an extension calls (directly or through the monitor's `ChoicesStore.applyDue`); anything only the app or the tunnel uses goes in `FaroKitApp`, which the extensions never link. That is Leave Faro's flow, the VPN and context checks, enrollment link parsing, the setup flow, the monthly notice, the domain update schedule and the choices' text. When you add code to the package, put it in `FaroKitApp` unless an extension needs it. The budget is a tripwire: raise it deliberately.

- **`FaroKit`** (`apps/ios/FaroKit`) is a local Swift package, Foundation only, for what the targets share and what can be tested: the app group's paths (`AppGroup`), the settings file model the monitor re-applies (`FaroSettings`, `SettingsStore`), marker files and `flock`-protected counters, and the member's choices: the key vocabulary of an iPhone `settings_change` (`IosSettingKey`, with `ChoiceDiff` working out which part of a change blocks more and which less; the words for it, `ChoiceText`, are in `FaroKitApp`), the pending-loosening state machine (`PendingState`) and the `flock`-protected store the app, the monitor and the tunnel share (`ChoicesStore`: settings, pending changes and the events waiting for a process that can sign them), and the tunnel's copy of the choices (`TunnelConfig`), and the tamper watchers' book (`TamperLedger`: what each watcher saw, one signal per layer until it is seen on again, and the requests the monitor leaves for the app or the tunnel to record, under a `flock` with the settings events' claim lease) with the checks the monitor needs (`TunnelWatch`, `StoreCheck`) and the monitor's schedule (`MonitorSchedule`, the 15-minute chain and the 80-minute backbone). `FaroKitApp`, the package's second library, linked only by the app and the tunnel, holds the enrollment link parsing (`EnrollLink`), the setup state machine (`SetupFlow`, `SetupProgressStore`), the monthly notice's schedule (`MonthlyNotice`), the domain update schedule (`DomainUpdateSchedule`), the choices' text (`ChoiceText`), Leave Faro's state machine (`LeaveFlow`), the meaning of a tunnel stop (`TunnelStopMeaning`), the VPN configuration's verdict with the best cause (`FilterVerdict`) and the context checks (`OtherVPN`, `JailbreakCheck`). The Keychain `KeyStore` is `KeychainKeyStore` in `Shared/CoreLink.swift`. Its XCTest tests run on the host and the Simulator: `swift test --package-path apps/ios/FaroKit`, or `xcodebuild test -scheme FaroKit -destination 'platform=iOS Simulator,name=iPhone 17'` in that directory (use any Simulator you have). Put logic here, not in a target, when it can run without Screen Time or a tunnel.
- **Identifiers.** App group `group.org.faro.ios` in all five targets; Keychain access group `$(AppIdentifierPrefix)org.faro.ios.shared` in the app and the tunnel, the two that hold keys. `com.apple.developer.family-controls` is on all five, and `packet-tunnel-provider` on the app and the tunnel. The `Info.plist` and `.entitlements` files are written by `xcodegen generate` from `project.yml` and checked in, so a change shows in review; CI fails if regenerating changes them.
- **`uniffi-bindgen`** is `apps/ios/uniffi-bindgen`, a small crate outside the root workspace with its own lockfile, `uniffi` pinned to the version `faro-mobile` uses. `build-rust.sh` fails if the two lockfiles disagree. When you bump UniFFI, change both.
- **Licences.** The app has a Licences screen that shows `third-party.txt` (the crates in `faro-mobile`'s tree, `release/notices/third-party.sh ios`) and `domains.txt` (the domain list's notice, made by `build-domains.sh` with the list itself, so the two match), both made by `build-notices.sh` into `apps/ios/Generated/Notices` and bundled as resources. A build without them still works, and the screen says so. A release build must have both ([Third-party notices](#third-party-notices)). The Swift package dependencies, if any are added later, need their notices there too.
- **Signing.** `DEVELOPMENT_TEAM` is empty in `project.yml` and CI builds with `CODE_SIGNING_ALLOWED=NO`. To run on a device, set your team in Xcode or pass `DEVELOPMENT_TEAM=...`. Family Controls and the packet tunnel need entitlements Apple grants per App ID, which the project doesn't have yet (IOS.md §14).

**What runs where.**

| Runs on | What |
|---|---|
| Host (`cargo test -p faro-mobile`, `swift test`) | The core's logic and `FaroKit` |
| Simulator | The `FaroKit` tests; the app launches. Screen Time authorization, the monitor, the shields and the packet tunnel **don't run in the Simulator** |
| Compiled only (CI, unsigned) | All five targets for the Simulator and for a device, the entitlements (not checked without signing) and the extensions |
| A real iPhone with the entitlements | Everything else (IOS.md §17 spikes) |

CI runs this as the `ios` job on GitHub's `xcode-27` runner (Xcode 27 on macOS 27, Apple Silicon), which installs `xcodegen` first. It still skips with a notice if a runner has no Xcode or no xcodegen. It is a macOS job, so its minutes count ten times.

### The packet tunnel

`FaroTunnel` (IOS.md §7, §10.1) is thin Swift over `DnsFilter`: it moves packets between the packet flow and the network's resolvers and keeps the timers. Every decision is in Rust, where it is tested on the host.

- **Network settings** come from `tunnel_network()`: the interface addresses `198.18.0.1` and `2001:2::1`, the DNS address `198.18.0.53` and `2001:2::53` with `matchDomains = [""]`, MTU 1500, and host routes for the DNS address and `RESOLVER_ADDRS` only. No other traffic enters the tunnel.
- **Upstream** is the network's own resolvers, read with libresolv (`SystemResolvers`, through the bridging header) before the tunnel's settings apply, and again when the network changes (`NWPathMonitor`, ignoring tunnel interfaces). While the tunnel's DNS settings apply, the system reports the tunnel's own address as the resolver, so to read again the tunnel lifts its DNS settings for a moment, keeping its routes, and puts them back: lookups in that moment, well under a second, go to the network's resolvers unfiltered (IOS.md §7.4). Queries go out on one connected UDP `NWConnection` per resolver, outside the tunnel (`Upstream`), and a truncated answer on a short TCP connection. There is never a fallback resolver: with none found, allowed names get `SERVFAIL` at once, blocked ones still `NXDOMAIN`, and the tunnel tries again after a minute, then every 5 minutes and on every network change.
- **The domain list** is `Generated/Domains` (from `build-domains.sh`), bundled into the extension. A build without it runs with the always-blocked names and the member's list only, and logs why. Every 10 minutes the tunnel switches to a newer verified list installed in the app group, if there is one. **Updates:** the app (not the tunnel) checks the instance's mirror at most every 6 hours, when it comes to the foreground and from a `BGAppRefreshTask` (`org.faro.ios.refresh-domains`, in Info.plist through `project.yml`). `faro-mobile`'s `update_domains` verifies the metadata against the project's root of trust and installs a newer bundle into the app group; the instance can delay a list but never forge one (invariant 5). The root is `Generated/Update/update-root.json`, made by `build-update-root.sh` (run by `build-rust.sh`) from `FARO_UPDATE_ROOT` or `release/update-root.json` and bundled as a resource of the app only. Until the key ceremony commits root 1 there is none, and a build without it checks no updates, as a desktop `--dev` package without `FARO_UPDATE_ROOT`; set `FARO_REQUIRE_UPDATE_ROOT=1` for a release build so a missing root fails. The tunnel stays on the packaged list unless the installed one is newer, so it never goes below the packaged version, and a bundle that no longer matches what was installed is removed and reported as an `integrity_failure` ("domain list update (changed)"). A tunnel that downloads on its own, for a phone whose app hasn't run for days, would need the root bundled into the tunnel too; it is not built.
- **Heartbeats** go through `FaroCore` every 5 minutes while the phone is awake, with `state: sleeping` from `sleep(completionHandler:)` (which waits at most 5 seconds for it) and a fresh one on `wake()`. While the keys are locked (before the first unlock) they are skipped and filtering goes on. There is no `shutting_down` heartbeat when the tunnel stops: the instance shouldn't read the filter being switched off as an expected silence.
- **Reports.** Every minute the tunnel records bursts as `flag` events (an alert shouldn't wait ten minutes). Every 10 minutes, on `sleep` and on stop it records ended buckets and the shield counters as events, takes a protection sample (`filter_on`, Screen Time unknown until the tunnel can read it, spike S6), asks the core to queue the day's report, and saves the counters again. A locked key store or an unapproved device skips the step and tries again later. **Screen on** for a burst is the tunnel's `awake`: true from `wake()`, false from `sleep(completionHandler:)`. The tunnel sees the device only through those callbacks, so a lookup made while the phone is awake counts as made with the screen on; lookups made while it sleeps (background fetches, push) never count toward a burst. The app doesn't flush yet, so with the tunnel off the shield counters and the report wait for it.
- **Watching** (IOS.md §10.2). Every minute and on `wake` the tunnel reads Screen Time authorization into the tamper ledger (a revocation counts only after a second reading 5 seconds later, and only from a tunnel that has read it approved before, which also covers spike S6), and records and uploads whatever the ledger holds. `stopTunnel` maps the stop reason (`TunnelStopMeaning`): switched off in Settings, another VPN or the configuration removed is a `FilterOff` with that cause, recorded and sent within 5 seconds; sleep, no network or an app update touch `tunnel_resting` instead, so the monitor doesn't read the quiet marker as tamper. Every 10 minutes the count of packets dropped to the known encrypted-DNS resolvers (`DnsFilter::take_doh_dropped`) becomes the `doh_dropped` context, at most once an hour. The protection samples for the report carry Screen Time as the tunnel reads it, or as the app and the monitor last read it (`TamperBook.screenTimeState`), and `null` only when nobody knows.
- **The app group.** The `tunnel_alive` marker (`MarkerName.tunnelAlive`) every minute and `tunnel_resting` on sleep; the counters (`counters/dns_blocked.json`, blocked lookups only) every 10 minutes, on `sleep` and on stop; `filter.json` (the member's choices) read on start and every 10 minutes, together with the copy of the choices in the VPN configuration's `providerConfiguration`, which the tunnel prefers unless `filter.json` is newer (`TunnelConfig`). On each of those rounds the tunnel also applies a loosening whose time has come and sends the settings events the monitor or the app left. Before the first unlock the files can't be read or written, and the tunnel goes on with the `providerConfiguration` copy (or the defaults without one) and in memory.
- **Logging** (`os.Logger`, subsystem `org.faro.ios.tunnel`) never includes a name. Every 10 minutes it logs the filter's state and `os_proc_available_memory()`. On the host, `dnsfilter-measure` with the shipped list (69,340 domains, 542,149 bytes) measured about 530 KiB of heap in the steady state, 1.3 MiB more with the counters at their bound, and at most 2 MiB of queries in flight.

## The Android core

`crates/faro-android` is the Rust half of the Android client (ANDROID.md §6), behind a Kotlin interface generated by UniFFI (package `org.faro.core`). Unlike `faro-mobile` it embeds the desktop service's whole runtime: `faro_service::Service` with `source::InProcessFrameSource` over an `AgentPlatform` whose calls go to the app's `AndroidPlatform` (Kotlin), on Faro's own Tokio threads. It builds and tests on the host:

```sh
cargo test -p faro-android
```

The app's Gradle build runs `crates/faro-android/build-android.sh <out-dir>`, which needs the Android NDK (`ANDROID_NDK_HOME`, or `ANDROID_HOME` with `ndk/<version>`) and `cargo-ndk`. It writes `<out-dir>/jniLibs/{arm64-v8a,x86_64}/libfaro_android.so` (and `libonnxruntime.so`), `<out-dir>/notices` and the Kotlin bindings under `<out-dir>/kotlin`, generated from the arm64 library by the crate's own `uniffi-bindgen` binary (`--features bindgen`, host only, so it is always the library's UniFFI version).

- **faro-service on Android.** Android is `unix`, so the desktop-only parts are compiled out for `target_os = "android"`: the agent IPC and its code-signature checks, the OS session list (`source::{ipc, codesign, sessions}`), the enroll socket, the default IPC source and agent spawning. The runtime is otherwise unchanged.
- **The adapter** (`faro_android::platform`) checks every frame (non-zero, longest side at most 768, exactly `width * height * 4` bytes; otherwise wiped and counted as a failed capture) and moves it into a zeroizing `Frame`. A capture refused for want of the accessibility service is the platform's permission error, and the source names the permission `accessibility_service` (`InProcessFrameSource::with_capture_permission`), so the service's `permission_revoked` rules apply as to Screen Recording on a Mac. A capture refused by a `FLAG_SECURE` window, or by the system's own secure UI (`Unavailable { reason: "system window" }`), is `SourceEvent::CaptureHidden`: counted as failed on the report and the status, never towards `capture_failing`. The same third-party app refusing two captures in a row is one `window_hidden_from_capture`, and again only after five minutes without it; the system's own packages never are. Browser addresses are reduced again to `scheme://host/`.
- **Enrollment** is `faro_service::enroll`. `preview_enrollment` refuses an instance whose `server_version` is below `MIN_SERVER_VERSION` (`0.1.0-beta.1`, the first release that knows `android`; raise it if Android ships later), and `enroll` requires that preview and the same instance identity. `poll_approval` activates the device itself while the runtime isn't running, holding the state lock.
- **Urgent signals.** `report_tamper_now` hands the signal to the running runtime (starting it if needed), waits until it is recorded, uploads, and returns when the instance has acknowledged it or after five seconds.
- **The image model.** `build-android.sh` builds with `--features onnx` (`--no-onnx` leaves it off; the host tests never have it). pyke's prebuilt ONNX Runtime has no Android build, so `crates/faro-android/fetch-onnxruntime.sh` downloads Microsoft's own, the `onnxruntime-android` 1.22.0 AAR on Maven Central (the version `ort` 2.0.0-rc.10 is written for), checks its SHA-256 and unpacks `jni/<abi>/libonnxruntime.so` for `arm64-v8a` and `x86_64`. The AAR has no licence files, so those come from the same release's Python wheel, by digest, as in the macOS package. Downloads are cached by digest in `FARO_ORT_CACHE` (default `%LOCALAPPDATA%aro-onnxruntime` on Windows, `~/.cache/faro-onnxruntime` elsewhere) and checked again on every use. The script then runs cargo-ndk once per ABI, with `ORT_LIB_LOCATION` the directory of that ABI's library, `ORT_PREFER_DYNAMIC_LINK=1` and `ORT_CXX_STDLIB` empty (every other `ORT_*` variable is cleared). The library is a plain C API that needs only libc, libm, libdl and liblog, so `libfaro_android.so` links `libonnxruntime.so` dynamically and no `libc++_shared.so` ships; both go into `jniLibs/<abi>/`. To move to a new ONNX Runtime, change the pins here, in the macOS and Windows fetch scripts and `ort` together.
  - **The model is packaged only when the build is given it.** The model is built on macOS only ([The image model](#the-image-model)); give Gradle that directory with `-Pfaro.modelDir=<dir>` or `FARO_MODEL_DIR` (`manifest.json`, `opennsfw-int8.onnx`, `NOTICE.txt`). It goes into the APK's `assets/model/opennsfw/`, with the notices in `assets/notices/` (ONNX Runtime's licence and third-party notices, and `opennsfw.txt`; without a `NOTICE.txt` Gradle writes it from the manifest). The About screen shows them.
  - **Where the core finds it.** At startup the app copies the packaged model to `<noBackupFilesDir>/faro/models/opennsfw/` (`ModelAssets`: only the files that are missing or differ, the manifest last) and then creates `FaroAndroid(dataDir, platform, modelPackaged)`. With `modelPackaged` the core gives `faro_android::android::MODEL_MANIFEST` to `ServiceBuilder::model_manifest`, so the service's own rules apply: `load_model`'s checks, CPU provider, one thread, and a model that is missing, altered or can't be loaded is an urgent `integrity_failure` (`image model (missing)`, `(changed)` or `(cannot load)`), with frames rated from context signals meanwhile. A core built without `onnx` counts as unable to load it. `modelPackaged` is true exactly when the APK has `assets/model/opennsfw/manifest.json`, so a development build without a model raises nothing; the assets of an installed APK can't be changed without breaking its signature, which is why the flag comes from the APK and not from a file in app storage.
- **Logging** goes to logcat (tag `faro`) at `info`.
- **Trying it on an emulator or a phone.** `crates/faro-android/tests/emulator.rs` is an ignored test that runs the test harness's instance (an admin, a member with keys, an ally) on a fixed port, prints an enrollment link, approves the first device that enrolls as the member's browser would, and prints every event it uploads, opened with the member's key:

  ```sh
  FARO_EMULATOR_PORT=8787 cargo test -p faro-android --test emulator -- --ignored --nocapture
  adb reverse tcp:8787 tcp:8787
  adb shell am start -a android.intent.action.VIEW -d '<the faro://enroll link it printed>'
  ```

  The link is `http://127.0.0.1` because the client allows plain HTTP only for loopback, which `adb reverse` provides. `FARO_EMULATOR_MINUTES` (default 30) is how long it runs. Don't use `uiautomator dump` while testing: a UI-automation session suspends other accessibility services, so Faro correctly reports its accessibility service as turned off.
- **Seeing a flag without explicit content.** As on desktop ([Testing the whole flag path](#testing-the-whole-flag-path)), a core built with the `dev` feature lowers the detection thresholds, here from `<data_dir>/dev-thresholds.toml` (`<noBackupFilesDir>/faro/`, a `[dev_thresholds]` section). Build with `./gradlew :app:assembleDebug -Pfaro.dev=true -Pfaro.modelDir=<model dir>` (`build-android.sh --dev`, which refuses `--release`), then, on a debug build:

  ```sh
  printf '[dev_thresholds]\nany_low = 0.0001\nexplicit_medium = 0.0002\n' |
    adb shell "run-as org.faro.android sh -c 'cat > no_backup/faro/dev-thresholds.toml'"
  ```

  The thresholds must keep `any_low <= explicit_medium <= explicit_high`, or the file is ignored with a warning. The core reads the file when its runtime starts, so restart the app; logcat then shows `DEVELOPMENT THRESHOLDS`, and ordinary screens arrive at the instance as `medium` flags with their blurred thumbnails. A build without `dev` never reads the file.

## CI runners

Every workflow runs on GitHub's hosted runners. There are no self-hosted runners.

| Runner | Jobs |
|---|---|
| `macos-15` (Apple Silicon) | `test (macos)` (also `faro-detect` with ONNX Runtime), `macos-pkg`, `model-eval`, the release package (`release.yml`) |
| `macos-15-intel` | `test (macos-intel)` (also `faro-detect` with ONNX Runtime), `macos-pkg-intel` |
| `ubuntu-24.04` | `fmt`, `test (linux)`, `web`, `deny`, `release-scripts`, the amd64 container build and the multi-arch publish, the nightly `fuzz` workflow; in `release.yml` everything else on Linux, including the signing jobs; all of `update-timestamp.yml` |
| `xcode-27` (Xcode 27 on macOS 27, Apple Silicon) | `ios` |
| `ubuntu-24.04-arm` | the arm64 container build, and the arm64 server build in `release.yml` |
| `windows-2025` | `test (windows)`, `windows-msi`, the release MSI (`release.yml`) |

Both container platforms build natively, never under QEMU. The repository variables `FARO_LINUX_X64_RUNNER` (the amd64 build) and `FARO_SIGNING_RUNNER` (the jobs that read the update signing keys, [Releasing](#releasing)) take a runner as JSON, for example `"ubuntu-24.04"`, if either needs to move.

**Cost.** The repository is private, so jobs use the org's Actions minutes, and macOS minutes count ten times (Windows twice). The macOS jobs are most of a CI run's cost. A new push to a pull request cancels its older CI run. **While the org's spending limit is reached, no job can start**, including the timestamp re-signing ([If the timestamp job fails](#if-the-timestamp-job-fails)).

**Registry credentials.** The image is pushed with the job's `GITHUB_TOKEN`; there is no other registry secret. Only the `build` job (pushes to `main` and manual runs) and the `publish multi-arch image` job have `packages: write`, and only they log in to `ghcr.io`, logging out when the job ends. On a pull request the `test` job builds and smoke-tests both platforms with a read-only token, and pushes nothing. Both jobs show as `build (linux/amd64)` and `build (linux/arm64)`.

The workflows install Rust (`dtolnay/rust-toolchain`), Node (`actions/setup-node`), cargo-about, cargo-deny and WiX themselves; everything else comes with GitHub's runner images. The `ios` job installs `xcodegen` with Homebrew.
