# Developing Faro

**Audience:** contributors working on the Rust workspace and the web app.

## Toolchain

- Rust stable, 1.94 or newer (`rust-version` in the root `Cargo.toml`; set by `sqlx` 0.9, which the server needs so it can share the patched SQLite that `rusqlite` 0.41 bundles). CI uses the latest stable.
- No nightly is needed, except for the optional `cargo fuzz` targets.
- `cargo-deny` is used for license, ban and advisory checks: `cargo deny check`.
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
| `faro-detect` | dHash, classifier, domain categories, fusion, blurred thumbnails | `faro-platform`, `faro-proto` |
| `faro-ipc` | Agent ↔ service protocol and transport | `faro-platform`, `faro-proto` |
| `faro-core` | Scheduler, urgency, recipients, event writer, outbox, reports | `faro-proto`, `faro-crypto` |
| `faro-update` | TUF-style signed update verification | `faro-proto`, `faro-crypto` |
| `faro-service` / `faro-agent` | Client binaries | most of the above |
| `faro-server` (`server/`) | The self-hosted instance | `faro-proto`, `faro-crypto`, `faro-update` |

`faro-proto` and `faro-crypto` are the contract between the client, the server and the web app. Change them deliberately: any change to a `signing_bytes()` encoding or a domain-separation tag is a protocol change and needs a version bump and an update to `docs/PROTOCOL.md`.

## Invariants every change must keep

These come from ARCHITECTURE.md §3.5, §4.3, §5 and §12. Reviewers check them on every PR.

1. **No unblurred image leaves memory.** `faro_platform::Frame` has no `Clone`, `Serialize` or pixel-printing `Debug`, and it is zeroized on drop. The only image type in any wire or storage format is `BlurredThumbnail`.
2. **The instance only sees ciphertext and header metadata.** Nothing in `faro-server` can decrypt anything.
3. **Devices encrypt only to member-endorsed keys,** checked against the member key pinned at enrollment.
4. **Tamper can't be silenced.** The server floors urgency with `EventKind::min_urgency()`, and urgent tamper alerts can only be moved to the digest, never turned off.
5. **Clients trust project signatures for updates, never the instance.**
6. **Disabling an account is never silent.** The person and every accountability partner are told, and the alerts can't be switched off (`account_disabled`, `ally_disabled`). Disabling stops sign-in, never monitoring.

## Dependency notes

- **The crypto stack is pinned to the `rand_core` 0.6 generation:** `ed25519-dalek` 2, `crypto_box` 0.9 (sealed boxes), `chacha20poly1305` 0.10 and `argon2` 0.5. Newer major versions exist (dalek 3, `rand_core` 0.10, `crypto_box` 0.10 is still a pre-release), but mixing generations means duplicated RNG traits and awkward glue. Upgrade the whole set together in one PR, and keep the libsodium interop properties (sealed boxes; Argon2id with `p = 1`) covered by tests.
- **Internal workspace dependencies carry `version = "0.1.0-beta.1"`** (the workspace version) next to `path`. `cargo-deny`'s wildcard ban requires it. A requirement without a pre-release suffix doesn't match a pre-release crate, so when the workspace version changes, change these with it (root `Cargo.toml` and `faro-server` in `crates/faro-service/Cargo.toml`).
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
npm test            # the crypto port against the Rust test vectors
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
| `/settings` | everyone | Name, key fingerprints, changing a member's passphrase or recovery code, a member's retention and own notifications |
| `/privacy` | everyone | The operator privacy notice |
| `/admin/…` | admins | Overview, people, settings, email |

**Keys in the browser.** Private keys are created, wrapped and unwrapped in the page (`web/src/lib/keys`), held in memory only (`keyring.svelte.ts`: forgotten on reload, sign-out, "Lock" or after 30 idle minutes) and never sent anywhere unwrapped. Everything the browser builds on is checked first: a recipient manifest the server returns must verify against the member's own key, enrollment links take the member key fingerprint from the unlocked key, and safety codes are computed from the viewer's own key, never the server's copy. The storage formats are in PROTOCOL.md §4.3.

**Crypto.** `web/src/lib/crypto` ports what browsers need from `faro-proto` and `faro-crypto` (canonical encoding, key ids, safety codes, Ed25519, opening sealed boxes and items, Argon2id wrapping, manifests and endorsements) on the audited, pure-JavaScript `@noble` libraries. WebAssembly libsodium isn't an option: the page CSP has no `'wasm-unsafe-eval'`. Argon2id at the default 64 MiB / 3 passes takes well under a second. Both implementations check `crates/faro-crypto/tests/data/web-vectors.json`, in both directions; change one side, run both tests.

**The logo** is imported from `assets/brand` (the `$brand` alias in `vite.config.ts`), never copied into `web/` or redrawn; the container build copies that directory into its web stage.

For `npm run dev`, start a server in another terminal with `cargo run -p faro-server -- serve --dev` (it prints a setup token; set `FARO_DEV_API` to proxy somewhere other than `127.0.0.1:8080`). To test the embedded build instead, run `npm run build` and rebuild the server: `/setup` is then served on :8080 itself.

Without `web/build`, `faro-server` still builds and its API works; page requests get a plain-text note and the setup token message points at the `curl` instructions. Release builds set `FARO_REQUIRE_WEB=1`, which makes a missing bundle a build error. CI's `web` job runs lint, check, the crypto tests and build, then the server's web-serving tests against the real bundle.

**CSP.** Pages are served with a strict Content Security Policy built by `web::page_csp`. Scripts and stylesheets load from the instance only. The only inline script allowed is SvelteKit's per-page bootstrap, by hash (`build.rs` hashes it). Inline `style="…"` attributes are allowed only with a constant value, also by hash, and `<style>` blocks are never allowed. In components, use classes, and use Svelte's `style:` directive for dynamic values. Keep `inlineStyleThreshold` at 0, and never load anything from another origin.

**API types** are hand-written in `web/src/lib/types.ts` for now, mirroring the serde types in `server/src/api` and `faro-proto`. Change both sides together.

## Update metadata in tests

`faro-update`'s `testing` feature adds `faro_update::testing::ToyProject`, a project with its own keys. It signs releases (root, targets, timestamp, artifacts) and writes them in the upstream layout (PROTOCOL.md §8.1), so the mirror and client tests can publish whatever they need. Enable it only in `[dev-dependencies]`, never in a shipped binary. `server/tests/updates.rs` serves such a directory over HTTP on localhost to exercise the online mirror.

## Testing without real hardware

`faro_platform::synthetic::Script` drives a fake screen, foreground app, session state and tamper signals. Use it for anything above the OS layer. Tests that need real OS permissions (for example macOS Screen Recording) are `#[ignore]`d and say so in their name or doc comment.

On macOS the agent binary shows a menu-bar icon and the service's notices, which needs a GUI session. `cargo run -p faro-platform-macos --example session_ui` shows that UI with a sample notice and no service. A `dev` agent started outside a GUI session (over SSH, for example) can skip it with `--no-ui`. AppKit's main thread can't be driven from `cargo test`, so the UI has no automated tests.

## The macOS installer

`installers/macos/build-pkg.sh` builds the `.pkg` and `installers/macos/check-pkg.sh` checks one without installing it. CI builds and checks the development package on every pull request and keeps it for 14 days as the `faro-dev-pkg-arm64-<sha>` artifact of the `macos-pkg` job (Apple Silicon only).

```sh
installers/macos/build-pkg.sh --dev                         # unsigned, for testing only
installers/macos/check-pkg.sh target/pkg/Faro-*-dev.pkg
installers/macos/test-uninstall.sh                          # the uninstaller's decisions, on a fake /Library
```

- **A `--dev` package is not safe to use on anyone.** Its `faro-service` is built with the `dev` feature, so it accepts any program running as a logged-in user as the agent. Install it only on a test machine.
- **A release package** needs `FARO_SIGN_IDENTITY` (Developer ID Application), `FARO_INSTALLER_IDENTITY` (Developer ID Installer) and `FARO_TEAM_ID`. The package's default `service.toml` sets `ipc.agent_requirement` from the team ID. `FARO_NOTARY_PROFILE` (a `notarytool` keychain profile) also notarizes and staples it.
- **The layout is fixed:** programs in `/Library/Faro` (the agent inside `Faro Agent.app`, bundle id `org.faro.agent`), the daemon in `/Library/LaunchDaemons` and the **global** LaunchAgent in `/Library/LaunchAgents`, which launchd starts in every account's session. The paths live in `faro_platform_macos::pkg_layout`.
- **The launchd plists are checked in** under `installers/macos/payload`, and a test keeps them equal to the generator. After changing `pkg_daemon_job` or `pkg_agent_job`, run `FARO_BLESS=1 cargo test -p faro-platform-macos --test installer_plists`.
- **After installing,** the service waits for enrollment. `sudo /Library/Faro/bin/faro-service enroll --link '…'` lists the computer's accounts, enrolls it, and leaves activation to the running service.
- **Uninstalling:** `sudo /Library/Faro/bin/faro-uninstall` stops the service, runs `faro-service goodbye` so allies get an urgent "Faro was uninstalled" (§3.7), then stops every session's agent and removes the programs, the launchd jobs, the state directory and the package receipt. If the instance can't be reached, `goodbye` writes nothing, so the uninstaller restarts the service and removes nothing. `--force` removes Faro anyway, and allies then see a missed check-in instead. A goodbye that is written but not delivered (exit status 3) never backs out: a service running again after its own goodbye would contradict it.
- **One writer per chain:** `run` and `goodbye` both hold an exclusive lock on `service.lock` in the state directory (`StateDir::try_lock`), so a second `faro-service run`, or a `goodbye` while the service runs, is refused instead of forking the event chain.
- **Updates:** `FARO_UPDATE_ROOT` (a signed root document, for example from `cargo run -p faro-update --example faro-release -- sign-root …`) is installed as `/Library/Faro/update-root.json`. A release package requires it; a `--dev` one may have it. With it, the service checks its instance's mirror about every 6 hours (`[updates] check_secs`) and installs newer client packages through the one-shot launchd job `org.faro.update` (`faro_platform_macos::update_job`). It runs as its own job because the package's preinstall stops the service, which would kill an `installer` running as its child. Only the packaged service, run as root from `/Library/Faro/bin/faro-service`, installs anything. A development build checks and logs, nothing more. The job's output goes to `update-install.log` in the state directory, and `update-attempts.json` there records the pending install and failed packages.
- **Not there yet:** universal (arm64 + x86_64) binaries and the tray app.

## CI runners

CI runs on the project's self-hosted runners, registered to the `faro-project` org and matched by label:

| Labels | Machine | Jobs |
|---|---|---|
| `self-hosted, macOS, ARM64` | Apple Silicon Mac | `test (macos)`, `macos-pkg` |
| `self-hosted, Linux, ARM64` | Raspberry Pi | `fmt`, `test (linux)`, `web`, `deny`, the arm64 container build |
| `self-hosted, Windows, X64` | Windows PC | `test (windows)` |

There is no x86_64 Linux runner yet, so the amd64 container build and the multi-arch publish still run on GitHub's `ubuntu-24.04`.

Each runner runs one job at a time, and a new push to a pull request cancels its older CI run. The workflows install Rust (`dtolnay/rust-toolchain`) and Node (`actions/setup-node`) themselves. Each machine needs:

- **All:** `git`, `curl`, and a C compiler and linker for the crates with C code.
- **Linux:** `build-essential` and `pkg-config`. Docker with Buildx for the container build. If `rustup` is missing, the first job installs it with its default profile edits; give the runner its own user.
- **Windows:** Git for Windows in its default location (the `test` job puts `C:\Program Files\Git\bin` first on `PATH`, ahead of WSL's `bash`, for the toolchain action's bash steps), and the Visual Studio Build Tools C++ workload for the MSVC linker.
- **macOS:** Xcode Command Line Tools. On a Mac someone also develops on, give the runner its own rustup so CI doesn't edit their shell profile: install it with `--no-modify-path` under the runner directory, set `CARGO_HOME` and `RUSTUP_HOME` in the runner's `.env`, prepend `$CARGO_HOME/bin` to its `.path`, and restart the runner.

Jobs aren't sandboxed: anyone who can push a branch can run code on these machines as the runner's user, and files stay between jobs. Keep the runners in an account with nothing else on it where you can, and never let them take jobs from a public repository.
