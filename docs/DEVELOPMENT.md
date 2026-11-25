# Developing Faro

**Audience:** contributors working on the Rust workspace and the web app.

## Toolchain

- Rust stable, 1.94 or newer (`rust-version` in the root `Cargo.toml`; set by `sqlx` 0.9, which the server needs so it can share the patched SQLite that `rusqlite` 0.41 bundles). CI uses the latest stable.
- No nightly is needed, except for the optional `cargo fuzz` targets (see [Fuzzing](#fuzzing)).
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
4. **Tamper can't be silenced.** The server floors urgency with `EventKind::min_urgency()`, and tamper-class alerts can only be moved to the digest, never turned off. `notify::policy::is_tamper_class` decides which alerts those are; ARCHITECTURE.md §5.4 lists them.
5. **Clients trust project signatures for updates, never the instance.**
6. **Disabling or deleting an account is never silent.** The person and every accountability partner are told, and the alerts can't be switched off: `account_disabled` and `ally_disabled` when an admin disables an account, `account_deleted` and `ally_deleted` when someone asks for theirs to be deleted, and `account_deletion_cancelled` when they cancel. Disabling stops sign-in, never monitoring. Deleting stops monitoring only at the purge, after the 7-day hold and once every notice has been delivered. The purge removes every row that names the person: a migration that adds a reference to `users` must add it to `db::repo::deletion::USER_COLUMNS` too, or `every_reference_to_users_is_purged` fails.

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
| `/admin/…` | admins | Overview, people, settings, branding, email |

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

For `npm run dev`, start a server in another terminal with `cargo run -p faro-server -- serve --dev` (it prints a setup token; set `FARO_DEV_API` to proxy somewhere other than `127.0.0.1:8080`). To test the embedded build instead, run `npm run build` and rebuild the server: `/setup` is then served on :8080 itself.

Without `web/build`, `faro-server` still builds and its API works; page requests get a plain-text note and the setup token message points at the `curl` instructions. Release builds set `FARO_REQUIRE_WEB=1`, which makes a missing bundle a build error. CI's `web` job runs lint, check, the crypto tests and build, then the server's web-serving tests against the real bundle.

**CSP.** Pages are served with a strict Content Security Policy built by `web::page_csp`. Scripts and stylesheets load from the instance only. The only inline script allowed is SvelteKit's per-page bootstrap, by hash (`build.rs` hashes it). Inline `style="…"` attributes are allowed only with a constant value, also by hash, and `<style>` blocks are never allowed. In components, use classes, and use Svelte's `style:` directive for dynamic values. Keep `inlineStyleThreshold` at 0, and never load anything from another origin.

**API types** are hand-written in `web/src/lib/types.ts` for now, mirroring the serde types in `server/src/api` and `faro-proto`. Change both sides together.

## Update metadata in tests

`faro-update`'s `testing` feature adds `faro_update::testing::ToyProject`, a project with its own keys. It signs releases (root, targets, timestamp, artifacts) and writes them in the upstream layout (PROTOCOL.md §8.1), so the mirror and client tests can publish whatever they need. `ToyProject::from_seed` derives the keys from a seed, so separate processes sign identical documents, and `sign_raw` signs any payload bytes without validating them. Enable it only in `[dev-dependencies]`, never in a shipped binary. `server/tests/updates.rs` serves such a directory over HTTP on localhost to exercise the online mirror.

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

Every target fails on a panic. Beyond that, every faro-proto decoder must round-trip (decode, encode, decode to an equal value, encode to the same bytes), and the faro-update targets check the state machine's rules after every call: nothing trusted rolls back, a failed call changes nothing but the observed time, and the persisted state loads back unchanged and stays small.

- **Seeds.** `faro-update`'s seeds are documents signed by `ToyProject::from_seed`, a toy project with fixed keys whose first root every target trusts, so a seed written by one process verifies in another. `faro-proto`'s are sample values of each type. Both are written by the crate's `seed_corpus` example, and `corpus/` is not checked in. The `src/lib.rs` tests check that the seeds still decode and reach as far into the verifier as they should, so run them after changing a type.
- **A shared machine.** libFuzzer uses one process unless asked for more; keep it that way (`-jobs=1`) and fuzz one target at a time.
- **Findings.** Fix the bug with a regression test in the crate's normal test suite, not only in the corpus. A finding in `faro-update` is a security issue: describe it in the pull request that fixes it, never in a public issue.
- **CI.** `.github/workflows/fuzz.yml` runs every target nightly and on demand (`workflow_dispatch`, with the seconds per target as input; 300 by default) on the Linux runner, and never on pull requests. Each run starts from the corpus the previous one grew (kept in the Actions cache), and a crashing input is uploaded as the `fuzz-crashes-<crate>-<run id>` artifact, kept for 30 days.

## The domain category bundle

`faro-detect`'s `DomainCategorizer` (§3.5 "Context signals") loads a compiled FST bundle. The `domains-compile` example builds it from the blocklists listed in `crates/faro-detect/domains/sources.toml`. Run it from the repository root:

```sh
cargo run -p faro-detect --example domains-compile -- fetch --config crates/faro-detect/domains/sources.toml
cargo run -p faro-detect --example domains-compile -- build --config crates/faro-detect/domains/sources.toml \
    --out target/domains/domains.bin
```

- **`fetch`** downloads each approved `url` source with `curl` into `target/domains/sources` (`--sources-dir` changes it) and keeps it only if its BLAKE3 matches the pin in `sources.toml`. Sources can also be local files (`path`, relative to the config).
- **`build`** reads only those files, refuses any that don't match their pin, and writes `domains.bin` and `domains.manifest.json`: the sources, their licences, attribution and entry counts, the licence texts, and the bundle's size and BLAKE3. Nothing in either depends on the time or the machine, so the same config always gives byte-identical files.
- **Approved, pending and refused (§11).** Every source records an SPDX licence and a state, and the maintainer decides it:
  - **Approved** (`approved = true`) sources are always fetched and compiled. Their licence must be on `faro_detect::ALLOWED_MODEL_LICENSES`, or the config is rejected.
  - **Pending** (`approved = false`) sources are left out. `--allow-unapproved` includes them for local experiments only: the manifest then says `"unapproved_included": true`, and such a bundle must never ship. Their `terms` field says what the upstream terms are.
  - **Refused** (`refused = "reason"`) sources stay in the config, so nobody proposes them again, but they are never fetched or compiled, even with `--allow-unapproved`.
- **Attribution travels with the bundle.** The manifest ships next to `domains.bin` and has to be enough to comply on its own. So an approved source whose licence asks for attribution (anything on the allowlist except CC0-1.0 and the Unlicense) needs a `[source.attribution]` table: `author`, the upstream's verbatim `copyright` lines, `source_url`, `license_url`, and `changes`, a note of what the conversion did. For licences whose text must accompany copies (MIT, BSD, ISC, Zlib, Apache-2.0), the `copyright` lines are required and the text goes once under `[license_texts]`. CC BY 4.0 only needs the link to the licence. Without any of these, `fetch` and `build` refuse the config. The manifest copies every source's attribution and the texts of the licences it uses.
- **Moving to a newer upstream revision:** change the commit in the URL, run `fetch` (it stops at a file whose hash changed and prints the new hash), review what changed upstream and that its licence and copyright notices didn't, then update the pin.
- **Never commit a downloaded list or a built bundle.** The tests use the hand-written fixtures in `crates/faro-detect/examples/domains-compile/fixtures` (`.gitattributes` there keeps their bytes, and so their pins, the same on Windows).
- `domains-compile hash FILE…` prints BLAKE3 hashes for pinning a new source.

Shipping the bundle through the update channel and loading it in the packaged service come later. The service already accepts one through the `domains` builder method in `faro-service`'s runtime.

## Testing without real hardware

`faro_platform::synthetic::Script` drives a fake screen, foreground app, session state and tamper signals. Use it for anything above the OS layer. Tests that need real OS permissions (for example macOS Screen Recording) are `#[ignore]`d and say so in their name or doc comment.

On macOS the agent binary shows a menu-bar icon and the service's notices, which needs a GUI session. `cargo run -p faro-platform-macos --example session_ui` shows that UI with a sample notice and no service. A `dev` agent started outside a GUI session (over SSH, for example) can skip it with `--no-ui`. AppKit's main thread can't be driven from `cargo test`, so the UI has no automated tests.

Browser tab URLs (`faro_platform_macos::browser`) need Accessibility and a real browser, so their live path has no automated test either. `cargo run -p faro-platform-macos --example browser_probe` prints what the agent would send every 2 seconds: the frontmost app and the reduced URL (`scheme://host/`). Run it from a terminal that has Accessibility and switch between browsers. `--pid PID --as safari|chrome|…` reads one process instead, which works for any app with a web view.

## Model benchmark

`faro_detect::bench` and the `model-bench` example measure a candidate image classifier the way the service uses it, and gate regressions against a baseline (ARCHITECTURE.md §3.5). Build it with `--release`: an unoptimized build says so in its output, and its latency means nothing.

```sh
B="cargo run --release -p faro-detect --features onnx --example model-bench --"
$B --manifest m.json --set /Volumes/FaroEval/set --json results.json      # run
$B --manifest m.json --model candidate.onnx --set … --json results.json   # weights elsewhere
$B --manifest m.json --set … --baseline models/eval-baseline.json         # run and gate
$B --results results.json --baseline models/eval-baseline.json            # gate only
$B --help                                                                 # every option
```

The manifest is the same `ModelInfo` JSON the update channel ships, and the same checks apply: the licence must be on `ALLOWED_MODEL_LICENSES` and `blake3` must match the weights (`b3sum candidate.onnx`). `--policy policy.json` benchmarks other thresholds (a partial `PolicyConfig`; the default is the built-in policy).

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

**The gate** exits 1 when recall on `explicit` drops by more than `--max-recall-drop` (absolute, default 0.02) or p95 latency rises by more than `--max-p95-increase` (relative, default 0.25). It exits 2 when the reports can't be compared: the set's digest differs (an image was added, removed, edited or moved to another class) or a report has no explicit images. A different model, policy or machine is printed as a note. Latency only compares on the same machine and build, so the baseline comes from the CI runner.

**The baseline** is `models/eval-baseline.json`: a results file from the macOS runner, metrics only, so it is safe to commit. There is none until the maintainer picks a model and the set is on the runner; until then the CI job warns and passes. To create or update it, download the `model-eval-metrics-<sha>` artifact of the run you accept and commit its `results.json` as the baseline, in the same pull request that changes the model, the set or the policy (or accepts a regression), and say why.

**In CI.** The harness itself is tested on every pull request against a synthetic set the tests generate (solid colours and UI-like windows) and a tiny ONNX graph they encode by hand (`classifier/test_onnx.rs`), so no model or image is downloaded or committed: `cargo test -p faro-detect` on every runner uses a pure-Rust stand-in for the graph, and the macOS `test` job also runs `cargo test -p faro-detect --features onnx` (the `onnx` feature's build script downloads ONNX Runtime). The `model-eval` job runs the gate on the real set on the macOS runner. It runs on `main` only (each push, or a manual run from the Actions tab), never on a pull request, so a change to the harness is reviewed before it touches the set. To gate a candidate model before merging, run the tool locally. The job also runs only when the runner's `.env` sets:

| Variable | Value |
|---|---|
| `FARO_MODEL_EVAL_SET` | the set's directory; unset, the job is skipped |
| `FARO_MODEL_EVAL_MANIFEST` | the manifest of the model under test, with the model next to it |

It uploads `results.json` and nothing else.

**Handling the real set.** It contains explicit imagery, so:

- **Never commit it,** and never copy it into the repository, a worktree, `target/`, an issue, a pull request or a CI artifact. Keep it on an encrypted volume outside the repository, readable by no account but yours and the runner's.
- **Adults only, obtained lawfully.** Anything that might depict a minor stays out of the set, without exception.
- **The tool writes metrics only.** Images enter through `Frame`, one at a time, and are zeroized when dropped (`privacy_tests::benchmark_frames_are_zeroized`); no image, thumbnail or per-image result is written, and the set appears only as a digest. It deliberately doesn't list which images were missed. File names can appear in error messages, and so in CI logs: name files neutrally (`0001.png`).
- **The runner can read it.** Keeping `model-eval` off pull requests stops unreviewed harness changes from running on the set, but it is not a sandbox: anyone who can push a branch can run any code on the macOS runner (see CI runners), and so read the set. Keep push access to maintainers, and remove `FARO_MODEL_EVAL_SET` (and the set itself) from the runner before the repository goes public or that changes.

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
- **On Intel.** The `macos-pkg-intel` job runs on the Intel Mac runner after `macos-pkg`. It checks the same universal package, expands it without installing it, and runs the x86_64 `faro-service` and `faro-agent` with `--version`. On an Apple Silicon Mac with Rosetta 2, `cargo test --target x86_64-apple-darwin` runs the x86_64 tests locally.

- **A `--dev` package is not safe to use on anyone.** Its `faro-service` is built with the `dev` feature, so it accepts any program running as a logged-in user as the agent. Install it only on a test machine.
- **A release package** needs `FARO_SIGN_IDENTITY` (Developer ID Application), `FARO_INSTALLER_IDENTITY` (Developer ID Installer) and `FARO_TEAM_ID`. The package's default `service.toml` sets `ipc.agent_requirement` from the team ID. `FARO_NOTARY_PROFILE` (a `notarytool` keychain profile) also notarizes and staples it.
- **The layout is fixed:** programs in `/Library/Faro` (the agent inside `Faro Agent.app`, bundle id `org.faro.agent`), the daemon in `/Library/LaunchDaemons` and the **global** LaunchAgent in `/Library/LaunchAgents`, which launchd starts in every account's session. The paths live in `faro_platform_macos::pkg_layout`.
- **The launchd plists are checked in** under `installers/macos/payload`, and a test keeps them equal to the generator. After changing `pkg_daemon_job` or `pkg_agent_job`, run `FARO_BLESS=1 cargo test -p faro-platform-macos --test installer_plists`.
- **After installing,** the service waits for enrollment. `sudo /Library/Faro/bin/faro-service enroll --link '…'` lists the computer's accounts, enrolls it, and leaves activation to the running service.
- **Uninstalling:** `sudo /Library/Faro/bin/faro-uninstall` stops the service, runs `faro-service goodbye` so allies get an urgent "Faro was uninstalled" (§3.7), then stops every session's agent and removes the programs, the launchd jobs, the state directory and the package receipt. If the instance can't be reached, `goodbye` writes nothing, so the uninstaller restarts the service and removes nothing. If the instance has already retired the computer (`403 device_removed` or `403 account_deleted`), allies were told then: `goodbye` writes nothing, exits 0, and the uninstall goes ahead. `--force` removes Faro anyway, and allies then see a missed check-in instead. A goodbye that is written but not delivered (exit status 3) never backs out: a service running again after its own goodbye would contradict it.
- **One writer per chain:** `run` and `goodbye` both hold an exclusive lock on `service.lock` in the state directory (`StateDir::try_lock`), so a second `faro-service run`, or a `goodbye` while the service runs, is refused instead of forking the event chain.
- **Updates:** `FARO_UPDATE_ROOT` (a signed root document, for example from `cargo run -p faro-update --example faro-release -- sign-root …`) is installed as `/Library/Faro/update-root.json`. A release package requires it; a `--dev` one may have it. With it, the service checks its instance's mirror about every 6 hours (`[updates] check_secs`) and installs newer client packages through the one-shot launchd job `org.faro.update` (`faro_platform_macos::update_job`). It runs as its own job because the package's preinstall stops the service, which would kill an `installer` running as its child. Only the packaged service, run as root from `/Library/Faro/bin/faro-service`, installs anything. A development build checks and logs, nothing more. The job's output goes to `update-install.log` in the state directory, and `update-attempts.json` there records the pending install and failed packages.
- **Not there yet:** the tray app.

## CI runners

CI runs on the project's self-hosted runners, registered to the `faro-project` org and matched by label:

| Labels | Machine | Jobs |
|---|---|---|
| `self-hosted, macOS, ARM64` | Apple Silicon Mac | `test (macos)` (also `faro-detect` with ONNX Runtime), `macos-pkg`, `model-eval` |
| `self-hosted, macOS, X64` | Intel Mac | `test (macos-intel)` (also `faro-detect` with ONNX Runtime), `macos-pkg-intel` |
| `self-hosted, Linux, ARM64` | Raspberry Pi | `fmt`, `test (linux)`, `web`, `deny`, the arm64 container build, the nightly `fuzz` workflow |
| `self-hosted, Windows, X64` | Windows PC | `test (windows)` |

There is no x86_64 Linux runner yet, so the amd64 container build and the multi-arch publish still run on GitHub's `ubuntu-24.04`.

Each runner runs one job at a time, and a new push to a pull request cancels its older CI run. The workflows install Rust (`dtolnay/rust-toolchain`) and Node (`actions/setup-node`) themselves. Each machine needs:

- **All:** `git`, `curl`, and a C compiler and linker for the crates with C code.
- **Linux:** `build-essential` and `pkg-config`. Docker with Buildx for the container build. If `rustup` is missing, the first job installs it with its default profile edits; give the runner its own user.
- **Windows:** Git for Windows in its default location (the `test` job puts `C:\Program Files\Git\bin` first on `PATH`, ahead of WSL's `bash`, for the toolchain action's bash steps), and the Visual Studio Build Tools C++ workload for the MSVC linker.
- **macOS:** Xcode Command Line Tools. On a Mac someone also develops on, give the runner its own rustup so CI doesn't edit their shell profile: install it with `--no-modify-path` under the runner directory, set `CARGO_HOME` and `RUSTUP_HOME` in the runner's `.env`, prepend `$CARGO_HOME/bin` to its `.path`, and restart the runner.

Jobs aren't sandboxed: anyone who can push a branch can run code on these machines as the runner's user, and files stay between jobs. Keep the runners in an account with nothing else on it where you can, and never let them take jobs from a public repository.
