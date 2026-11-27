# Faro: what is built

**As of 2026-11-27, at `0.1.0-beta.1` (checked against `main` at `cf18216`).**

[ARCHITECTURE.md](ARCHITECTURE.md) is the design. It describes the finished system, and parts of it are not built yet. This page says which parts. Where the two disagree, this page is right for today and ARCHITECTURE.md is right for the intent. Each item below was checked against the code on the date above; the evidence column names the file. The phone clients have their own status in [IOS.md](IOS.md) and [ANDROID.md](ANDROID.md).

## Built

- Email sign-in links, the only way to sign in today.
- Built-in ACME (HTTPS), and the strict Content Security Policy.
- Local-disk blob storage, SQLite, SMTP email, in-process workers, `faro-server backup` to a tarball, `faro-server doctor`.
- Clock-tamper detection, burst-mode capture, dHash dedupe, safety codes, quiet hours, hourly digests, version channel pinning.
- The IPC code-signature check.
- macOS and Windows desktop clients (Windows x64 only; no signed Windows release is published yet).
- Daily reports, built on the device.

## Partly built

| Item | What exists | What is missing | Evidence |
|---|---|---|---|
| Linux client | Session parsing (`faro-platform-linux`) | Capture, agent UI, packages; the agent refuses to run | `crates/faro-agent/src/main.rs` (`native_platform`) |
| Pausing | The service handles a pause request and sends `paused` and `resumed` | Nothing can start a pause: no web or menu control | `crates/faro-service/src/runtime/mod.rs` (`pause` has no caller outside tests) |
| Member settings (capture mean, urgency mapping, top domains) | Settings in `service.toml`, announced to allies when changed | No web or menu control | `crates/faro-service/src/config.rs` |
| False-positive marking | The report field and its display to allies | Nothing sets it; the report builder always writes none | `crates/faro-proto/src/report.rs` |
| Binary integrity check | Windows checks program-file ACLs | macOS has no check of the binaries | `crates/faro-service/src/cli.rs` |
| Device keys | A key file in the protected state directory (desktop); Keychain on iOS | TPM, CNG, Keychain and Secure Enclave on desktop; hardware keys on Android | `crates/faro-service/src/state.rs` |
| Monthly on-device notice | The notice at sign-in | The monthly notice; the sign-in text names no allies | `crates/faro-agent/src/notice.rs` |
| Privacy notice | A link on the dashboard, and `/privacy` | Showing it at signup | `web/src/routes/+page.svelte` |
| Postgres | Code path in `server/src/db` | Experimental and unsupported in the beta | `server/faro.example.toml` |
| Feed verification | In progress ([#181](https://github.com/faro-project/faro/issues/181)) | See the issue; ARCHITECTURE.md §5.3 describes the finished design | |
| Idle pause, guest sessions, the capture-hiding allowlists | Under review in [#183](https://github.com/faro-project/faro/issues/183), [#185](https://github.com/faro-project/faro/issues/185), [#186](https://github.com/faro-project/faro/issues/186) and [#187](https://github.com/faro-project/faro/issues/187) | See those issues | |

## Planned (not built)

| Item | Evidence it isn't there |
|---|---|
| Passkeys (WebAuthn, and passkey PRF unlock) | `server/src/auth/passkey.rs` is a design note with no routes |
| Signed web bundle, and the server refusing an unsigned one | `server/src/web.rs` ("Not built yet") |
| Subresource Integrity | No `integrity` attributes in `web/` or `server/build.rs` |
| Tauri tray app | `apps/` holds only `android` and `ios`; the status menu lives in the agent |
| Browser extension | `apps/` has no extension; URLs come from Accessibility or UI Automation |
| S3 blob storage, presigned URLs, backup to S3 | `server/src/blob.rs` ("Not implemented"); `backup` writes a tarball only |
| Web Push | A CHECK constraint in `0001_init.sql` only |
| `faro-server worker` | No such subcommand (`server/src/cli.rs`) |
| DNS and network signals on desktop | The trigger exists in `faro-core`'s scheduler and is never raised |
| CoreML and DirectML execution providers | CPU only |
| Weekly reports | Daily only |
| Installer link in the web app | The computers page has no link |
| Playwright E2E, Xvfb and Weston tests, reproducible builds | `crates/faro-service/tests/e2e.rs` says the Playwright suite doesn't exist |
| Generated TypeScript types | Hand-written (`DEVELOPMENT.md`, "API types") |
| Helm chart, `.deb` and `.rpm` packages | None in the tree |
| A fully static server binary | The image links against Debian's glibc (`deploy/Dockerfile`) |
| Faro Ally desktop app, OIDC/SAML SSO, an opt-in list of instances | Roadmap only (ARCHITECTURE.md §13) |

## What this means for security

Every account is as strong as its mailbox: sign-in is by emailed link, and the web app's JavaScript is neither signed nor pinned by Subresource Integrity, so an ally using the web app trusts the instance operator not to modify it. ARCHITECTURE.md §5.3 and §9 say so; [SECURITY.md](../SECURITY.md) links here.
