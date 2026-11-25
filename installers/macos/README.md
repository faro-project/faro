# macOS installer

`build-pkg.sh` builds the universal (arm64 + x86_64) `target/pkg/Faro-<version>[-dev].pkg`, and `check-pkg.sh` checks a built package without installing it. See [docs/DEVELOPMENT.md](../../docs/DEVELOPMENT.md#the-macos-installer) for how to build signed packages and what is still missing.

| Path | What |
|---|---|
| `payload/` | The launchd plists, laid out as installed. Generated; see `crates/faro-platform-macos/tests/installer_plists.rs` |
| `fetch-onnxruntime.sh` | Downloads ONNX Runtime's static library for each architecture and its licence files, checked against pinned SHA-256 digests; `build-pkg.sh` links faro-service with it |
| `faro-uninstall` | Installed as `/Library/Faro/bin/faro-uninstall`: stops Faro, sends allies a `goodbye`, then removes everything |
| `Info.plist.in` | `Faro Agent.app`'s Info.plist (`@VERSION@` is filled in) |
| `Distribution.xml.in` | The Installer definition: whole-computer install only, macOS 13+ |
| `resources/` | The Installer's welcome and conclusion pages |
| `test-uninstall.sh` | Checks `faro-uninstall`'s decisions on a fake `/Library` with stubbed `launchctl` and `faro-service` (CI runs it) |
| `scripts/` | `preinstall` stops a running Faro before an upgrade; `postinstall` sets ownership, installs the default `service.toml`, and starts the service and an agent in every logged-in account |

**Updates.** The service installs updates with this same package, through the launchd job `org.faro.update` (`crates/faro-platform-macos/src/update_job.rs`). The job runs `installer`, then starts the service and agents again if a failed install left them stopped. A release package must ship the project's update root of trust (`FARO_UPDATE_ROOT`, installed as `/Library/Faro/update-root.json`). `check-pkg.sh` fails a release package without it.
