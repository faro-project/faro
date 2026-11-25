# macOS installer

`build-pkg.sh` builds `target/pkg/Faro-<version>[-dev].pkg`, and `check-pkg.sh` checks a built package without installing it. See [docs/DEVELOPMENT.md](../../docs/DEVELOPMENT.md#the-macos-installer) for how to build signed packages and what is still missing.

| Path | What |
|---|---|
| `payload/` | The launchd plists, laid out as installed. Generated; see `crates/faro-platform-macos/tests/installer_plists.rs` |
| `faro-uninstall` | Installed as `/Library/Faro/bin/faro-uninstall`: stops Faro, sends allies a `goodbye`, then removes everything |
| `Info.plist.in` | `Faro Agent.app`'s Info.plist (`@VERSION@` is filled in) |
| `Distribution.xml.in` | The Installer definition: whole-computer install only, macOS 13+ |
| `resources/` | The Installer's welcome and conclusion pages |
| `test-uninstall.sh` | Checks `faro-uninstall`'s decisions on a fake `/Library` with stubbed `launchctl` and `faro-service` (CI runs it) |
| `scripts/` | `preinstall` stops a running Faro before an upgrade; `postinstall` sets ownership, installs the default `service.toml`, and starts the service and an agent in every logged-in account |
