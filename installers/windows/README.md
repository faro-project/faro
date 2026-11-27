# Windows installer

`build-msi.ps1` builds `target\msi\Faro-<version>[-dev]-x64.msi`, a per-machine x64 Windows Installer package (WiX 5.0.2, pinned), and `check-msi.ps1` checks one: statically, then (elevated) with a real install and uninstall. See [docs/DEVELOPMENT.md](../../docs/DEVELOPMENT.md#the-windows-installer) for how to build signed packages and what is still missing.

```powershell
dotnet tool install --global wix --version 5.0.2                  # once
installers\windows\build-msi.ps1 -Dev -NoOnnx                      # unsigned, no image classifier
installers\windows\build-msi.ps1 -Dev -ModelDir <dir>              # unsigned, with the model
installers\windows\check-msi.ps1 target\msi\Faro-0.1.0-beta.1-dev-x64.msi   # elevated shell: also installs it
```

| Path | What |
|---|---|
| `Faro.wxs` | The package: files, the service, the `faro://` handler, the state directory, the uninstall's goodbye |
| `build-msi.ps1` | Builds the programs, the domain list and the notices, stages the payload, builds the MSI |
| `check-msi.ps1` | Checks the MSI's tables and files, and (elevated) installs, checks and uninstalls it |
| `sign.ps1` | Authenticode signing through the SignPath Foundation or Azure Trusted Signing, chosen by `FARO_WINDOWS_SIGNING` |
| `fetch-onnxruntime.ps1` | Downloads Microsoft's ONNX Runtime 1.22.0 DLL and import library, checked against a pinned SHA-256 and Microsoft's signature |
| `notice.rtf` | The installer's first page |

## What it installs

The paths are `faro_platform_windows::layout`'s.

| Where | What |
|---|---|
| `C:\Program Files\Faro\faro-service.exe`, `faro-agent.exe` | The programs |
| `C:\Program Files\Faro\onnxruntime.dll`, `models\opennsfw\`, `domains\`, `notices\` | ONNX Runtime and the image model (not with `-NoOnnx`), the domain list, licences |
| `C:\Program Files\Faro\update-root.json` | The update root of trust (`FARO_UPDATE_ROOT`; optional for `-Dev`) |
| `C:\ProgramData\Faro\` | The state directory: SYSTEM and Administrators only, not inherited. `logs\` is readable by Administrators. `service.toml` is the default config, written only if there is none |
| `HKLM\Software\Classes\faro` | `faro://` links open `"C:\Program Files\Faro\faro-agent.exe" open-url "%1"`, for every account |
| Apps & features | "Faro" by Faro Project; no Modify |

## Decisions

- **The service is registered by Windows Installer, not by a faro-service subcommand.** `ServiceInstall` (LocalSystem, automatic start, `faro-service.exe run-service`), `util:ServiceConfig` (restart after each of the first three failures, 10 s, reset after a day), a `PermissionEx` DACL (SYSTEM and Administrators full control; authenticated users may only query it, so an ordinary account can't stop Faro), and `ServiceControl` (start on install, stop on install and uninstall, `Wait="yes"`). Windows Installer rolls all of that back if the new service doesn't start, which is what a failed update relies on. Nothing in faro-service has to run during install.
- **Uninstall sends the goodbye first.** A deferred custom action runs `faro-service.exe goodbye --reason uninstalled --within 30` (the command `faro-uninstall` runs on macOS) as SYSTEM after `StopServices` (the command takes the state lock, which a running service holds) and before the service is deleted or any file is removed. It runs on a real uninstall only, not on an upgrade, and `Return="ignore"`: offline, nothing is delivered and allies see a missed check-in instead. Its output is in the MSI log. A third custom action stops every session's agent (`taskkill /F /T /IM faro-agent.exe`) so its file can be removed.
- **A real uninstall removes the state directory** (the device key, outbox, downloaded updates, logs). An upgrade never does: those components are permanent, and the old product is removed before the new one is installed.
- **Versions.** An MSI's `ProductVersion` is numeric (`major.minor.build`), so `0.1.0-beta.1` is `0.1.0`. The MSI also carries the full version in the `FaroVersion` property, which the updater reads, and `MajorUpgrade` allows same-version upgrades so beta N to beta N+1 works. The updater orders versions by `FaroVersion`.
- **The UpgradeCode never changes** (`07FB4D24-3048-4FE8-AFCF-2C9549BC9982`). The updater refuses an MSI with another one.
- **Windows 10 22H2 (build 19045) or later, 64-bit**, checked by launch conditions.

## ONNX Runtime

`faro-service` is built with the image classifier (`--features onnx`) against Microsoft's `onnxruntime.dll`, which the MSI installs next to it (`fetch-onnxruntime.ps1`). The macOS package links pyke's static library instead; on Windows that library needs MSVC 14.40 or newer, so the DLL is the portable choice. The model is the macOS build's (`crates/faro-detect/models/opennsfw/build.sh` uses macOS-only Python wheels): pass its output with `-ModelDir`. Release MSIs always include the model. `-NoOnnx` builds a service that rates frames from context signals only, with no model and no ONNX Runtime; it is for development, and CI's per-PR MSI is built that way because CI has no model build. CI still lints and tests the classifier on Windows (`test-onnx.ps1`), and the release job's `check-msi.ps1` checks the packaged model's scores and `onnxruntime.dll`, and its install half checks that the installed service loads the model and domain list from their default paths. Windows ships its own older `onnxruntime.dll` in `System32`; Faro's copy next to `faro-service.exe` is the one loaded, because the application's directory is searched first.

## Subcommands this package relies on

The package assumes these exist in the programs it installs (the integration step adds the missing ones):

- `faro-service.exe run-service`: runs as the Windows service (the SCM entry point).
- `faro-service.exe goodbye --reason uninstalled --within 30`: exists (`crates/faro-service/src/cli.rs`). Without `--state-dir` it must use `C:\ProgramData\Faro`.
- `faro-agent.exe open-url "<faro:// URL>"`: hands the link to the running agent for this account, or starts one.
- `faro-service.exe model-check --manifest <path> --runs 3` and `domains-check --manifest <path>`: exist; `build-msi.ps1` and `check-msi.ps1` run them.

## Signing

`sign.ps1` signs with the provider named by the Actions variable `FARO_WINDOWS_SIGNING`:

- `signpath` (the SignPath Foundation): `SIGNPATH_API_TOKEN` (secret), `FARO_SIGNPATH_ORGANIZATION_ID`, `FARO_SIGNPATH_PROJECT`, optionally `FARO_SIGNPATH_POLICY`, `FARO_SIGNPATH_CONFIG_EXE`, `FARO_SIGNPATH_CONFIG_MSI`.
- `trusted-signing` (Azure Trusted Signing): `FARO_TRUSTED_SIGNING_ENDPOINT`, `FARO_TRUSTED_SIGNING_ACCOUNT`, `FARO_TRUSTED_SIGNING_PROFILE`, and Azure credentials (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` secrets).
- empty: nothing is signed, with a loud "UNSIGNED BUILD" warning. A release MSI can't be built then (`build-msi.ps1` refuses), and the release workflow builds no Windows package.

A release MSI also needs `FARO_WINDOWS_SIGNER` (`subject="<certificate CN>"` plus a pin: `; sha256=<leaf thumbprint>[,...]` and/or `; issuer_sha256=<issuing CA thumbprint>[,...]`): the signer requirement compiled into `faro-service`, which it checks update packages and agents against. `build-msi.ps1` refuses a release whose requirement has no pin, because a subject alone is satisfied by any CA that will issue a certificate with that name. `sign.ps1` prints both thumbprints after signing. Examples:

- SignPath Foundation (its certificate names the foundation for every project it serves, so the leaf pin is what makes it yours): `subject="SignPath Foundation"; sha256=<64 hex digits>`.
- Azure Trusted Signing (leaf certificates are renewed every few days, so pin the issuing CA, whose thumbprint is stable): `subject="<your validated name>"; issuer_sha256=<64 hex digits>`.

Also `FARO_UPDATE_ROOT` (`release/update-root.json`).

A `-Dev` MSI is unsigned, and its service accepts any program in a signed-in account as the agent and skips the update signature check. Never use one on anyone.

## Updates

The service installs updates with this same MSI: `msiexec /i <package> /qn /norestart /l*v C:\ProgramData\Faro\update-install.log REBOOT=ReallySuppress`, started detached so it outlives the service that the MSI stops (`crates/faro-service/src/update/install.rs`). Before that, `update/msi.rs` checks the package's Authenticode signature against the compiled-in signer, its UpgradeCode, and its `FaroVersion`. `check-msi.ps1` fails a release MSI without `update-root.json`.
