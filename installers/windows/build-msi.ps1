<#
.SYNOPSIS
Build Faro's Windows installer, an x64 MSI (ARCHITECTURE.md §3.3 "Windows",
§3.8).

.DESCRIPTION
  installers\windows\build-msi.ps1 -Dev -ModelDir <dir>     # unsigned development MSI
  installers\windows\build-msi.ps1 -Dev -NoOnnx             # ... without the image classifier
  $env:FARO_WINDOWS_SIGNING = 'trusted-signing'             # or signpath (sign.ps1)
  $env:FARO_WINDOWS_SIGNER = 'subject="Faro Project"'
  $env:FARO_UPDATE_ROOT = 'release\update-root.json'
  installers\windows\build-msi.ps1 -ModelDir <dir>          # release MSI

Output: target\msi\Faro-<version>[-dev]-x64.msi

Needs: Rust (x86_64-pc-windows-msvc) with the Visual Studio C++ build
tools, the .NET SDK and WiX 5.0.2 (`dotnet tool install --global wix
--version 5.0.2`; the WiX extensions are added at the same version),
cargo-about at the version release/notices/third-party.sh pins, Git for
Windows (its bash runs that script), and network access on a first build.

faro-service is built with the image classifier (feature `onnx`), linked
against Microsoft's ONNX Runtime DLL, which fetch-onnxruntime.ps1 downloads
and checks; onnxruntime.dll is installed next to faro-service.exe. (The
macOS package links ONNX Runtime statically; on Windows that needs MSVC
14.40 or newer, see fetch-onnxruntime.ps1.) The model is the one the macOS
build makes from Yahoo's original files (crates/faro-detect/models/opennsfw/
build.sh, whose pinned Python tools are macOS wheels): -ModelDir is a
directory with its manifest.json, opennsfw-int8.onnx and NOTICE.txt (CI and
the release take it from the macOS job). -NoOnnx builds faro-service without
the classifier and ships no model and no ONNX Runtime: the service then rates
frames from context signals only.

The domain list is compiled by the domains-compile example from the
approved, pinned sources, as for the macOS package, so both ship the same
bytes.

What it installs (faro_platform_windows::layout):
  C:\Program Files\Faro\faro-service.exe       the service (FaroService, LocalSystem)
  C:\Program Files\Faro\faro-agent.exe         the session agent; faro:// links open it
  C:\Program Files\Faro\onnxruntime.dll        ONNX Runtime (not with -NoOnnx)
  C:\Program Files\Faro\models\opennsfw\       the image model and its manifest
  C:\Program Files\Faro\domains\               the domain list and its manifest
  C:\Program Files\Faro\notices\               licences and attribution
  C:\Program Files\Faro\service.toml.default   the default config
  C:\Program Files\Faro\update-root.json       the update root of trust
                                               (FARO_UPDATE_ROOT; optional for -Dev)
  C:\ProgramData\Faro\service.toml             the default config, if there is none
  C:\ProgramData\Faro\, \logs\                 SYSTEM and Administrators only

A release MSI needs FARO_WINDOWS_SIGNING (a provider for sign.ps1),
FARO_WINDOWS_SIGNER (the signer requirement its service checks update
packages and agents against: compiled into faro-service and written as the
default ipc.agent_requirement) and FARO_UPDATE_ROOT. -Dev builds faro-service
with the `dev` feature instead (agents accepted by account alone, update
packages not signature-checked) and signs nothing. Never ship a -Dev MSI.
#>
[CmdletBinding()]
param(
    [switch]$Dev,
    [switch]$NoOnnx,
    [string]$ModelDir
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$WixVersion = '5.0.2'
$here = $PSScriptRoot
$repo = (Resolve-Path (Join-Path $here '..\..')).Path

function Fail([string]$msg) { throw "build-msi.ps1: $msg" }
function Step([string]$msg) { Write-Host "==> $msg" }
# Run a native command (a script block, so its arguments reach it as
# written) and fail on a non-zero exit. Windows PowerShell 5.1 turns a
# native program's stderr into error records when output is redirected (as
# in CI), so they must not stop the script: only the exit status counts.
function Exec([scriptblock]$Command) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Command } finally { $ErrorActionPreference = $old }
    if ($LASTEXITCODE -ne 0) { Fail "{ $Command } exited with $LASTEXITCODE" }
}

if ($env:OS -ne 'Windows_NT') { Fail 'build-msi.ps1 runs on Windows only' }

# ---- version ---------------------------------------------------------------
$m = Select-String -Path (Join-Path $repo 'Cargo.toml') -Pattern '^version = "(.*)"' | Select-Object -First 1
if (-not $m) { Fail 'cannot read the workspace version' }
$version = $m.Matches[0].Groups[1].Value
# Windows Installer versions are numeric (major <= 255, minor <= 255,
# build <= 65535) and can't hold a pre-release: 0.1.0-beta.1 -> 0.1.0. The
# full semver goes into the FaroVersion property, which the updater reads
# (crates/faro-service/src/update/msi.rs).
if ($version -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$') {
    Fail "the workspace version $version is not semver"
}
$productVersion = "$($Matches[1]).$($Matches[2]).$($Matches[3])"
if ([int]$Matches[1] -gt 255 -or [int]$Matches[2] -gt 255 -or [int]$Matches[3] -gt 65535) {
    Fail "$version doesn't fit a Windows Installer version"
}

# ---- mode --------------------------------------------------------------------
$features = @()
if (-not $NoOnnx) { $features += 'faro-service/onnx' }
$signing = & (Join-Path $here 'sign.ps1') -Provider
if ($Dev) {
    $name = "Faro-$version-dev-x64"
    $features += 'faro-service/dev'
    # A development service must not carry a release signer by accident.
    Remove-Item Env:FARO_WINDOWS_SIGNER -ErrorAction SilentlyContinue
} else {
    $name = "Faro-$version-x64"
    if ($signing -eq 'none') { Fail 'a release MSI needs FARO_WINDOWS_SIGNING (see sign.ps1), or build an unsigned one with -Dev' }
    foreach ($v in 'FARO_WINDOWS_SIGNER', 'FARO_UPDATE_ROOT') {
        if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($v))) {
            Fail "a release MSI needs $v (or build an unsigned one with -Dev)"
        }
    }
    # The SignerRequirement syntax (faro_platform_windows::authenticode).
    # faro-service compiles it in (option_env!) and the default config's
    # agent requirement is the same text, in single quotes.
    if ($env:FARO_WINDOWS_SIGNER -notmatch '^subject="[^"'']+"(; sha256=[0-9a-f]{64}(,[0-9a-f]{64})*)?$') {
        Fail 'FARO_WINDOWS_SIGNER must be subject="<CN>" optionally followed by "; sha256=<hex>[,<hex>...]"'
    }
}
if (-not $NoOnnx) {
    if (-not $ModelDir) { Fail 'give -ModelDir (the model from crates/faro-detect/models/opennsfw/build.sh) or build with -NoOnnx' }
    foreach ($f in 'manifest.json', 'opennsfw-int8.onnx', 'NOTICE.txt') {
        if (-not (Test-Path -LiteralPath (Join-Path $ModelDir $f))) { Fail "-ModelDir $ModelDir has no $f" }
    }
}
if ($env:FARO_UPDATE_ROOT -and -not (Test-Path -LiteralPath $env:FARO_UPDATE_ROOT -PathType Leaf)) {
    Fail "FARO_UPDATE_ROOT: no such file $env:FARO_UPDATE_ROOT"
}

# ---- tools ---------------------------------------------------------------------
$toolsDir = Join-Path $env:USERPROFILE '.dotnet\tools'
if ((Test-Path $toolsDir) -and ($env:PATH -notlike "*$toolsDir*")) { $env:PATH = "$env:PATH;$toolsDir" }
$wix = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wix) { Fail "WiX is missing: dotnet tool install --global wix --version $WixVersion" }
$have = (& wix --version) -replace '\+.*$', ''
if ($have -ne $WixVersion) { Fail "WiX $have is installed; this build needs $WixVersion (dotnet tool update --global wix --version $WixVersion)" }
foreach ($ext in 'WixToolset.Util.wixext', 'WixToolset.UI.wixext') {
    if (-not ((& wix extension list -g) -match "^$([regex]::Escape($ext)) $([regex]::Escape($WixVersion))")) {
        Exec { & wix extension add -g "$ext/$WixVersion" }
    }
}
$bash = 'C:\Program Files\Git\bin\bash.exe'
if (-not (Test-Path $bash)) { Fail "Git for Windows' bash is missing ($bash)" }

$out = Join-Path $repo 'target\msi'
$work = Join-Path $out 'work'
$payload = Join-Path $work 'payload'
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $payload, (Join-Path $payload 'notices'), (Join-Path $payload 'domains') | Out-Null

# ---- notices -------------------------------------------------------------------
Step 'third-party notices'
# Git Bash; the checkout may have CRLF line ends (core.autocrlf).
$bashPath = { param($p) (& $bash -c "cygpath -u '$p'") }
Exec { & $bash -o igncr (& $bashPath (Join-Path $repo 'release\notices\third-party.sh')) windows (& $bashPath (Join-Path $payload 'notices\third-party.txt')) }

# ---- the domain list -------------------------------------------------------------
Step 'the domain list'
$domainsConfig = Join-Path $repo 'crates\faro-detect\domains\sources.toml'
$sources = Join-Path $repo 'target\domains\sources'
$domains = Join-Path $payload 'domains'
$compile = @('run', '--manifest-path', (Join-Path $repo 'Cargo.toml'), '--locked', '--quiet', '-p', 'faro-detect', '--example', 'domains-compile', '--')
Exec { & cargo @compile fetch --config $domainsConfig --sources-dir $sources }
Exec { & cargo @compile build --config $domainsConfig --sources-dir $sources --out (Join-Path $domains 'domains.bin') }
Exec { & cargo @compile notice --manifest (Join-Path $domains 'domains.manifest.json') --out (Join-Path $payload 'notices\domains.txt') }

# ---- ONNX Runtime and the model ------------------------------------------------------
foreach ($v in 'ORT_LIB_LOCATION', 'ORT_PREFER_DYNAMIC_LINK', 'ORT_LIB_PROFILE', 'ORT_DYLIB_PATH', 'ORT_CXX_STDLIB', 'ORT_SKIP_DOWNLOAD') {
    Remove-Item "Env:$v" -ErrorAction SilentlyContinue
}
if (-not $NoOnnx) {
    $ort = Join-Path $work 'onnxruntime'
    & (Join-Path $here 'fetch-onnxruntime.ps1') -Out $ort
    # Link Microsoft's import library; never ort-sys's download or a
    # system copy.
    $env:ORT_LIB_LOCATION = Join-Path $ort 'lib'
    $env:ORT_PREFER_DYNAMIC_LINK = '1'
    $env:ORT_SKIP_DOWNLOAD = '1'
    $env:LIBONNXRUNTIME_NO_PKG_CONFIG = '1'
    Copy-Item (Join-Path $ort 'lib\onnxruntime.dll') $payload
    Copy-Item (Join-Path $ort 'notices\*') (Join-Path $payload 'notices')
    $modelOut = Join-Path $payload 'models\opennsfw'
    New-Item -ItemType Directory -Force $modelOut | Out-Null
    Copy-Item (Join-Path $ModelDir 'manifest.json'), (Join-Path $ModelDir 'opennsfw-int8.onnx') $modelOut
    Copy-Item (Join-Path $ModelDir 'NOTICE.txt') (Join-Path $payload 'notices\opennsfw.txt')
}

# ---- the programs ----------------------------------------------------------------------
Step "building faro-service and faro-agent ($version; x86_64-pc-windows-msvc; $(if ($features) { $features -join ', ' } else { 'no features' }))"
$cargoArgs = @('build', '--manifest-path', (Join-Path $repo 'Cargo.toml'), '--release', '--locked', '-p', 'faro-service', '-p', 'faro-agent')
foreach ($f in $features) { $cargoArgs += @('--features', $f) }
Exec { & cargo @cargoArgs }
$bin = Join-Path $repo 'target\release'
Copy-Item (Join-Path $bin 'faro-service.exe'), (Join-Path $bin 'faro-agent.exe') $payload
if ($env:FARO_UPDATE_ROOT) { Copy-Item -LiteralPath $env:FARO_UPDATE_ROOT (Join-Path $payload 'update-root.json') }

# The default service config. Only the agent requirement differs from the
# built-in defaults; the MSI installs it as C:\ProgramData\Faro\service.toml
# if there is none.
$toml = @(
    '# Faro service configuration (installed by the MSI).'
    '# See crates/faro-service/src/config.rs for every setting.'
    '#'
    '# How much goes to C:\ProgramData\Faro\logs\faro-service.log (restart the'
    '# service after changing it). debug and trace may log private details.'
    '# log_level = "info"'
)
if ($Dev) {
    $toml += '# Development package: no agent_requirement; the dev build accepts'
    $toml += '# agents by account alone.'
} else {
    $toml += ''
    $toml += '[ipc]'
    $toml += "agent_requirement = '$env:FARO_WINDOWS_SIGNER'"
}
[IO.File]::WriteAllText((Join-Path $payload 'service.toml.default'), (($toml -join "`r`n") + "`r`n"))

# The service loads the staged model and domain list as it will once
# installed: licence, attribution and digest checks, then ONNX Runtime on a
# few synthetic frames.
$service = Join-Path $payload 'faro-service.exe'
if (-not $NoOnnx) {
    Step 'checking the model with the staged faro-service'
    Exec { & $service model-check --manifest (Join-Path $payload 'models\opennsfw\manifest.json') --runs 3 }
}
Step 'checking the domain list with the staged faro-service'
Exec { & $service domains-check --manifest (Join-Path $domains 'domains.manifest.json') }

# ---- signing the programs ----------------------------------------------------------
# onnxruntime.dll keeps Microsoft's signature.
if (-not $Dev) {
    Step "signing the programs ($signing)"
    & (Join-Path $here 'sign.ps1') -Files (Join-Path $payload 'faro-service.exe'), (Join-Path $payload 'faro-agent.exe')
}

# ---- the MSI -----------------------------------------------------------------------
Step 'building the MSI'
$rtf = [IO.File]::ReadAllText((Join-Path $here 'notice.rtf'))
$banner = ''
if ($Dev) {
    $banner = '{\b\cf0 Development package.} Unsigned, and its service accepts any program running in a signed-in account as the agent. Do not use it to monitor anyone.\par '
}
$noticeRtf = Join-Path $work 'notice.rtf'
[IO.File]::WriteAllText($noticeRtf, $rtf.Replace('%DEV-BANNER%', $banner))
$msi = Join-Path $out "$name.msi"
Remove-Item -Force $msi -ErrorAction SilentlyContinue
$defines = @{
    Payload        = $payload
    ProductVersion = $productVersion
    FaroVersion    = $version
    HasUpdateRoot  = $(if (Test-Path (Join-Path $payload 'update-root.json')) { '1' } else { '0' })
    HasModel       = $(if ($NoOnnx) { '0' } else { '1' })
    NoticeRtf      = $noticeRtf
    Dev            = $(if ($Dev) { '1' } else { '0' })
}
$wixArgs = @('build', '-arch', 'x64', '-ext', "WixToolset.Util.wixext/$WixVersion", '-ext', "WixToolset.UI.wixext/$WixVersion",
    '-pdbtype', 'none', '-o', $msi)
foreach ($k in $defines.Keys) { $wixArgs += @('-d', "$k=$($defines[$k])") }
$wixArgs += (Join-Path $here 'Faro.wxs')
Exec { & wix @wixArgs }

if (-not $Dev) {
    Step "signing the MSI ($signing)"
    & (Join-Path $here 'sign.ps1') -Files $msi
}
Step $msi
