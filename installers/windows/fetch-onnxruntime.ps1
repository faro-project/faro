<#
.SYNOPSIS
Fetch ONNX Runtime for the Windows package, checked against a pinned SHA-256
digest (ARCHITECTURE.md §3.5). build-msi.ps1 runs it.

.DESCRIPTION
  installers\windows\fetch-onnxruntime.ps1 -Out DIR

Writes into DIR:
  lib\onnxruntime.dll, lib\onnxruntime.lib   for ORT_LIB_LOCATION
  notices\onnxruntime-LICENSE.txt, notices\onnxruntime-ThirdPartyNotices.txt

Unlike the macOS package, which links pyke's static ONNX Runtime build,
faro-service.exe links ONNX Runtime dynamically on Windows and the MSI ships
onnxruntime.dll next to it. pyke's static Windows build (the one ort-sys's
dist.txt pins) is compiled with a newer MSVC STL than Visual Studio 2022
17.8 has: linking it fails on unresolved __std_*_vectorized symbols unless
the build machine has MSVC 14.40 or newer. Microsoft's own build, in the
Microsoft.ML.OnnxRuntime NuGet package, is a DLL with a plain C API, so it
links with any MSVC. The DLL is Authenticode-signed by Microsoft; this
script checks that signature and its version too.

The version must be the one ort-sys was written for (its ORT API version):
ONNX Runtime 1.22.0 for ort-sys 2.0.0-rc.10. To move to a new ONNX Runtime,
update `ort` in crates/faro-detect/Cargo.toml, installers/macos/
fetch-onnxruntime.sh, and the version and digest here.

Downloads are cached by digest in FARO_ORT_CACHE (default
%LOCALAPPDATA%\faro-onnxruntime) and checked again on every use.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ONNX Runtime 1.22.0, as ort-sys 2.0.0-rc.10 pins it.
$Version = '1.22.0'
$Url = "https://api.nuget.org/v3-flatcontainer/microsoft.ml.onnxruntime/$Version/microsoft.ml.onnxruntime.$Version.nupkg"
$Sha256 = 'd571e63a2329baacb713f441e65ad75284de354db6e1ac435fe4bebbb417986a'
# What the DLL's signature must say.
$Signer = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'

function Fail([string]$msg) { throw "fetch-onnxruntime.ps1: $msg" }

$cache = if ($env:FARO_ORT_CACHE) { $env:FARO_ORT_CACHE } else { Join-Path $env:LOCALAPPDATA 'faro-onnxruntime' }
New-Item -ItemType Directory -Force $cache, $Out | Out-Null
$cached = Join-Path $cache "sha256-$Sha256"

function Get-Sha256([string]$path) { (Get-FileHash -Algorithm SHA256 $path).Hash.ToLowerInvariant() }

if (-not (Test-Path $cached) -or (Get-Sha256 $cached) -ne $Sha256) {
    Write-Host "    downloading $Url"
    $part = "$cached.$PID.part"
    & curl.exe -fsSL --proto '=https' --retry 3 -o $part $Url
    if ($LASTEXITCODE -ne 0) { Fail "download failed: $Url" }
    $got = Get-Sha256 $part
    if ($got -ne $Sha256) { Remove-Item -Force $part; Fail "${Url}: sha256 $got, want $Sha256" }
    Move-Item -Force $part $cached
}

Write-Host "==> ONNX Runtime $Version for x86_64-pc-windows-msvc"
Add-Type -AssemblyName System.IO.Compression.FileSystem
$lib = Join-Path $Out 'lib'
$notices = Join-Path $Out 'notices'
Remove-Item -Recurse -Force $lib, $notices -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $lib, $notices | Out-Null
$want = @{
    'runtimes/win-x64/native/onnxruntime.dll' = (Join-Path $lib 'onnxruntime.dll')
    'runtimes/win-x64/native/onnxruntime.lib' = (Join-Path $lib 'onnxruntime.lib')
    'LICENSE'                                 = (Join-Path $notices 'onnxruntime-LICENSE.txt')
    'ThirdPartyNotices.txt'                   = (Join-Path $notices 'onnxruntime-ThirdPartyNotices.txt')
}
$zip = [System.IO.Compression.ZipFile]::OpenRead($cached)
try {
    foreach ($name in $want.Keys) {
        $entry = $zip.GetEntry($name)
        if ($null -eq $entry) { Fail "the package has no $name" }
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $want[$name], $true)
    }
} finally {
    $zip.Dispose()
}

$dll = $want['runtimes/win-x64/native/onnxruntime.dll']
$sig = Get-AuthenticodeSignature $dll
if ($sig.Status -ne 'Valid') { Fail "onnxruntime.dll's signature is $($sig.Status)" }
if ($sig.SignerCertificate.Subject -ne $Signer) { Fail "onnxruntime.dll is signed by $($sig.SignerCertificate.Subject)" }
# Microsoft's builds say major.minor.<build date>.<n>.<commit>: 1.22.20250508.2.f217402.
$fileVersion = (Get-Item $dll).VersionInfo.ProductVersion
$majorMinor = ($Version -split '\.')[0..1] -join '.'
if (-not $fileVersion.StartsWith("$majorMinor.")) { Fail "onnxruntime.dll is version $fileVersion (want $Version)" }
Write-Host "    onnxruntime.dll $fileVersion, signed by Microsoft"
