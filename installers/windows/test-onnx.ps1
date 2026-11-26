<#
.SYNOPSIS
Lint and test the ONNX Runtime classifier on Windows, the Windows half of
ci.yml's "faro-detect and faro-service with ONNX Runtime" step.

.DESCRIPTION
  powershell -ExecutionPolicy Bypass -File installers\windows\test-onnx.ps1

Links Microsoft's onnxruntime.dll as the MSI does (fetch-onnxruntime.ps1,
checked against its pinned SHA-256 and Microsoft's signature), never
ort-sys's download.

Windows itself ships an older onnxruntime.dll in System32 (1.17 on
Windows 11), and the loader searches System32 before PATH, so a test
binary that doesn't have the DLL in its own directory loads that one and
fails with "Failed to initialize ORT API". The installed service is not
affected: the MSI puts onnxruntime.dll next to faro-service.exe, and the
application's directory is searched first. So this script builds the test
binaries, copies the DLL next to each one, then runs them.
#>
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$repo = (Resolve-Path (Join-Path $here '..\..')).Path
function Exec([scriptblock]$cmd) {
    & $cmd
    if ($LASTEXITCODE -ne 0) { throw "test-onnx.ps1: '$cmd' exited with $LASTEXITCODE" }
}

$ort = Join-Path $repo 'target\tmp\onnxruntime-tests'
& (Join-Path $here 'fetch-onnxruntime.ps1') -Out $ort
$env:ORT_LIB_LOCATION = Join-Path $ort 'lib'
$env:ORT_PREFER_DYNAMIC_LINK = '1'
$env:ORT_SKIP_DOWNLOAD = '1'
$env:LIBONNXRUNTIME_NO_PKG_CONFIG = '1'
$dll = Join-Path $ort 'lib\onnxruntime.dll'

Push-Location $repo
try {
    Exec { cargo clippy -p faro-detect --features onnx --all-targets -- -D warnings }
    Exec { cargo clippy -p faro-service --features onnx --all-targets -- -D warnings }
    $runs = @(
        @('-p', 'faro-detect', '--features', 'onnx'),
        @('-p', 'faro-service', '--features', 'onnx', '--lib')
    )
    foreach ($args_ in $runs) {
        # Build first and put the DLL next to every test binary cargo reports.
        $json = cargo test @args_ --no-run --message-format=json
        if ($LASTEXITCODE -ne 0) { throw "test-onnx.ps1: building the tests for $($args_ -join ' ') failed" }
        $exes = $json | ForEach-Object {
            if ($_ -like '{*') {
                $m = $_ | ConvertFrom-Json
                if ($m.reason -eq 'compiler-artifact' -and $m.executable) { $m.executable }
            }
        } | Sort-Object -Unique
        foreach ($exe in $exes) { Copy-Item $dll (Split-Path $exe) -Force }
    }
    Exec { cargo test -p faro-detect --features onnx }
    Exec { cargo test -p faro-service --features onnx --lib model }
} finally {
    Pop-Location
}
