<#
.SYNOPSIS
Check a built Faro MSI: what it would install and how, then (elevated)
install it, check the live result, uninstall it and check nothing is left.
The Windows counterpart of installers/macos/check-pkg.sh.

.DESCRIPTION
  installers\windows\check-msi.ps1 target\msi\Faro-<version>[-dev]-x64.msi
  installers\windows\check-msi.ps1 -NoInstall <msi>     # the static checks only
  installers\windows\check-msi.ps1 -RequireInstall <msi>  # fail if not elevated

Static checks (any account; nothing is installed). From the MSI's tables
(read with the Windows Installer API):
  - per-machine, x64, Faro's UpgradeCode, a ProductVersion that is the
    numeric part of the version in the file name, and FaroVersion (the full
    semver version, which the updater reads) equal to it;
  - every file at its place under C:\Program Files\Faro
    (faro_platform_windows::layout);
  - the service FaroService: own process, automatic start, LocalSystem,
    `faro-service.exe run-service`, started on install and stopped and
    removed on uninstall with Windows Installer waiting for it, restarted on
    failure (util:ServiceConfig), and a DACL that lets only SYSTEM and
    Administrators start, stop, change or delete it;
  - %ProgramData%\Faro and its logs with SYSTEM/Administrators-only DACLs;
  - the faro:// handler under HKLM\Software\Classes;
  - the uninstall's goodbye: `faro-service.exe goodbye --reason uninstalled`,
    deferred, as SYSTEM, never failing the uninstall, on a real uninstall
    only (not an upgrade), after the service is stopped and before it is
    deleted or any file is removed.
From the files (extracted with an administrative install into a temporary
directory, which needs no elevation for this package):
  - the notices with the licence texts and attribution, as check-pkg.sh
    wants them;
  - faro-service.exe reports the version; it loads the packaged model and
    scores three solid colours within 0.05 of Yahoo's original, and loads
    the domain list as the service does; a release build ignores
    [dev_thresholds], a -Dev one applies it;
  - a release MSI: the MSI and both programs carry valid Authenticode
    signatures, update-root.json is a signed root, and faro-service.exe has
    the default config's signer requirement compiled in.

Install checks (elevated, and only where the environment variable
FARO_CHECK_MSI_INSTALL=1 is set or -RequireInstall is given, since they install
and remove a service as an administrator; skipped otherwise): install
quietly, then check the files, the service's configuration, recovery actions
and DACL (sc.exe), that it runs, the URL handler, the ProgramData ACLs and the
Apps & features entry; uninstall quietly, check the log shows the goodbye
ran, and check the service, the files, the state directory and the registry
keys are gone. It refuses to run where Faro is already installed: the
uninstall would remove it and tell its allies.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)][string]$Msi,
    [switch]$NoInstall,
    [switch]$RequireInstall
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$UpgradeCode = '{07FB4D24-3048-4FE8-AFCF-2C9549BC9982}'
$ServiceName = 'FaroService'
$ProgramDir = 'C:\Program Files\Faro'
$DataDir = Join-Path $env:ProgramData 'Faro'
# Equal to faro_platform_windows::scm::SERVICE_SDDL and the PermissionEx in
# Faro.wxs (a test in scm.rs checks all three agree).
$ServiceSddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLORC;;;IU)(A;;CCLCSWLORC;;;SU)'
$UrlCommand = '"C:\Program Files\Faro\faro-agent.exe" open-url "%1"'
# p(nsfw) of Yahoo's Caffe model for solid black, white and grey (128), as
# check-pkg.sh has them (crates/faro-detect/models/opennsfw/parity.py).
$ModelReference = @{ 'solid-black' = 0.066799; 'solid-white' = 0.014106; 'solid-grey' = 0.197584 }
$ModelTolerance = 0.05

function Fail([string]$msg) { throw "check-msi: $msg" }
function Say([string]$msg) { Write-Host "check-msi: $msg" }
function Exec([scriptblock]$Command) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Command } finally { $ErrorActionPreference = $old }
}

$Msi = (Resolve-Path -LiteralPath $Msi).Path
$leaf = Split-Path -Leaf $Msi
if ($leaf -notmatch '^Faro-(.+?)(-dev)?-x64\.msi$') { Fail "cannot read a version from the file name $leaf" }
$version = $Matches[1]
$dev = [bool]$Matches[2]
if ($version -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$') {
    Fail "$version (from the file name) is not semver"
}
$productVersion = "$($Matches[1]).$($Matches[2]).$($Matches[3])"
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

# ==== the MSI's tables ========================================================
$installer = New-Object -ComObject WindowsInstaller.Installer
function Invoke-Com($obj, [string]$member, [string]$kind, [object[]]$params) {
    $obj.GetType().InvokeMember($member, [Reflection.BindingFlags]$kind, $null, $obj, $params)
}
$db = Invoke-Com $installer 'OpenDatabase' 'InvokeMethod' @($Msi, 0)
# Rows of a query, each an array of strings.
function Get-Rows([string]$sql, [int]$columns) {
    $view = Invoke-Com $db 'OpenView' 'InvokeMethod' @($sql)
    Invoke-Com $view 'Execute' 'InvokeMethod' @() | Out-Null
    $rows = @()
    while ($true) {
        $rec = Invoke-Com $view 'Fetch' 'InvokeMethod' @()
        if ($null -eq $rec) { break }
        $row = @(for ($i = 1; $i -le $columns; $i++) { Invoke-Com $rec 'StringData' 'GetProperty' @($i) })
        $rows += , $row
    }
    Invoke-Com $view 'Close' 'InvokeMethod' @() | Out-Null
    , $rows
}
function Get-Property([string]$name) {
    $r = Get-Rows "SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = '$name'" 1
    if ($r.Count -eq 0) { return $null }
    $r[0][0]
}
function Expect-Property([string]$name, [string]$want) {
    $got = Get-Property $name
    if ($got -ne $want) { Fail "property $name is '$got' (want '$want')" }
}
function Has-Table([string]$name) {
    (Get-Rows "SELECT ``Name`` FROM ``_Tables`` WHERE ``Name`` = '$name'" 1).Count -eq 1
}

Say "$leaf ($version, $(if ($dev) { 'development' } else { 'release' }))"
$summary = Invoke-Com $db 'SummaryInformation' 'GetProperty' @(0)
$template = Invoke-Com $summary 'Property' 'GetProperty' @(7)
if ($template -notmatch '^x64;') { Fail "the package's platform is '$template' (want x64)" }
Expect-Property 'UpgradeCode' $UpgradeCode
Expect-Property 'ProductVersion' $productVersion
Expect-Property 'FaroVersion' $version
Expect-Property 'ALLUSERS' '1'
Expect-Property 'Manufacturer' 'Faro Project'
Expect-Property 'ARPNOMODIFY' '1'
if (-not (Get-Rows "SELECT ``UpgradeCode`` FROM ``Upgrade`` WHERE ``UpgradeCode`` = '$UpgradeCode'" 1).Count) {
    Fail 'no MajorUpgrade of Faro''s UpgradeCode'
}

# Directories, resolved to install paths.
$dirs = @{}
foreach ($r in (Get-Rows 'SELECT `Directory`, `Directory_Parent`, `DefaultDir` FROM `Directory`' 3)) {
    $dirs[$r[0]] = $r
}
function Resolve-Dir([string]$id) {
    switch ($id) {
        'ProgramFiles64Folder' { return 'C:\Program Files' }
        'CommonAppDataFolder' { return $env:ProgramData }
        'TARGETDIR' { return '' }
    }
    $d = $dirs[$id]
    if ($null -eq $d) { Fail "no directory $id" }
    $name = ($d[2] -split ':')[-1]
    $name = ($name -split '\|')[-1]
    $parent = Resolve-Dir $d[1]
    if ($name -eq '.') { return $parent }
    if ($parent -eq '') { return $name }
    Join-Path $parent $name
}
$comps = @{}
foreach ($r in (Get-Rows 'SELECT `Component`, `Directory_`, `Attributes` FROM `Component`' 3)) { $comps[$r[0]] = $r }
$files = @{}
foreach ($r in (Get-Rows 'SELECT `File`, `Component_`, `FileName` FROM `File`' 3)) {
    $name = ($r[2] -split '\|')[-1]
    $files[(Join-Path (Resolve-Dir $comps[$r[1]][1]) $name)] = $r
}
$want = @(
    "$ProgramDir\faro-service.exe"
    "$ProgramDir\faro-agent.exe"
    "$ProgramDir\service.toml.default"
    "$ProgramDir\domains\domains.manifest.json"
    "$ProgramDir\domains\domains.bin"
    "$ProgramDir\notices\domains.txt"
    "$ProgramDir\notices\third-party.txt"
    "$DataDir\service.toml"
)
$hasModel = $files.ContainsKey("$ProgramDir\models\opennsfw\manifest.json")
if ($hasModel) {
    $want += @(
        "$ProgramDir\onnxruntime.dll"
        "$ProgramDir\models\opennsfw\opennsfw-int8.onnx"
        "$ProgramDir\notices\opennsfw.txt"
        "$ProgramDir\notices\onnxruntime-LICENSE.txt"
        "$ProgramDir\notices\onnxruntime-ThirdPartyNotices.txt"
    )
} else {
    Say 'no image model in this MSI (built with -NoOnnx): the service rates frames from context signals only'
}
$hasRoot = $files.ContainsKey("$ProgramDir\update-root.json")
if (-not $hasRoot -and -not $dev) { Fail "a release MSI must ship $ProgramDir\update-root.json" }
foreach ($f in $want) { if (-not $files.ContainsKey($f)) { Fail "the MSI doesn't install $f" } }
foreach ($f in $files.Keys) {
    if (-not ($f.StartsWith("$ProgramDir\") -or $f -eq "$DataDir\service.toml")) { Fail "the MSI installs $f, outside Faro's directories" }
}
# The default config is installed only if there is none, and kept.
$tomlComp = $comps[$files["$DataDir\service.toml"][1]]
$attrs = [int]$tomlComp[2]
if (-not ($attrs -band 0x10) -or -not ($attrs -band 0x80)) { Fail "$DataDir\service.toml must be Permanent and NeverOverwrite" }

# The service.
$svc = Get-Rows "SELECT ``Name``, ``ServiceType``, ``StartType``, ``ErrorControl``, ``StartName``, ``Arguments``, ``Component_`` FROM ``ServiceInstall``" 7
if ($svc.Count -ne 1) { Fail "the MSI installs $($svc.Count) services (want 1)" }
$s = $svc[0]
if ($s[0] -ne $ServiceName) { Fail "the service is named $($s[0])" }
if ([int]$s[1] -ne 0x10) { Fail "the service type is $($s[1]) (want own process, 16)" }
if ([int]$s[2] -ne 2) { Fail "the service start type is $($s[2]) (want automatic, 2)" }
if ($s[4] -ne 'LocalSystem') { Fail "the service runs as '$($s[4])' (want LocalSystem)" }
if ($s[5] -ne 'run-service') { Fail "the service runs with '$($s[5])' (want run-service)" }
if ($files["$ProgramDir\faro-service.exe"][1] -ne $s[6]) { Fail 'the service is not faro-service.exe''s component' }
$ctl = Get-Rows "SELECT ``Name``, ``Event``, ``Wait`` FROM ``ServiceControl``" 3
if ($ctl.Count -ne 1 -or $ctl[0][0] -ne $ServiceName) { Fail 'the MSI must control FaroService only' }
# Start on install (1), stop on install (2) and uninstall (0x20), delete on uninstall (0x80).
if ([int]$ctl[0][1] -ne (0x1 -bor 0x2 -bor 0x20 -bor 0x80)) { Fail "ServiceControl events are $($ctl[0][1]) (want 163)" }
if ($ctl[0][2] -ne '1') { Fail 'Windows Installer must wait for the service' }
if (-not (Has-Table 'Wix4ServiceConfig')) { Fail 'no recovery actions (util:ServiceConfig)' }
$rec = Get-Rows 'SELECT `ServiceName`, `FirstFailureActionType`, `SecondFailureActionType`, `ThirdFailureActionType`, `ResetPeriodInDays`, `RestartServiceDelayInSeconds` FROM `Wix4ServiceConfig`' 6
if ($rec.Count -ne 1 -or $rec[0][0] -ne $ServiceName -or ($rec[0][1..3] -ne 'restart').Count -ne 0) {
    Fail "recovery actions: $($rec | ForEach-Object { $_ -join ',' })"
}
$locks = Get-Rows 'SELECT `LockObject`, `Table`, `SDDLText` FROM `MsiLockPermissionsEx`' 3
function Get-Lock([string]$table, [string]$object) {
    $l = @($locks | Where-Object { $_[1] -eq $table -and $_[0] -eq $object })
    if ($l.Count -ne 1) { Fail "no single DACL for $table $object" }
    $l[0][2]
}
$got = Get-Lock 'ServiceInstall' 'FaroService'
if ($got -ne $ServiceSddl) { Fail "the service DACL is $got (want $ServiceSddl)" }
$dataSddl = Get-Lock 'CreateFolder' 'FaroDataDir'
if ($dataSddl -ne 'O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)') { Fail "the state directory's DACL is $dataSddl" }
$logSddl = Get-Lock 'CreateFolder' 'FaroLogDir'
if ($logSddl -ne 'O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FR;;;BA)') { Fail "the log directory's DACL is $logSddl" }
if ((Resolve-Dir 'FaroDataDir') -ne $DataDir -or (Resolve-Dir 'FaroLogDir') -ne "$DataDir\logs") { Fail 'the state directories are not where layout.rs says' }

# The faro:// handler, per machine (Root 2 = HKLM).
$reg = Get-Rows 'SELECT `Root`, `Key`, `Name`, `Value` FROM `Registry`' 4
function Get-Reg([string]$key, [string]$name) {
    $r = @($reg | Where-Object { $_[0] -eq '2' -and $_[1] -eq $key -and $_[2] -eq $name })
    if ($r.Count -ne 1) { Fail "no HKLM\$key [$name] in the MSI" }
    $r[0][3]
}
if ((Get-Reg 'Software\Classes\faro' '') -ne 'URL:Faro') { Fail 'the faro: key has no URL description' }
Get-Reg 'Software\Classes\faro' 'URL Protocol' | Out-Null
$cmd = Get-Reg 'Software\Classes\faro\shell\open\command' ''
if ($cmd -ne '"[FaroProgramDir]faro-agent.exe" open-url "%1"') { Fail "the faro: command is $cmd" }
if (Get-Rows 'SELECT `Root` FROM `Registry` WHERE `Root` = 1' 1 | Where-Object { $_ }) { Fail 'the MSI writes per-user registry keys' }

# The goodbye and the agents, in the execute sequence.
$seq = @{}
foreach ($r in (Get-Rows 'SELECT `Action`, `Condition`, `Sequence` FROM `InstallExecuteSequence`' 3)) { $seq[$r[0]] = $r }
foreach ($a in 'StopServices', 'FaroStopAgents', 'FaroGoodbye', 'FaroRemoveState', 'DeleteServices', 'RemoveFiles', 'InstallFiles') {
    if (-not $seq.ContainsKey($a)) { Fail "the execute sequence has no $a" }
}
$order = 'StopServices', 'FaroStopAgents', 'FaroGoodbye', 'FaroRemoveState', 'DeleteServices', 'RemoveFiles'
for ($i = 1; $i -lt $order.Count; $i++) {
    if ([int]$seq[$order[$i - 1]][2] -ge [int]$seq[$order[$i]][2]) { Fail "$($order[$i - 1]) must come before $($order[$i])" }
}
foreach ($a in 'FaroGoodbye', 'FaroRemoveState') {
    $cond = $seq[$a][1]
    if ($cond -notmatch 'REMOVE~="ALL"' -or $cond -notmatch 'NOT UPGRADINGPRODUCTCODE') { Fail "$a runs on '$cond' (want a real uninstall only)" }
}
$cas = @{}
foreach ($r in (Get-Rows 'SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction`' 4)) { $cas[$r[0]] = $r }
foreach ($a in 'FaroGoodbye', 'FaroStopAgents', 'FaroRemoveState') {
    $t = [int]$cas[$a][1]
    # Deferred (0x400), no impersonation (0x800), return ignored (0x40).
    if (($t -band 0x400) -eq 0 -or ($t -band 0x800) -eq 0 -or ($t -band 0x40) -eq 0) { Fail "$a is not deferred as SYSTEM with its exit status ignored (type $t)" }
}
# The property holding its command line (a type 51 action, WiX's SetProperty).
$data = @($cas.Values | Where-Object { ((([int]$_[1]) -band 0x3F) -eq 0x33) -and $_[2] -eq 'FaroGoodbye' })
if ($data.Count -ne 1) { Fail 'no command line for FaroGoodbye' }
if ($data[0][3] -ne '"[FaroProgramDir]faro-service.exe" goodbye --reason uninstalled --within 30') { Fail "the goodbye runs $($data[0][3])" }
$data = @($cas.Values | Where-Object { ((([int]$_[1]) -band 0x3F) -eq 0x33) -and $_[2] -eq 'FaroRemoveState' })
if ($data.Count -ne 1 -or $data[0][3] -ne '"[System64Folder]cmd.exe" /d /c rmdir /s /q "[FaroDataDir]"') { Fail "the state directory is removed with $($data[0][3])" }
$remove = Get-Rows 'SELECT `Component_`, `Property`, `InstallMode` FROM `Wix4RemoveFolderEx`' 3
if ($remove.Count -ne 1 -or $remove[0][1] -ne 'FARODATADIR' -or $remove[0][2] -ne '2') { Fail 'the uninstall does not remove the state directory' }
Say 'tables: ok'

# ==== the files ===============================================================
$work = Join-Path ([IO.Path]::GetTempPath()) ("check-msi-" + [guid]::NewGuid())
New-Item -ItemType Directory $work | Out-Null
try {
    $x = Join-Path $work 'x'
    $p = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -Wait -PassThru -WindowStyle Hidden `
        -ArgumentList @('/a', "`"$Msi`"", '/qn', "TARGETDIR=`"$x`"", '/l*v', "`"$work\admin.log`"")
    if ($p.ExitCode -ne 0) { Fail "the administrative install (extracting the files) exited with $($p.ExitCode); see $work\admin.log" }
    # An administrative install lays the 64-bit Program Files out as PFiles64.
    $px = Join-Path $x 'PFiles64\Faro'
    $service = Join-Path $px 'faro-service.exe'
    if (-not (Test-Path $service)) { Fail "no faro-service.exe in the extracted files ($x)" }
    $notices = Join-Path $px 'notices'
    function Has([string]$file, [string]$text) {
        if (-not (Select-String -LiteralPath (Join-Path $notices $file) -SimpleMatch -Quiet -Pattern $text)) { Fail "notices\$file lacks `"$text`"" }
    }
    Has 'third-party.txt' 'Third-party software in the Faro package for Windows'
    foreach ($section in 'faro-service', 'faro-agent') {
        if (-not (Select-String -LiteralPath (Join-Path $notices 'third-party.txt') -Pattern "^$section\s*$" -Quiet)) { Fail "notices\third-party.txt has no $section section" }
    }
    Has 'third-party.txt' '  ed25519-dalek '
    Has 'third-party.txt' 'Permission is hereby granted, free of charge'
    Has 'domains.txt' '--- MIT ---'
    Has 'domains.txt' 'https://creativecommons.org/licenses/by/4.0/'
    if ($hasModel) {
        Has 'third-party.txt' '  ort '
        Has 'opennsfw.txt' 'Copyright 2016, Yahoo Inc.'
        Has 'opennsfw.txt' 'BSD-2-Clause'
        Has 'opennsfw.txt' 'Redistributions in binary form must reproduce the above copyright notice'
        Has 'onnxruntime-LICENSE.txt' 'Copyright (c) Microsoft Corporation'
        Has 'onnxruntime-ThirdPartyNotices.txt' 'THIRD PARTY SOFTWARE NOTICES AND INFORMATION'
        $ortSig = Get-AuthenticodeSignature (Join-Path $px 'onnxruntime.dll')
        if ($ortSig.Status -ne 'Valid' -or $ortSig.SignerCertificate.Subject -notmatch '^CN=Microsoft Corporation,') { Fail 'onnxruntime.dll is not signed by Microsoft' }
    }
    $toml = Get-Content -Raw (Join-Path $px 'service.toml.default')
    if ($hasRoot) {
        $root = Get-Content -Raw (Join-Path $px 'update-root.json')
        if ($root -notmatch '"application/vnd.faro.root\+json"') { Fail 'update-root.json is not a signed root document' }
    }

    $got = (Exec { & $service --version }) | Select-Object -First 1
    if ($got -ne "faro-service $version") { Fail "faro-service --version printed '$got' (want $version)" }
    if ($hasModel) {
        $check = @(Exec { & $service model-check --manifest (Join-Path $px 'models\opennsfw\manifest.json') --runs 5 })
        if ($LASTEXITCODE -ne 0) { Fail 'faro-service cannot use the packaged model' }
        $check | ForEach-Object { Write-Host $_ }
        foreach ($frame in $ModelReference.Keys) {
            $line = $check | Where-Object { $_ -match "^$frame\s" } | Select-Object -First 1
            if ($line -notmatch '\bnsfw\s+([0-9.]+)') { Fail "model-check printed no nsfw score for $frame" }
            $d = [math]::Abs([double]$Matches[1] - $ModelReference[$frame])
            if ($d -gt $ModelTolerance) { Fail "${frame}: the packaged model gives p(nsfw) $($Matches[1]), the original $($ModelReference[$frame])" }
        }
    }
    $check = @(Exec { & $service domains-check --manifest (Join-Path $px 'domains\domains.manifest.json') })
    if ($LASTEXITCODE -ne 0) { Fail 'faro-service cannot load the packaged domain list' }
    $check | ForEach-Object { Write-Host $_ }
    $domainsVersion = (Select-String -Path (Join-Path $repo 'crates\faro-detect\domains\sources.toml') -Pattern '^bundle_version = "(.*)"').Matches[0].Groups[1].Value
    if (-not ($check | Where-Object { $_ -match "^domains\s+$([regex]::Escape($domainsVersion))\b" })) { Fail "domains-check did not load version $domainsVersion" }
    foreach ($category in 'adult', 'gambling') {
        if (-not ($check | Where-Object { $_ -match "^source\s+\S+\s+$category\b" })) { Fail "the packaged domain list has no $category source" }
    }
    # Only a development build may lower the detection thresholds.
    [IO.File]::WriteAllText("$work\dev-thresholds.toml", "[dev_thresholds]`nexplicit_high = 0.5`nexplicit_medium = 0.05`nany_low = 0.03`n")
    $status = @(Exec { & $service --config "$work\dev-thresholds.toml" --state-dir "$work\state" status }) | Where-Object { $_ -match '^Thresholds:' }
    if (-not $status) { Fail 'faro-service status printed no Thresholds line for [dev_thresholds]' }
    if ($dev -and $status -notmatch 'LOWERED') { Fail "the development service does not apply [dev_thresholds]: $status" }
    if (-not $dev -and $status -notmatch 'ignored') { Fail "the release service does not ignore [dev_thresholds]: $status" }

    if ($dev) {
        if ($toml -match '(?m)^agent_requirement') { Fail 'a development MSI''s default config must not set agent_requirement' }
    } else {
        if ($toml -notmatch "(?m)^agent_requirement = '(subject=`"[^`"]+`"[^']*)'") { Fail 'service.toml.default names no signer requirement' }
        $signer = $Matches[1]
        $bytes = [IO.File]::ReadAllBytes($service)
        if ([Text.Encoding]::ASCII.GetString($bytes).IndexOf($signer) -lt 0) { Fail "faro-service.exe was built without the signer requirement $signer (FARO_WINDOWS_SIGNER)" }
        foreach ($f in $Msi, $service, (Join-Path $px 'faro-agent.exe')) {
            $sig = Get-AuthenticodeSignature -LiteralPath $f
            if ($sig.Status -ne 'Valid') { Fail "$(Split-Path -Leaf $f) is not validly signed: $($sig.Status)" }
        }
    }
    Say 'files: ok'

    # ==== install, check, uninstall ===============================================
    $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($NoInstall) {
        Say 'install checks skipped (-NoInstall)'
    } elseif (-not $RequireInstall -and $env:FARO_CHECK_MSI_INSTALL -ne '1') {
        Say 'install checks skipped: the install half runs only when FARO_CHECK_MSI_INSTALL=1 is set on this machine (or with -RequireInstall)'
    } elseif (-not $elevated) {
        if ($RequireInstall) { Fail 'the install checks need an elevated shell' }
        Say 'install checks skipped: not elevated (run from an administrator shell, or pass -RequireInstall to make this an error)'
    } else {
        if ((Get-Service $ServiceName -ErrorAction SilentlyContinue) -or (Test-Path $ProgramDir) -or (Test-Path $DataDir)) {
            Fail "Faro is already installed here; the install checks would uninstall it (and tell its allies). Run them on a test machine."
        }
        $log = Join-Path $work 'install.log'
        $p = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -Wait -PassThru `
            -ArgumentList @('/i', "`"$Msi`"", '/qn', '/norestart', '/l*v', "`"$log`"")
        if ($p.ExitCode -ne 0) { Get-Content $log -Tail 60 | Write-Host; Fail "the install exited with $($p.ExitCode); log: $log" }
        try {
            foreach ($f in $want) { if (-not (Test-Path -LiteralPath $f)) { Fail "$f was not installed" } }
            $w = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
            if ($null -eq $w) { Fail 'the service is not installed' }
            if ($w.StartMode -ne 'Auto') { Fail "the service starts $($w.StartMode)" }
            if ($w.StartName -ne 'LocalSystem') { Fail "the service runs as $($w.StartName)" }
            if ($w.PathName -ne "`"$ProgramDir\faro-service.exe`" run-service") { Fail "the service runs $($w.PathName)" }
            if ($w.State -ne 'Running') { Fail "the service is $($w.State) after the install" }
            $sd = ((Exec { & sc.exe sdshow $ServiceName }) -join '').Trim()
            if (-not $sd.StartsWith($ServiceSddl)) { Fail "the service's security descriptor is $sd" }
            $qf = (Exec { & sc.exe qfailure $ServiceName }) -join "`n"
            if ($qf -notmatch 'RESET_PERIOD \(in seconds\)\s*:\s*86400' -or ([regex]::Matches($qf, 'RESTART -- Delay = 10000')).Count -ne 3) {
                Fail "the service's recovery actions: $qf"
            }
            $cmdKey = Get-ItemProperty 'HKLM:\Software\Classes\faro\shell\open\command'
            if ($cmdKey.'(default)' -ne $UrlCommand) { Fail "the faro: command is $($cmdKey.'(default)')" }
            if ($null -eq (Get-ItemProperty 'HKLM:\Software\Classes\faro').'URL Protocol') { Fail 'faro: is not marked as a URL protocol' }
            foreach ($d in @(@($DataDir, 'FullControl'), @("$DataDir\logs", 'ReadAndExecute'))) {
                $acl = Get-Acl -LiteralPath $d[0]
                if (-not $acl.AreAccessRulesProtected) { Fail "$($d[0]) inherits its permissions" }
                foreach ($rule in $acl.Access) {
                    $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
                    $ok = ($sid -eq 'S-1-5-18' -and $rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -or
                        ($sid -eq 'S-1-5-32-544')
                    if (-not $ok -or $rule.AccessControlType -ne 'Allow') { Fail "$($d[0]) grants $($rule.FileSystemRights) to $($rule.IdentityReference)" }
                    if ($sid -eq 'S-1-5-32-544' -and $d[1] -eq 'ReadAndExecute' -and ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write)) {
                        Fail "$($d[0]) lets Administrators write"
                    }
                }
            }
            # The installed service finds its model and domain list where the
            # MSI put them: with no --manifest, model-check and domains-check
            # use the same default paths the running service loads at start
            # (model::packaged_manifest, artifacts::packaged_domains_manifest).
            $installedService = "$ProgramDir\faro-service.exe"
            if ($hasModel) {
                $check = @(Exec { & $installedService model-check --runs 1 })
                if ($LASTEXITCODE -ne 0) { Fail 'the installed service cannot load its packaged model from the default path' }
                if (-not ($check | Where-Object { $_ -match '^model\s+opennsfw\b' })) { Fail "model-check (default path) did not load opennsfw: $check" }
            }
            $check = @(Exec { & $installedService domains-check })
            if ($LASTEXITCODE -ne 0) { Fail 'the installed service cannot load its packaged domain list from the default path' }
            if (-not ($check | Where-Object { $_ -match '^domains\s+\S' })) { Fail "domains-check (default path) loaded no list: $check" }
            if (-not (Test-Path "$DataDir\service.toml")) { Fail 'no service.toml in the state directory' }
            $arp = Get-ChildItem 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall' |
                Get-ItemProperty | Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -eq 'Faro' }
            if (@($arp).Count -ne 1) { Fail 'Faro is not listed once in Apps & features' }
            if ($arp.DisplayVersion -ne $productVersion -or $arp.NoModify -ne 1) { Fail "the Apps & features entry: $($arp | Out-String)" }
            Say 'install: ok'
        } finally {
            $ulog = Join-Path $work 'uninstall.log'
            $p = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -Wait -PassThru `
                -ArgumentList @('/x', "`"$Msi`"", '/qn', '/norestart', '/l*v', "`"$ulog`"")
            if ($p.ExitCode -ne 0) { Fail "the uninstall exited with $($p.ExitCode); log: $ulog" }
        }
        # Windows Installer logs are UTF-16.
        $u = Get-Content -Raw -Encoding Unicode $ulog
        if ($u -notmatch 'Doing action: FaroGoodbye') { Fail "the uninstall did not run the goodbye; log: $ulog" }
        if ($u -notmatch 'faro-service\.exe" goodbye --reason uninstalled') { Fail "the goodbye's command line is not in the log: $ulog" }
        if (Get-Service $ServiceName -ErrorAction SilentlyContinue) { Fail 'the service is still installed after the uninstall' }
        foreach ($d in $ProgramDir, $DataDir, 'HKLM:\Software\Classes\faro', 'HKLM:\Software\Faro') {
            if (Test-Path $d) {
                if ($d -eq $DataDir) {
                    # What is left, and what the uninstall said about it.
                    Get-ChildItem -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue |
                        ForEach-Object { Write-Host "left: $($_.FullName)" }
                    $u -split "`r?`n" |
                        Select-String -Pattern 'RemoveFolder|FARODATADIR|RemoveFiles|StateCleanup|Return value 3|Error \d' |
                        Select-Object -First 60 | ForEach-Object { Write-Host "log: $_" }
                }
                Fail "$d is still there after the uninstall"
            }
        }
        Say 'uninstall: ok'
    }
} finally {
    # Keep the Windows Installer logs where CI can upload them.
    if ($env:FARO_CHECK_MSI_LOGS) {
        New-Item -ItemType Directory -Force $env:FARO_CHECK_MSI_LOGS | Out-Null
        Copy-Item (Join-Path $work '*.log') $env:FARO_CHECK_MSI_LOGS -ErrorAction SilentlyContinue
    }
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
Say "$leaf is well-formed"
