<#
.SYNOPSIS
Authenticode-sign Faro's Windows files in place, with the provider the
repository chose (ARCHITECTURE.md §3.3: the SignPath Foundation or Azure
Trusted Signing; the maintainer hasn't chosen yet, issue #85).

.DESCRIPTION
  installers\windows\sign.ps1 -Files faro-service.exe,faro-agent.exe
  installers\windows\sign.ps1 -Files target\msi\Faro-0.1.0-beta.1-x64.msi
  installers\windows\sign.ps1 -Provider        # prints signpath, trusted-signing or none

The provider is FARO_WINDOWS_SIGNING (an Actions variable in the release
workflow):

  signpath          SignPath (signpath.io), through its PowerShell module.
                    SIGNPATH_API_TOKEN (secret), FARO_SIGNPATH_ORGANIZATION_ID,
                    FARO_SIGNPATH_PROJECT (project slug), FARO_SIGNPATH_POLICY
                    (signing policy slug, default release-signing), and the
                    artifact configuration slug for each file type:
                    FARO_SIGNPATH_CONFIG_EXE (default exe) and
                    FARO_SIGNPATH_CONFIG_MSI (default msi).
  trusted-signing   Azure Trusted Signing, through Microsoft's TrustedSigning
                    PowerShell module. FARO_TRUSTED_SIGNING_ENDPOINT (for
                    example https://eus.codesigning.azure.net/),
                    FARO_TRUSTED_SIGNING_ACCOUNT, FARO_TRUSTED_SIGNING_PROFILE,
                    and Azure credentials the module's DefaultAzureCredential
                    finds (AZURE_TENANT_ID, AZURE_CLIENT_ID and
                    AZURE_CLIENT_SECRET, or an azure/login step before).
  (empty)           Nothing is signed. A loud warning says so (a GitHub
                    Actions warning too), and the script exits 0, so an
                    unsigned build goes on. Such a build is a development
                    build: build-msi.ps1 refuses a release MSI without a
                    provider.

Every signature is SHA-256 with an RFC 3161 timestamp, and each signed file
is checked with Get-AuthenticodeSignature afterwards.

Whichever provider is chosen, the service checks update packages and agents
against the signer compiled in from FARO_WINDOWS_SIGNER (`subject="<CN>"`,
optionally `; sha256=<leaf thumbprint>`): set it to the certificate this
provider signs with. The SignPath Foundation signs as "SignPath Foundation"
for every project it serves, so pin its thumbprint as well; Azure Trusted
Signing renews its certificates every few days, so pin the subject only.
#>
[CmdletBinding(DefaultParameterSetName = 'Sign')]
param(
    [Parameter(ParameterSetName = 'Sign', Mandatory = $true)][string[]]$Files,
    [Parameter(ParameterSetName = 'Provider')][switch]$Provider
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Pinned module versions. Check them on the first real signing run: they
# were chosen before either provider was set up.
$SignPathModuleVersion = '4.0.0'
$TrustedSigningModuleVersion = '0.5.0'
$TimestampUrl = 'http://timestamp.acs.microsoft.com'

function Fail([string]$msg) { throw "sign.ps1: $msg" }
function Need([string]$name) {
    $v = [Environment]::GetEnvironmentVariable($name)
    if ([string]::IsNullOrWhiteSpace($v)) { Fail "FARO_WINDOWS_SIGNING=$mode needs $name" }
    $v
}
function Opt([string]$name, [string]$default) {
    $v = [Environment]::GetEnvironmentVariable($name)
    if ([string]::IsNullOrWhiteSpace($v)) { $default } else { $v }
}

$mode = "$env:FARO_WINDOWS_SIGNING".Trim().ToLowerInvariant()
if ($mode -eq '') { $mode = 'none' }
if ($mode -notin @('signpath', 'trusted-signing', 'none')) {
    Fail "FARO_WINDOWS_SIGNING must be signpath, trusted-signing or empty (got '$env:FARO_WINDOWS_SIGNING')"
}
if ($Provider) { Write-Output $mode; exit 0 }

$paths = foreach ($f in $Files) {
    foreach ($one in ($f -split ',')) {
        if ($one -ne '') { (Resolve-Path -LiteralPath $one).Path }
    }
}

if ($mode -eq 'none') {
    $msg = "UNSIGNED BUILD: FARO_WINDOWS_SIGNING is not set, so $($paths.Count) file(s) were NOT signed: " +
        (($paths | ForEach-Object { Split-Path -Leaf $_ }) -join ', ') +
        '. Choose SignPath or Azure Trusted Signing (installers/windows/README.md).'
    Write-Warning $msg
    if ($env:GITHUB_ACTIONS -eq 'true') { Write-Output "::warning title=UNSIGNED WINDOWS BUILD::$msg" }
    exit 0
}

function Import-Pinned([string]$name, [string]$version) {
    if (-not (Get-Module -ListAvailable -Name $name | Where-Object { $_.Version -eq [version]$version })) {
        Write-Host "    installing the $name PowerShell module $version"
        Install-Module -Name $name -RequiredVersion $version -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module -Name $name -RequiredVersion $version -Force
}

switch ($mode) {
    'signpath' {
        Import-Pinned 'SignPath' $SignPathModuleVersion
        $common = @{
            OrganizationId    = (Need 'FARO_SIGNPATH_ORGANIZATION_ID')
            ApiToken          = (Need 'SIGNPATH_API_TOKEN')
            ProjectSlug       = (Need 'FARO_SIGNPATH_PROJECT')
            SigningPolicySlug = (Opt 'FARO_SIGNPATH_POLICY' 'release-signing')
        }
        foreach ($p in $paths) {
            $ext = [IO.Path]::GetExtension($p).TrimStart('.').ToLowerInvariant()
            $config = switch ($ext) {
                'exe' { Opt 'FARO_SIGNPATH_CONFIG_EXE' 'exe' }
                'dll' { Opt 'FARO_SIGNPATH_CONFIG_EXE' 'exe' }
                'msi' { Opt 'FARO_SIGNPATH_CONFIG_MSI' 'msi' }
                default { Fail "don't know how to sign $p" }
            }
            $signed = "$p.signed"
            Write-Host "==> SignPath: $(Split-Path -Leaf $p) ($config)"
            Submit-SigningRequest @common -ArtifactConfigurationSlug $config `
                -InputArtifactPath $p -OutputArtifactPath $signed -WaitForCompletion -Force
            Move-Item -Force $signed $p
        }
    }
    'trusted-signing' {
        Import-Pinned 'TrustedSigning' $TrustedSigningModuleVersion
        Write-Host "==> Azure Trusted Signing: $(($paths | ForEach-Object { Split-Path -Leaf $_ }) -join ', ')"
        $ts = @{
            Endpoint               = (Need 'FARO_TRUSTED_SIGNING_ENDPOINT')
            CodeSigningAccountName = (Need 'FARO_TRUSTED_SIGNING_ACCOUNT')
            CertificateProfileName = (Need 'FARO_TRUSTED_SIGNING_PROFILE')
            Files                  = ($paths -join ',')
            FileDigest             = 'SHA256'
            TimestampRfc3161       = $TimestampUrl
            TimestampDigest        = 'SHA256'
            Description            = 'Faro'
            DescriptionUrl         = 'https://github.com/faro-project/faro'
        }
        Invoke-TrustedSigning @ts
    }
}

foreach ($p in $paths) {
    $sig = Get-AuthenticodeSignature -LiteralPath $p
    if ($sig.Status -ne 'Valid') { Fail "$p is not validly signed after signing: $($sig.Status) $($sig.StatusMessage)" }
    if ($null -eq $sig.TimeStamperCertificate) { Fail "$p has no timestamp" }
    $sha = [Security.Cryptography.SHA256]::Create()
    $thumb = (($sha.ComputeHash($sig.SignerCertificate.RawData) | ForEach-Object { $_.ToString('x2') }) -join '')
    Write-Host "    $(Split-Path -Leaf $p): $($sig.SignerCertificate.Subject) (sha256 $thumb)"
}
