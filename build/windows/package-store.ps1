<#
.SYNOPSIS
  Packages the already-built SecCorp executable as an unsigned Store MSIX.

.DESCRIPTION
  Microsoft Store signs MSIX packages after certification, so the package
  produced here is intentionally unsigned. The manifest identity must stay in
  sync with the values assigned to SecCorp in Partner Center.

.PARAMETER Target
  Rust target triple that was built by build.ps1.

.PARAMETER ProfileDir
  Cargo profile directory (release or debug).
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc")]
  [string]$Target,
  [ValidateSet("release", "debug")]
  [string]$ProfileDir = "release"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$CargoToml = Join-Path $Root "Cargo.toml"
$CargoText = [System.IO.File]::ReadAllText($CargoToml)
$VersionMatch = [regex]::Match($CargoText, '(?m)^version\s*=\s*"(\d+)\.(\d+)\.(\d+)"')
if (-not $VersionMatch.Success) { throw "Could not read the workspace version from $CargoToml" }
$StoreVersion = "$($VersionMatch.Groups[1].Value).$($VersionMatch.Groups[2].Value).$($VersionMatch.Groups[3].Value).0"

$Architecture = switch ($Target) {
  "x86_64-pc-windows-msvc" { "x64" }
  "aarch64-pc-windows-msvc" { "arm64" }
}

$ReleaseDir = Join-Path $Root "target\$Target\$ProfileDir"
$Binary = Join-Path $ReleaseDir "seccom-app.exe"
if (-not (Test-Path $Binary)) {
  $Binary = Join-Path $ReleaseDir "SecCorp.exe"
}
if (-not (Test-Path $Binary)) { throw "SecCorp executable was not found in $ReleaseDir" }

$MakeAppxCandidates = @()
$KitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
if (Test-Path $KitsRoot) {
  $MakeAppxCandidates += Get-ChildItem $KitsRoot -Directory |
    Sort-Object Name -Descending |
    ForEach-Object { Join-Path $_.FullName "x64\makeappx.exe" }
}
$MakeAppxCandidates += Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\App Certification Kit\makeappx.exe"
$MakeAppx = $MakeAppxCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $MakeAppx) { throw "makeappx.exe was not found. Install the Windows 10/11 SDK." }

$TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "seccom-msix-$PID-$Architecture"
$Layout = Join-Path $TempRoot "layout"
$Inspect = Join-Path $TempRoot "inspect"
$Assets = Join-Path $Layout "Assets"
$BundledDb = Join-Path $Layout "databases\bundled"
$OutDir = Join-Path $Root "dist-release\windows\store"
$Output = Join-Path $OutDir "SecCorp_${StoreVersion}_${Architecture}.msix"

try {
  New-Item -ItemType Directory -Force -Path $Assets, $BundledDb, $OutDir | Out-Null
  Copy-Item $Binary (Join-Path $Layout "SecCorp.exe")
  Copy-Item (Join-Path $Root "app\src-tauri\icons\StoreLogo.png") $Assets
  Copy-Item (Join-Path $Root "app\src-tauri\icons\Square44x44Logo.png") $Assets
  Copy-Item (Join-Path $Root "app\src-tauri\icons\Square150x150Logo.png") $Assets
  Copy-Item (Join-Path $Root "signatures\base\*") $BundledDb -Recurse

  $Manifest = @"
<?xml version="1.0" encoding="utf-8"?>
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
  xmlns:uap10="http://schemas.microsoft.com/appx/manifest/uap/windows10/10"
  xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
  IgnorableNamespaces="uap uap10 rescap">
  <Identity
    Name="38078WebNet.kz.SecCorp"
    Publisher="CN=E352DCED-B383-4C1F-91A8-E772B76C141A"
    Version="$StoreVersion"
    ProcessorArchitecture="$Architecture" />
  <Properties>
    <DisplayName>SecCorp</DisplayName>
    <PublisherDisplayName>WebNet.kz</PublisherDisplayName>
    <Description>Locally analyzes selected files and folders.</Description>
    <Logo>Assets\StoreLogo.png</Logo>
  </Properties>
  <Resources>
    <Resource Language="en-us" />
    <Resource Language="ru-ru" />
  </Resources>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.26100.0" />
  </Dependencies>
  <Applications>
    <Application
      Id="SecCorp"
      Executable="SecCorp.exe"
      EntryPoint="Windows.FullTrustApplication"
      uap10:RuntimeBehavior="packagedClassicApp"
      uap10:TrustLevel="mediumIL">
      <uap:VisualElements
        DisplayName="SecCorp"
        Description="Local file scanner"
        BackgroundColor="transparent"
        Square44x44Logo="Assets\Square44x44Logo.png"
        Square150x150Logo="Assets\Square150x150Logo.png" />
    </Application>
  </Applications>
  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
  </Capabilities>
</Package>
"@
  [System.IO.File]::WriteAllText((Join-Path $Layout "AppxManifest.xml"), $Manifest, [System.Text.UTF8Encoding]::new($false))

  & $MakeAppx pack /o /v /d $Layout /p $Output
  if ($LASTEXITCODE -ne 0) { throw "MakeAppx failed with exit code $LASTEXITCODE" }

  # Unpack once as a structural check and verify the Store identity that was
  # embedded in the package. Store signing happens after submission.
  & $MakeAppx unpack /o /p $Output /d $Inspect | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "MakeAppx validation unpack failed with exit code $LASTEXITCODE" }
  [xml]$PackedManifest = Get-Content (Join-Path $Inspect "AppxManifest.xml")
  $Identity = $PackedManifest.Package.Identity
  if ($Identity.Name -ne "38078WebNet.kz.SecCorp" -or
      $Identity.Publisher -ne "CN=E352DCED-B383-4C1F-91A8-E772B76C141A" -or
      $Identity.Version -ne $StoreVersion -or
      $Identity.ProcessorArchitecture -ne $Architecture) {
    throw "The packaged Store identity does not match Partner Center."
  }

  $Hash = (Get-FileHash -Algorithm SHA256 $Output).Hash.ToLowerInvariant()
  Write-Host "  -> dist-release\windows\store\$(Split-Path $Output -Leaf)"
  Write-Host "     version=$StoreVersion architecture=$Architecture sha256=$Hash"
}
finally {
  if (Test-Path $TempRoot) { Remove-Item $TempRoot -Recurse -Force }
}
