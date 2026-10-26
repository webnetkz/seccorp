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
$WebView2Runtime = Join-Path $Layout "WebView2Runtime"
$OutDir = Join-Path $Root "dist-release\windows\store"
$Output = Join-Path $OutDir "SecCorp_${StoreVersion}_${Architecture}.msix"
$ClamAvVersion = "1.5.4"
$ClamAvBaseUrl = "https://github.com/Cisco-Talos/clamav/releases/download/clamav-$ClamAvVersion"
$ClamAvSourceName = "clamav-$ClamAvVersion.tar.gz"
$ClamAvSourceSha256 = "1af1117a228f1b5bc7fa91a0dabc37848a99e7d25188e9be8043332ce721dfd3"
if ($Architecture -eq "x64") {
  $ClamAvArchiveName = "clamav-$ClamAvVersion.win.x64.zip"
  $ClamAvArchiveSha256 = "0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395"
} else {
  $ClamAvArchiveName = "clamav-$ClamAvVersion.win.arm64.zip"
  $ClamAvArchiveSha256 = "21ec99e522435258e5fe2ef1b6345375a94748c83e4e1561c53d5b3842cf9c00"
}
$VendorDir = Join-Path $TempRoot "vendor"
$ClamAvExtractDir = Join-Path $VendorDir "clamav-$ClamAvVersion.win.$Architecture"
$ClamAvArchive = Join-Path $VendorDir $ClamAvArchiveName
$ClamAvSourceArchive = Join-Path $VendorDir $ClamAvSourceName

try {
  New-Item -ItemType Directory -Force -Path $Assets, $BundledDb, $OutDir, $VendorDir,
    (Join-Path $Layout "clamav"), (Join-Path $Layout "Legal\clamav") | Out-Null

  # Pin and verify the official ClamAV portable package and corresponding source.
  Invoke-WebRequest -Uri "$ClamAvBaseUrl/$ClamAvArchiveName" -OutFile $ClamAvArchive
  $ActualClamAvSha256 = (Get-FileHash -Algorithm SHA256 $ClamAvArchive).Hash.ToLowerInvariant()
  if ($ActualClamAvSha256 -ne $ClamAvArchiveSha256) {
    throw "ClamAV $ClamAvVersion binary archive SHA-256 mismatch: $ActualClamAvSha256"
  }
  Invoke-WebRequest -Uri "$ClamAvBaseUrl/$ClamAvSourceName" -OutFile $ClamAvSourceArchive
  $ActualSourceSha256 = (Get-FileHash -Algorithm SHA256 $ClamAvSourceArchive).Hash.ToLowerInvariant()
  if ($ActualSourceSha256 -ne $ClamAvSourceSha256) {
    throw "ClamAV $ClamAvVersion source archive SHA-256 mismatch: $ActualSourceSha256"
  }
  Expand-Archive -LiteralPath $ClamAvArchive -DestinationPath $VendorDir

  $ClamAvLayout = Join-Path $Layout "clamav"
  $ClamAvLegal = Join-Path $Layout "Legal\clamav"
  $ClamAvCerts = Join-Path $ClamAvLayout "certs"
  $ClamAvLicenseDir = Join-Path $ClamAvLegal "COPYING"
  $ClamAvPayload = Get-ChildItem -LiteralPath $ClamAvExtractDir -File |
    Where-Object { $_.Extension -ieq ".dll" -or $_.Name -ieq "freshclam.exe" }
  if (-not ($ClamAvPayload | Where-Object { $_.Name -ieq "freshclam.exe" })) {
    throw "FreshClam executable was not found in the verified ClamAV archive."
  }
  foreach ($File in $ClamAvPayload) {
    Copy-Item -LiteralPath $File.FullName -Destination $ClamAvLayout
  }
  New-Item -ItemType Directory -Force -Path $ClamAvCerts, $ClamAvLicenseDir | Out-Null
  Get-ChildItem -LiteralPath (Join-Path $ClamAvExtractDir "certs") -File |
    Copy-Item -Destination $ClamAvCerts
  Get-ChildItem -LiteralPath (Join-Path $ClamAvExtractDir "COPYING") -File |
    Copy-Item -Destination $ClamAvLicenseDir
  Copy-Item -LiteralPath (Join-Path $ClamAvExtractDir "COPYING.txt") -Destination $ClamAvLegal
  Copy-Item -LiteralPath $ClamAvSourceArchive -Destination $ClamAvLegal
  Copy-Item -LiteralPath (Join-Path $Root "build\windows\THIRD-PARTY-NOTICES.txt") -Destination (Join-Path $Layout "Legal\ThirdPartyNotices.txt")

  Copy-Item $Binary (Join-Path $Layout "SecCorp.exe")
  Copy-Item (Join-Path $Root "app\src-tauri\icons\StoreLogo.png") $Assets
  Copy-Item (Join-Path $Root "app\src-tauri\icons\Square44x44Logo.png") $Assets
  Copy-Item (Join-Path $Root "app\src-tauri\icons\Square150x150Logo.png") $Assets
  Copy-Item (Join-Path $Root "signatures\base\*") $BundledDb -Recurse

  # Store MSIX installs do not run Tauri's MSI/NSIS WebView2 bootstrapper.
  # Bundle the latest Microsoft Fixed Version runtime so users do not need a
  # separate runtime installation and the app can start on clean Windows images.
  $DownloadPage = Invoke-WebRequest -Uri "https://developer.microsoft.com/en-us/microsoft-edge/webview2/" -UseBasicParsing
  $PageContent = $DownloadPage.Content.Replace('\u002F', '/')
  $RuntimePattern = 'https://msedge\.sf\.dl\.delivery\.mp\.microsoft\.com/filestreamingservice/files/[^"]+/Microsoft\.WebView2\.FixedVersionRuntime\.(?<version>\d+(?:\.\d+){3})\.(?<architecture>x64|arm64)\.cab'
  $RuntimeMatch = $null
  foreach ($Candidate in [regex]::Matches($PageContent, $RuntimePattern)) {
    if ($Candidate.Groups['architecture'].Value -eq $Architecture) {
      $RuntimeMatch = $Candidate
      break
    }
  }
  if (-not $RuntimeMatch) { throw "Microsoft's latest Fixed Version WebView2 runtime for $Architecture was not found." }

  $WebView2Version = $RuntimeMatch.Groups['version'].Value
  $WebView2Cab = Join-Path $TempRoot "Microsoft.WebView2.FixedVersionRuntime.$WebView2Version.$Architecture.cab"
  New-Item -ItemType Directory -Force -Path $WebView2Runtime | Out-Null
  $WebView2Extract = Join-Path $TempRoot "webview2-extracted"
  New-Item -ItemType Directory -Force -Path $WebView2Extract | Out-Null
  Invoke-WebRequest -Uri $RuntimeMatch.Value -OutFile $WebView2Cab
  $Expand = Join-Path $env:SystemRoot "System32\expand.exe"
  & $Expand $WebView2Cab "-F:*" $WebView2Extract
  if ($LASTEXITCODE -ne 0) { throw "WebView2 Fixed Version extraction failed with exit code $LASTEXITCODE" }

  # The CAB stores its payload under a versioned top-level directory. Flatten
  # that one directory so the runtime sits beside SecCorp.exe as expected by
  # configure_bundled_webview2_runtime().
  $WebView2SourceExecutable = Get-ChildItem -LiteralPath $WebView2Extract -Filter "msedgewebview2.exe" -File -Recurse |
    Select-Object -First 1
  if (-not $WebView2SourceExecutable) {
    throw "The extracted WebView2 runtime is missing msedgewebview2.exe."
  }
  $WebView2SourceDir = Split-Path -Parent $WebView2SourceExecutable.FullName
  Get-ChildItem -LiteralPath $WebView2SourceDir -Force |
    Copy-Item -Destination $WebView2Runtime -Recurse -Force

  $WebView2Executable = Join-Path $WebView2Runtime "msedgewebview2.exe"
  if (-not (Test-Path $WebView2Executable)) {
    throw "The extracted WebView2 runtime is missing msedgewebview2.exe."
  }
  $WebView2Signature = Get-AuthenticodeSignature -FilePath $WebView2Executable
  if ($WebView2Signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
      $WebView2Signature.SignerCertificate.Subject -notmatch "Microsoft Corporation") {
    throw "The extracted WebView2 runtime does not have a valid Microsoft signature."
  }

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
  if ($PackedManifest.OuterXml -match 'Name="allowElevation"') {
    throw "The Store package must not request the denied allowElevation capability."
  }
  if ($PackedManifest.OuterXml -notmatch 'Name="runFullTrust"') {
    throw "The packaged classic app is missing the required runFullTrust capability."
  }
  foreach ($RequiredFile in @(
    "WebView2Runtime\msedgewebview2.exe",
    "clamav\freshclam.exe",
    "clamav\certs\clamav.crt",
    "Legal\ThirdPartyNotices.txt",
    "Legal\clamav\COPYING.txt",
    "Legal\clamav\clamav-$ClamAvVersion.tar.gz"
  )) {
    if (-not (Test-Path (Join-Path $Inspect $RequiredFile))) {
      throw "Store MSIX is missing required FreshClam or license content: $RequiredFile"
    }
  }

  $Hash = (Get-FileHash -Algorithm SHA256 $Output).Hash.ToLowerInvariant()
  Write-Host "  -> dist-release\windows\store\$(Split-Path $Output -Leaf)"
  Write-Host "     version=$StoreVersion architecture=$Architecture webview2=$WebView2Version sha256=$Hash"
}
finally {
  if (Test-Path $TempRoot) { Remove-Item $TempRoot -Recurse -Force }
}
