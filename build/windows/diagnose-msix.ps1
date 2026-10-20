<#
.SYNOPSIS
  Signs, installs, launches and inspects a SecCorp Store MSIX on a clean
  Windows runner.

.DESCRIPTION
  Partner Center signs production packages. For a repeatable pre-publication
  launch test, this script creates a disposable certificate with the same
  publisher subject, trusts it only on the runner, signs the unsigned build,
  installs the package and captures the Tauri/WebView2 startup evidence.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$ArtifactRoot,
  [string]$OutputDir = "diagnostics"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$Package = Get-ChildItem -LiteralPath $ArtifactRoot -Filter "SecCorp_*.msix" -File -Recurse |
  Sort-Object FullName |
  Select-Object -First 1
if (-not $Package) { throw "SecCorp MSIX was not found under $ArtifactRoot" }
Write-Host "Preparing packaged-launch test from $($Package.Name)"

# Signing the production package (which includes the ~350 MB emergency fixed
# WebView2 runtime) is unnecessarily slow on a hosted runner. The normal launch
# path uses Windows' serviced Evergreen runtime, so rebuild a lightweight test
# copy without only that fallback directory. The original Store MSIX remains
# untouched and is still uploaded as the release artifact.
$MakeAppx = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\makeappx.exe" -File |
  Sort-Object FullName -Descending |
  Select-Object -First 1
if (-not $MakeAppx) { throw "makeappx.exe was not found" }

$TestLayout = Join-Path $OutputDir "test-layout"
$TestPackagePath = Join-Path $OutputDir "$($Package.BaseName)-launch-test.msix"
New-Item -ItemType Directory -Force -Path $TestLayout | Out-Null
Write-Host "Unpacking the disposable launch-test package"
& $MakeAppx.FullName unpack /o /p $Package.FullName /d $TestLayout | Out-Null
if ($LASTEXITCODE -ne 0) { throw "makeappx unpack failed with exit code $LASTEXITCODE" }
$FallbackRuntime = Join-Path $TestLayout "WebView2Runtime"
if (Test-Path -LiteralPath $FallbackRuntime) {
  Remove-Item -LiteralPath $FallbackRuntime -Recurse -Force
}
Write-Host "Repacking the lightweight launch-test package"
& $MakeAppx.FullName pack /o /d $TestLayout /p $TestPackagePath | Out-Null
if ($LASTEXITCODE -ne 0) { throw "makeappx pack failed with exit code $LASTEXITCODE" }
Remove-Item -LiteralPath $TestLayout -Recurse -Force

$Publisher = "CN=E352DCED-B383-4C1F-91A8-E772B76C141A"
Write-Host "Creating a disposable package-signing certificate"
$PasswordText = [Guid]::NewGuid().ToString("N")
$Password = ConvertTo-SecureString -String $PasswordText -Force -AsPlainText
$Certificate = New-SelfSignedCertificate `
  -Type CodeSigningCert `
  -Subject $Publisher `
  -KeyAlgorithm RSA `
  -KeyLength 2048 `
  -KeyExportPolicy Exportable `
  -HashAlgorithm SHA256 `
  -NotAfter (Get-Date).AddDays(1) `
  -FriendlyName "SecCorp disposable MSIX test certificate" `
  -CertStoreLocation "Cert:\CurrentUser\My"

$PfxPath = Join-Path $env:RUNNER_TEMP "seccorp-msix-test.pfx"
$CerPath = Join-Path $env:RUNNER_TEMP "seccorp-msix-test.cer"
Export-PfxCertificate -Cert $Certificate -FilePath $PfxPath -Password $Password | Out-Null
Export-Certificate -Cert $Certificate -FilePath $CerPath | Out-Null
$CertUtil = Join-Path $env:SystemRoot "System32\certutil.exe"
& $CertUtil -f -user -addstore Root $CerPath | Out-Null
if ($LASTEXITCODE -ne 0) { throw "certutil could not trust the disposable root certificate" }
Import-Certificate -FilePath $CerPath -CertStoreLocation "Cert:\CurrentUser\TrustedPeople" | Out-Null
Write-Host "The disposable signing certificate is trusted for the current runner user"

$SignTool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -File |
  Sort-Object FullName -Descending |
  Select-Object -First 1
if (-not $SignTool) { throw "signtool.exe was not found" }

Write-Host "Signing the disposable launch-test package"
& $SignTool.FullName sign /fd SHA256 /f $PfxPath /p $PasswordText $TestPackagePath
if ($LASTEXITCODE -ne 0) { throw "signtool failed with exit code $LASTEXITCODE" }

Write-Host "Installing the launch-test package"
Add-AppxPackage -Path $TestPackagePath -ForceApplicationShutdown
$Installed = Get-AppxPackage -Name "38078WebNet.kz.SecCorp"
if (-not $Installed) { throw "The SecCorp package was not installed" }

$Identity = [pscustomobject]@{
  Name = $Installed.Name
  Version = $Installed.Version.ToString()
  Architecture = $Installed.Architecture.ToString()
  PackageFamilyName = $Installed.PackageFamilyName
  InstallLocation = $Installed.InstallLocation
}
$Identity | ConvertTo-Json | Set-Content (Join-Path $OutputDir "package.json") -Encoding utf8

Write-Host "Launching SecCorp through its AppsFolder identity"
Start-Process explorer.exe -ArgumentList "shell:AppsFolder\$($Installed.PackageFamilyName)!SecCorp"
Start-Sleep -Seconds 20

$Processes = @()
$Processes += Get-CimInstance Win32_Process -Filter "Name = 'SecCorp.exe'" |
  Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine
$Processes += Get-CimInstance Win32_Process -Filter "Name = 'msedgewebview2.exe'" |
  Where-Object { $_.CommandLine -match "SecCorp\.exe|com\.webnetkz\.seccom|38078WebNet" } |
  Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine
$Processes | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $OutputDir "processes.json") -Encoding utf8

$CandidateLogs = @(
  (Join-Path $env:LOCALAPPDATA "SecCorp\logs\startup.log"),
  (Join-Path $env:LOCALAPPDATA "Packages\$($Installed.PackageFamilyName)\LocalCache\Local\SecCorp\logs\startup.log"),
  (Join-Path $env:LOCALAPPDATA "Packages\$($Installed.PackageFamilyName)\LocalState\SecCorp\logs\startup.log")
)
$StartupLog = $CandidateLogs | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if ($StartupLog) {
  Copy-Item -LiteralPath $StartupLog -Destination (Join-Path $OutputDir "startup.log") -Force
} else {
  $CandidateLogs | Set-Content (Join-Path $OutputDir "startup-log-locations.txt") -Encoding utf8
}

if (-not ($Processes | Where-Object Name -eq "SecCorp.exe")) {
  throw "SecCorp.exe is not running after packaged activation"
}
if (-not ($Processes | Where-Object Name -eq "msedgewebview2.exe")) {
  throw "No WebView2 process belongs to SecCorp after packaged activation"
}
if (-not $StartupLog) {
  throw "SecCorp did not create its startup log"
}
$LogText = Get-Content -LiteralPath $StartupLog -Raw
if ($LogText -notmatch "page load Finished") {
  throw "The packaged WebView did not finish loading. See the diagnostic artifact."
}
if ($LogText -notmatch "frontend rendered") {
  throw "The packaged frontend did not render. See the diagnostic artifact."
}

Write-Host "SecCorp packaged launch completed and the frontend rendered."

