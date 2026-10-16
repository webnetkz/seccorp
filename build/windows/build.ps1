<#
.SYNOPSIS
  Builds SecCorp for Windows: NSIS installer (.exe) and MSI.

.DESCRIPTION
  Requirements: Windows 10/11, Visual Studio 2022 Build Tools with "Desktop development
  with C++", Node.js 20+, Rust (rustup). WebView2 is installed by the installer itself.

  Optional environment:
    SECCOM_UPDATE_PUBKEY, SECCOM_UPDATE_URL   online signature updates (see README)
    SECCOM_WINDOWS_SIGN_COMMAND               code signing command, "%1" is the file, e.g.
        signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a "%1"

.PARAMETER Arch
  x64 (default), arm64 or both.

.PARAMETER Bundles
  Comma-separated installer types: nsis,msi (default). ARM64 builds use NSIS only.

.PARAMETER DebugBuild
  Unoptimized build with developer tools enabled.

.PARAMETER StoreMsix
  Also package an unsigned MSIX using the identity assigned in Partner Center.
  Microsoft Store signs it after certification.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File build\windows\build.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File build\windows\build.ps1 -Arch both
#>
[CmdletBinding()]
param(
  [ValidateSet("x64", "arm64", "both")]
  [string]$Arch = "x64",
  [string]$Bundles = "nsis,msi",
  [switch]$DebugBuild,
  [switch]$StoreMsix
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$App = Join-Path $Root "app"

function Require([string]$Command, [string]$Hint) {
  if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
    throw "$Command not found. $Hint"
  }
}

function Invoke-Checked([string]$Exe, [string[]]$Arguments) {
  & $Exe @Arguments
  if ($LASTEXITCODE -ne 0) { throw "'$Exe $($Arguments -join ' ')' failed with exit code $LASTEXITCODE" }
}

Require "node" "Install Node.js 20+ from https://nodejs.org"
Require "npm" "Install Node.js 20+ from https://nodejs.org"
Require "cargo" "Install Rust from https://rustup.rs"
Require "rustup" "Install Rust from https://rustup.rs"

if (-not $env:SECCOM_UPDATE_PUBKEY) {
  Write-Warning "SECCOM_UPDATE_PUBKEY is not set: online signature updates are disabled in this build (manual import still works)."
}

$targets = switch ($Arch) {
  "x64" { @("x86_64-pc-windows-msvc") }
  "arm64" { @("aarch64-pc-windows-msvc") }
  "both" { @("x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc") }
}
$profileDir = if ($DebugBuild) { "debug" } else { "release" }

$signConfig = $null
if ($env:SECCOM_WINDOWS_SIGN_COMMAND) {
  # Passed to the Tauri CLI as an extra config file (UTF-8 without BOM).
  $signConfig = Join-Path ([System.IO.Path]::GetTempPath()) "seccom-sign-$PID.json"
  $json = @{ bundle = @{ windows = @{ signCommand = $env:SECCOM_WINDOWS_SIGN_COMMAND } } } | ConvertTo-Json -Depth 5
  [System.IO.File]::WriteAllText($signConfig, $json)
} else {
  Write-Host "note: SECCOM_WINDOWS_SIGN_COMMAND is not set - installers will be unsigned (SmartScreen will warn)."
}

$outRoot = Join-Path $Root "dist-release\windows"
New-Item -ItemType Directory -Force -Path $outRoot | Out-Null

Push-Location $App
try {
  Invoke-Checked "npm" @("ci", "--no-audit", "--no-fund")

  foreach ($target in $targets) {
    Invoke-Checked "rustup" @("target", "add", $target)

    $bundleList = $Bundles
    if ($target -like "aarch64-*" -and $bundleList -match "msi") {
      Write-Host "note: MSI is not produced for ARM64, building NSIS only."
      $bundleList = "nsis"
    }

    $tauriArgs = @("tauri", "build", "--target", $target, "--bundles", $bundleList)
    if ($DebugBuild) { $tauriArgs += "--debug" }
    if ($signConfig) { $tauriArgs += @("--config", $signConfig) }
    $started = (Get-Date).AddSeconds(-5)
    Invoke-Checked "npx" $tauriArgs

    # Collect only the installers produced by this run.
    $bundleDir = Join-Path $Root "target\$target\$profileDir\bundle"
    $out = Join-Path $outRoot $target
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    foreach ($kind in ($bundleList -split ",")) {
      $pattern = if ($kind.Trim() -eq "msi") { "*.msi" } else { "*.exe" }
      $dir = Join-Path $bundleDir $kind.Trim()
      if (-not (Test-Path $dir)) { continue }
      Get-ChildItem -Path $dir -File -Filter $pattern |
        Where-Object { $_.LastWriteTime -ge $started } |
        ForEach-Object {
          Copy-Item $_.FullName -Destination $out -Force
          Write-Host "  -> dist-release\windows\$target\$($_.Name)"
        }
    }

    if ($StoreMsix) {
      & (Join-Path $PSScriptRoot "package-store.ps1") -Target $target -ProfileDir $profileDir
      if ($LASTEXITCODE -ne 0) { throw "Store MSIX packaging failed with exit code $LASTEXITCODE" }
    }
  }
}
finally {
  Pop-Location
  if ($signConfig -and (Test-Path $signConfig)) { Remove-Item $signConfig -Force }
}

Write-Host "Windows build finished."
