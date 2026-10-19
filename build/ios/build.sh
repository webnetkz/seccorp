#!/usr/bin/env bash
# Builds SecCorp for iOS / iPadOS (.ipa).
#
# Usage:
#   build/ios/build.sh [--export app-store-connect|release-testing|debugging]
#   build/ios/build.sh --simulator        run a development build in the iOS Simulator
#
# Requirements: a Mac with Xcode 26+ (iOS 26 SDK), Node.js 20+, Rust (rustup) and an Apple
# Developer account. APPLE_DEVELOPMENT_TEAM (10-character Team ID) is required.
#
# Optional environment:
#   SECCOM_UPDATE_PUBKEY, SECCOM_UPDATE_URL           online signature updates (see README)
#   IOS_MOBILE_PROVISION_PATH, IOS_PROVISIONING_PROFILE_NAME   manual App Store signing (CI)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP="$ROOT/app"
GEN="$APP/src-tauri/gen/apple"

EXPORT="app-store-connect"
SIMULATOR=0

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"; }
die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 not found. $2"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --export) [[ $# -ge 2 ]] || die "--export needs a value"; EXPORT="$2"; shift 2 ;;
    --simulator) SIMULATOR=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$EXPORT" in
  app-store-connect | release-testing | debugging) ;;
  *) die "unknown --export '$EXPORT' (use app-store-connect, release-testing or debugging)" ;;
esac

[[ "$(uname -s)" == "Darwin" ]] || die "the iOS build must run on a Mac with Xcode."
need xcodebuild "Install Xcode from the App Store and run: sudo xcode-select -s /Applications/Xcode.app"
need node "Install Node.js 20+ (https://nodejs.org)."
need npm "Install Node.js 20+ (https://nodejs.org)."
need cargo "Install Rust (https://rustup.rs)."
need rustup "Install Rust via rustup (https://rustup.rs)."

if [[ $SIMULATOR -eq 1 ]]; then
  if [[ "$(uname -m)" == "arm64" ]]; then rustup target add aarch64-apple-ios-sim; else rustup target add x86_64-apple-ios; fi
else
  rustup target add aarch64-apple-ios
  [[ -n "${APPLE_DEVELOPMENT_TEAM:-}" ]] ||
    die "set APPLE_DEVELOPMENT_TEAM to your 10-character Apple Team ID (developer.apple.com → Membership)."
fi

[[ -n "${SECCOM_UPDATE_PUBKEY:-}" ]] ||
  echo "warning: SECCOM_UPDATE_PUBKEY is not set — online signature updates are disabled in this build (manual import still works)."

cd "$APP"
npm ci --no-audit --no-fund

if [[ ! -d "$GEN" ]]; then
  echo "Generating the Xcode project (tauri ios init)…"
  npx tauri ios init --ci
fi

if [[ $SIMULATOR -eq 1 ]]; then
  exec npx tauri ios dev
fi

IPA_DIR="$GEN/build/arm64"
if [[ "$EXPORT" == "app-store-connect" ]]; then
  [[ -n "${IOS_MOBILE_PROVISION_PATH:-}" && -f "$IOS_MOBILE_PROVISION_PATH" ]] ||
    die "install the SecCorp App Store provisioning profile and set IOS_MOBILE_PROVISION_PATH."
  [[ -n "${IOS_PROVISIONING_PROFILE_NAME:-}" ]] ||
    die "set IOS_PROVISIONING_PROFILE_NAME to the installed App Store profile name."

  echo "Building an unsigned iOS archive for manual App Store signing…"
  npx tauri ios build --ci --export-method "$EXPORT" --archive-only

  archives=("$GEN"/build/*.xcarchive)
  [[ ${#archives[@]} -eq 1 && -d "${archives[0]}" ]] ||
    die "expected one Xcode archive in $GEN/build; found ${#archives[@]}"

  EXPORT_OPTIONS="$RUNNER_TEMP/seccom-ios-export-options.plist"
  cp "$ROOT/build/ios/ExportOptions.plist" "$EXPORT_OPTIONS"
  /usr/libexec/PlistBuddy -c "Set :teamID $APPLE_DEVELOPMENT_TEAM" "$EXPORT_OPTIONS"
  /usr/libexec/PlistBuddy -c "Set :provisioningProfiles:com.webnetkz.seccom \"$IOS_PROVISIONING_PROFILE_NAME\"" "$EXPORT_OPTIONS"

  IPA_DIR="$GEN/build/arm64/export"
  mkdir -p "$IPA_DIR"
  xcodebuild -exportArchive \
    -archivePath "${archives[0]}" \
    -exportPath "$IPA_DIR" \
    -exportOptionsPlist "$EXPORT_OPTIONS"
else
  npx tauri ios build --ci --export-method "$EXPORT"
fi

OUT="$ROOT/dist-release/ios"
mkdir -p "$OUT"
found=0
for ipa in "$IPA_DIR"/*.ipa; do
  [[ -e "$ipa" ]] || continue
  cp -f "$ipa" "$OUT/"
  echo "  → dist-release/ios/$(basename "$ipa")"
  found=1
done
[[ $found -eq 1 ]] || echo "note: look for the .ipa in $GEN/build"
cat <<'EOF'
iOS build finished.
Upload to App Store Connect (TestFlight) with:
  xcrun altool --upload-app --type ios --file dist-release/ios/SecCorp.ipa \
    --apiKey "$APPLE_API_KEY" --apiIssuer "$APPLE_API_ISSUER"
EOF
