#!/usr/bin/env bash
# Build a sandboxed Mac App Store package for SecCorp.
#
# Requirements: Xcode Command Line Tools, Rust, Node.js, and Apple distribution
# certificates/profiles installed in the current keychain/account.
#
# Optional environment:
#   APPLE_MAC_APP_SIGNING_IDENTITY   3rd Party Mac Developer Application identity
#   APPLE_MAC_INSTALLER_IDENTITY     3rd Party Mac Developer Installer identity
#   APPLE_API_KEY, APPLE_API_ISSUER, APPLE_API_KEY_PATH   upload with altool
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP="$ROOT/app"
PROFILE="$APP/src-tauri/macos/SecCorp-AppStore.provisionprofile"
TARGET="aarch64-apple-darwin"
APP_BUNDLE="$ROOT/target/$TARGET/release/bundle/macos/SecCorp.app"
OUT="$ROOT/dist-release/appstore/macos"
BUNDLE_ID="com.webnetkz.seccom"

die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 not found"; }
find_identity() {
  security find-identity -v -p codesigning 2>/dev/null |
    sed -n "s/^ *[0-9]*) [0-9A-F]* \"\\($1[^\"]*\\)\".*/\\1/p" | head -n 1
}

need xcodebuild
need xcrun
need codesign
need productbuild
need security
need cargo
need node
need npm
[[ -f "$PROFILE" ]] || die "install the Mac App Store provisioning profile at $PROFILE"

APP_IDENTITY="${APPLE_MAC_APP_SIGNING_IDENTITY:-$(find_identity '3rd Party Mac Developer Application')}"
INSTALLER_IDENTITY="${APPLE_MAC_INSTALLER_IDENTITY:-$(find_identity '3rd Party Mac Developer Installer')}"
[[ -n "$APP_IDENTITY" ]] || die "a Mac App Distribution signing identity is required"
[[ -n "$INSTALLER_IDENTITY" ]] || die "a Mac Installer Distribution signing identity is required"

cd "$APP"
npx tauri build \
  --target "$TARGET" \
  --features mac-app-store \
  --bundles app \
  --config src-tauri/tauri.appstore.conf.json

[[ -d "$APP_BUNDLE" ]] || die "SecCorp.app was not produced at $APP_BUNDLE"
codesign --force --deep --options runtime --entitlements "$APP/src-tauri/macos/AppStore.entitlements" \
  --sign "$APP_IDENTITY" "$APP_BUNDLE"
codesign --verify --deep --strict "$APP_BUNDLE"
[[ "$(defaults read "$APP_BUNDLE/Contents/Info" CFBundleIdentifier)" == "$BUNDLE_ID" ]] || die "unexpected bundle identifier"

mkdir -p "$OUT"
PKG="$OUT/SecCorp-1.0.0.pkg"
productbuild --component "$APP_BUNDLE" /Applications --sign "$INSTALLER_IDENTITY" "$PKG"
echo "Built Mac App Store package: $PKG"

if [[ -n "${APPLE_API_KEY:-}" && -n "${APPLE_API_ISSUER:-}" ]]; then
  [[ -n "${APPLE_API_KEY_PATH:-}" ]] || die "set APPLE_API_KEY_PATH for App Store Connect upload"
  [[ -f "$APPLE_API_KEY_PATH" ]] || die "App Store Connect private key not found at $APPLE_API_KEY_PATH"
  [[ "$(basename "$APPLE_API_KEY_PATH")" == "AuthKey_${APPLE_API_KEY}.p8" ]] || die "private key must be named AuthKey_${APPLE_API_KEY}.p8"
  export API_PRIVATE_KEYS_DIR="$(dirname "$APPLE_API_KEY_PATH")"
  xcrun altool --upload-app --type macos --file "$PKG" \
    --apiKey "$APPLE_API_KEY" --apiIssuer "$APPLE_API_ISSUER"
fi
