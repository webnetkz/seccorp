#!/usr/bin/env bash
# Builds SecCorp for macOS (.app and .dmg).
#
# Usage:
#   build/macos/build.sh [--arch universal|arm64|x64] [--debug] [--no-dmg]
#                        [--install] [--reset-permissions]
#
#   --arch               universal (default), arm64 (Apple Silicon) or x64 (Intel)
#   --no-dmg             build only SecCorp.app (faster test builds)
#   --install            replace /Applications/SecCorp.app (the old copy goes to the Trash)
#   --reset-permissions  forget SecCorp's privacy permissions so macOS asks again
#
# Requirements: macOS 12+, Xcode Command Line Tools, Node.js 20+, Rust (rustup).
#
# Code signing: macOS remembers privacy permissions (Full Disk Access) only for
# signed apps. The script picks, in this order: APPLE_SIGNING_IDENTITY, a
# "Developer ID Application" or "Apple Development" certificate from the
# keychain, the local "SecCorp Local Signing" certificate (create it once with
# build/macos/create-signing-cert.sh), otherwise an ad-hoc signature (then
# Full Disk Access has to be granted again after every rebuild).
#
# Optional environment:
#   SECCOM_UPDATE_PUBKEY, SECCOM_UPDATE_URL   online signature updates (see README)
#   APPLE_SIGNING_IDENTITY                    e.g. "Developer ID Application: Name (TEAMID)" or "-" (ad-hoc)
#   APPLE_ID, APPLE_PASSWORD, APPLE_TEAM_ID   notarization (app-specific password), or
#   APPLE_API_KEY, APPLE_API_ISSUER, APPLE_API_KEY_PATH   notarization with an API key
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP="$ROOT/app"
BUNDLE_ID="com.webnetkz.seccom"
LOCAL_CERT="SecCorp Local Signing"

ARCH="universal"
PROFILE="release"
BUNDLES="app,dmg"
INSTALL=0
RESET=0
declare -a EXTRA=()

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"; }
die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 not found. $2"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch) [[ $# -ge 2 ]] || die "--arch needs a value"; ARCH="$2"; shift 2 ;;
    --debug) PROFILE="debug"; EXTRA+=(--debug); shift ;;
    --no-dmg) BUNDLES="app"; shift ;;
    --install) INSTALL=1; shift ;;
    --reset-permissions) RESET=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "$(uname -s)" == "Darwin" ]] || die "the macOS build must run on a Mac."
need xcrun "Install the Xcode Command Line Tools: xcode-select --install"
need codesign "Install the Xcode Command Line Tools: xcode-select --install"
need node "Install Node.js 20+ (https://nodejs.org)."
need npm "Install Node.js 20+ (https://nodejs.org)."
need cargo "Install Rust (https://rustup.rs)."
need rustup "Install Rust via rustup (https://rustup.rs)."

case "$ARCH" in
  universal)
    TARGET="universal-apple-darwin"
    rustup target add aarch64-apple-darwin x86_64-apple-darwin
    ;;
  arm64)
    TARGET="aarch64-apple-darwin"
    rustup target add "$TARGET"
    ;;
  x64)
    TARGET="x86_64-apple-darwin"
    rustup target add "$TARGET"
    ;;
  *) die "unknown --arch '$ARCH' (use universal, arm64 or x64)" ;;
esac

[[ -n "${SECCOM_UPDATE_PUBKEY:-}" ]] ||
  echo "note: the SecCorp signed feed is not set; the app will use FreshClam when installed (manual import also works)."

# ---------------------------------------------------------------- signing
find_identity() {
  # Prints the first valid code-signing identity whose name contains $1.
  security find-identity -v -p codesigning 2>/dev/null |
    sed -n "s/^ *[0-9]*) [0-9A-F]* \"\\($1[^\"]*\\)\".*/\\1/p" | head -n 1
}

if [[ -z "${APPLE_SIGNING_IDENTITY:-}" ]]; then
  for kind in "Developer ID Application" "Apple Development" "$LOCAL_CERT"; do
    ident="$(find_identity "$kind")"
    if [[ -n "$ident" ]]; then
      export APPLE_SIGNING_IDENTITY="$ident"
      break
    fi
  done
fi
if [[ -z "${APPLE_SIGNING_IDENTITY:-}" ]]; then
  export APPLE_SIGNING_IDENTITY="-"
fi

if [[ "$APPLE_SIGNING_IDENTITY" == "-" ]]; then
  SIGN_MODE="ad-hoc"
  cat <<EOF
note: no code signing certificate found — SecCorp gets an ad-hoc signature.
      macOS will forget Full Disk Access after every rebuild. To keep it, create
      a local certificate once:  build/macos/create-signing-cert.sh
EOF
else
  SIGN_MODE="certificate"
  echo "Signing identity: $APPLE_SIGNING_IDENTITY"
  if [[ "$APPLE_SIGNING_IDENTITY" == Developer\ ID\ Application* && -z "${APPLE_ID:-}${APPLE_API_KEY:-}" ]]; then
    echo "note: no notarization credentials (APPLE_ID or APPLE_API_KEY) — fine for this Mac, other Macs will warn."
  fi
fi

if [[ $INSTALL -eq 1 && "$APPLE_SIGNING_IDENTITY" == "-" ]]; then
  die "refusing to install an ad-hoc build because macOS would ask for disk permissions again after the next update.
Run build/macos/create-signing-cert.sh once, then repeat this command."
fi

# ------------------------------------------------------------------ build
cd "$APP"
npm ci --no-audit --no-fund
npx tauri build --target "$TARGET" --bundles "$BUNDLES" ${EXTRA[@]+"${EXTRA[@]}"}

BUNDLE="$ROOT/target/$TARGET/$PROFILE/bundle"
APP_BUNDLE="$BUNDLE/macos/SecCorp.app"
[[ -d "$APP_BUNDLE" ]] || die "SecCorp.app was not produced (expected $APP_BUNDLE)"

# Seal the whole bundle. A stable certificate and bundle identifier are what
# let macOS remember Full Disk Access across rebuilt versions.
if [[ "$APPLE_SIGNING_IDENTITY" == "-" ]]; then
  codesign --force --deep --sign - "$APP_BUNDLE"
else
  codesign --force --deep --options runtime --timestamp=none --sign "$APPLE_SIGNING_IDENTITY" "$APP_BUNDLE"
fi
codesign --verify --deep --strict "$APP_BUNDLE" || die "SecCorp.app is not correctly signed"
[[ "$(defaults read "$APP_BUNDLE/Contents/Info" CFBundleIdentifier)" == "$BUNDLE_ID" ]] || die "unexpected bundle identifier"
echo "Signature:"
codesign -dv "$APP_BUNDLE" 2>&1 | grep -E "^(Identifier|Authority|Signature|TeamIdentifier)=" | sed 's/^/  /'

OUT="$ROOT/dist-release/macos"
mkdir -p "$OUT"
if [[ "$BUNDLES" == *dmg* ]]; then
  for dmg in "$BUNDLE"/dmg/*.dmg; do
    [[ -e "$dmg" ]] || continue
    cp -f "$dmg" "$OUT/"
    echo "  → dist-release/macos/$(basename "$dmg")"
  done
fi
ditto -c -k --keepParent "$APP_BUNDLE" "$OUT/SecCorp-$ARCH.app.zip"
echo "  → dist-release/macos/SecCorp-$ARCH.app.zip"

# ---------------------------------------------------------------- install
if [[ $INSTALL -eq 1 ]]; then
  APP_PROCESS_PATTERN='/Applications/(SecCom|SecCorp)\.app/Contents/MacOS/'
  if pgrep -f "$APP_PROCESS_PATTERN" >/dev/null 2>&1; then
    echo "Quitting the running SecCorp…"
    osascript -e "tell application id \"$BUNDLE_ID\" to quit" >/dev/null 2>&1 || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      pgrep -f "$APP_PROCESS_PATTERN" >/dev/null 2>&1 || break
      sleep 0.5
    done
    pgrep -f "$APP_PROCESS_PATTERN" >/dev/null 2>&1 && die "SecCorp is still running — quit it from the menu bar icon and run again."
  fi
  if [[ -d /Applications/SecCom.app ]]; then
    trashed="$HOME/.Trash/SecCom-$(date +%Y%m%d-%H%M%S).app"
    mv /Applications/SecCom.app "$trashed"
    echo "Previous version moved to the Trash: $(basename "$trashed")"
  fi
  if [[ -d /Applications/SecCorp.app ]]; then
    trashed="$HOME/.Trash/SecCorp-$(date +%Y%m%d-%H%M%S).app"
    mv /Applications/SecCorp.app "$trashed"
    echo "Previous version moved to the Trash: $(basename "$trashed")"
  fi
  ditto "$APP_BUNDLE" /Applications/SecCorp.app
  echo "Installed: /Applications/SecCorp.app"
fi

if [[ $RESET -eq 1 ]]; then
  tccutil reset All "$BUNDLE_ID" >/dev/null 2>&1 && echo "Privacy permissions of SecCorp were reset." ||
    echo "note: could not reset permissions automatically; remove SecCorp from the Full Disk Access list by hand."
fi

WHERE="$APP_BUNDLE"
[[ $INSTALL -eq 1 ]] && WHERE="/Applications/SecCorp.app"
cat <<EOF

macOS build finished ($SIGN_MODE signature).
Next steps:
  1. Open $WHERE
  2. System Settings → Privacy & Security → Full Disk Access: turn SecCorp on once.
     If an older SecCom is listed, remove it with "−" and add SecCorp with "+".
  3. Restart SecCorp when macOS offers "Quit & Reopen" — access applies after a restart.
EOF
