#!/usr/bin/env bash
# Builds SecCorp for Android (APK and/or AAB).
#
# Usage:
#   build/android/build.sh [--apk | --aab | --both] [--debug]
#                          [--targets "aarch64 armv7 x86_64"] [--split-per-abi]
#
# Requirements: Node.js 20+, Rust (rustup), JDK 17+, Android SDK (ANDROID_HOME)
# with the NDK installed (NDK_HOME, detected automatically from ANDROID_HOME/ndk).
#
# Optional environment:
#   SECCOM_UPDATE_PUBKEY, SECCOM_UPDATE_URL     online signature updates (see README)
#   SECCOM_ANDROID_KEYSTORE, SECCOM_ANDROID_KEYSTORE_PASSWORD,
#   SECCOM_ANDROID_KEY_ALIAS, SECCOM_ANDROID_KEY_PASSWORD   release signing
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP="$ROOT/app"
GEN="$APP/src-tauri/gen/android"

FORMAT="--both"
DEBUG=0
TARGETS="aarch64 armv7 x86_64"
SPLIT=0

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"; }
die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 not found. $2"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apk | --aab | --both) FORMAT="$1"; shift ;;
    --debug) DEBUG=1; shift ;;
    --targets) [[ $# -ge 2 ]] || die "--targets needs a value"; TARGETS="$2"; shift 2 ;;
    --split-per-abi) SPLIT=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

need node "Install Node.js 20+ (https://nodejs.org)."
need npm "Install Node.js 20+ (https://nodejs.org)."
need cargo "Install Rust (https://rustup.rs)."
need rustup "Install Rust via rustup (https://rustup.rs)."
need java "Install JDK 17+ (for example Temurin) and set JAVA_HOME."

export ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
[[ -n "$ANDROID_HOME" && -d "$ANDROID_HOME" ]] || die "ANDROID_HOME is not set (path to the Android SDK)."
if [[ -z "${NDK_HOME:-}" ]]; then
  if [[ -d "$ANDROID_HOME/ndk" ]]; then
    latest="$(ls -1 "$ANDROID_HOME/ndk" | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1)"
    [[ -n "$latest" ]] && export NDK_HOME="$ANDROID_HOME/ndk/$latest"
  fi
fi
[[ -n "${NDK_HOME:-}" && -d "$NDK_HOME" ]] || die "Android NDK not found. Install it with: sdkmanager \"ndk;27.2.12479018\" or set NDK_HOME."
echo "Android SDK: $ANDROID_HOME"
echo "Android NDK: $NDK_HOME"

declare -a RUST_TARGETS=()
for t in $TARGETS; do
  case "$t" in
    aarch64) RUST_TARGETS+=(aarch64-linux-android) ;;
    armv7) RUST_TARGETS+=(armv7-linux-androideabi) ;;
    i686) RUST_TARGETS+=(i686-linux-android) ;;
    x86_64) RUST_TARGETS+=(x86_64-linux-android) ;;
    *) die "unknown Android target '$t' (use aarch64, armv7, i686, x86_64)" ;;
  esac
done
[[ ${#RUST_TARGETS[@]} -gt 0 ]] || die "no Android targets selected"
rustup target add "${RUST_TARGETS[@]}"

[[ -n "${SECCOM_UPDATE_PUBKEY:-}" ]] ||
  echo "Database updates: using the built-in Android Store signing key and feed."
if [[ $DEBUG -eq 0 && -z "${SECCOM_ANDROID_KEYSTORE:-}" ]]; then
  echo "warning: SECCOM_ANDROID_KEYSTORE is not set — the release APK/AAB will be unsigned."
fi
if [[ -n "${SECCOM_ANDROID_KEYSTORE:-}" ]]; then
  [[ -f "$SECCOM_ANDROID_KEYSTORE" ]] || die "keystore not found: $SECCOM_ANDROID_KEYSTORE"
  [[ -n "${SECCOM_ANDROID_KEYSTORE_PASSWORD:-}" && -n "${SECCOM_ANDROID_KEY_ALIAS:-}" ]] ||
    die "set SECCOM_ANDROID_KEYSTORE_PASSWORD and SECCOM_ANDROID_KEY_ALIAS for release signing."
fi

cd "$APP"
npm ci --no-audit --no-fund

if [[ ! -f "$GEN/app/build.gradle.kts" ]]; then
  echo "Generating the Android project (tauri android init)…"
  npx tauri android init --ci --skip-targets-install
fi

# `tauri android init` keeps launcher resources in the generated (and ignored)
# Gradle project. Regenerate them on every build so a stale default Tauri icon
# can never get into a release package.
ICON_OUT="$GEN/.seccom-icons"
npx tauri icon src-tauri/icons/icon.png -o "$ICON_OUT"
RES="$GEN/app/src/main/res"
mkdir -p "$RES/mipmap-anydpi-v26" "$RES/values"
cp -f "$ICON_OUT/android/mipmap-anydpi-v26/ic_launcher.xml" "$RES/mipmap-anydpi-v26/"
cp -f "$ICON_OUT/android/values/ic_launcher_background.xml" "$RES/values/"
for density in mdpi hdpi xhdpi xxhdpi xxxhdpi; do
  mkdir -p "$RES/mipmap-$density"
  cp -f "$ICON_OUT/android/mipmap-$density/"*.png "$RES/mipmap-$density/"
done

node "$ROOT/build/android/configure-gradle.mjs" "$GEN"

declare -a ARGS=(tauri android build --ci --target $TARGETS)
case "$FORMAT" in
  --apk) ARGS+=(--apk) ;;
  --aab) ARGS+=(--aab) ;;
  --both) ARGS+=(--apk --aab) ;;
esac
[[ $SPLIT -eq 1 ]] && ARGS+=(--split-per-abi)
[[ $DEBUG -eq 1 ]] && ARGS+=(--debug)

STAMP="$(mktemp)"
trap 'rm -f "$STAMP"' EXIT
npx "${ARGS[@]}"

OUT="$ROOT/dist-release/android"
mkdir -p "$OUT"
found=0
while IFS= read -r -d '' f; do
  cp -f "$f" "$OUT/"
  echo "  → dist-release/android/$(basename "$f")"
  found=1
done < <(find "$GEN/app/build/outputs" -type f \( -name '*.apk' -o -name '*.aab' \) -newer "$STAMP" -print0 2>/dev/null)
[[ $found -eq 1 ]] || echo "note: look for the build outputs in $GEN/app/build/outputs"
echo "Android build finished."
