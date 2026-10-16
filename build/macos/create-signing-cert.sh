#!/usr/bin/env bash
# Creates a self-signed code signing certificate "SecCorp Local Signing" in your
# login keychain (run once per Mac).
#
# build/macos/build.sh then signs SecCorp with it automatically, so macOS keeps
# SecCorp's privacy permissions (Full Disk Access) across rebuilds. It is meant
# for local test builds only: other Macs do not trust this certificate. If you
# have an Apple Developer certificate ("Apple Development" or "Developer ID
# Application"), build.sh uses that one instead and you do not need this script.
#
# macOS asks for your login password once, to trust the certificate for code
# signing. To remove it later: Keychain Access → login → My Certificates.
set -euo pipefail

NAME="SecCorp Local Signing"
KEYCHAIN="$HOME/Library/Keychains/login.keychain-db"
OPENSSL=/usr/bin/openssl # system LibreSSL: its PKCS#12 files import cleanly into the keychain

die() { echo "error: $*" >&2; exit 1; }

[[ "$(uname -s)" == "Darwin" ]] || die "run this script on a Mac."
[[ -x "$OPENSSL" ]] || die "$OPENSSL not found."

if security find-identity -v -p codesigning 2>/dev/null | grep -q "\"$NAME\""; then
  echo "\"$NAME\" already exists and is trusted for code signing — nothing to do."
  exit 0
fi
if security find-certificate -c "$NAME" "$KEYCHAIN" >/dev/null 2>&1; then
  die "a certificate named \"$NAME\" exists but is not trusted for code signing.
Open Keychain Access → login → My Certificates → \"$NAME\" → Get Info → Trust → Code Signing: Always Trust,
or delete it there and run this script again."
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/seccom-cert.XXXXXX")"
cleanup() {
  rm -f "$WORK/openssl.cnf" "$WORK/key.pem" "$WORK/cert.pem" "$WORK/identity.p12"
  rmdir "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

cat >"$WORK/openssl.cnf" <<EOF
[ req ]
distinguished_name = dn
x509_extensions = ext
prompt = no

[ dn ]
CN = $NAME

[ ext ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
subjectKeyIdentifier = hash
EOF

"$OPENSSL" req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -config "$WORK/openssl.cnf" -keyout "$WORK/key.pem" -out "$WORK/cert.pem" 2>/dev/null
PASS="$("$OPENSSL" rand -hex 16)"
"$OPENSSL" pkcs12 -export -name "$NAME" -inkey "$WORK/key.pem" -in "$WORK/cert.pem" \
  -out "$WORK/identity.p12" -passout "pass:$PASS"

# -T lets codesign use the private key without asking every time.
security import "$WORK/identity.p12" -k "$KEYCHAIN" -P "$PASS" -T /usr/bin/codesign >/dev/null
echo "Certificate imported. macOS now asks for your password to trust it for code signing…"
security add-trusted-cert -r trustRoot -p codeSign -k "$KEYCHAIN" "$WORK/cert.pem"

if security find-identity -v -p codesigning | grep -q "\"$NAME\""; then
  echo "Done: \"$NAME\" is ready. Rebuild SecCorp with build/macos/build.sh."
else
  die "the certificate was imported but is not trusted for code signing yet.
Open Keychain Access → login → My Certificates → \"$NAME\" → Get Info → Trust → Code Signing: Always Trust."
fi
