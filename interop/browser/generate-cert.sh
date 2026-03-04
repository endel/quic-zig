#!/bin/bash
# Generate a short-lived ECDSA P-256 certificate for browser WebTransport testing.
# Browsers require certificates < 14 days for serverCertificateHashes.
#
# Usage: ./generate-cert.sh
# Output: certs/server.key, certs/server.crt

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="$SCRIPT_DIR/certs"
mkdir -p "$CERT_DIR"

# macOS LibreSSL doesn't support -addext, so use a config file
TMPCONF=$(mktemp)
cat > "$TMPCONF" <<EOF
[req]
default_bits = 256
prompt = no
distinguished_name = dn
x509_extensions = v3_ext

[dn]
CN = localhost

[v3_ext]
subjectAltName = DNS:localhost,IP:127.0.0.1
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = serverAuth
EOF

# Generate ECDSA P-256 key
openssl ecparam -genkey -name prime256v1 -noout -out "$CERT_DIR/server.key" 2>/dev/null

# Generate self-signed cert valid for 13 days
openssl req -new -x509 \
    -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -days 13 \
    -config "$TMPCONF" \
    2>/dev/null

rm -f "$TMPCONF"

# Compute SHA-256 hash of DER-encoded certificate
HASH=$(openssl x509 -in "$CERT_DIR/server.crt" -outform der 2>/dev/null | shasum -a 256 | cut -d' ' -f1)

echo ""
echo "Certificate generated:"
echo "  Key:  $CERT_DIR/server.key"
echo "  Cert: $CERT_DIR/server.crt"
echo "  Valid for 13 days"
echo ""
echo "SHA-256 hash: $HASH"
echo ""

# Print as JS Uint8Array for easy copy-paste
JS_ARRAY=$(echo "$HASH" | fold -w2 | while read byte; do printf "0x%s, " "$byte"; done | sed 's/, $//')
echo "JS: new Uint8Array([$JS_ARRAY])"
