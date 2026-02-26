#!/usr/bin/env bash
#
# Generate ECDSA P-256 certificates for QUIC interop testing.
# Output: interop/certs/{ca.crt, ca.key, server.crt, server.key}
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/certs"

mkdir -p "$CERTS_DIR"

echo "==> Generating CA key and certificate..."
openssl ecparam -genkey -name prime256v1 -noout -out "$CERTS_DIR/ca.key"
openssl req -new -x509 -key "$CERTS_DIR/ca.key" -out "$CERTS_DIR/ca.crt" \
    -days 3650 -subj "/CN=quic-zig interop CA"

echo "==> Generating server key and CSR..."
openssl ecparam -genkey -name prime256v1 -noout -out "$CERTS_DIR/server.key"
openssl req -new -key "$CERTS_DIR/server.key" -out "$CERTS_DIR/server.csr" \
    -subj "/CN=localhost"

echo "==> Signing server certificate with CA..."
cat > "$CERTS_DIR/server.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -in "$CERTS_DIR/server.csr" \
    -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" -CAcreateserial \
    -out "$CERTS_DIR/server.crt" -days 3650 \
    -extfile "$CERTS_DIR/server.ext"

# Clean up intermediate files
rm -f "$CERTS_DIR/server.csr" "$CERTS_DIR/server.ext" "$CERTS_DIR/ca.srl"

echo ""
echo "==> Certificates generated in $CERTS_DIR/"
echo "    ca.crt      - CA certificate"
echo "    ca.key      - CA private key"
echo "    server.crt  - Server certificate (ECDSA P-256, SAN: localhost, 127.0.0.1)"
echo "    server.key  - Server private key (ECDSA P-256)"
echo ""
echo "Verify with: openssl x509 -in $CERTS_DIR/server.crt -text -noout"
