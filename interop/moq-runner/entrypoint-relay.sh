#!/bin/sh
# moq-interop-runner relay conventions.
# https://github.com/englishm/moq-interop-runner/blob/main/IMPLEMENTATIONS.md
set -eu

ROLE=${MOQT_ROLE:-relay}
if [ "$ROLE" != "relay" ]; then
  echo "role '$ROLE' not supported by this image" >&2
  exit 127
fi

PORT=${MOQT_PORT:-4443}
CERT=${MOQT_CERT:-/certs/cert.pem}
KEY=${MOQT_KEY:-/certs/priv.key}

if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
  echo "missing $CERT or $KEY — the runner's ./generate-certs.sh creates them" >&2
  exit 1
fi

mkdir -p "${MOQT_MLOG_DIR:-/mlog}" 2>/dev/null || true

exec /app/moq-relay-wt --port "$PORT" --cert "$CERT" --key "$KEY" "$@"
