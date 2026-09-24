#!/usr/bin/env bash
# Deploy wt-echo-server to echo.web-transport.dev.
#
# Cross-compiles wt-echo-server locally for x86_64-linux-gnu ReleaseFast,
# scps it onto the droplet, and restarts the systemd unit. The server repo
# at /opt/quic-zig/ is NOT touched by this script — we only swap the binary
# at /opt/quic-zig/zig-out/bin/wt-echo-server.
#
# Prerequisites:
#   - Zig 0.16.0 in PATH (or ZIG env var pointing at the 0.16.0 binary).
#   - SSH access to root@echo.web-transport.dev (or the DEPLOY_HOST below).
#
# Usage:
#   ./deploy.sh              # build + deploy
#   DRY_RUN=1 ./deploy.sh    # build only, skip scp/restart
#
# Service info on the host:
#   Unit:   /etc/systemd/system/wt-echo.service
#   Binary: /opt/quic-zig/zig-out/bin/wt-echo-server
#   Port:   UDP 4433 (bound 0.0.0.0)
#   Certs:  /etc/letsencrypt/live/echo.web-transport.dev/{fullchain,privkey}.pem
#           (renewed by certbot timer — outside this script)

set -euo pipefail

DEPLOY_HOST=${DEPLOY_HOST:-root@137.184.1.19}
SERVICE=${SERVICE:-wt-echo}
REMOTE_BIN=${REMOTE_BIN:-/opt/quic-zig/zig-out/bin/wt-echo-server}
TARGET=${TARGET:-x86_64-linux-gnu}
# Baseline x86_64 has no AES-NI/PCLMUL: std falls back to software AES-GCM, ~35× slower.
CPU=${CPU:-x86_64_v3+aes+pclmul}
ZIG=${ZIG:-zig}

cd "$(dirname "$0")"

echo "=== build (target=$TARGET, cpu=$CPU, mode=ReleaseFast) ==="
"$ZIG" build -Dtarget="$TARGET" -Dcpu="$CPU" -Doptimize=ReleaseFast
local_bin="zig-out/bin/wt-echo-server"
ls -lh "$local_bin"

if [[ ${DRY_RUN:-0} == 1 ]]; then
    echo "DRY_RUN=1 — skipping upload/restart"
    exit 0
fi

echo
echo "=== stage new binary on $DEPLOY_HOST ==="
# Upload alongside the current binary as *.new so the swap is atomic —
# rename + restart happens in one SSH session below.
scp "$local_bin" "$DEPLOY_HOST:${REMOTE_BIN}.new"

echo
echo "=== swap + restart ==="
ssh "$DEPLOY_HOST" bash -se <<EOF
set -euo pipefail
# Backup the running binary (keep last one for rollback).
if [[ -f "$REMOTE_BIN" ]]; then
    cp -f "$REMOTE_BIN" "${REMOTE_BIN}.bak"
fi
mv "${REMOTE_BIN}.new" "$REMOTE_BIN"
chmod +x "$REMOTE_BIN"
systemctl restart "$SERVICE"
sleep 2
systemctl is-active --quiet "$SERVICE" || {
    echo "ERROR: $SERVICE failed to come up; rolling back"
    mv -f "${REMOTE_BIN}.bak" "$REMOTE_BIN"
    systemctl restart "$SERVICE"
    exit 1
}
echo "--- status ---"
systemctl status "$SERVICE" --no-pager -l | head -10
echo "--- listening ---"
ss -lunp | grep 4433 || echo "(no 4433 listener visible — check logs)"
EOF

echo
echo "Deploy OK. Rollback if needed:"
echo "  ssh $DEPLOY_HOST 'mv ${REMOTE_BIN}.bak $REMOTE_BIN && systemctl restart $SERVICE'"
