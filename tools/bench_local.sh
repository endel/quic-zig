#!/usr/bin/env bash
# Throughput / handshake benchmark over loopback, no docker.
#
#   tools/bench_local.sh [runs]
#
# Serves one file with interop-server-manual, times interop-client-manual
# fetching it, then measures handshake and request rate with the H3 bench
# client. One line per metric, so two revisions can be diffed directly.
set -u

cd "$(dirname "$0")/.."

BIN=${BIN:-zig-out/bin}
RUNS=${1:-5}
SIZE_MB=${SIZE_MB:-8}   # both servers cap a served file at 10 MB
PORT=${PORT:-15533}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; [ -n "${SRV:-}" ] && kill -9 "$SRV" 2>/dev/null' EXIT

mkdir -p "$WORK/certs" "$WORK/www"
cp interop/certs/server.crt "$WORK/certs/cert.pem"
cp interop/certs/server.key "$WORK/certs/priv.key"
dd if=/dev/urandom of="$WORK/www/bulk.bin" bs=1048576 count="$SIZE_MB" 2>/dev/null

CERTS="$WORK/certs" PORT=$PORT WWW="$WORK/www" TESTCASE=transfer \
    "$BIN/interop-server-manual" >"$WORK/server.log" 2>&1 &
SRV=$!
sleep 0.5
kill -0 $SRV 2>/dev/null || { echo "server did not start"; tail -5 "$WORK/server.log"; exit 1; }

echo "# ${SIZE_MB} MB single-stream hq-interop download, $RUNS runs"
BIN="$BIN" WORK="$WORK" PORT="$PORT" RUNS="$RUNS" SIZE_MB="$SIZE_MB" python3 - <<'PY'
import filecmp, os, shutil, subprocess, time

work, binp = os.environ["WORK"], os.environ["BIN"]
size = int(os.environ["SIZE_MB"])
src = f"{work}/www/bulk.bin"
env = dict(os.environ, TESTCASE="transfer", DOWNLOADS=f"{work}/dl")
rates = []
for _ in range(int(os.environ["RUNS"])):
    shutil.rmtree(f"{work}/dl", ignore_errors=True)
    os.makedirs(f"{work}/dl")
    t0 = time.monotonic()
    rc = subprocess.run([f"{binp}/interop-client-manual",
                         f"https://127.0.0.1:{os.environ['PORT']}/bulk.bin"],
                        env=env, capture_output=True).returncode
    dt = time.monotonic() - t0
    if rc != 0 or not filecmp.cmp(f"{work}/dl/bulk.bin", src, shallow=False):
        print(f"  run failed (exit {rc})")
        continue
    rates.append(size / dt)
    print(f"  {rates[-1]:.1f} MB/s  ({dt*1000:.0f} ms)")
if rates:
    rates.sort()
    print(f"throughput_best_MBps {rates[-1]:.1f}")
    print(f"throughput_median_MBps {rates[len(rates)//2]:.1f}")
PY

kill -9 $SRV 2>/dev/null; wait $SRV 2>/dev/null; SRV=

PORT=$((PORT + 1))
CERTS="$WORK/certs" PORT=$PORT WWW="$WORK/www" TESTCASE=http3 \
    "$BIN/interop-server-manual" >"$WORK/server2.log" 2>&1 &
SRV=$!
sleep 0.5
echo "# 20 connections x 50 H3 requests"
"$BIN/bench" --port "$PORT" -c 20 -n 50 2>&1 | sed 's/^/  /'
