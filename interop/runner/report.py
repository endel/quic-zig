#!/usr/bin/env python3
"""Turn matrix-results.txt into the SPEC/interop-results.md matrix table."""
import collections, subprocess, sys, datetime, pathlib

root = pathlib.Path(__file__).resolve().parents[2]
results = root / "interop/runner/matrix-results.txt"
rows = collections.defaultdict(dict)
for line in results.read_text().splitlines():
    if not line.strip():
        continue
    pair, test, verdict = line.split()
    rows[pair][test] = verdict

order = ["handshake", "transfer", "http3", "retry", "resumption", "zerortt",
         "multiplexing", "longrtt", "keyupdate", "chacha20", "v2", "ipv6", "ecn",
         "amplificationlimit", "rebind-port", "rebind-addr", "connectionmigration",
         "blackhole", "handshakeloss", "transferloss", "handshakecorruption",
         "transfercorruption"]
tests = [t for t in order if any(t in v for v in rows.values())]
tests += sorted({t for v in rows.values() for t in v} - set(tests))

rev = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=root,
                     capture_output=True, text=True).stdout.strip()
out = [f"# Interop Test Results",
       "",
       f"Date: {datetime.date.today()}  ·  quic-zig `{rev}`, "
       "Zig 0.16.0, `zig build -Doptimize=ReleaseSafe`",
       "Peers: `martenseemann/quic-go-interop:latest`, `cloudflare/quiche-qns:latest`",
       "Harness: `interop/runner/matrix.sh` (quic-interop-runner + "
       "quic-network-simulator)",
       "",
       "## QUIC / HTTP/3 matrix",
       "",
       "Read `A<-B` as \"A is the server, B is the client\".",
       ""]

mark = {"PASS": "✅", "FAIL": "❌", "UNSUPPORTED": "—", "UNKNOWN": "?", "ERROR": "!"}
pairs = sorted(rows)
out.append("| Test | " + " | ".join(pairs) + " |")
out.append("|---|" + "---|" * len(pairs))
for t in tests:
    cells = [mark.get(rows[p].get(t, ""), " ") for p in pairs]
    out.append(f"| {t} | " + " | ".join(cells) + " |")

out += ["", "Totals:"]
for p in pairs:
    c = collections.Counter(rows[p].values())
    out.append(f"- `{p}` — {c['PASS']} pass, {c['FAIL']} fail, "
               f"{c['UNSUPPORTED']} unsupported, of {sum(c.values())}")
out += ["", "Legend: ✅ pass · ❌ fail · — the peer does not implement the case."]
print("\n".join(out))
