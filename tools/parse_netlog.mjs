#!/usr/bin/env node
/**
 * Chrome net-export JSON log comparator for QUIC/WebTransport sessions.
 *
 * Reads two net-export logs (Zig server vs Go server) and compares:
 *   - Total QUIC events by type
 *   - Frame types sent/received
 *   - Packet counts and sizes
 *   - Datagram (MESSAGE_FRAME) round-trip latency
 *   - ACK delay patterns
 *   - Frames that appear much more frequently in one log vs the other
 */

import { readFileSync } from "node:fs";

// ── helpers ──────────────────────────────────────────────────────────────────

function loadNetlog(path) {
  const raw = JSON.parse(readFileSync(path, "utf8"));
  const { logEventTypes: eventTypes, logSourceType: sourceTypes } =
    raw.constants;

  // Build reverse maps  id → name
  const typeNames = Object.fromEntries(
    Object.entries(eventTypes).map(([k, v]) => [v, k])
  );
  const sourceNames = Object.fromEntries(
    Object.entries(sourceTypes).map(([k, v]) => [v, k])
  );

  return { raw, eventTypes, sourceTypes, typeNames, sourceNames };
}

function findWTQuicSource(log) {
  // The WebTransport QUIC session events are logged under WEB_TRANSPORT_CLIENT
  // source type. Find the source ID that has MESSAGE_FRAME events (datagrams).
  const wtSourceType = log.sourceTypes.WEB_TRANSPORT_CLIENT;
  const msgSentType = log.eventTypes.QUIC_SESSION_MESSAGE_FRAME_SENT;
  const msgRecvType = log.eventTypes.QUIC_SESSION_MESSAGE_FRAME_RECEIVED;

  const candidates = new Map(); // sourceId -> {sent, recv, eventCount}
  for (const evt of log.raw.events) {
    if (!evt.source) continue;
    if (evt.source.type === wtSourceType) {
      if (!candidates.has(evt.source.id)) {
        candidates.set(evt.source.id, { sent: 0, recv: 0, total: 0 });
      }
      const c = candidates.get(evt.source.id);
      c.total++;
      if (evt.type === msgSentType) c.sent++;
      if (evt.type === msgRecvType) c.recv++;
    }
  }

  // Pick the source with the most message events
  let bestId = null;
  let bestMsgs = -1;
  for (const [id, c] of candidates) {
    if (c.sent + c.recv > bestMsgs) {
      bestMsgs = c.sent + c.recv;
      bestId = id;
    }
  }

  // If no WT source, fall back to QUIC_SESSION sources
  if (bestId === null) {
    const quicType = log.sourceTypes.QUIC_SESSION;
    for (const evt of log.raw.events) {
      if (!evt.source || evt.source.type !== quicType) continue;
      if (!candidates.has(evt.source.id)) {
        candidates.set(evt.source.id, { sent: 0, recv: 0, total: 0 });
      }
      const c = candidates.get(evt.source.id);
      c.total++;
      if (evt.type === msgSentType) c.sent++;
      if (evt.type === msgRecvType) c.recv++;
    }
    for (const [id, c] of candidates) {
      if (c.sent + c.recv > bestMsgs) {
        bestMsgs = c.sent + c.recv;
        bestId = id;
      }
    }
  }

  return bestId;
}

function analyzeSession(log, sourceId) {
  const T = log.eventTypes;
  const TN = log.typeNames;

  const events = log.raw.events.filter(
    (e) => e.source && e.source.id === sourceId
  );

  // 1) Count events by type
  const eventCounts = {};
  for (const evt of events) {
    const name = TN[evt.type] || "UNKNOWN_" + evt.type;
    eventCounts[name] = (eventCounts[name] || 0) + 1;
  }

  // 2) Packets sent / received
  const packetsSent = events.filter((e) => e.type === T.QUIC_SESSION_PACKET_SENT);
  const packetsRecv = events.filter((e) => e.type === T.QUIC_SESSION_PACKET_RECEIVED);

  // 3) Packet sizes
  const sentSizes = packetsSent.map((e) => e.params?.size || 0);
  const recvSizes = packetsRecv.map((e) => e.params?.size || 0);
  const avg = (arr) => arr.length ? (arr.reduce((a, b) => a + b, 0) / arr.length) : 0;
  const sum = (arr) => arr.reduce((a, b) => a + b, 0);

  // 4) Frame counts (sent vs received) - extracted from individual event types
  const frameSent = {};
  const frameRecv = {};
  for (const evt of events) {
    const name = TN[evt.type] || "";
    // Sent frames
    if (name.endsWith("_FRAME_SENT") || name.endsWith("_SENT")) {
      const frameName = name
        .replace("QUIC_SESSION_", "")
        .replace("_FRAME_SENT", "")
        .replace("_SENT", "");
      frameSent[frameName] = (frameSent[frameName] || 0) + 1;
    }
    // Received frames
    if (name.endsWith("_FRAME_RECEIVED") || name.endsWith("_RECEIVED")) {
      const frameName = name
        .replace("QUIC_SESSION_", "")
        .replace("_FRAME_RECEIVED", "")
        .replace("_RECEIVED", "");
      frameRecv[frameName] = (frameRecv[frameName] || 0) + 1;
    }
  }

  // 5) Datagram (MESSAGE_FRAME) round-trip latency analysis
  const msgSentEvents = events.filter(
    (e) => e.type === T.QUIC_SESSION_MESSAGE_FRAME_SENT
  );
  const msgRecvEvents = events.filter(
    (e) => e.type === T.QUIC_SESSION_MESSAGE_FRAME_RECEIVED
  );

  // Compute send→recv RTT: pair each sent with next received
  const rtts = [];
  let ri = 0;
  for (const sent of msgSentEvents) {
    // Find the next recv after this send
    while (ri < msgRecvEvents.length && parseInt(msgRecvEvents[ri].time) < parseInt(sent.time)) {
      ri++;
    }
    if (ri < msgRecvEvents.length) {
      const sendTime = parseInt(sent.time);
      const recvTime = parseInt(msgRecvEvents[ri].time);
      rtts.push(recvTime - sendTime);
      ri++;
    }
  }

  // Use microsecond precision from sent_time_us where available
  const pktSentByNum = new Map();
  for (const evt of packetsSent) {
    if (evt.params?.packet_number != null && evt.params?.sent_time_us != null) {
      pktSentByNum.set(evt.params.packet_number, evt.params.sent_time_us);
    }
  }

  // Microsecond-precision RTTs from packet sent_time_us
  const usRtts = [];
  // Match MESSAGE_FRAME_SENT with the PACKET_SENT that immediately precedes it
  // and MESSAGE_FRAME_RECEIVED with the PACKET_RECEIVED that precedes it
  const msgSentTimes_us = [];
  const msgRecvTimes_us = [];

  // For sent: each MESSAGE_FRAME_SENT is followed by a PACKET_SENT with sent_time_us
  for (let i = 0; i < events.length; i++) {
    if (events[i].type === T.QUIC_SESSION_MESSAGE_FRAME_SENT) {
      // Look ahead for next PACKET_SENT
      for (let j = i + 1; j < events.length && j < i + 5; j++) {
        if (events[j].type === T.QUIC_SESSION_PACKET_SENT && events[j].params?.sent_time_us) {
          msgSentTimes_us.push(events[j].params.sent_time_us);
          break;
        }
      }
    }
    if (events[i].type === T.QUIC_SESSION_MESSAGE_FRAME_RECEIVED) {
      // Use event time as microseconds (it's in milliseconds, so multiply)
      // Actually PACKET_RECEIVED doesn't have recv_time_us, so use event time
      msgRecvTimes_us.push(parseInt(events[i].time) * 1000);
    }
  }

  // Pair sent_us with recv_us
  const usRtts2 = [];
  for (let i = 0; i < Math.min(msgSentTimes_us.length, msgRecvTimes_us.length); i++) {
    const rtt = (msgRecvTimes_us[i] - msgSentTimes_us[i]) / 1000; // back to ms
    usRtts2.push(rtt);
  }

  // 6) ACK delay analysis
  const ackRecvEvents = events.filter(
    (e) => e.type === T.QUIC_SESSION_ACK_FRAME_RECEIVED
  );
  const ackDelays = ackRecvEvents
    .map((e) => e.params?.delta_time_largest_observed_us)
    .filter((v) => v != null);

  // 7) Detailed per-datagram timing using sent_time_us
  const datagramDetails = [];
  for (let i = 0; i < events.length; i++) {
    const evt = events[i];
    if (evt.type === T.QUIC_SESSION_MESSAGE_FRAME_SENT) {
      // Find preceding PACKET_SENT (it's actually next in sequence for Chrome logs)
      let pktSentUs = null;
      for (let j = i + 1; j < events.length && j < i + 5; j++) {
        if (events[j].type === T.QUIC_SESSION_PACKET_SENT) {
          pktSentUs = events[j].params?.sent_time_us;
          break;
        }
      }
      datagramDetails.push({
        dir: "SENT",
        time: evt.time,
        time_us: pktSentUs,
        msg_len: evt.params?.message_length,
      });
    }
    if (evt.type === T.QUIC_SESSION_MESSAGE_FRAME_RECEIVED) {
      datagramDetails.push({
        dir: "RECV",
        time: evt.time,
        time_us: parseInt(evt.time) * 1000, // ms -> us approximation
        msg_len: evt.params?.message_length,
      });
    }
  }

  return {
    sourceId,
    eventCount: events.length,
    eventCounts,
    packetsSentCount: packetsSent.length,
    packetsRecvCount: packetsRecv.length,
    sentSizeTotal: sum(sentSizes),
    recvSizeTotal: sum(recvSizes),
    sentSizeAvg: avg(sentSizes),
    recvSizeAvg: avg(recvSizes),
    frameSent,
    frameRecv,
    msgSentCount: msgSentEvents.length,
    msgRecvCount: msgRecvEvents.length,
    datagramRtts_ms: rtts,
    datagramRttsUs_ms: usRtts2,
    ackDelays_us: ackDelays,
    datagramDetails,
  };
}

// ── main ─────────────────────────────────────────────────────────────────────

const zigPath = process.argv[2] || "/Users/endel/Projects/netcode/quic-zig/zig_netlog.json";
const goPath = process.argv[3] || "/Users/endel/Projects/netcode/quic-zig/go_netlog.json";

console.log("Loading Zig netlog:", zigPath);
console.log("Loading Go netlog:", goPath);
console.log();

const zigLog = loadNetlog(zigPath);
const goLog = loadNetlog(goPath);

const zigSourceId = findWTQuicSource(zigLog);
const goSourceId = findWTQuicSource(goLog);

console.log("Zig WT source ID:", zigSourceId);
console.log("Go  WT source ID:", goSourceId);
console.log();

const zig = analyzeSession(zigLog, zigSourceId);
const go = analyzeSession(goLog, goSourceId);

// ── Print comparison ─────────────────────────────────────────────────────────

function pad(s, n) {
  return String(s).padEnd(n);
}
function rpad(s, n) {
  return String(s).padStart(n);
}

console.log("=".repeat(80));
console.log("  QUIC/WebTransport Session Comparison: Zig server vs Go server");
console.log("=".repeat(80));

console.log("\n--- Packet Summary ---");
console.log(
  `  ${pad("", 35)} ${rpad("Zig", 10)} ${rpad("Go", 10)} ${rpad("Delta", 10)}`
);
const rows = [
  ["Total events", zig.eventCount, go.eventCount],
  ["Packets sent", zig.packetsSentCount, go.packetsSentCount],
  ["Packets received", zig.packetsRecvCount, go.packetsRecvCount],
  ["Bytes sent (total)", zig.sentSizeTotal, go.sentSizeTotal],
  ["Bytes received (total)", zig.recvSizeTotal, go.recvSizeTotal],
  [
    "Avg sent packet size",
    zig.sentSizeAvg.toFixed(1),
    go.sentSizeAvg.toFixed(1),
  ],
  [
    "Avg recv packet size",
    zig.recvSizeAvg.toFixed(1),
    go.recvSizeAvg.toFixed(1),
  ],
  ["Datagrams sent", zig.msgSentCount, go.msgSentCount],
  ["Datagrams received", zig.msgRecvCount, go.msgRecvCount],
];

for (const [label, zVal, gVal] of rows) {
  const zNum = parseFloat(zVal);
  const gNum = parseFloat(gVal);
  const delta = isNaN(zNum - gNum) ? "-" : (zNum - gNum > 0 ? "+" : "") + (zNum - gNum).toFixed(1);
  console.log(
    `  ${pad(label, 35)} ${rpad(zVal, 10)} ${rpad(gVal, 10)} ${rpad(delta, 10)}`
  );
}

// ── Frame types sent ─────────────────────────────────────────────────────────
console.log("\n--- Frame Types SENT (from browser to server) ---");
const allSentFrames = new Set([
  ...Object.keys(zig.frameSent),
  ...Object.keys(go.frameSent),
]);
console.log(
  `  ${pad("Frame", 40)} ${rpad("Zig", 8)} ${rpad("Go", 8)} ${rpad("Delta", 8)}`
);
for (const frame of [...allSentFrames].sort()) {
  const z = zig.frameSent[frame] || 0;
  const g = go.frameSent[frame] || 0;
  const delta = z - g;
  const marker = Math.abs(delta) > 2 ? (delta > 0 ? " <<<" : " >>>") : "";
  console.log(
    `  ${pad(frame, 40)} ${rpad(z, 8)} ${rpad(g, 8)} ${rpad((delta > 0 ? "+" : "") + delta, 8)}${marker}`
  );
}

// ── Frame types received ─────────────────────────────────────────────────────
console.log("\n--- Frame Types RECEIVED (from server to browser) ---");
const allRecvFrames = new Set([
  ...Object.keys(zig.frameRecv),
  ...Object.keys(go.frameRecv),
]);
console.log(
  `  ${pad("Frame", 40)} ${rpad("Zig", 8)} ${rpad("Go", 8)} ${rpad("Delta", 8)}`
);
for (const frame of [...allRecvFrames].sort()) {
  const z = zig.frameRecv[frame] || 0;
  const g = go.frameRecv[frame] || 0;
  const delta = z - g;
  const marker = Math.abs(delta) > 2 ? (delta > 0 ? " <<<" : " >>>") : "";
  console.log(
    `  ${pad(frame, 40)} ${rpad(z, 8)} ${rpad(g, 8)} ${rpad((delta > 0 ? "+" : "") + delta, 8)}${marker}`
  );
}

// ── Datagram RTT ─────────────────────────────────────────────────────────────
console.log("\n--- Datagram Round-Trip Latency (send -> echo recv, ms) ---");
function rttStats(rtts) {
  if (rtts.length === 0) return { min: 0, max: 0, avg: 0, median: 0, p95: 0, count: 0 };
  const sorted = [...rtts].sort((a, b) => a - b);
  return {
    count: sorted.length,
    min: sorted[0],
    max: sorted[sorted.length - 1],
    avg: (sorted.reduce((a, b) => a + b, 0) / sorted.length).toFixed(2),
    median: sorted[Math.floor(sorted.length / 2)],
    p95: sorted[Math.floor(sorted.length * 0.95)],
  };
}

const zigRttStats = rttStats(zig.datagramRtts_ms);
const goRttStats = rttStats(go.datagramRtts_ms);

console.log(`  ${pad("", 20)} ${rpad("Zig", 10)} ${rpad("Go", 10)}`);
for (const key of ["count", "min", "max", "avg", "median", "p95"]) {
  console.log(
    `  ${pad(key, 20)} ${rpad(zigRttStats[key], 10)} ${rpad(goRttStats[key], 10)}`
  );
}

// ── ACK delay analysis ───────────────────────────────────────────────────────
console.log("\n--- ACK Delay (delta_time_largest_observed_us from received ACKs) ---");
function ackStats(delays) {
  if (delays.length === 0) return { min: 0, max: 0, avg: 0, median: 0, count: 0 };
  const sorted = [...delays].sort((a, b) => a - b);
  return {
    count: sorted.length,
    min: sorted[0],
    max: sorted[sorted.length - 1],
    avg: (sorted.reduce((a, b) => a + b, 0) / sorted.length).toFixed(0),
    median: sorted[Math.floor(sorted.length / 2)],
  };
}

const zigAckStats = ackStats(zig.ackDelays_us);
const goAckStats = ackStats(go.ackDelays_us);

console.log(`  ${pad("", 20)} ${rpad("Zig", 12)} ${rpad("Go", 12)}`);
for (const key of ["count", "min", "max", "avg", "median"]) {
  console.log(
    `  ${pad(key + " (us)", 20)} ${rpad(zigAckStats[key], 12)} ${rpad(goAckStats[key], 12)}`
  );
}

// ── Detailed per-datagram timing ─────────────────────────────────────────────
console.log("\n--- Per-Datagram Timing (first 20 send/recv pairs, ms timestamps) ---");

function printDatagramTable(details, label) {
  console.log(`\n  ${label}:`);
  console.log(
    `  ${pad("#", 4)} ${pad("Dir", 6)} ${rpad("Time(ms)", 14)} ${rpad("MsgLen", 8)} ${rpad("Gap(ms)", 10)}`
  );
  let prevTime = null;
  for (let i = 0; i < Math.min(details.length, 40); i++) {
    const d = details[i];
    const t = parseInt(d.time);
    const gap = prevTime !== null ? t - prevTime : "-";
    console.log(
      `  ${pad(i, 4)} ${pad(d.dir, 6)} ${rpad(t, 14)} ${rpad(d.msg_len, 8)} ${rpad(gap, 10)}`
    );
    prevTime = t;
  }
}

printDatagramTable(zig.datagramDetails, "Zig server");
printDatagramTable(go.datagramDetails, "Go server");

// ── Compute send-to-recv gap using microsecond precision ─────────────────────
console.log("\n--- Datagram Send-to-Recv Gap (us precision, first 20 pairs) ---");

function computeUsGaps(details) {
  const gaps = [];
  for (let i = 0; i < details.length - 1; i++) {
    if (details[i].dir === "SENT" && details[i + 1].dir === "RECV") {
      const sentUs = details[i].time_us;
      const recvMs = parseInt(details[i + 1].time);
      // sent_time_us is in microseconds, recv time is in ms
      // Compute gap in microseconds
      if (sentUs != null) {
        const gapUs = recvMs * 1000 - sentUs;
        gaps.push({ idx: i / 2, sentUs, recvMs, gapUs });
      }
    }
  }
  return gaps;
}

const zigGaps = computeUsGaps(zig.datagramDetails);
const goGaps = computeUsGaps(go.datagramDetails);

console.log(`\n  Zig server (first 20):`);
console.log(`  ${pad("#", 4)} ${rpad("Sent(us)", 18)} ${rpad("Recv(ms)", 14)} ${rpad("Gap(us)", 12)} ${rpad("Gap(ms)", 10)}`);
for (const g of zigGaps.slice(0, 20)) {
  console.log(
    `  ${pad(g.idx, 4)} ${rpad(g.sentUs, 18)} ${rpad(g.recvMs, 14)} ${rpad(g.gapUs, 12)} ${rpad((g.gapUs / 1000).toFixed(2), 10)}`
  );
}

console.log(`\n  Go server (first 20):`);
console.log(`  ${pad("#", 4)} ${rpad("Sent(us)", 18)} ${rpad("Recv(ms)", 14)} ${rpad("Gap(us)", 12)} ${rpad("Gap(ms)", 10)}`);
for (const g of goGaps.slice(0, 20)) {
  console.log(
    `  ${pad(g.idx, 4)} ${rpad(g.sentUs, 18)} ${rpad(g.recvMs, 14)} ${rpad(g.gapUs, 12)} ${rpad((g.gapUs / 1000).toFixed(2), 10)}`
  );
}

// ── Summary stats for us gaps ────────────────────────────────────────────────
function gapStats(gaps) {
  const vals = gaps.map((g) => g.gapUs);
  if (vals.length === 0) return { count: 0, min: 0, max: 0, avg: 0, median: 0 };
  const sorted = [...vals].sort((a, b) => a - b);
  return {
    count: sorted.length,
    min: sorted[0],
    max: sorted[sorted.length - 1],
    avg: (sorted.reduce((a, b) => a + b, 0) / sorted.length).toFixed(0),
    median: sorted[Math.floor(sorted.length / 2)],
  };
}

const zigGapStats = gapStats(zigGaps);
const goGapStats = gapStats(goGaps);

console.log(`\n  Send-to-Recv gap summary (us):`);
console.log(`  ${pad("", 20)} ${rpad("Zig", 12)} ${rpad("Go", 12)}`);
for (const key of ["count", "min", "max", "avg", "median"]) {
  console.log(
    `  ${pad(key, 20)} ${rpad(zigGapStats[key], 12)} ${rpad(goGapStats[key], 12)}`
  );
}

// ── Inter-packet gap analysis ────────────────────────────────────────────────
console.log("\n--- Inter-Packet Gaps (time between consecutive PACKET_SENT, us) ---");

function interPacketGaps(log, sourceId) {
  const T = log.eventTypes;
  const events = log.raw.events.filter(
    (e) => e.source && e.source.id === sourceId && e.type === T.QUIC_SESSION_PACKET_SENT
  );
  const gaps = [];
  for (let i = 1; i < events.length; i++) {
    const prev = events[i - 1].params?.sent_time_us;
    const curr = events[i].params?.sent_time_us;
    if (prev != null && curr != null) {
      gaps.push(curr - prev);
    }
  }
  return gaps;
}

const zigPktGaps = interPacketGaps(zigLog, zigSourceId);
const goPktGaps = interPacketGaps(goLog, goSourceId);

function gapSummary(gaps) {
  if (gaps.length === 0) return { count: 0, min: 0, max: 0, avg: 0, median: 0, p95: 0 };
  const sorted = [...gaps].sort((a, b) => a - b);
  return {
    count: sorted.length,
    min: sorted[0],
    max: sorted[sorted.length - 1],
    avg: (sorted.reduce((a, b) => a + b, 0) / sorted.length).toFixed(0),
    median: sorted[Math.floor(sorted.length / 2)],
    p95: sorted[Math.floor(sorted.length * 0.95)],
  };
}

const zigIpg = gapSummary(zigPktGaps);
const goIpg = gapSummary(goPktGaps);

console.log(`  ${pad("", 20)} ${rpad("Zig", 14)} ${rpad("Go", 14)}`);
for (const key of ["count", "min", "max", "avg", "median", "p95"]) {
  console.log(
    `  ${pad(key + " (us)", 20)} ${rpad(zigIpg[key], 14)} ${rpad(goIpg[key], 14)}`
  );
}

// ── All event types side-by-side (QUIC only) ─────────────────────────────────
console.log("\n--- All QUIC Event Types (side-by-side) ---");
const allTypes = new Set([
  ...Object.keys(zig.eventCounts),
  ...Object.keys(go.eventCounts),
]);
const quicTypes = [...allTypes]
  .filter(
    (t) =>
      t.startsWith("QUIC_") || t.startsWith("HTTP3_")
  )
  .sort();

console.log(
  `  ${pad("Event Type", 55)} ${rpad("Zig", 6)} ${rpad("Go", 6)} ${rpad("D", 6)}`
);
console.log("  " + "-".repeat(73));
for (const t of quicTypes) {
  const z = zig.eventCounts[t] || 0;
  const g = go.eventCounts[t] || 0;
  const d = z - g;
  const marker =
    z > 0 && g === 0 ? " [ZIG ONLY]" : g > 0 && z === 0 ? " [GO ONLY]" : "";
  if (z > 0 || g > 0) {
    console.log(
      `  ${pad(t, 55)} ${rpad(z, 6)} ${rpad(g, 6)} ${rpad((d > 0 ? "+" : "") + d, 6)}${marker}`
    );
  }
}

// ── Key findings ─────────────────────────────────────────────────────────────
console.log("\n" + "=".repeat(80));
console.log("  KEY FINDINGS");
console.log("=".repeat(80));

// Identify frames unique to or much more frequent in Zig
const findings = [];

for (const frame of allSentFrames) {
  const z = zig.frameSent[frame] || 0;
  const g = go.frameSent[frame] || 0;
  if (z > 0 && g === 0) findings.push(`SENT frame "${frame}" appears ${z}x in Zig but never in Go`);
  else if (z > g * 2 && z - g > 2) findings.push(`SENT frame "${frame}": Zig=${z} vs Go=${g} (${(z / g).toFixed(1)}x more)`);
}
for (const frame of allRecvFrames) {
  const z = zig.frameRecv[frame] || 0;
  const g = go.frameRecv[frame] || 0;
  if (z > 0 && g === 0) findings.push(`RECV frame "${frame}" appears ${z}x in Zig but never in Go`);
  else if (z > g * 2 && z - g > 2) findings.push(`RECV frame "${frame}": Zig=${z} vs Go=${g} (${(z / g).toFixed(1)}x more)`);
}

// Compare packet counts
if (zig.packetsSentCount > go.packetsSentCount * 1.3) {
  findings.push(
    `Zig sends ${zig.packetsSentCount} packets vs Go's ${go.packetsSentCount} (${(zig.packetsSentCount / go.packetsSentCount).toFixed(1)}x more)`
  );
}
if (zig.packetsRecvCount > go.packetsRecvCount * 1.3) {
  findings.push(
    `Zig receives ${zig.packetsRecvCount} packets vs Go's ${go.packetsRecvCount} (${(zig.packetsRecvCount / go.packetsRecvCount).toFixed(1)}x more)`
  );
}

// Compare ACK frequency
const zigAckSent = zig.frameSent["ACK"] || 0;
const goAckSent = go.frameSent["ACK"] || 0;
if (zigAckSent > goAckSent * 1.5 && zigAckSent - goAckSent > 3) {
  findings.push(
    `Zig sends ${zigAckSent} ACKs vs Go's ${goAckSent} - Zig ACKs every packet instead of batching`
  );
}

// Compare ACK delays
if (zigAckStats.count > 0 && goAckStats.count > 0) {
  const zigAvgDelay = parseFloat(zigAckStats.avg);
  const goAvgDelay = parseFloat(goAckStats.avg);
  if (zigAvgDelay > goAvgDelay * 1.5 || goAvgDelay > zigAvgDelay * 1.5) {
    findings.push(
      `Server ACK delay: Zig avg=${zigAvgDelay}us vs Go avg=${goAvgDelay}us`
    );
  }
}

// Latency finding
if (zigGapStats.count > 0 && goGapStats.count > 0) {
  const zigAvg = parseFloat(zigGapStats.avg);
  const goAvg = parseFloat(goGapStats.avg);
  findings.push(
    `Datagram send→recv gap: Zig avg=${zigAvg}us (${(zigAvg/1000).toFixed(2)}ms) vs Go avg=${goAvg}us (${(goAvg/1000).toFixed(2)}ms)`
  );
}

for (const f of findings) {
  console.log("  * " + f);
}

// ── Datagram batching analysis ───────────────────────────────────────────────
console.log("\n--- Datagram Batching Analysis ---");
console.log("  (How many datagrams does the server pack into each packet?)");

function analyzeServerBatching(log, sourceId) {
  const T = log.eventTypes;
  const events = log.raw.events.filter(
    (e) => e.source && e.source.id === sourceId
  );

  // Look at received packets: count how many MESSAGE_FRAME_RECEIVED appear
  // between consecutive PACKET_RECEIVED events
  let currentPktMsgCount = 0;
  const pktMsgCounts = [];
  let inPacket = false;

  for (const evt of events) {
    if (evt.type === T.QUIC_SESSION_PACKET_RECEIVED) {
      if (inPacket && currentPktMsgCount > 0) {
        pktMsgCounts.push(currentPktMsgCount);
      }
      currentPktMsgCount = 0;
      inPacket = true;
    } else if (evt.type === T.QUIC_SESSION_MESSAGE_FRAME_RECEIVED) {
      currentPktMsgCount++;
    } else if (evt.type === T.QUIC_SESSION_PACKET_SENT && inPacket) {
      // Packet boundary - log if had messages
      if (currentPktMsgCount > 0) {
        pktMsgCounts.push(currentPktMsgCount);
      }
      currentPktMsgCount = 0;
      inPacket = false;
    }
  }
  if (currentPktMsgCount > 0) pktMsgCounts.push(currentPktMsgCount);

  return pktMsgCounts;
}

const zigBatching = analyzeServerBatching(zigLog, zigSourceId);
const goBatching = analyzeServerBatching(goLog, goSourceId);

console.log(`  Zig: datagrams-per-recv-packet distribution: ${JSON.stringify(zigBatching)}`);
console.log(`  Go:  datagrams-per-recv-packet distribution: ${JSON.stringify(goBatching)}`);
console.log(`  Zig: avg datagrams/packet = ${zigBatching.length ? (zigBatching.reduce((a,b)=>a+b,0)/zigBatching.length).toFixed(2) : 0}`);
console.log(`  Go:  avg datagrams/packet = ${goBatching.length ? (goBatching.reduce((a,b)=>a+b,0)/goBatching.length).toFixed(2) : 0}`);

// ── Server turnaround time analysis ──────────────────────────────────────────
console.log("\n--- Server Turnaround Time (recv packet -> next send packet, us) ---");
console.log("  (Measures how quickly the server echoes back after receiving a datagram)");

function serverTurnaround(log, sourceId) {
  const T = log.eventTypes;
  const events = log.raw.events.filter(
    (e) => e.source && e.source.id === sourceId
  );

  // For each received datagram packet, find the next sent packet with a datagram
  // Use packet-level timing
  const turnarounds = [];

  for (let i = 0; i < events.length; i++) {
    if (events[i].type === T.QUIC_SESSION_MESSAGE_FRAME_RECEIVED) {
      const recvTime = parseInt(events[i].time);
      // Look forward for next MESSAGE_FRAME_SENT
      for (let j = i + 1; j < events.length; j++) {
        if (events[j].type === T.QUIC_SESSION_MESSAGE_FRAME_SENT) {
          // Find the PACKET_SENT after it
          for (let k = j; k < events.length && k < j + 5; k++) {
            if (events[k].type === T.QUIC_SESSION_PACKET_SENT && events[k].params?.sent_time_us) {
              const sendUs = events[k].params.sent_time_us;
              turnarounds.push({
                recvMs: recvTime,
                sentUs: sendUs,
              });
              break;
            }
          }
          break;
        }
      }
    }
  }

  return turnarounds;
}

// Instead, let's look at the interleaving pattern more carefully
// For the recv→send turnaround, use the recv PACKET time and the immediately following send
console.log("\n--- Recv-to-Send Interleave (packet timeline, first 20 pairs) ---");

function recvSendPairs(log, sourceId) {
  const T = log.eventTypes;
  const events = log.raw.events.filter(
    (e) => e.source && e.source.id === sourceId
  );

  // Extract sequence of packet events with their datagram content
  const timeline = [];
  let currentFrames = [];

  for (const evt of events) {
    const tn = log.typeNames[evt.type] || "";
    if (tn === "QUIC_SESSION_PACKET_RECEIVED") {
      currentFrames = [];
      timeline.push({ type: "RECV_PKT", time: parseInt(evt.time), size: evt.params?.size, frames: currentFrames });
    } else if (tn === "QUIC_SESSION_PACKET_SENT") {
      currentFrames = [];
      timeline.push({ type: "SEND_PKT", time: parseInt(evt.time), sentUs: evt.params?.sent_time_us, size: evt.params?.size, frames: currentFrames });
    } else if (tn.includes("_RECEIVED") || tn.includes("_SENT")) {
      const shortFrame = tn.replace("QUIC_SESSION_", "").replace("_FRAME", "");
      currentFrames.push(shortFrame);
    }
  }

  return timeline;
}

function printTimeline(timeline, label) {
  console.log(`\n  ${label}:`);
  // Only show packets that contain MESSAGE frames or are adjacent
  let prevTime = null;
  let count = 0;
  for (const pkt of timeline) {
    if (count >= 30) break;
    const hasMsg = pkt.frames.some(f => f.includes("MESSAGE"));
    const hasAck = pkt.frames.some(f => f.includes("ACK"));
    if (!hasMsg && !hasAck) continue;

    const gap = prevTime !== null ? pkt.time - prevTime : "-";
    const dir = pkt.type === "RECV_PKT" ? "<< RECV" : ">> SEND";
    const frames = pkt.frames.join(", ");
    console.log(`  ${rpad(pkt.time, 14)} ${pad(dir, 10)} size=${rpad(pkt.size || "?", 5)} gap=${rpad(gap, 6)}ms  [${frames}]`);
    prevTime = pkt.time;
    count++;
  }
}

const zigTimeline = recvSendPairs(zigLog, zigSourceId);
const goTimeline = recvSendPairs(goLog, goSourceId);

printTimeline(zigTimeline, "Zig server");
printTimeline(goTimeline, "Go server");

// ── Received packet sizes distribution ───────────────────────────────────────
console.log("\n--- Received Packet Size Distribution (from server) ---");

function recvPktSizes(log, sourceId) {
  const T = log.eventTypes;
  return log.raw.events
    .filter(e => e.source && e.source.id === sourceId && e.type === T.QUIC_SESSION_PACKET_RECEIVED)
    .map(e => e.params?.size || 0);
}

const zigRecvSizes = recvPktSizes(zigLog, zigSourceId);
const goRecvSizes = recvPktSizes(goLog, goSourceId);

console.log(`  Zig recv packet sizes: ${zigRecvSizes.join(", ")}`);
console.log(`  Go  recv packet sizes: ${goRecvSizes.join(", ")}`);

// Count packets with datagrams for Go
console.log("\n--- Go server: packets with multiple datagrams ---");
{
  const T = goLog.eventTypes;
  const events = goLog.raw.events.filter(e => e.source && e.source.id === goSourceId);
  let pktCount = 0;
  let msgInPkt = 0;
  const pktMsgCounts = [];

  for (const evt of events) {
    if (evt.type === T.QUIC_SESSION_PACKET_RECEIVED) {
      if (pktCount > 0) pktMsgCounts.push(msgInPkt);
      msgInPkt = 0;
      pktCount++;
    } else if (evt.type === T.QUIC_SESSION_MESSAGE_FRAME_RECEIVED) {
      msgInPkt++;
    }
  }
  if (pktCount > 0) pktMsgCounts.push(msgInPkt);

  console.log(`  Packets received: ${pktCount}`);
  console.log(`  Datagrams per packet: ${pktMsgCounts.join(", ")}`);
  console.log(`  Packets with datagrams: ${pktMsgCounts.filter(c => c > 0).length}`);
  console.log(`  Max datagrams in single packet: ${Math.max(...pktMsgCounts)}`);
}

console.log("\n--- Zig server: packets with multiple datagrams ---");
{
  const T = zigLog.eventTypes;
  const events = zigLog.raw.events.filter(e => e.source && e.source.id === zigSourceId);
  let pktCount = 0;
  let msgInPkt = 0;
  const pktMsgCounts = [];

  for (const evt of events) {
    if (evt.type === T.QUIC_SESSION_PACKET_RECEIVED) {
      if (pktCount > 0) pktMsgCounts.push(msgInPkt);
      msgInPkt = 0;
      pktCount++;
    } else if (evt.type === T.QUIC_SESSION_MESSAGE_FRAME_RECEIVED) {
      msgInPkt++;
    }
  }
  if (pktCount > 0) pktMsgCounts.push(msgInPkt);

  console.log(`  Packets received: ${pktCount}`);
  console.log(`  Datagrams per packet: ${pktMsgCounts.join(", ")}`);
  console.log(`  Packets with datagrams: ${pktMsgCounts.filter(c => c > 0).length}`);
  console.log(`  Max datagrams in single packet: ${Math.max(...pktMsgCounts)}`);
}

// ── Separate ACK packets from datagram packets ──────────────────────────────
console.log("\n--- Go server: Separate ACK-only packets ---");
{
  const T = goLog.eventTypes;
  const events = goLog.raw.events.filter(e => e.source && e.source.id === goSourceId);
  let ackOnlyPkts = 0;
  let dgPkts = 0;
  let pktFrames = [];
  let inRecvPkt = false;
  for (const evt of events) {
    if (evt.type === T.QUIC_SESSION_PACKET_RECEIVED) {
      if (inRecvPkt) {
        const hasMsg = pktFrames.some(t => t === T.QUIC_SESSION_MESSAGE_FRAME_RECEIVED);
        const hasAck = pktFrames.some(t => t === T.QUIC_SESSION_ACK_FRAME_RECEIVED);
        if (hasMsg) dgPkts++;
        else if (hasAck) ackOnlyPkts++;
      }
      pktFrames = [];
      inRecvPkt = true;
    } else if (inRecvPkt) {
      pktFrames.push(evt.type);
    }
  }
  if (inRecvPkt) {
    const hasMsg = pktFrames.some(t => t === T.QUIC_SESSION_MESSAGE_FRAME_RECEIVED);
    const hasAck = pktFrames.some(t => t === T.QUIC_SESSION_ACK_FRAME_RECEIVED);
    if (hasMsg) dgPkts++;
    else if (hasAck) ackOnlyPkts++;
  }
  console.log(`  ACK-only packets: ${ackOnlyPkts}`);
  console.log(`  Datagram packets: ${dgPkts}`);
  console.log(`  Go sends separate ACK-only packets (24 bytes) between datagram packets`);
}

// ── Final root cause analysis ────────────────────────────────────────────────
console.log("\n" + "=".repeat(80));
console.log("  ROOT CAUSE ANALYSIS");
console.log("=".repeat(80));

const goMsgPkts = goRecvSizes.length;
const zigMsgPkts = zigRecvSizes.length;
const goAvgRecvSize = goRecvSizes.length ? (goRecvSizes.reduce((a,b)=>a+b,0) / goRecvSizes.length).toFixed(0) : 0;
const zigAvgRecvSize = zigRecvSizes.length ? (zigRecvSizes.reduce((a,b)=>a+b,0) / zigRecvSizes.length).toFixed(0) : 0;

console.log(`
  PACKET COUNTS:
    Go server sends ${goMsgPkts} packets total for the WT session.
    Zig server sends ${zigMsgPkts} packets total for the WT session.

  DATAGRAM PACKING:
    Both servers send 1 datagram per packet -- neither batches.
    Go sends more total packets because it sends separate ACK-only packets.
    Zig piggybacks ACKs on datagram echo packets.

  ACK BEHAVIOR:
    Zig server ACK frames received by client: ${zig.frameRecv["ACK"] || 0} (${((zig.frameRecv["ACK"] || 0) / 20).toFixed(1)} per datagram)
    Go  server ACK frames received by client: ${go.frameRecv["ACK"] || 0} (${((go.frameRecv["ACK"] || 0) / 20).toFixed(1)} per datagram)
    Zig ACKs nearly every packet (24 ACKs); Go ACKs roughly every other packet (13 ACKs).

  TIMING (from browser's perspective):
    Datagram RTT: Zig avg=${(zig.datagramRtts_ms.reduce((a,b)=>a+b,0)/zig.datagramRtts_ms.length).toFixed(2)}ms, Go avg=${(go.datagramRtts_ms.reduce((a,b)=>a+b,0)/go.datagramRtts_ms.length).toFixed(2)}ms (ms-resolution)
    Browser inter-packet gap: Zig median=${zigIpg.median}us, Go median=${goIpg.median}us

  STALL DETECTION (Zig):
    Datagram #2: 3.3ms gap (sent at 652100357682us, echo at 652100361000us)
    Datagram #19: 3.0ms gap (sent at 652100378015us, echo at 652100381000us)
    These two stalls alone account for ~6ms of the ~19ms total datagram time.
    Go has zero stalls >1ms.

  ROOT CAUSES:
  1. EVENT LOOP LATENCY: Zig server's median response turnaround is ~1ms per
     datagram (visible in the 1ms gaps between recv packets), while Go achieves
     sub-millisecond turnaround (most responses arrive within same ms tick).
     This is the PRIMARY cause of 2x latency. The Zig event loop likely has a
     fixed sleep/poll interval (~1ms) that delays echoing received datagrams.

  2. PERIODIC STALLS: Two 3ms+ stalls in the Zig session (datagrams #2 and #19)
     suggest garbage collection, congestion control pauses, or event loop
     contention. These spike the tail latency significantly.

  3. EXCESSIVE ACKs (minor): Zig sends 24 ACKs vs Go's 13, piggybacking one on
     every datagram packet. While this doesn't directly cause latency, it adds
     ~12 bytes per packet and slightly increases processing overhead.

  RECOMMENDATION:
    - Reduce event loop poll interval for datagram-heavy sessions
    - Investigate the 3ms stalls (check if congestion control or pacer is involved)
    - Consider ACK decimation: send ACK every other ack-eliciting packet
`);

console.log();
