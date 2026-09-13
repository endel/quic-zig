// WebKit 319818: does a browser keep extending MAX_DATA / MAX_STREAMS while
// its page reads a server's firehose of small FIN'd uni streams?
//
//   node tools/wt_firehose_test.mjs [--safari|--safari-preview|--chrome]
//        [--url URL] [--seconds N]
//
// Start a server first — `zig-out/bin/wpt-server` serves /firehose?size=N.
// It holds at the peer's credit; &unbounded=1 queues past it instead. With a
// stream per chunk that is still bounded, by MAX_STREAMS; add &single=1 for
// one long stream, which is the server-memory side of the reproduction.
// The page reads every stream to EOF and the runner reports where, if
// anywhere, delivery stopped. Exits 1 on a stall.

import { execSync } from 'node:child_process';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CERT_PATH = path.join(ROOT, 'interop/browser/certs/server.crt');
const HTTP_PORT = 8788;

const args = process.argv.slice(2);
let browser = 'safari';
let url = 'https://127.0.0.1:4433/webtransport/handlers/firehose?size=16384';
let seconds = 40;
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--safari') browser = 'safari';
  else if (args[i] === '--safari-preview') browser = 'safari-preview';
  else if (args[i] === '--chrome') browser = 'chrome';
  else if (args[i] === '--url') url = args[++i];
  else if (args[i] === '--seconds') seconds = parseInt(args[++i], 10);
}

const certHash = execSync(
  `openssl x509 -in "${CERT_PATH}" -outform der 2>/dev/null | shasum -a 256 | cut -d' ' -f1`
).toString().trim();
const hashBytes = certHash.match(/.{2}/g).map((b) => parseInt(b, 16));

// Same reader as the WebKit attachment's index.html: every stream read to EOF
// immediately, nothing retained.
const PAGE = `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body><script>
let received = 0, streams = 0, err = '';
const report = () => { document.title = 'FH:' + received + ':' + streams + ':' + err; };
setInterval(report, 250);
(async () => {
  const wt = new WebTransport(${JSON.stringify(url)}, {
    serverCertificateHashes: [{ algorithm: 'sha-256', value: new Uint8Array([${hashBytes}]).buffer }],
  });
  wt.closed.then(() => { err = 'closed'; }, (e) => { err = 'closed:' + (e.message || e); });
  try { await wt.ready; } catch (e) { err = 'connect:' + (e.message || e); report(); return; }
  const incoming = wt.incomingUnidirectionalStreams.getReader();
  for (;;) {
    const { value: stream, done } = await incoming.read();
    if (done) break;
    streams++;
    (async () => {
      const reader = stream.getReader();
      for (;;) {
        const { value, done: d } = await reader.read();
        if (d) break;
        received += value.length;
      }
    })().catch((e) => { err = 'stream:' + (e.message || e); });
  }
})();
</script></body></html>`;

const server = http.createServer((_, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(PAGE);
});
await new Promise((r) => server.listen(HTTP_PORT, r));
const pageUrl = `http://127.0.0.1:${HTTP_PORT}/`;

// Each driver hands back a title getter and a closer.
async function openSafari(preview) {
  const bin = preview
    ? '/Applications/Safari Technology Preview.app/Contents/MacOS/safaridriver'
    : 'safaridriver';
  const port = preview ? 9516 : 9515;
  const proc = spawn(bin, ['-p', String(port)], { stdio: 'ignore' });
  await new Promise((r) => setTimeout(r, 1500));
  const wd = async (method, p, body) => {
    const res = await fetch(`http://localhost:${port}${p}`, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: body && JSON.stringify(body),
      signal: AbortSignal.timeout(10000),
    });
    return res.json();
  };
  const sess = await wd('POST', '/session', {
    capabilities: { alwaysMatch: { browserName: preview ? 'Safari Technology Preview' : 'safari' } },
  });
  const sid = sess?.value?.sessionId;
  if (!sid) throw new Error(sess?.value?.message || 'could not create a safaridriver session');
  await wd('POST', `/session/${sid}/url`, { url: pageUrl });
  return {
    title: async () => (await wd('GET', `/session/${sid}/title`))?.value || '',
    close: async () => { try { await wd('DELETE', `/session/${sid}`); } catch {} proc.kill(); },
  };
}

async function openChrome() {
  const { default: puppeteer } = await import('puppeteer');
  const host = new URL(url).host;
  const installed = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
  const b = await puppeteer.launch({
    headless: 'new',
    // Puppeteer's own download may be missing; an installed Chrome will do.
    executablePath: process.env.CHROME_PATH || (fs.existsSync(installed) ? installed : undefined),
    args: ['--no-sandbox', '--enable-quic', `--origin-to-force-quic-on=${host}`, '--ignore-certificate-errors'],
  });
  const page = await b.newPage();
  await page.goto(pageUrl, { waitUntil: 'domcontentloaded' });
  return { title: () => page.title(), close: () => b.close() };
}

console.log(`browser: ${browser}\nurl:     ${url}\nfor:     ${seconds}s\n`);
const drv = browser === 'chrome' ? await openChrome() : await openSafari(browser === 'safari-preview');

const MiB = (n) => (n / 1048576).toFixed(2);
const start = Date.now();
let last = { received: 0, streams: 0, err: '' };
let lastProgressAt = Date.now();
let stalled = null;
try {
  while (Date.now() - start < seconds * 1000) {
    await new Promise((r) => setTimeout(r, 1000));
    const t = await drv.title();
    if (!t.startsWith('FH:')) continue;
    const [, rx, st, ...rest] = t.split(':');
    const cur = { received: +rx, streams: +st, err: rest.join(':') };
    if (cur.received !== last.received || cur.streams !== last.streams) lastProgressAt = Date.now();
    const el = Math.round((Date.now() - start) / 1000);
    if (el % 5 === 0 || cur.err !== last.err) {
      console.log(`t=${String(el).padStart(3)}s  received ${MiB(cur.received).padStart(7)} MiB  streams ${String(cur.streams).padStart(6)}${cur.err ? '  ' + cur.err : ''}`);
    }
    last = cur;
    // server.py's page calls it a stall after 5 s without progress.
    if (cur.received > 0 && Date.now() - lastProgressAt > 5000 && !stalled) {
      stalled = { ...cur, at: el };
      console.log(`  -> no progress for 5 s: stalled at ${MiB(cur.received)} MiB / ${cur.streams} streams`);
    }
    if (cur.err.startsWith('connect')) break;
  }
} finally {
  await drv.close();
  server.close();
}

if (last.received === 0) {
  console.log(`\nRESULT: nothing received${last.err ? ' — ' + last.err : ''}`);
  process.exit(2);
}
if (stalled) {
  console.log(`\nRESULT: STALLED at ${MiB(stalled.received)} MiB / ${stalled.streams} streams (t=${stalled.at}s)`);
  process.exit(1);
}
console.log(`\nRESULT: still flowing — ${MiB(last.received)} MiB / ${last.streams} streams in ${seconds}s`);
