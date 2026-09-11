// WebTransport application-protocol negotiation, checked against a real
// browser (draft-ietf-webtrans-http3-13 §3.3).
//
// The structured-field shape Chrome puts in WT-Available-Protocols is not
// something we can confirm from our own client alone — both ends would
// share our reading of the spec. So this drives Chrome against
// wt-browser-server and asserts on `transport.protocol`.
//
// Usage: node tools/wt_protocol_test.mjs
import { spawn } from 'node:child_process';
import http from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import puppeteer from 'puppeteer';

const PORT = 4468;
const HTTP_PORT = 8124;
const procs = [];
const cleanup = () => procs.forEach((p) => { try { p.kill('SIGKILL'); } catch {} });

// The server prefers moqt-18, so an offer listing moqt-17 first must still
// come back as moqt-18: the server's preference wins, not the client's.
const CASES = [
  { name: 'server preference wins',   offer: ['moqt-17', 'moqt-18'], expect: 'moqt-18' },
  { name: 'single supported protocol', offer: ['moqt-17'],           expect: 'moqt-17' },
  { name: 'no overlap',                offer: ['h3-nonsense'],       expect: '' },
  { name: 'no offer at all',           offer: null,                  expect: '' },
];

try {
  const server = spawn('zig-out/bin/wt-browser-server', ['--port', String(PORT)], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  procs.push(server);

  let out = '';
  let certHash = null;
  await new Promise((resolve, reject) => {
    const onData = (b) => {
      out += b.toString();
      const m = out.match(/Certificate SHA-256:\s*([0-9a-f]{64})/i);
      if (m && !certHash) { certHash = m[1]; resolve(); }
    };
    server.stdout.on('data', onData);
    server.stderr.on('data', onData);
    server.on('exit', (c) => reject(new Error(`server exited early (${c})\n${out}`)));
    setTimeout(() => reject(new Error(`no cert hash in 8s\n${out}`)), 8000);
  });
  await delay(500);

  // WebTransport needs a secure context; http://127.0.0.1 counts as one,
  // about:blank does not.
  const httpd = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><title>wt protocol test</title>');
  }).listen(HTTP_PORT, '127.0.0.1');
  procs.push({ kill: () => httpd.close() });

  const browser = await puppeteer.launch({
    headless: true,
    args: ['--ignore-certificate-errors'],
    protocolTimeout: 60000,
  });
  procs.push({ kill: () => browser.close() });
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${HTTP_PORT}/`, { waitUntil: 'domcontentloaded' });

  let failures = 0;
  for (const c of CASES) {
    const got = await page.evaluate(async (port, hash, offer) => {
      const opts = {
        serverCertificateHashes: [{
          algorithm: 'sha-256',
          value: Uint8Array.from(hash.match(/../g).map((h) => parseInt(h, 16))),
        }],
      };
      if (offer) opts.protocols = offer;
      const wt = new WebTransport(`https://127.0.0.1:${port}/wt`, opts);
      try {
        await wt.ready;
        const p = wt.protocol ?? '';
        wt.close();
        return p;
      } catch (e) {
        return `ERROR: ${e.message}`;
      }
    }, PORT, certHash, c.offer);

    const ok = got === c.expect;
    if (!ok) failures++;
    console.log(
      `${ok ? 'ok  ' : 'FAIL'}  ${c.name}: offered ${JSON.stringify(c.offer)} -> ` +
      `${JSON.stringify(got)}${ok ? '' : ` (expected ${JSON.stringify(c.expect)})`}`,
    );
  }

  if (failures > 0) {
    // Chrome caps serverCertificateHashes certs at 14 days, so a stale
    // interop/browser/certs/server.crt fails every case identically.
    console.log('\nIf every case failed the handshake, run interop/browser/generate-cert.sh.');
  }
  console.log(`\nserver log:\n${out.split('\n').filter((l) => l.includes('WT protocol')).join('\n') || '  (none)'}`);
  cleanup();
  process.exit(failures === 0 ? 0 : 1);
} catch (e) {
  console.error('ERROR:', e.message);
  cleanup();
  process.exit(2);
}
