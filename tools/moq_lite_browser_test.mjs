// moq-lite in a browser, against our own origin.
//
// Our Zig client and Zig server agreeing proves they share one reading of
// the draft. This drives the standalone JS client in
// interop/browser/moq_lite.html through Chrome instead, which at least
// shares no code with the Zig encoder.
//
// Usage: node tools/moq_lite_browser_test.mjs           # against the origin
//        RELAY=1 node tools/moq_lite_browser_test.mjs   # through the relay
import { spawn } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import puppeteer from 'puppeteer';

const ROOT = path.resolve('interop/browser');
const HTTP_PORT = 8125;
const MOQ_PORT = 4449;
// With RELAY=1 the page subscribes through our relay, with a separate
// moq-lite publisher upstream of it — three implementations in the path.
const VIA_RELAY = process.env.RELAY === '1';
const procs = [];
const cleanup = () => procs.forEach((p) => { try { p.kill('SIGKILL'); } catch {} });

try {
  const serverArgs = VIA_RELAY
    ? ['--port', String(MOQ_PORT),
       '--cert', 'interop/browser/certs/server.crt',
       '--key', 'interop/browser/certs/server.key']
    : ['serve', '--port', String(MOQ_PORT),
       '--broadcast', 'clock', '--track', 'seconds',
       '--cert', 'interop/browser/certs/server.crt',
       '--key', 'interop/browser/certs/server.key'];
  const server = spawn(
    VIA_RELAY ? 'zig-out/bin/moq-lite-relay' : 'zig-out/bin/moq-lite',
    serverArgs,
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  procs.push(server);

  if (VIA_RELAY) {
    await delay(1200);
    const pub = spawn('zig-out/bin/moq-lite', [
      'publish', '--url', `https://127.0.0.1:${MOQ_PORT}/`,
      '--broadcast', 'clock', '--track', 'seconds',
      '--tls-disable-verify', '--seconds', '60',
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    procs.push(pub);
  }

  let out = '';
  server.stdout.on('data', (b) => { out += b.toString(); });
  server.stderr.on('data', (b) => { out += b.toString(); });
  await delay(1500);
  if (server.exitCode !== null) throw new Error(`origin exited (${server.exitCode})\n${out}`);

  // Chrome caps serverCertificateHashes certs at 14 days; regenerate with
  // interop/browser/generate-cert.sh if the handshake fails outright.
  const der = fs.readFileSync(path.join(ROOT, 'certs/server.crt'));
  const { createHash } = await import('node:crypto');
  const b64 = der.toString().replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const hash = createHash('sha256').update(Buffer.from(b64, 'base64')).digest('hex');

  const httpd = http.createServer((req, res) => {
    const file = path.join(ROOT, req.url === '/' ? 'moq_lite.html' : req.url.split('?')[0]);
    if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
    fs.readFile(file, (err, data) => {
      if (err) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(data);
    });
  }).listen(HTTP_PORT, '127.0.0.1');
  procs.push({ kill: () => httpd.close() });

  const browser = await puppeteer.launch({ headless: true, protocolTimeout: 60000 });
  procs.push({ kill: () => browser.close() });
  const page = await browser.newPage();
  page.on('pageerror', (e) => console.log('  [page error]', e.message));
  await page.goto(`http://127.0.0.1:${HTTP_PORT}/moq_lite.html`, { waitUntil: 'domcontentloaded' });

  await page.evaluate((port, h) => {
    document.getElementById('url').value = `https://127.0.0.1:${port}/`;
    document.getElementById('hash').value = h;
    connect();
  }, MOQ_PORT, hash);

  const connected = await page
    .waitForFunction(() => document.getElementById('status').textContent === 'connected', { timeout: 10000 })
    .then(() => true).catch(() => false);
  console.log('connect:', connected ? 'OK' : 'FAIL');

  const protocol = await page.$eval('#protocol', (e) => e.textContent);
  console.log('negotiated protocol:', protocol, protocol === 'moq-lite-05' ? 'OK' : 'FAIL');

  const gotFrames = await page
    .waitForFunction(() => Number(document.getElementById('frames').textContent) >= 6, { timeout: 15000 })
    .then(() => true).catch(() => false);

  const groups = await page.$eval('#groups', (e) => e.textContent);
  const frames = await page.$eval('#frames', (e) => e.textContent);
  console.log(`frames: ${frames} in ${groups} groups`, gotFrames ? 'OK' : 'FAIL');
  console.log('\n=== browser log ===\n' + await page.$eval('#log', (e) => e.textContent));

  cleanup();
  process.exit(connected && protocol === 'moq-lite-05' && gotFrames ? 0 : 1);
} catch (e) {
  console.error('ERROR:', e.message);
  cleanup();
  process.exit(2);
}
