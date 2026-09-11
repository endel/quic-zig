// Local WebTransport regression test: drives Chrome (Puppeteer) against our
// own wt-browser-server-manual to confirm bidi-stream + datagram echo still
// work after the TLS refactor.
//
// Spawns the Zig server + a static httpd for interop/browser, reads the
// server's printed cert SHA-256, then connects with serverCertificateHashes.
//
// Usage: node tools/wt_local_test.mjs
import { spawn } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import puppeteer from 'puppeteer';

const ROOT = path.resolve('interop/browser');
const HTTP_PORT = 8123;
const procs = [];
const cleanup = () => procs.forEach((p) => { try { p.kill('SIGKILL'); } catch {} });

try {
  // 1. Start the Zig WebTransport server, capture the cert hash it prints.
  const server = spawn('zig-out/bin/wt-browser-server-manual', [], { stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(server);
  let serverOut = '';
  let certHash = null;
  const hashRe = /Certificate SHA-256:\s*([0-9a-f]{64})/i;
  await new Promise((resolve, reject) => {
    const onData = (b) => {
      serverOut += b.toString();
      const m = serverOut.match(hashRe);
      if (m && !certHash) { certHash = m[1]; resolve(); }
    };
    server.stdout.on('data', onData);
    server.stderr.on('data', onData);
    server.on('exit', (c) => reject(new Error(`server exited early (${c})\n${serverOut}`)));
    setTimeout(() => reject(new Error(`no cert hash in 8s\n${serverOut}`)), 8000);
  });
  console.log('server cert SHA-256:', certHash);
  await delay(500); // let it reach listen()

  // 2. Static httpd for the test page.
  const httpd = http.createServer((req, res) => {
    const file = path.join(ROOT, req.url === '/' ? 'index.html' : req.url.split('?')[0]);
    if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
    fs.readFile(file, (err, data) => {
      if (err) { res.writeHead(404); return res.end(); }
      const ext = path.extname(file);
      res.writeHead(200, { 'Content-Type': ext === '.html' ? 'text/html' : 'text/plain' });
      res.end(data);
    });
  }).listen(HTTP_PORT, '127.0.0.1');

  // 3. Drive Chrome.
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--ignore-certificate-errors'],
    protocolTimeout: 60000,
  });
  procs.push({ kill: () => browser.close() });

  const page = await browser.newPage();
  page.on('console', (m) => console.log('  [page]', m.text()));
  await page.goto(`http://127.0.0.1:${HTTP_PORT}/index.html`, { waitUntil: 'domcontentloaded' });

  await page.evaluate((hash) => {
    document.getElementById('url').value = 'https://127.0.0.1:4433';
    document.getElementById('hash').value = hash;
    doConnect();
  }, certHash);

  await page.waitForFunction(
    () => document.getElementById('status').textContent.trim() === 'Connected',
    { timeout: 10000 },
  );
  console.log('connected ✓');

  await page.evaluate(() => sendBidi());
  const bidiOk = await page
    .waitForFunction(() => (document.getElementById('bidiResp').textContent || '').includes('Hello from browser!'), { timeout: 8000 })
    .then(() => true).catch(() => false);
  console.log('bidi echo:', bidiOk ? 'OK ✓' : 'FAIL ✗', JSON.stringify(await page.$eval('#bidiResp', (e) => e.textContent)));

  await page.evaluate(() => sendDatagram());
  const dgOk = await page
    .waitForFunction(() => (document.getElementById('dgResp').textContent || '').includes('Datagram ping!'), { timeout: 8000 })
    .then(() => true).catch(() => false);
  console.log('datagram echo:', dgOk ? 'OK ✓' : 'FAIL ✗', JSON.stringify(await page.$eval('#dgResp', (e) => e.textContent)));

  console.log('\n=== browser log ===\n' + await page.$eval('#log', (e) => e.innerText));
  httpd.close();
  cleanup();
  process.exit(bidiOk && dgOk ? 0 : 1);
} catch (e) {
  console.error('ERROR:', e.message);
  cleanup();
  process.exit(2);
}
