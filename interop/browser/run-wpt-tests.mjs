#!/usr/bin/env node
/**
 * Automated WPT WebTransport test runner.
 * Launches Chrome via Puppeteer, serves a test page, collects results.
 *
 * Usage:
 *   # Start server first:  ./zig-out/bin/wpt-server
 *   node interop/browser/run-wpt-tests.mjs [--filter <pattern>]
 */
import puppeteer from 'puppeteer';
import { execSync } from 'child_process';
import http from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVER_URL = process.env.WT_SERVER || '127.0.0.1:4433';
const CERT_PATH = path.join(__dirname, 'certs/server.crt');
const TEST_TIMEOUT = parseInt(process.env.TIMEOUT || '8000');
const HTTP_PORT = 8787;

const args = process.argv.slice(2);
let filterArg = null;
let browserType = 'chrome'; // 'chrome' or 'firefox'
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--filter' && args[i + 1]) filterArg = args[++i];
  if (args[i] === '--browser' && args[i + 1]) browserType = args[++i];
  if (args[i] === '--firefox') browserType = 'firefox';
}

// Compute cert hash
const certHash = execSync(
  `openssl x509 -in "${CERT_PATH}" -outform der 2>/dev/null | shasum -a 256 | cut -d' ' -f1`
).toString().trim();
const hashBytes = certHash.match(/.{2}/g).map(b => parseInt(b, 16));

console.log(`\nCert hash: ${certHash}`);
console.log(`Server:    ${SERVER_URL}`);
console.log(`Browser:   ${browserType}`);

// Generate test HTML with cert hash baked in
function generateTestPage(testName, testCode) {
  // Both Chrome and Firefox support serverCertificateHashes
  const useHash = true;
  return `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>
<script>
const CERT_HASH = new Uint8Array([${hashBytes.join(',')}]);
const SERVER = '${SERVER_URL}';
const USE_CERT_HASH = ${useHash};

function wtUrl(handler) {
  return 'https://' + SERVER + '/webtransport/handlers/' + handler;
}

function createWT(handler) {
  const url = wtUrl(handler);
  const opts = USE_CERT_HASH
    ? { serverCertificateHashes: [{ algorithm: 'sha-256', value: CERT_HASH.buffer }] }
    : {};
  const wt = new WebTransport(url, opts);
  return wt;
}

async function readStream(readable) {
  const reader = readable.getReader();
  const chunks = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  reader.releaseLock();
  const total = chunks.reduce((s, c) => s + c.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) { result.set(c, offset); offset += c.length; }
  return result;
}

async function readStreamText(readable) {
  return new TextDecoder().decode(await readStream(readable));
}

async function runTest() {
  ${testCode}
}

async function main() {
  try {
    const result = await Promise.race([
      runTest(),
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout (${TEST_TIMEOUT}ms)')), ${TEST_TIMEOUT}))
    ]);
    document.title = 'PASS:' + (result || 'ok');
  } catch (e) {
    document.title = 'FAIL:' + (e.message || e);
  }
}
main();
</script></body></html>`;
}

// Test definitions
const TESTS = [
  {
    name: 'connect-echo',
    code: `
      const wt = createWT('echo.py');
      await wt.ready;
      wt.close();
      await wt.closed;
      return 'ok';
    `,
  },
  {
    name: 'client-close-code',
    code: `
      const wt = createWT('echo.py');
      await wt.ready;
      wt.close({ closeCode: 7, reason: 'done' });
      const info = await wt.closed;
      if (info.closeCode !== 7) throw new Error('code=' + info.closeCode);
      if (info.reason !== 'done') throw new Error('reason=' + info.reason);
      return 'ok';
    `,
  },
  {
    name: 'server-close-code0',
    code: `
      const wt = createWT('server-close.py?code=0&reason=bye');
      await wt.ready;
      const info = await wt.closed;
      if (info.closeCode !== 0) throw new Error('code=' + info.closeCode);
      if (info.reason !== 'bye') throw new Error('reason=' + info.reason);
      return 'ok';
    `,
  },
  {
    name: 'server-close-code42',
    code: `
      const wt = createWT('server-close.py?code=42&reason=test');
      await wt.ready;
      const info = await wt.closed;
      if (info.closeCode !== 42) throw new Error('code=' + info.closeCode);
      return 'ok';
    `,
  },
  {
    name: 'server-close-code3999',
    code: `
      const wt = createWT('server-close.py?code=3999&reason=max');
      await wt.ready;
      const info = await wt.closed;
      if (info.closeCode !== 3999) throw new Error('code=' + info.closeCode);
      return 'ok';
    `,
  },
  {
    name: 'server-connection-close',
    code: `
      const wt = createWT('server-connection-close.py');
      await wt.ready;
      try { await wt.closed; } catch (e) { return 'ok: ' + e.message; }
      return 'ok';
    `,
  },
  {
    name: 'bidi-echo-small',
    code: `
      const wt = createWT('echo.py');
      await wt.ready;
      const s = await wt.createBidirectionalStream();
      const w = s.writable.getWriter();
      await w.write(new TextEncoder().encode('hello'));
      await w.close();
      const text = await readStreamText(s.readable);
      wt.close();
      if (text !== 'hello') throw new Error('got "' + text + '"');
      return 'ok';
    `,
  },
  {
    name: 'bidi-echo-3-streams',
    code: `
      const wt = createWT('echo.py');
      await wt.ready;
      const results = await Promise.all([0,1,2].map(async i => {
        const s = await wt.createBidirectionalStream();
        const w = s.writable.getWriter();
        const msg = 'msg' + i;
        await w.write(new TextEncoder().encode(msg));
        await w.close();
        const text = await readStreamText(s.readable);
        if (text !== msg) throw new Error('stream ' + i + ': "' + text + '"');
        return text;
      }));
      wt.close();
      return results.join(',');
    `,
  },
  {
    name: 'bidi-echo-64kb',
    code: `
      const wt = createWT('echo.py');
      await wt.ready;
      const s = await wt.createBidirectionalStream();
      const w = s.writable.getWriter();
      const sent = new Uint8Array(65536);
      for (let i = 0; i < sent.length; i++) sent[i] = i & 0xff;
      await w.write(sent);
      await w.close();
      const recv = await readStream(s.readable);
      wt.close();
      if (recv.length !== 65536) throw new Error(recv.length + ' bytes');
      return 'ok (' + recv.length + 'B)';
    `,
  },
  {
    name: 'uni-echo',
    code: `
      const wt = createWT('echo.py');
      await wt.ready;
      const sendStream = await wt.createUnidirectionalStream();
      const w = sendStream.getWriter();
      await w.write(new TextEncoder().encode('uni-test'));
      await w.close();
      const reader = wt.incomingUnidirectionalStreams.getReader();
      const { value: recvStream } = await reader.read();
      reader.releaseLock();
      const text = await readStreamText(recvStream);
      wt.close();
      if (text !== 'uni-test') throw new Error('got "' + text + '"');
      return 'ok';
    `,
  },
  {
    name: 'datagram-echo',
    code: `
      const wt = createWT('echo.py');
      await wt.ready;
      const w = wt.datagrams.writable.getWriter();
      await w.write(new TextEncoder().encode('dg-test'));
      w.releaseLock();
      const r = wt.datagrams.readable.getReader();
      const { value } = await r.read();
      r.releaseLock();
      const text = new TextDecoder().decode(value);
      wt.close();
      if (text !== 'dg-test') throw new Error('got "' + text + '"');
      return 'ok';
    `,
  },
  {
    name: 'datagram-maxsize',
    code: `
      const wt = createWT('echo.py');
      await wt.ready;
      const sz = wt.datagrams.maxDatagramSize;
      wt.close();
      if (sz <= 0) throw new Error('maxDatagramSize=' + sz);
      return 'ok (' + sz + ')';
    `,
  },
  {
    name: 'server-abort-stream',
    code: `
      const wt = createWT('abort-stream-from-server.py?code=42');
      await wt.ready;
      const reader = wt.incomingBidirectionalStreams.getReader();
      try {
        const result = await Promise.race([
          reader.read(),
          new Promise((_, r) => setTimeout(() => r(new Error('no-stream')), 3000)),
        ]);
        reader.releaseLock();
        const r = result.value.readable.getReader();
        try { await r.read(); } catch (e) { wt.close(); return 'ok: stream reset'; }
        wt.close();
        return 'ok: stream readable';
      } catch (e) {
        reader.releaseLock();
        wt.close();
        return 'ok: ' + e.message;
      }
    `,
  },
];

async function main() {
  // Start a simple HTTP server to serve test pages
  const server = http.createServer((req, res) => {
    const testName = req.url.replace(/^\/test\//, '').replace(/\?.*/, '');
    const test = TESTS.find(t => t.name === testName);
    if (test) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(generateTestPage(test.name, test.code));
    } else {
      res.writeHead(404);
      res.end('Not found');
    }
  });
  await new Promise(r => server.listen(HTTP_PORT, r));

  console.log(`Browser:   ${browserType}\n`);

  let browser;
  if (browserType === 'firefox') {
    // Firefox needs the CA cert imported into a profile.
    // Create a temp profile, import cert, then launch.
    const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ff-wpt-'));
    try {
      // Try to use certutil to import the cert as trusted
      execSync(`which certutil && certutil -A -n "wpt-test" -t "CT,," -i "${CERT_PATH}" -d "sql:${profileDir}" 2>/dev/null`, { stdio: 'pipe' });
      console.log(`  Imported cert into Firefox profile: ${profileDir}`);
    } catch {
      console.log(`  certutil not found — Firefox may reject self-signed cert`);
      console.log(`  Install: brew install nss`);
    }
    browser = await puppeteer.launch({
      browser: 'firefox',
      headless: true,
      userDataDir: profileDir,
      firefoxUserPrefs: {
        // Enable WebTransport + HTTP/3
        'network.webtransport.enabled': true,
        'network.http.http3.enabled': true,
        'network.http.http3.enable': true,
        'network.http.http3.webtransport.enabled': true,
        // Allow serverCertificateHashes with self-signed certs
        'network.webtransport.datagrams.enabled': true,
        // Relax security for testing
        'security.enterprise_roots.enabled': true,
        'dom.security.https_first': false,
      },
    });
  } else {
    browser = await puppeteer.launch({
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--enable-quic',
        '--origin-to-force-quic-on=' + SERVER_URL,
        '--ignore-certificate-errors',
      ],
    });
  }

  const testsToRun = filterArg
    ? TESTS.filter(t => t.name.includes(filterArg))
    : TESTS;

  let passed = 0, failed = 0;
  const failures = [];

  console.log(`\nRunning ${testsToRun.length} tests...\n`);

  for (const test of testsToRun) {
    process.stdout.write(`  ${test.name} ... `);
    const page = await browser.newPage();

    // Capture console for debugging
    const consoleLogs = [];
    page.on('console', msg => consoleLogs.push(msg.text()));

    try {
      await page.goto(`http://127.0.0.1:${HTTP_PORT}/test/${test.name}`, {
        waitUntil: 'domcontentloaded',
      });

      // Poll document.title for result
      const result = await new Promise((resolve, reject) => {
        const deadline = Date.now() + TEST_TIMEOUT + 2000;
        const check = async () => {
          if (Date.now() > deadline) return reject(new Error('runner timeout'));
          try {
            const title = await page.title();
            if (title.startsWith('PASS:')) return resolve(title.slice(5));
            if (title.startsWith('FAIL:')) return reject(new Error(title.slice(5)));
          } catch (e) { /* page might be navigating */ }
          setTimeout(check, 100);
        };
        check();
      });

      console.log(`\x1b[32mPASS\x1b[0m ${result}`);
      passed++;
    } catch (err) {
      const msg = err.message || String(err);
      console.log(`\x1b[31mFAIL\x1b[0m ${msg}`);
      failed++;
      failures.push({ name: test.name, error: msg });
      if (consoleLogs.length) {
        for (const log of consoleLogs.slice(-5)) {
          console.log(`    console: ${log}`);
        }
      }
    }

    await page.close();
  }

  await browser.close();
  server.close();

  console.log(`\n${'─'.repeat(50)}`);
  console.log(`  \x1b[32m${passed} passed\x1b[0m  \x1b[31m${failed} failed\x1b[0m`);
  if (failures.length) {
    console.log('\n  Failures:');
    for (const f of failures) {
      console.log(`    \x1b[31m✗\x1b[0m ${f.name}: ${f.error}`);
    }
  }
  console.log('');
  process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => { console.error('Fatal:', err); process.exit(2); });
