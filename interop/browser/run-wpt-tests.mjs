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
import { execFileSync } from 'child_process';
import { MANIFEST, BODIES, assertComplete, scenariosFor } from '../conformance/scenarios.mjs';

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
  if (args[i] === '--safari') browserType = 'safari';
  if (args[i] === '--safari-preview') browserType = 'safari-preview';
}

// An expired cert fails every test identically, which reads as a protocol
// regression rather than a 13-day certificate that lapsed overnight.
function ensureCert() {
  try {
    const end = execSync(`openssl x509 -in "${CERT_PATH}" -noout -enddate`).toString().trim();
    const expiry = new Date(end.replace('notAfter=', ''));
    if (expiry.getTime() - Date.now() > 24 * 3600 * 1000) return;
    console.log(`  Certificate expires ${expiry.toISOString()} — regenerating`);
  } catch {
    console.log('  No usable certificate — generating one');
  }
  execFileSync(path.join(__dirname, 'generate-cert.sh'), { stdio: 'inherit' });
}
ensureCert();

assertComplete();

// Compute cert hash
const certHash = execSync(
  `openssl x509 -in "${CERT_PATH}" -outform der 2>/dev/null | shasum -a 256 | cut -d' ' -f1`
).toString().trim();
const hashBytes = certHash.match(/.{2}/g).map(b => parseInt(b, 16));

console.log(`\nCert hash: ${certHash}`);
console.log(`Server:    ${SERVER_URL}`);
console.log(`Browser:   ${browserType}`);

// Generate test HTML with cert hash baked in
function generateTestPage(test) {
  // Both Chrome and Firefox support serverCertificateHashes
  const useHash = true;
  return `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>
<script>
const CERT_HASH = new Uint8Array([${hashBytes.join(',')}]);
const SERVER = '${SERVER_URL}';
const USE_CERT_HASH = ${useHash};
// The handler path comes from the manifest, so the scenario body cannot name
// one the manifest disagrees with.
const HANDLER = '${test.handler}';

function wtUrl(handler) {
  return 'https://' + SERVER + '/webtransport/handlers/' + handler;
}

function createWT(handler, extra) {
  const url = wtUrl(handler);
  const opts = Object.assign({}, extra || {});
  if (USE_CERT_HASH) {
    opts.serverCertificateHashes = [{ algorithm: 'sha-256', value: CERT_HASH.buffer }];
  }
  return new WebTransport(url, opts);
}

// Chrome takes the init dictionary as the only argument; the W3C IDL puts a
// message first. Try both rather than picking one and being wrong somewhere.
function webTransportError(code) {
  try {
    return new WebTransportError('abort', { streamErrorCode: code });
  } catch {
    return new WebTransportError({ streamErrorCode: code });
  }
}

// Safari 26.4 dropped the datagrams.writable attribute for createWritable();
// Chrome and Firefox still only have writable. Neither is safe to assume.
function datagramWriter(wt) {
  const d = wt.datagrams;
  const w = typeof d.createWritable === 'function' ? d.createWritable() : d.writable;
  return w.getWriter();
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
  ${test.code}
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

// Test definitions come from the shared manifest; this runner only decides
// which of them this browser is expected to be able to run.
let passed = 0, failed = 0, xfailed = 0;
const failures = [];
const results = [];

// A scenario the manifest already marks as failing here is reported but not
// counted against the run; one that starts passing IS counted, so a stale note
// gets noticed instead of quietly outliving the bug it describes.
function record(test, ok, detail) {
  if (ok && !test.expectFail) {
    passed++;
    console.log(`\x1b[32mPASS\x1b[0m ${detail}`);
  } else if (ok && test.expectFail) {
    failed++;
    console.log(`\x1b[33mXPASS\x1b[0m ${detail}`);
    failures.push({ name: test.name, error: `passed although marked expect_fail — drop the note: ${test.expectFail}` });
  } else if (!ok && test.expectFail) {
    xfailed++;
    console.log(`\x1b[33mXFAIL\x1b[0m ${detail}`);
  } else {
    failed++;
    console.log(`\x1b[31mFAIL\x1b[0m ${detail}`);
    failures.push({ name: test.name, error: detail });
  }
  results.push({ id: test.name, ok, expected_fail: test.expectFail ?? null, detail });
}

const TESTS = scenariosFor(browserType).map((s) => ({
  name: s.id,
  handler: s.handler,
  title: s.title,
  expectFail: s.expect_fail?.[browserType] ?? null,
  code: BODIES[s.id],
}));

async function main() {
  // Start a simple HTTP server to serve test pages
  const server = http.createServer((req, res) => {
    const testName = req.url.replace(/^\/test\//, '').replace(/\?.*/, '');
    const test = TESTS.find(t => t.name === testName);
    if (test) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(generateTestPage(test));
    } else {
      res.writeHead(404);
      res.end('Not found');
    }
  });
  await new Promise(r => server.listen(HTTP_PORT, r));

  console.log(`Browser:   ${browserType}\n`);

  // Safari drives through safaridriver below and needs no Puppeteer browser;
  // launching one anyway made a Safari run fail when Chrome was not installed.
  const safari = browserType === 'safari' || browserType === 'safari-preview';

  let browser;
  if (safari) {
    // nothing to launch
  } else if (browserType === 'firefox') {
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


  console.log(`Running ${testsToRun.length} tests...\n`);

  if (safari) {
    // Safari: use safaridriver via WebDriver protocol. Technology Preview
    // ships its own driver and its own Allow Remote Automation setting, so it
    // gets its own binary and port rather than a capability flag.
    const { execSync, spawn } = await import('child_process');
    const preview = browserType === 'safari-preview';
    const driverBin = preview
      ? '/Applications/Safari Technology Preview.app/Contents/MacOS/safaridriver'
      : 'safaridriver';
    const wdPort = preview ? 9516 : 9515;
    const driverProc = spawn(driverBin, ['-p', String(wdPort)], { stdio: 'ignore' });
    await new Promise(r => setTimeout(r, 1500));

    // safaridriver wedges from time to time — it stops answering and the next
    // request hangs until undici's header timeout fires. Bound every call and
    // return null instead of throwing, so one stuck scenario costs one result
    // rather than the rest of the run.
    async function wdFetch(method, path, body) {
      const url = `http://localhost:${wdPort}${path}`;
      const opts = {
        method,
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(TEST_TIMEOUT + 5000),
      };
      if (body) opts.body = JSON.stringify(body);
      try {
        const res = await fetch(url, opts);
        return await res.json();
      } catch {
        return null;
      }
    }

    for (const test of testsToRun) {
      process.stdout.write(`  ${test.name} ... `);

      // Create new session per test
      const sessRes = await wdFetch('POST', '/session', {
        // Preview reports itself under its full product name, not 'safari'.
        capabilities: { alwaysMatch: { browserName: preview ? 'Safari Technology Preview' : 'safari' } },
      });
      const sid = sessRes?.value?.sessionId;
      if (!sid) {
        // safaridriver's own message is the useful one — it names the setting
        // that is off, and Technology Preview has its own copy of it.
        record(test, false, sessRes?.value?.message || 'could not create session');
        continue;
      }

      try {
        // Navigate to test page
        await wdFetch('POST', `/session/${sid}/url`, {
          url: `http://127.0.0.1:${HTTP_PORT}/test/${test.name}`
        });

        // Poll document.title for result
        const deadline = Date.now() + TEST_TIMEOUT + 2000;
        let result = null;
        while (Date.now() < deadline) {
          await new Promise(r => setTimeout(r, 200));
          const titleRes = await wdFetch('GET', `/session/${sid}/title`);
          if (titleRes === null) throw new Error('safaridriver stopped responding');
          const title = titleRes?.value || '';
          if (title.startsWith('PASS:')) { result = title.slice(5); break; }
          if (title.startsWith('FAIL:')) { throw new Error(title.slice(5)); }
        }
        if (result === null) throw new Error('runner timeout');

        record(test, true, result);
      } catch (err) {
        record(test, false, err.message || String(err));
      }

      await wdFetch('DELETE', `/session/${sid}`);
      if (driverProc.exitCode !== null) {
        console.log('  safaridriver exited — remaining scenarios not run');
        break;
      }
    }

    driverProc.kill();
  } else {
    // Chrome/Firefox: use Puppeteer
    for (const test of testsToRun) {
      process.stdout.write(`  ${test.name} ... `);
      const page = await browser.newPage();

      const consoleLogs = [];
      page.on('console', msg => consoleLogs.push(msg.text()));

      try {
        await page.goto(`http://127.0.0.1:${HTTP_PORT}/test/${test.name}`, {
          waitUntil: 'domcontentloaded',
        });

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

        record(test, true, result);
      } catch (err) {
        record(test, false, err.message || String(err));
        if (consoleLogs.length) {
          for (const log of consoleLogs.slice(-5)) {
            console.log(`    console: ${log}`);
          }
        }
      }

      await page.close();
    }

    await browser.close();
  }
  server.close();

  console.log(`\n${'─'.repeat(50)}`);
  const xf = xfailed ? `  \x1b[33m${xfailed} expected-fail\x1b[0m` : '';
  console.log(`  \x1b[32m${passed} passed\x1b[0m  \x1b[31m${failed} failed\x1b[0m${xf}`);
  if (process.env.RESULTS_JSON) {
    fs.writeFileSync(process.env.RESULTS_JSON, JSON.stringify({ runner: browserType, results }, null, 2));
  }
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
