// Safari 26.4 WebTransport bidi-stream diagnostic harness.
//
// Starts apps/wt_browser_server.zig, grabs the SHA-256 cert hash from its
// stdout, drives Safari via safaridriver/selenium-webdriver against a
// file:// copy of interop/browser/index.html (avoids having to trust the
// self-signed HTTPS cert for the page load; WT itself uses the cert-hash
// pin), connects, sends a bidi message, and prints the event log + server
// log so we can see exactly where it hangs.

import { spawn } from 'node:child_process';
import { Builder, By, until } from 'selenium-webdriver';
import safari from 'selenium-webdriver/safari.js';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import fs from 'node:fs';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const SERVER_KIND = process.env.SERVER || 'zig'; // 'zig' or 'go'
const SERVER_BIN = SERVER_KIND === 'go'
  ? path.join(ROOT, 'interop/quic-go/wt_browser_server_bin')
  : path.join(ROOT, 'zig-out/bin/wt-browser-server');
const CERT = path.join(ROOT, 'interop/browser/certs/server.crt');
const KEY = path.join(ROOT, 'interop/browser/certs/server.key');
const PORT = process.env.WT_PORT || '4435';

// Copy index.html to a unique temp path each run so Safari can't serve a
// cached `file://` page with stale JS.
const tmpHtml = `/tmp/safari_wt_${Date.now()}.html`;
fs.copyFileSync(path.join(ROOT, 'interop/browser/index.html'), tmpHtml);
const PAGE_URL = 'file://' + tmpHtml;

function waitForHash(proc) {
  return new Promise((resolve, reject) => {
    let buf = '';
    const onChunk = (tag) => (chunk) => {
      const s = chunk.toString();
      buf += s;
      process.stdout.write(`[${tag}] ` + s);
      const m = buf.match(/Certificate SHA-256:\s*([0-9a-f]{64})/i);
      if (m) {
        proc.stdout.off('data', outListener);
        proc.stderr.off('data', errListener);
        resolve(m[1]);
      }
    };
    const outListener = onChunk('server');
    const errListener = onChunk('server-err');
    proc.stdout.on('data', outListener);
    proc.stderr.on('data', errListener);
    proc.on('exit', (code) => reject(new Error(`server exited early: ${code}`)));
    setTimeout(() => reject(new Error('timed out waiting for cert hash')), 10000);
  });
}

async function main() {
  // REMOTE mode: skip the local server entirely and drive Safari against an
  // already-deployed URL whose cert is CA-trusted. Used to isolate whether
  // the Safari 26.4 bidi hang is specific to the serverCertificateHashes path.
  const REMOTE = process.env.REMOTE; // e.g. https://echo.web-transport.dev:4440/
  const remoteMode = Boolean(REMOTE);

  let server = null;
  let hash = '';
  let pageUrl = PAGE_URL;
  if (remoteMode) {
    // Page served by the same host; no cert-hash pin, rely on CA trust.
    pageUrl = REMOTE;
    console.log(`REMOTE mode: ${REMOTE} — no local server, no cert pin`);
  } else {
    console.log('Starting wt-browser-server...');
    const serverLog = fs.createWriteStream('/tmp/wt_browser_server.log');
    const serverArgs = SERVER_KIND === 'go'
      ? ['-addr', `0.0.0.0:${PORT}`, '-cert', CERT, '-key', KEY]
      : ['--port', PORT, '--cert', CERT, '--key', KEY];
    server = spawn(SERVER_BIN, serverArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
    server.stdout.pipe(serverLog);
    server.stderr.pipe(serverLog);
    try {
      hash = await waitForHash(server);
    } catch (e) {
      console.error('Failed to get cert hash:', e.message);
      server.kill('SIGTERM');
      process.exit(1);
    }
    console.log('Got cert hash:', hash);
  }

  console.log('Launching Safari via safaridriver...');
  const driver = await new Builder()
    .forBrowser('safari')
    .setSafariOptions(new safari.Options())
    .build();

  let failed = false;
  try {
    await driver.get(pageUrl);
    await driver.wait(until.elementLocated(By.id('hash')), 5000);
    // Make sure inline <script> has executed and defined doConnect/log.
    await driver.wait(async () => (await driver.executeScript('return typeof doConnect')) === 'function', 5000);

    if (remoteMode) {
      // Point the URL input at the same origin we loaded the page from;
      // hash stays empty so the page uses CA trust.
      await driver.executeScript(
        `document.getElementById('url').value = arguments[0];
         document.getElementById('hash').value = '';
         if (typeof log === 'function') log('harness: URL override applied, hash cleared', 'info');`,
        REMOTE,
      );
    } else {
      await driver.executeScript(
        `document.getElementById('url').value = arguments[0];`,
        `https://127.0.0.1:${PORT}`,
      );
      await driver.findElement(By.id('hash')).sendKeys(hash);
    }
    // Trigger connect via JS rather than WebDriver click — Safari's safaridriver
    // occasionally no-ops onclick= handlers on buttons when the click originates
    // from automation; calling doConnect() directly sidesteps that.
    await driver.executeScript('doConnect();');

    // Wait for status to become Connected (up to 8s)
    await driver.wait(async () => {
      const txt = await driver.findElement(By.id('status')).getText();
      return txt.trim() === 'Connected';
    }, 25000, 'connect timeout');
    console.log('Safari connected to WT server.');

    // Trigger Bidi send via JS for the same reason as doConnect above.
    await driver.executeScript('sendBidi();');

    // Give bidi up to 5s to complete
    await delay(5000);

    const bidiResp = await driver.findElement(By.id('bidiResp')).getText();
    const logHtml = await driver.findElement(By.id('log')).getAttribute('innerText');

    console.log('\n=== Bidi response field ===');
    console.log(JSON.stringify(bidiResp));

    console.log('\n=== Browser event log ===');
    console.log(logHtml);

    if (!bidiResp.startsWith('Echo:')) {
      failed = true;
      console.log('\n!!! Bidi echo NOT received — this reproduces the Safari 26.4 hang.');
    } else {
      console.log('\nBidi echo received OK.');
    }
  } catch (e) {
    console.error('Harness error:', e.message || e);
    failed = true;
  } finally {
    try {
      const logEl = await driver.findElement(By.id('log'));
      const browserLog = await logEl.getAttribute('innerText');
      console.log('\n=== Browser event log (on error) ===');
      console.log(browserLog || '(empty)');
    } catch {}
    try { await driver.quit(); } catch {}
    if (server) server.kill('SIGTERM');
    await delay(300);
  }

  if (remoteMode) {
    console.log('\n=== Remote server log (last 30 lines from journalctl) ===');
    try {
      const { execSync } = await import('node:child_process');
      const out = execSync(
        `ssh -o ConnectTimeout=5 root@137.184.1.19 'journalctl -u wt-browser --no-pager -n 30'`,
        { encoding: 'utf8' },
      );
      console.log(out);
    } catch (e) {
      console.log('(could not fetch remote journal: ' + (e.message || e) + ')');
    }
  } else {
    console.log('\n=== Server log (tail) ===');
    try {
      const log = fs.readFileSync('/tmp/wt_browser_server.log', 'utf8');
      const tail = log.split('\n').slice(-60).join('\n');
      console.log(tail);
    } catch (e) {
      console.log('(no server log)');
    }
  }

  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });
