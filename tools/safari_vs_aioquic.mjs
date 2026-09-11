// Drive Safari against an already-running aioquic demo WT server.
// aioquic runs on localhost:4436 with its WT echo at path /wt, using the
// same interop/browser/certs/server.crt we use in-tree. We compute the same
// SHA-256 cert hash, load our browser/index.html via file://, override the
// URL to point at aioquic's /wt, and check whether bidi echo works.
//
// Expected behavior if this *is* Safari's bug: aioquic reproduces the same
// bidi hang we see against our Zig server. That gives us independent repro
// on a completely different codebase (pure-Python QUIC stack).

import { createHash } from 'node:crypto';
import { readFileSync, copyFileSync } from 'node:fs';
import path from 'node:path';
import { Builder, By, until } from 'selenium-webdriver';
import safari from 'selenium-webdriver/safari.js';
import { setTimeout as delay } from 'node:timers/promises';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const CERT_PEM = readFileSync(path.join(ROOT, 'interop/browser/certs/server.crt'), 'utf8');

// Extract the first PEM block's DER bytes and SHA-256 hash it.
const derB64 = CERT_PEM
  .split('-----BEGIN CERTIFICATE-----')[1]
  .split('-----END CERTIFICATE-----')[0]
  .replace(/\s+/g, '');
const der = Buffer.from(derB64, 'base64');
const hash = createHash('sha256').update(der).digest('hex');
console.log('cert hash:', hash);

const tmpHtml = `/tmp/safari_aioquic_${Date.now()}.html`;
copyFileSync(path.join(ROOT, 'interop/browser/index.html'), tmpHtml);
const PAGE_URL = 'file://' + tmpHtml;
const WT_URL = process.env.WT_URL || 'https://127.0.0.1:4436/wt';

const driver = await new Builder()
  .forBrowser('safari')
  .setSafariOptions(new safari.Options())
  .build();

try {
  console.log(`Loading ${PAGE_URL} in Safari, pointing WT at ${WT_URL} ...`);
  await driver.get(PAGE_URL);
  await driver.wait(until.elementLocated(By.id('hash')), 5000);
  await driver.wait(
    async () => (await driver.executeScript('return typeof doConnect')) === 'function',
    5000,
  );

  await driver.executeScript(
    `document.getElementById('url').value = arguments[0];
     document.getElementById('hash').value = arguments[1];`,
    WT_URL,
    hash,
  );
  await driver.executeScript('doConnect();');

  let connected = false;
  try {
    await driver.wait(async () => {
      const txt = await driver.findElement(By.id('status')).getText();
      return txt.trim() === 'Connected';
    }, 15000, 'connect timeout');
    connected = true;
    console.log('Safari connected to aioquic.');
  } catch (e) {
    console.log('Safari did NOT connect within 15s.');
  }

  if (connected) {
    await driver.executeScript('sendBidi();');
    await delay(5000);

    const bidiResp = await driver.findElement(By.id('bidiResp')).getText();
    console.log('\n=== bidiResp ===');
    console.log(JSON.stringify(bidiResp));
    console.log(bidiResp.startsWith('Echo:') ? 'BIDI ECHO OK ✓' : '!!! BIDI HANG reproduced on aioquic');
  }

  console.log('\n=== Browser event log ===');
  console.log(await driver.findElement(By.id('log')).getAttribute('innerText'));
} catch (e) {
  console.error('Harness error:', e.message || e);
  try {
    console.log('\n=== Browser event log (on error) ===');
    console.log(await driver.findElement(By.id('log')).getAttribute('innerText'));
  } catch {}
} finally {
  try { await driver.quit(); } catch {}
}
