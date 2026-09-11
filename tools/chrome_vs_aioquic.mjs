// Chrome control: drive Chrome against aioquic WT echo at https://127.0.0.1:4436/wt.
// Confirms aioquic is a healthy server before we blame Safari.

import { createHash } from 'node:crypto';
import { readFileSync, copyFileSync } from 'node:fs';
import path from 'node:path';
import puppeteer from 'puppeteer';
import { setTimeout as delay } from 'node:timers/promises';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const CERT_PEM = readFileSync(path.join(ROOT, 'interop/browser/certs/server.crt'), 'utf8');
const derB64 = CERT_PEM
  .split('-----BEGIN CERTIFICATE-----')[1]
  .split('-----END CERTIFICATE-----')[0]
  .replace(/\s+/g, '');
const der = Buffer.from(derB64, 'base64');
const hash = createHash('sha256').update(der).digest('hex');

const tmpHtml = `/tmp/chrome_aioquic_${Date.now()}.html`;
copyFileSync(path.join(ROOT, 'interop/browser/index.html'), tmpHtml);
const PAGE_URL = 'file://' + tmpHtml;
const WT_URL = process.env.WT_URL || 'https://127.0.0.1:4436/wt';

const browser = await puppeteer.launch({
  headless: true,
  args: ['--ignore-certificate-errors', '--origin-to-force-quic-on=127.0.0.1:4436'],
  protocolTimeout: 60000,
});

try {
  const page = await browser.newPage();
  page.on('console', (msg) => console.log('  [page]', msg.text()));
  await page.goto(PAGE_URL, { timeout: 30000 });
  await page.waitForFunction(() => typeof doConnect === 'function', { timeout: 10000 });

  await page.evaluate((url, h) => {
    document.getElementById('url').value = url;
    document.getElementById('hash').value = h;
  }, WT_URL, hash);

  await page.evaluate(() => doConnect());

  const connected = await page
    .waitForFunction(
      () => document.getElementById('status').textContent.trim() === 'Connected',
      { timeout: 15000 },
    )
    .then(() => true)
    .catch(() => false);

  console.log('connected:', connected);
  if (connected) {
    await page.evaluate(() => sendBidi());
    const ok = await page
      .waitForFunction(
        () => (document.getElementById('bidiResp').textContent || '').startsWith('Echo:'),
        { timeout: 8000 },
      )
      .then(() => true)
      .catch(() => false);
    const resp = await page.$eval('#bidiResp', (el) => el.textContent);
    console.log('bidiResp:', JSON.stringify(resp), ok ? '✓' : '✗');
  }

  const log = await page.$eval('#log', (el) => el.innerText);
  console.log('\n=== log ===\n' + log);
} finally {
  await browser.close();
}
