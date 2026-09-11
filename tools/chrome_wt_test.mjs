// Chrome-side WebTransport bidi echo test — companion to safari_wt_test.mjs.
// Drives Chrome via Puppeteer against a deployed URL (default
// https://echo.web-transport.dev:4440/) to confirm whether bidi echo works
// *anywhere* before blaming Safari for the Safari 26.4 hang.
//
// Usage: node tools/chrome_wt_test.mjs
//        REMOTE=https://other.example/ node tools/chrome_wt_test.mjs

import puppeteer from 'puppeteer';
import { setTimeout as delay } from 'node:timers/promises';

const REMOTE = process.env.REMOTE || 'https://echo.web-transport.dev:4440/';

const browser = await puppeteer.launch({
  headless: true,
  args: ['--ignore-certificate-errors'],
  protocolTimeout: 60000,
});

try {
  const page = await browser.newPage();
  page.on('console', (msg) => console.log('  [page]', msg.text()));
  await page.goto(REMOTE, { waitUntil: 'domcontentloaded', timeout: 60000 });

  // Override URL input to match REMOTE (page defaults to 127.0.0.1:4433),
  // leave hash empty → CA trust.
  await page.evaluate((url) => {
    document.getElementById('url').value = url;
    document.getElementById('hash').value = '';
  }, REMOTE);

  // Call the page's handler directly to avoid any click-routing quirks.
  await page.evaluate(() => doConnect());

  await page.waitForFunction(
    () => document.getElementById('status').textContent.trim() === 'Connected',
    { timeout: 10000 },
  );
  console.log('Chrome connected.');

  await page.evaluate(() => sendBidi());

  // Wait up to 8s for bidi echo to complete.
  const ok = await page
    .waitForFunction(
      () => (document.getElementById('bidiResp').textContent || '').startsWith('Echo:'),
      { timeout: 8000 },
    )
    .then(() => true)
    .catch(() => false);

  const resp = await page.$eval('#bidiResp', (el) => el.textContent);
  const log = await page.$eval('#log', (el) => el.innerText);

  console.log('\n=== Bidi response ===');
  console.log(JSON.stringify(resp));
  console.log('\n=== Browser event log ===');
  console.log(log);

  if (ok) {
    console.log('\nChrome bidi echo OK ✓');
    process.exit(0);
  } else {
    console.log('\n!!! Chrome bidi echo NOT received — server-side bug, not Safari-specific.');
    process.exit(1);
  }
} finally {
  await browser.close();
}
