// Firefox-side WebTransport bidi echo test — companion to chrome_wt_test.mjs.
// Drives Firefox via Playwright against a deployed URL (default
// https://echo.web-transport.dev:4440/) to establish a third data point in the
// Chrome/Safari/Firefox compat matrix.
//
// Usage: node tools/firefox_wt_test.mjs
//        REMOTE=https://other.example/ node tools/firefox_wt_test.mjs
//
// Firefox WebTransport is enabled by default since v114 (neqo-based). This
// harness connects, runs the bidi echo and datagram echo paths, and reports
// on both — unlike Chrome/Safari harnesses which only exercise bidi, because
// datagram compat is the second thing we care about.

import { firefox } from 'playwright';

const REMOTE = process.env.REMOTE || 'https://echo.web-transport.dev:4440/';

const browser = await firefox.launch({
  headless: true,
  firefoxUserPrefs: {
    // Enable WebTransport explicitly (default-on since 114, but force it).
    'network.webtransport.enabled': true,
    'network.webtransport.datagrams.enabled': true,
    'network.webtransport.redirect.enabled': false,
    // Don't let Firefox's HTTPS upgrade / HSTS interfere with a local test.
    'security.mixed_content.block_active_content': false,
  },
});

let failed = false;
try {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  page.on('console', (msg) => console.log('  [page]', msg.text()));
  page.on('pageerror', (err) => console.log('  [pageerror]', err.message));

  console.log(`Loading ${REMOTE} ...`);
  await page.goto(REMOTE, { waitUntil: 'domcontentloaded', timeout: 30000 });

  // Feature detection first — tells us immediately if Firefox shipped WT.
  const hasWT = await page.evaluate(() => typeof WebTransport !== 'undefined');
  const ua = await page.evaluate(() => navigator.userAgent);
  console.log('UA:', ua);
  console.log('WebTransport available:', hasWT);
  if (!hasWT) {
    console.log('!!! Firefox build has no WebTransport global — test cannot proceed.');
    process.exit(2);
  }

  // Match REMOTE and clear any hash pin — rely on CA trust for deployed hosts.
  await page.evaluate((url) => {
    document.getElementById('url').value = url;
    document.getElementById('hash').value = '';
  }, REMOTE);

  await page.evaluate(() => doConnect());

  try {
    await page.waitForFunction(
      () => document.getElementById('status').textContent.trim() === 'Connected',
      null,
      { timeout: 10000 },
    );
    console.log('Firefox connected.');
  } catch (e) {
    console.log('!!! Firefox did not reach Connected state within 10s.');
    const status = await page.$eval('#status', (el) => el.textContent).catch(() => '?');
    const log = await page.$eval('#log', (el) => el.innerText).catch(() => '(no log)');
    console.log('Final status:', status);
    console.log('\n=== Browser event log ===');
    console.log(log);
    process.exit(1);
  }

  // Bidi echo.
  await page.evaluate(() => sendBidi());
  const bidiOK = await page
    .waitForFunction(
      () => (document.getElementById('bidiResp').textContent || '').startsWith('Echo:'),
      null,
      { timeout: 8000 },
    )
    .then(() => true)
    .catch(() => false);
  const bidiResp = await page.$eval('#bidiResp', (el) => el.textContent);
  console.log('\n=== Bidi response ===');
  console.log(JSON.stringify(bidiResp));

  // Datagram echo.
  let dgramOK = null;
  const hasDgramBtn = await page.evaluate(
    () => typeof sendDatagram === 'function' && !!document.getElementById('dgResp'),
  );
  if (hasDgramBtn) {
    await page.evaluate(() => sendDatagram());
    dgramOK = await page
      .waitForFunction(
        () => {
          const t = (document.getElementById('dgResp').textContent || '').trim();
          return t.length > 0 && t !== '—' && !t.toLowerCase().includes('waiting');
        },
        null,
        { timeout: 5000 },
      )
      .then(() => true)
      .catch(() => false);
    const dgramResp = await page.$eval('#dgResp', (el) => el.textContent);
    console.log('\n=== Datagram response ===');
    console.log(JSON.stringify(dgramResp));
  } else {
    console.log('(page has no datagram control; skipping datagram test)');
  }

  const logHtml = await page.$eval('#log', (el) => el.innerText);
  console.log('\n=== Browser event log ===');
  console.log(logHtml);

  console.log('\n=== Summary ===');
  console.log('Connect:  OK');
  console.log('Bidi:    ', bidiOK ? 'OK ✓' : 'FAIL ✗');
  if (dgramOK !== null) console.log('Datagram:', dgramOK ? 'OK ✓' : 'FAIL ✗');

  failed = !bidiOK || dgramOK === false;
} catch (e) {
  console.error('Harness error:', e.message || e);
  failed = true;
} finally {
  await browser.close();
}

process.exit(failed ? 1 : 0);
