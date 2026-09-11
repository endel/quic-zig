// Drive a browser against a Chromium-samples style WT demo page (default:
// akaleapi's echo on https://wt-ord.akaleapi.net/echo/). The demo pages share
// a common set of element IDs — #url / #connect / #data / #bidi-stream /
// #send / #event-log — so the same script works for any of them.
//
// Usage:
//   node tools/safari_webtransport_day.mjs                            # Safari vs akaleapi
//   PAGE_URL=https://webtransport.day/ node ...                       # other demo page
//   BROWSER=chrome node tools/safari_webtransport_day.mjs             # Chrome control

import { Builder, By, until } from 'selenium-webdriver';
import safari from 'selenium-webdriver/safari.js';

const PAGE_URL = process.env.PAGE_URL || 'https://wt-ord.akaleapi.net/echo/';
const BROWSER = process.env.BROWSER || 'safari';

let driver;
if (BROWSER === 'safari') {
  driver = await new Builder()
    .forBrowser('safari')
    .setSafariOptions(new safari.Options())
    .build();
} else {
  driver = await new Builder().forBrowser(BROWSER).build();
}

try {
  console.log(`Loading ${PAGE_URL} in ${BROWSER} ...`);
  await driver.get(PAGE_URL);
  await driver.wait(until.elementLocated(By.id('connect')), 15000);

  // Sanity-check default URL.
  const urlValue = await driver.findElement(By.id('url')).getAttribute('value');
  console.log('URL field default:', urlValue);

  // Click Connect.
  await driver.findElement(By.id('connect')).click();

  // Wait for "connected" to show up in the event log.
  const logLoc = By.id('event-log');
  const waitForLogContains = (needle, timeoutMs) =>
    driver.wait(async () => {
      const txt = await driver.findElement(logLoc).getAttribute('innerText');
      return txt.includes(needle) ? txt : false;
    }, timeoutMs, `"${needle}" not seen in log within ${timeoutMs}ms`);

  const connectedLog = await waitForLogContains('established', 15000).catch(async () => {
    // Some builds log "Connection ready" instead. Try both.
    return waitForLogContains('ready', 5000).catch(() => null);
  });
  if (!connectedLog) {
    console.log('Did not observe connection-established log within 20s. Dumping current log:');
    console.log(await driver.findElement(logLoc).getAttribute('innerText'));
    process.exit(2);
  }
  console.log('Safari reports WT connection established ✓');

  // Select bidi mode and send a payload.
  await driver.findElement(By.id('bidi-stream')).click();
  await driver.findElement(By.id('data')).clear();
  await driver.findElement(By.id('data')).sendKeys('hello-from-safari');
  await driver.findElement(By.id('send')).click();

  // The echo server should reply with the same bytes prefixed/suffixed or
  // just echoed. Wait for evidence of a received payload in the log.
  let bidiResult = null;
  try {
    const t0 = Date.now();
    bidiResult = await driver.wait(async () => {
      const txt = await driver.findElement(logLoc).getAttribute('innerText');
      // Heuristic: look for the string we sent, or any "received" line after our send.
      if (txt.includes('hello-from-safari') && txt.split('hello-from-safari').length > 2) {
        return txt;
      }
      if (/received|Read/i.test(txt.split('\n').slice(-6).join('\n'))) {
        return txt;
      }
      return false;
    }, 8000, 'no bidi echo observed');
    console.log('Bidi echo observed in log ✓');
  } catch (e) {
    console.log('Did NOT observe bidi echo within 8s. Error:', e.message || e);
  }

  console.log('\n=== event-log ===');
  console.log(await driver.findElement(logLoc).getAttribute('innerText'));
  process.exit(bidiResult ? 0 : 1);
} catch (e) {
  console.error('Harness error:', e.message || e);
  try {
    const logEl = await driver.findElement(By.id('event-log'));
    console.log('\n=== event-log (on error) ===');
    console.log(await logEl.getAttribute('innerText'));
  } catch {}
  process.exit(2);
} finally {
  try { await driver.quit(); } catch {}
}
