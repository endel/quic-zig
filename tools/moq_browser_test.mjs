// The MoQ WebTransport relay's own job: one browser publishing a track to
// it and another subscribing, both speaking draft-17 on the wire from
// hand-written JS.
//
// This exists because the page's encoders are a second implementation of
// the draft, and they drifted from it the same way the Zig ones had.
//
// Usage: node tools/moq_browser_test.mjs
import { spawn, execFileSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import puppeteer from 'puppeteer';


// Chrome caps a serverCertificateHashes cert at 14 days, and the certs
// directory is untracked — so a fresh checkout has none and an old one has
// an expired one. Both fail every case identically, which reads like a
// protocol regression.
function ensureCert() {
  const dir = 'interop/browser/certs';
  const crt = `${dir}/server.crt`;
  let stale = true;
  try {
    const notAfter = execFileSync('openssl', ['x509', '-in', crt, '-noout', '-enddate'],
      { stdio: ['ignore', 'pipe', 'ignore'] }).toString().split('=')[1].trim();
    stale = new Date(notAfter).getTime() < Date.now() + 24 * 3600 * 1000;
  } catch { stale = true; }
  if (stale) {
    console.log('regenerating interop/browser/certs (missing or expiring)');
    execFileSync('interop/browser/generate-cert.sh', { stdio: 'ignore' });
  }
}

const PORT = 4466;
const procs = [];
const cleanup = () => procs.forEach((p) => { try { p.kill('SIGKILL'); } catch {} });

try {
  ensureCert();

  const server = spawn('zig-out/bin/moq-relay', ['--port', String(PORT)],
    { stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(server);

  let out = '';
  let hash = null;
  await new Promise((resolve, reject) => {
    const on = (b) => {
      out += b.toString();
      const m = out.match(/Certificate SHA-256:\s*([0-9a-f]{64})/i);
      if (m && !hash) { hash = m[1]; resolve(); }
    };
    server.stdout.on('data', on);
    server.stderr.on('data', on);
    server.on('exit', (c) => reject(new Error(`relay exited (${c})\n${out}`)));
    setTimeout(() => reject(new Error(`no cert hash in 8s\n${out}`)), 8000);
  });
  await delay(600);

  // Chrome's fake camera stands in for getUserMedia, so the publisher
  // exercises the real capture -> WebCodecs -> MoQ path.
  const browser = await puppeteer.launch({
    headless: true,
    protocolTimeout: 60000,
    args: [
      // The demo pages are served over the relay's own self-signed cert;
      // the MoQ session itself is still pinned by serverCertificateHashes.
      '--ignore-certificate-errors',
      '--use-fake-device-for-media-stream',
      '--use-fake-ui-for-media-stream',
      '--autoplay-policy=no-user-gesture-required',
    ],
  });
  procs.push({ kill: () => browser.close() });

  // The relay serves the demo pages over HTTP/1.1 on the same port, so
  // the page's origin is the relay's and no extra httpd is needed.
  const open = async () => {
    const page = await browser.newPage();
    page.on('pageerror', (e) => console.log('  [page error]', e.message));
    await page.goto(`https://127.0.0.1:${PORT}/moq_video.html`, {
      waitUntil: 'domcontentloaded',
      timeout: 15000,
    });
    return page;
  };

  const pub = await open();
  const sub = await open();
  console.log('pages loaded: OK');

  const setup = async (page) => page.evaluate((port, h) => {
    document.getElementById('url').value = `https://127.0.0.1:${port}`;
    document.getElementById('hash').value = h;
  }, PORT, hash);
  await setup(pub);
  await setup(sub);

  const pubOk = await pub.evaluate(async () => {
    try { await startPublish(); return 'ok'; } catch (e) { return String(e.message || e); }
  }).catch((e) => String(e.message));
  console.log('publisher:', pubOk === 'ok' ? 'OK' : `FAIL — ${pubOk}`);

  await delay(1000);

  const subOk = await sub.evaluate(async () => {
    try { await startSubscribe(); return 'ok'; } catch (e) { return String(e.message || e); }
  }).catch((e) => String(e.message));
  console.log('subscriber:', subOk === 'ok' ? 'OK' : `FAIL — ${subOk}`);

  await delay(3000);

  const pubStats = await pub.$eval('#pubStats', (e) => e.textContent).catch(() => '');
  const subStats = await sub.$eval('#subStats', (e) => e.textContent).catch(() => '');
  console.log(`publisher stats: ${pubStats}`);
  console.log(`subscriber stats: ${subStats}`);

  const relay = out.split('\n').filter((l) => l.includes('[relay]'));
  const sawPublish = relay.some((l) => l.includes('PUBLISH client'));
  const sawSubscribeOk = relay.some((l) => l.includes('SUBSCRIBE_OK'));
  const sawError = relay.some((l) => l.includes('REQUEST_ERROR'));
  // The point of the relay: the publisher's groups reaching a subscriber.
  const sawForward = relay.some((l) => /→ [1-9]\d* subs/.test(l)) ||
                     relay.some((l) => l.includes('Replayed'));

  console.log('relay accepted PUBLISH:', sawPublish ? 'OK' : 'FAIL');
  console.log('relay accepted SUBSCRIBE:', sawSubscribeOk && !sawError ? 'OK' : 'FAIL');
  console.log('relay forwarded groups:', sawForward ? 'OK' : 'FAIL');
  console.log('\nrelay log:\n' + relay.slice(0, 12).join('\n'));

  cleanup();
  process.exit(
    pubOk === 'ok' && subOk === 'ok' && sawPublish && sawSubscribeOk && sawForward && !sawError ? 0 : 1,
  );
} catch (e) {
  console.error('ERROR:', e.message);
  cleanup();
  process.exit(2);
}
