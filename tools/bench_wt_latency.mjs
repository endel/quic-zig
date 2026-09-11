// Puppeteer benchmark: compare WebTransport datagram latency
// between quic-zig (4433) and quic-go (4434) servers.
import puppeteer from 'puppeteer';

const CERT_HASH = process.argv[2] || '6519694984b2d4fe967c7a3392cafc0ba02b68ee67c83d143d830d1475799cce';
const ITERATIONS = parseInt(process.argv[3] || '50', 10);

const servers = [
  { name: 'quic-zig', url: 'https://127.0.0.1:4433' },
  { name: 'quic-go ', url: 'https://127.0.0.1:4434' },
];

async function benchmark(page, url, hashHex, iterations) {
  return await page.evaluate(async (url, hashHex, iterations) => {
    const hexToBytes = (hex) => {
      const b = new Uint8Array(hex.length / 2);
      for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.substr(i * 2, 2), 16);
      return b;
    };

    const transport = new WebTransport(url, {
      serverCertificateHashes: [{ algorithm: 'sha-256', value: hexToBytes(hashHex).buffer }]
    });
    const t0 = performance.now();
    await transport.ready;
    const connMs = performance.now() - t0;

    const dgReader = transport.datagrams.readable.getReader();
    const times = [];
    for (let i = 0; i < iterations; i++) {
      const start = performance.now();
      const dgWriter = transport.datagrams.writable.getWriter();
      await dgWriter.write(new TextEncoder().encode('ping'));
      dgWriter.releaseLock();
      await dgReader.read();
      times.push(performance.now() - start);
    }

    transport.close();
    return { connMs, times };
  }, url, hashHex, iterations);
}

function stats(times) {
  const s = [...times].sort((a, b) => a - b);
  const n = s.length;
  const avg = times.reduce((a, b) => a + b, 0) / n;
  const med = s[Math.floor(n / 2)];
  const p95 = s[Math.floor(n * 0.95)];
  const p99 = s[Math.floor(n * 0.99)];
  const stddev = Math.sqrt(times.reduce((x, v) => x + (v - avg) ** 2, 0) / n);
  return { n, min: s[0], max: s[n - 1], med, avg, p95, p99, stddev };
}

(async () => {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: [
      `--ignore-certificate-errors-spki-list=${CERT_HASH}`,
      '--enable-features=WebTransport,SharedArrayBuffer',
      '--disable-features=IsolateOrigins,site-per-process',
    ],
  });
  const page = await browser.newPage();
  await page.goto('http://127.0.0.1:8000/latency.html');
  const isolated = await page.evaluate(() => self.crossOriginIsolated);
  console.log(`crossOriginIsolated: ${isolated} (sub-µs timer=${isolated ? 'YES' : 'NO'})`);
  page.on('console', (m) => { if (m.type() === 'error') console.error('[page]', m.text()); });

  // Warmup + measure
  for (const { name, url } of servers) {
    try {
      // Warmup connection
      await benchmark(page, url, CERT_HASH, 5);
      // Real run
      const { connMs, times } = await benchmark(page, url, CERT_HASH, ITERATIONS);
      const st = stats(times);
      console.log(
        `${name}  conn=${connMs.toFixed(1)}ms  ` +
        `med=${st.med.toFixed(2)}  avg=${st.avg.toFixed(2)}  ` +
        `p95=${st.p95.toFixed(2)}  p99=${st.p99.toFixed(2)}  ` +
        `min=${st.min.toFixed(2)}  max=${st.max.toFixed(2)}  stddev=${st.stddev.toFixed(2)}  ` +
        `(${st.n} iter)`
      );
    } catch (err) {
      console.error(`${name}  ERROR: ${err.message}`);
    }
  }

  await browser.close();
})();
