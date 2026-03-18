#!/usr/bin/env node
// Headless WebTransport latency benchmark using Puppeteer
// Usage: node tools/wt_bench.mjs [url] [iterations] [cert-hash-hex]

import puppeteer from 'puppeteer';

const url = process.argv[2] || 'https://127.0.0.1:4433';
const iterations = parseInt(process.argv[3] || '50');
const certHash = process.argv[4] || '';

if (!certHash) {
  // Try to compute from cert file
  const { execSync } = await import('child_process');
  try {
    const hash = execSync(
      "openssl x509 -in interop/browser/certs/server.crt -outform der 2>/dev/null | shasum -a 256 | cut -d' ' -f1"
    ).toString().trim();
    if (hash.length === 64) {
      process.argv[4] = hash;
      console.log(`Auto-detected cert hash: ${hash}`);
      run(url, iterations, hash);
    } else {
      console.error('Could not auto-detect cert hash. Pass it as 3rd argument.');
      process.exit(1);
    }
  } catch {
    console.error('Could not auto-detect cert hash. Pass it as 3rd argument.');
    process.exit(1);
  }
} else {
  run(url, iterations, certHash);
}

async function run(url, iterations, certHash) {
  // Use system Chrome/Brave instead of puppeteer's bundled Chrome
  const fs = await import('fs');
  const executablePath = [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',
  ].find(p => { try { fs.accessSync(p); return true; } catch { return false; } });

  const browser = await puppeteer.launch({
    headless: false,  // WebTransport requires full Chrome (not available in headless)
    executablePath,
    args: [
      '--enable-experimental-web-platform-features',
      '--ignore-certificate-errors',
      '--no-sandbox',
      '--window-size=400,300',
      '--window-position=2000,2000',  // Move off-screen
    ],
  });

  const page = await browser.newPage();

  // Navigate to a secure origin to enable WebTransport API
  await page.goto('https://example.com', { waitUntil: 'domcontentloaded', timeout: 10000 }).catch(() => {});

  // Inject and run the benchmark
  const results = await page.evaluate(async (url, iterations, certHash) => {
    function hexToBytes(hex) {
      const b = new Uint8Array(hex.length / 2);
      for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.substr(i * 2, 2), 16);
      return b;
    }

    try {
      const transport = new WebTransport(url, {
        serverCertificateHashes: [{
          algorithm: 'sha-256',
          value: hexToBytes(certHash).buffer
        }]
      });
      await transport.ready;

      // Bidi benchmark
      const bidiTimes = [];
      for (let i = 0; i < iterations; i++) {
        const start = performance.now();
        const stream = await transport.createBidirectionalStream();
        const writer = stream.writable.getWriter();
        await writer.write(new TextEncoder().encode('ping'));
        await writer.close();
        const reader = stream.readable.getReader();
        let resp = '';
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          resp += new TextDecoder().decode(value);
        }
        const elapsed = performance.now() - start;
        bidiTimes.push(elapsed);
      }

      // Datagram benchmark
      const dgTimes = [];
      const dgReader = transport.datagrams.readable.getReader();
      for (let i = 0; i < iterations; i++) {
        const start = performance.now();
        const dgWriter = transport.datagrams.writable.getWriter();
        await dgWriter.write(new TextEncoder().encode('ping'));
        dgWriter.releaseLock();
        const { value } = await dgReader.read();
        const elapsed = performance.now() - start;
        dgTimes.push(elapsed);
      }

      transport.close();
      return { bidiTimes, dgTimes, error: null };
    } catch (err) {
      return { bidiTimes: [], dgTimes: [], error: err.toString() };
    }
  }, url, iterations, certHash);

  await browser.close();

  if (results.error) {
    console.error('Error:', results.error);
    process.exit(1);
  }

  // Print results
  function stats(times, label) {
    const sorted = [...times].sort((a, b) => a - b);
    const n = sorted.length;
    const avg = times.reduce((a, b) => a + b, 0) / n;
    const med = sorted[Math.floor(n / 2)];
    const p95 = sorted[Math.floor(n * 0.95)];
    const p99 = sorted[Math.floor(n * 0.99)];
    const min = sorted[0];
    const max = sorted[n - 1];
    const stddev = Math.sqrt(times.reduce((s, x) => s + (x - avg) ** 2, 0) / n);
    const spikes = times.filter(t => t > 20).length;

    console.log(`\n=== ${label} (${n} iterations) ===`);
    if (n <= 100) {
      for (let i = 0; i < n; i++) {
        const t = times[i];
        console.log(`  #${String(i + 1).padStart(4)} ${t.toFixed(1).padStart(6)}ms`);
      }
    } else {
      // Only print spikes for large iteration counts
      for (let i = 0; i < n; i++) {
        if (times[i] > 5) {
          console.log(`  SPIKE #${String(i + 1).padStart(4)} ${times[i].toFixed(1).padStart(6)}ms`);
        }
      }
    }
    console.log(`\n  med=${med.toFixed(2)}  avg=${avg.toFixed(2)}  p95=${p95.toFixed(2)}  p99=${p99.toFixed(2)}  min=${min.toFixed(2)}  max=${max.toFixed(2)}  stddev=${stddev.toFixed(2)}`);
    console.log(`  spikes >5ms: ${times.filter(t => t > 5).length}  >10ms: ${times.filter(t => t > 10).length}  >20ms: ${spikes}`);
  }

  console.log(`\nWebTransport Benchmark: ${url}, ${iterations} iterations`);
  stats(results.bidiTimes, 'Bidi Stream');
  stats(results.dgTimes, 'Datagram');
}
