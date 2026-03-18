#!/usr/bin/env node
// Runs latency.html in Chrome via puppeteer - reproduces manual browser testing exactly.
// Usage: node tools/wt_bench_html.mjs [port] [iterations]

import puppeteer from 'puppeteer';
import http from 'http';
import fs from 'fs';
import { execSync } from 'child_process';

const port = parseInt(process.argv[2] || '4433');
const iterations = parseInt(process.argv[3] || '1000');

// Compute cert hash
const hash = execSync(
  "openssl x509 -in interop/browser/certs/server.crt -outform der 2>/dev/null | shasum -a 256 | cut -d' ' -f1"
).toString().trim();
console.log(`Cert hash: ${hash}`);
console.log(`Target: https://127.0.0.1:${port}, ${iterations} iterations`);

// Serve latency.html on a local HTTP server
const htmlPath = 'interop/browser/latency.html';
const htmlContent = fs.readFileSync(htmlPath, 'utf-8');
const srv = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(htmlContent);
});
srv.listen(8181);

// Find Chrome
const executablePath = [
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',
].find(p => { try { fs.accessSync(p); return true; } catch { return false; } });

const browser = await puppeteer.launch({
  headless: false,
  executablePath,
  args: [
    '--enable-experimental-web-platform-features',
    '--ignore-certificate-errors',
    '--no-sandbox',
    '--window-size=800,600',
    '--window-position=2000,2000',
  ],
});

const page = await browser.newPage();
await page.goto('http://127.0.0.1:8181/', { waitUntil: 'domcontentloaded' });

// Fill in the form
await page.$eval('#url', (el, v) => el.value = v, `https://127.0.0.1:${port}`);
await page.$eval('#hash', (el, v) => el.value = v, hash);
await page.$eval('#iterations', (el, v) => el.value = v, String(iterations));

// Click Run and wait for completion
await page.click('#btnRun');

// Wait for "Done." to appear in results (poll every 500ms, timeout 5min)
const timeout = 300_000;
const start = Date.now();
while (Date.now() - start < timeout) {
  const text = await page.$eval('#results', el => el.textContent);
  if (text.includes('Done.')) break;
  if (text.includes('Error:')) {
    console.error('Test error:', text.match(/Error:.*/)?.[0]);
    break;
  }
  await new Promise(r => setTimeout(r, 500));
}

// Extract results text
const results = await page.$eval('#results', el => el.textContent);

// Parse and print the stats lines
const lines = results.split('\n');
let section = '';
for (const line of lines) {
  if (line.includes('Bidi Stream')) { section = 'Bidi'; console.log('\n' + line.trim()); }
  else if (line.includes('Datagram')) { section = 'DG'; console.log('\n' + line.trim()); }
  else if (line.includes('med=')) { console.log(line.trim()); }
  else if (line.includes('Connected')) { console.log(line.trim()); }
  else if (line.includes('Done')) { console.log(line.trim()); }
}

// Count spikes from the raw data
const allLines = lines.filter(l => l.match(/^\s+#\d/));
const spikeLines = allLines.filter(l => {
  const m = l.match(/([\d.]+)ms/);
  return m && parseFloat(m[1]) > 5;
});
if (spikeLines.length > 0) {
  console.log(`\nSpikes >5ms: ${spikeLines.length}`);
  spikeLines.slice(0, 20).forEach(l => console.log('  ' + l.trim()));
  if (spikeLines.length > 20) console.log(`  ... and ${spikeLines.length - 20} more`);
}

await browser.close();
srv.close();
