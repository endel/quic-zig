#!/usr/bin/env node
/**
 * Puppeteer test for WASM QUIC demo.
 * Serves wasm/ over HTTP, loads index.html, clicks Start, and validates
 * that both client and server reach "connected" state.
 *
 * Usage: node wasm/test.mjs
 */
import puppeteer from 'puppeteer';
import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const HTTP_PORT = 8899;
const TIMEOUT = 15000;

const MIME_TYPES = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.wasm': 'application/wasm',
  '.der': 'application/octet-stream',
  '.pem': 'application/x-pem-file',
};

// Simple static file server for the wasm/ directory
function startServer() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const urlPath = req.url.split('?')[0];
      const filePath = path.join(__dirname, urlPath === '/' ? 'index.html' : urlPath);

      if (!filePath.startsWith(__dirname)) {
        res.writeHead(403);
        return res.end();
      }

      try {
        const data = fs.readFileSync(filePath);
        const ext = path.extname(filePath);
        res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
        res.end(data);
      } catch {
        res.writeHead(404);
        res.end('Not found');
      }
    });
    server.listen(HTTP_PORT, () => resolve(server));
  });
}

async function main() {
  // Verify wasm/quic.wasm exists
  const wasmPath = path.join(__dirname, 'quic.wasm');
  if (!fs.existsSync(wasmPath)) {
    console.error('Error: wasm/quic.wasm not found. Run: zig build wasm');
    process.exit(1);
  }

  // Verify certs exist
  const certPath = path.join(__dirname, 'certs/cert.der');
  const keyPath = path.join(__dirname, 'certs/key.der');
  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    console.error('Error: wasm/certs/cert.der or key.der not found.');
    process.exit(1);
  }

  console.log('Starting HTTP server on port', HTTP_PORT);
  const server = await startServer();

  console.log('Launching Chrome...');
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });

  const page = await browser.newPage();

  // Collect console logs from the page
  const logs = [];
  page.on('console', (msg) => logs.push(msg.text()));
  page.on('pageerror', (err) => logs.push('PAGE ERROR: ' + err.message));

  let exitCode = 0;

  try {
    console.log('Loading WASM demo page...');
    await page.goto(`http://127.0.0.1:${HTTP_PORT}/`, { waitUntil: 'domcontentloaded' });

    // Click Start Handshake
    console.log('Clicking Start Handshake...');
    await page.click('#btn-start');

    // Wait for both client and server to reach "connected" state
    console.log('Waiting for handshake...');
    await page.waitForFunction(
      () => {
        const cs = document.getElementById('stat-client')?.textContent;
        const ss = document.getElementById('stat-server')?.textContent;
        return cs === 'connected' && ss === 'connected';
      },
      { timeout: TIMEOUT }
    );

    // Read stats
    const stats = await page.evaluate(() => ({
      packets: document.getElementById('stat-packets')?.textContent,
      client: document.getElementById('stat-client')?.textContent,
      server: document.getElementById('stat-server')?.textContent,
    }));

    // Check that runtime certs were loaded (not embedded fallback)
    const usedRuntimeCerts = await page.evaluate(() => {
      const logs = document.getElementById('server-log')?.textContent || '';
      return logs.includes('Loaded runtime cert');
    });

    console.log('');
    console.log(`  Client:  ${stats.client}`);
    console.log(`  Server:  ${stats.server}`);
    console.log(`  Packets: ${stats.packets}`);
    console.log(`  Certs:   ${usedRuntimeCerts ? 'runtime (qz_set_cert)' : 'embedded (fallback)'}`);
    console.log('');

    if (!usedRuntimeCerts) {
      console.log('\x1b[31mFAIL\x1b[0m Runtime certs were not used (fell back to embedded)');
      exitCode = 1;
    } else {
      console.log('\x1b[32mPASS\x1b[0m WASM QUIC handshake completed with runtime certificates');
    }

  } catch (err) {
    console.error('\n\x1b[31mFAIL\x1b[0m', err.message);
    exitCode = 1;

    // Dump page console logs for debugging
    if (logs.length) {
      console.log('\nBrowser console:');
      for (const l of logs.slice(-20)) {
        console.log('  ', l);
      }
    }
  }

  await browser.close();
  server.close();
  process.exit(exitCode);
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(2);
});
