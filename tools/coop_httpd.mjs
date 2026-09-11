// Minimal HTTP server with COOP/COEP for crossOriginIsolated context.
// Needed so performance.now() gives sub-µs precision in Chrome.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(process.argv[2] || 'interop/browser');
const PORT = parseInt(process.argv[3] || '8000', 10);

http.createServer((req, res) => {
  const file = path.join(ROOT, req.url === '/' ? 'latency.html' : req.url);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end(err.message); }
    const ext = path.extname(file);
    const type = ext === '.html' ? 'text/html' : ext === '.mjs' || ext === '.js' ? 'text/javascript' : 'text/plain';
    res.writeHead(200, {
      'Content-Type': type,
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
      'Cross-Origin-Resource-Policy': 'same-origin',
    });
    res.end(data);
  });
}).listen(PORT, '127.0.0.1', () => console.log(`coop-httpd ${ROOT} http://127.0.0.1:${PORT}`));
