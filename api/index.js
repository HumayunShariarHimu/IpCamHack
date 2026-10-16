const express = require('express');
const cors = require('cors');
const net = require('net');
const path = require('path');

const app = express();
app.disable('x-powered-by');
app.use(cors({ origin: process.env.CORS_ORIGIN || false }));
app.use(express.json({ limit: '16kb' }));
app.use(express.static(path.join(__dirname, '..', 'public'), { index: 'index.html' }));

const PORTS = [80, 443, 554, 8000, 8080, 8554, 37777];
const TIMEOUT_MS = 900;
const MAX_HOSTS = 256;
const MAX_CONCURRENT = 24;
let stats = { scanned: 0, found: 0, lastScanAt: null };
let foundCameras = [];
let scanInProgress = false;

function isPrivateIPv4(ip) {
  if (net.isIP(ip) !== 4) return false;
  const p = ip.split('.').map(Number);
  return p[0] === 10 ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 127);
}
function ipToInt(ip) {
  return ip.split('.').reduce((n, octet) => ((n << 8) | Number(octet)) >>> 0, 0);
}
function intToIp(n) {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}
function expandRange(input) {
  const range = String(input || '').trim();
  if (range.includes('/')) {
    const [base, maskText, ...extra] = range.split('/');
    if (extra.length || net.isIP(base) !== 4 || !/^\d{1,2}$/.test(maskText)) {
      throw new Error('Enter a valid IPv4 CIDR, such as 192.168.1.0/24.');
    }
    const mask = Number(maskText);
    if (mask < 24 || mask > 32) throw new Error('CIDR must be /24 to /32; larger ranges exceed the 256-address scan limit.');
    const count = 2 ** (32 - mask);
    const start = ipToInt(base);
    const network = (start & ((0xffffffff << (32 - mask)) >>> 0)) >>> 0;
    const hosts = Array.from({ length: count }, (_, i) => intToIp((network + i) >>> 0));
    if (!hosts.every(isPrivateIPv4)) throw new Error('Only private or loopback IPv4 addresses are allowed.');
    return hosts;
  }
  if (range.includes('-')) {
    const parts = range.split('-').map(s => s.trim());
    if (parts.length !== 2 || parts.some(ip => net.isIP(ip) !== 4)) {
      throw new Error('Enter a valid range, such as 192.168.1.10-192.168.1.30.');
    }
    const start = ipToInt(parts[0]), end = ipToInt(parts[1]);
    if (end < start || end - start + 1 > MAX_HOSTS) throw new Error('Range must be ascending and contain at most 256 addresses.');
    const hosts = Array.from({ length: end - start + 1 }, (_, i) => intToIp((start + i) >>> 0));
    if (!hosts.every(isPrivateIPv4)) throw new Error('Only private or loopback IPv4 addresses are allowed.');
    return hosts;
  }
  if (net.isIP(range) !== 4 || !isPrivateIPv4(range)) {
    throw new Error('Enter a private IPv4 address (10/8, 172.16/12, 192.168/16) or loopback address.');
  }
  return [range];
}
function checkPort(ip, port) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    let settled = false;
    const finish = open => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(open);
    };
    const timer = setTimeout(() => finish(false), TIMEOUT_MS);
    socket.setTimeout(TIMEOUT_MS, () => finish(false));
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
    socket.connect(port, ip);
  });
}
async function mapLimit(items, limit, fn) {
  const out = [];
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return out;
}
async function inspectHost(ip) {
  const checks = await Promise.all(PORTS.map(async port => (await checkPort(ip, port)) ? port : null));
  const openPorts = checks.filter(Boolean);
  if (!openPorts.length) return null;
  return {
    ip, openPorts,
    possibleCamera: openPorts.some(p => [554, 8554, 37777].includes(p)),
    checkedAt: new Date().toISOString()
  };
}

app.get('/api/health', (_req, res) => res.json({
  ok: true,
  service: 'IpCamHack private-network camera inventory',
  version: '4.0.0',
  environment: process.env.VERCEL ? 'serverless' : 'local'
}));
app.get('/api/status', (_req, res) => res.json({ stats, results: foundCameras, scanInProgress }));
app.post('/api/scan/range', async (req, res) => {
  // A cloud function cannot reach the user's LAN; do not turn this endpoint into a private-network probe.
  if (process.env.VERCEL) {
    return res.status(501).json({
      error: 'Private-network scanning is available when running IpCamHack locally on the network you own. A hosted server cannot scan your local LAN.'
    });
  }
  if (scanInProgress) return res.status(409).json({ error: 'A scan is already in progress. Please wait for it to finish.' });
  let hosts;
  try {
    hosts = expandRange(req.body && req.body.range);
    if (!hosts.length) return res.status(400).json({ error: 'No private addresses were found in that range.' });
  } catch (error) {
    return res.status(400).json({ error: error.message || 'Invalid range.' });
  }
  scanInProgress = true;
  try {
    const results = (await mapLimit(hosts, MAX_CONCURRENT, inspectHost)).filter(Boolean);
    foundCameras = results;
    stats = { scanned: hosts.length, found: results.length, lastScanAt: new Date().toISOString() };
    return res.json({
      summary: 'Checked ' + hosts.length + ' authorized private-network address(es); ' + results.length + ' host(s) have camera-related ports open.',
      found: results, stats
    });
  } catch (_error) {
    return res.status(500).json({ error: 'The scan failed unexpectedly. Check the local runtime and try again.' });
  } finally {
    scanInProgress = false;
  }
});
app.post('/api/clear', (_req, res) => {
  foundCameras = [];
  stats = { scanned: 0, found: 0, lastScanAt: null };
  res.json({ success: true, stats });
});

if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  app.listen(port, '0.0.0.0', () => {
    console.log('IpCamHack running at http://localhost:' + port);
    if (process.env.VERCEL) console.log('Hosted mode: private LAN scanning is disabled.');
  });
}
module.exports = app;
