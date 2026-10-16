const express = require('express');
const cors = require('cors');
const net = require('net');
const http = require('http');
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
const BRAND_SIGNATURES = [
  [/Hikvision/i, 'Hikvision'], [/Dahua/i, 'Dahua'], [/TP-Link/i, 'TP-Link'],
  [/Xiaomi/i, 'Xiaomi'], [/Axis/i, 'Axis'], [/Sony/i, 'Sony'],
  [/Panasonic/i, 'Panasonic'], [/Bosch/i, 'Bosch'], [/Samsung/i, 'Samsung'],
  [/Vivotek/i, 'Vivotek'], [/Reolink/i, 'Reolink'], [/Amcrest/i, 'Amcrest'],
  [/Ubiquiti/i, 'Ubiquiti'], [/Hanwha/i, 'Hanwha']
];

// Passive HTTP banner fingerprinting only: no login attempts and no stream access.
function fingerprintHttp(ip, port) {
  if (![80, 443, 8000, 8080].includes(port)) {
    return Promise.resolve({ brand: 'Unknown', service: port === 554 || port === 8554 ? 'RTSP' : 'TCP service', server: null });
  }
  return new Promise(resolve => {
    const transport = port === 443 ? https : http;
    let settled = false;
    let body = '';
    const finish = value => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const request = transport.get({
      hostname: ip, port, path: '/', method: 'GET', timeout: 1800,
      headers: { 'User-Agent': 'IpCamHack-Authorized-Research/4.1', 'Accept': 'text/html,application/json,text/plain;q=0.8,*/*;q=0.1' },
      ...(port === 443 ? { rejectUnauthorized: false } : {})
    }, response => {
      const server = typeof response.headers.server === 'string' ? response.headers.server.slice(0, 160) : null;
      response.setEncoding('utf8');
      response.on('data', chunk => {
        body += chunk;
        if (body.length >= 8192) request.destroy();
      });
      response.on('end', () => {
        const sample = body + ' ' + (server || '');
        const match = BRAND_SIGNATURES.find(([pattern]) => pattern.test(sample));
        finish({ brand: match ? match[1] : 'Unknown', service: 'HTTP ' + response.statusCode, server });
      });
      response.on('error', () => finish({ brand: 'Unknown', service: 'HTTP', server }));
    });
    request.on('timeout', () => request.destroy());
    request.on('error', () => finish({ brand: 'Unknown', service: 'HTTP', server: null }));
    request.end();
  });
}

async function inspectHost(ip) {
  const checks = await Promise.all(PORTS.map(async port => (await checkPort(ip, port)) ? port : null));
  const openPorts = checks.filter(Boolean);
  if (!openPorts.length) return null;
  const webPort = openPorts.find(port => [80, 443, 8000, 8080].includes(port));
  const fingerprint = webPort ? await fingerprintHttp(ip, webPort) : { brand: 'Unknown', service: 'RTSP/TCP service', server: null };
  return {
    ip, openPorts, brand: fingerprint.brand, service: fingerprint.service, server: fingerprint.server,
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

const https = require('https');

const APNIC_COUNTRIES = [
  ['BD','Bangladesh'],['IN','India'],['CN','China'],['JP','Japan'],['SG','Singapore'],
  ['PK','Pakistan'],['AU','Australia'],['NZ','New Zealand'],['VN','Vietnam'],['TH','Thailand'],
  ['KR','South Korea'],['MY','Malaysia'],['PH','Philippines'],['ID','Indonesia'],['LK','Sri Lanka'],
  ['NP','Nepal'],['KH','Cambodia'],['LA','Laos'],['MM','Myanmar'],['BN','Brunei'],
  ['PG','Papua New Guinea'],['FJ','Fiji'],['SB','Solomon Islands'],['VU','Vanuatu'],['WS','Samoa'],
  ['TO','Tonga'],['KI','Kiribati'],['TV','Tuvalu'],['MH','Marshall Islands'],['FM','Micronesia'],
  ['PW','Palau'],['NR','Nauru'],['CK','Cook Islands'],['NU','Niue'],['TK','Tokelau'],
  ['WF','Wallis and Futuna'],['AS','American Samoa'],['GU','Guam'],['MP','Northern Mariana Islands'],
  ['VI','U.S. Virgin Islands'],['PR','Puerto Rico'],['UM','U.S. Minor Outlying Islands'],
  ['HK','Hong Kong'],['MO','Macao'],['TW','Taiwan']
];

function isPublicIPv4(ip) {
  if (net.isIP(ip) !== 4) return false;
  const [a,b,c] = ip.split('.').map(Number);
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0 && c === 0) return false;
  if (a === 192 && b === 0 && c === 2) return false;
  if (a === 192 && b === 88 && c === 99) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

function lookupGeo(ip) {
  return new Promise((resolve, reject) => {
    const request = https.get('https://ipwho.is/' + encodeURIComponent(ip), { timeout: 4500 }, response => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', chunk => {
        body += chunk;
        if (body.length > 32768) request.destroy(new Error('Geolocation response too large.'));
      });
      response.on('end', () => {
        try {
          const data = JSON.parse(body);
          if (response.statusCode !== 200 || data.success === false) {
            return reject(new Error(data.message || 'Geolocation provider could not resolve this IP.'));
          }
          resolve({
            ip,
            country: data.country || 'Unknown',
            countryCode: data.country_code || 'XX',
            region: data.region || 'Unknown',
            city: data.city || 'Unknown',
            latitude: Number.isFinite(data.latitude) ? data.latitude : null,
            longitude: Number.isFinite(data.longitude) ? data.longitude : null,
            isp: data.connection && data.connection.isp ? data.connection.isp : 'Unknown',
            asn: data.connection && data.connection.asn ? data.connection.asn : null,
            checkedAt: new Date().toISOString()
          });
        } catch (_error) {
          reject(new Error('Invalid response from geolocation provider.'));
        }
      });
    });
    request.on('timeout', () => request.destroy(new Error('Geolocation lookup timed out.')));
    request.on('error', reject);
  });
}

app.get('/api/countries', (_req, res) => res.json({ countries: APNIC_COUNTRIES.map(([code, name]) => ({ code, name })) }));
app.get('/api/geo', async (req, res) => {
  const ip = String(req.query.ip || '').trim();
  if (net.isIP(ip) !== 4) return res.status(400).json({ error: 'Enter a valid IPv4 address.' });
  if (!isPublicIPv4(ip)) return res.status(400).json({ error: 'Geo lookup accepts public IPv4 addresses only. Use the private-network scanner for local addresses.' });
  try {
    return res.json({ geo: await lookupGeo(ip) });
  } catch (error) {
    return res.status(502).json({ error: error.message || 'Geolocation lookup failed.' });
  }
});
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

app.post('/api/scan/targets', async (req, res) => {
  if (process.env.VERCEL) {
    return res.status(501).json({ error: 'Run this scan locally or in your approved assessment environment; hosted serverless scanning is disabled.' });
  }
  if (scanInProgress) return res.status(409).json({ error: 'A scan is already in progress.' });
  const body = req.body || {};
  if (body.authorized !== true) return res.status(403).json({ error: 'Confirm you own these systems or have written permission to assess them.' });
  if (!Array.isArray(body.ips) || body.ips.length < 1 || body.ips.length > 20) {
    return res.status(400).json({ error: 'Provide 1 to 20 explicit IPv4 addresses; ranges and random targets are not accepted.' });
  }
  const ips = [...new Set(body.ips.map(v => String(v).trim()))];
  if (ips.some(ip => !isPublicIPv4(ip))) return res.status(400).json({ error: 'Only explicit public IPv4 targets are accepted by this endpoint. Use the private range scanner for LAN targets.' });
  const countries = Array.isArray(body.countries) ? body.countries.filter(c => /^[A-Z]{2}$/.test(c)).slice(0, 44) : [];
  scanInProgress = true;
  try {
    const candidates = await mapLimit(ips, 4, async ip => {
      const geo = await lookupGeo(ip).catch(() => null);
      if (countries.length && (!geo || !countries.includes(geo.countryCode))) return null;
      const checks = await Promise.all(PORTS.map(async port => (await checkPort(ip, port)) ? port : null));
      const openPorts = checks.filter(Boolean);
      if (!openPorts.length) return null;
      const webPort = openPorts.find(port => [80, 443, 8000, 8080].includes(port));
      const fingerprint = webPort ? await fingerprintHttp(ip, webPort) : { brand: 'Unknown', service: 'RTSP/TCP service', server: null };
      return {
        ip, openPorts, brand: fingerprint.brand, service: fingerprint.service, server: fingerprint.server,
        possibleCamera: openPorts.some(p => [554, 8554, 37777].includes(p)),
        geo: geo ? { country: geo.country, countryCode: geo.countryCode, city: geo.city, isp: geo.isp } : null,
        checkedAt: new Date().toISOString()
      };
    });
    const results = candidates.filter(Boolean);
    foundCameras = results;
    stats = { scanned: ips.length, found: results.length, lastScanAt: new Date().toISOString() };
    return res.json({
      summary: 'Checked ' + ips.length + ' explicitly supplied, authorized target(s); ' + results.length + ' had one or more monitored ports open.',
      found: results, stats
    });
  } catch (_error) {
    return res.status(500).json({ error: 'The target assessment failed unexpectedly.' });
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
