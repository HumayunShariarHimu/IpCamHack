const express = require('express');
const cors = require('cors');
const net = require('net');
const http = require('http');
const path = require('path');

const app = express();
app.disable('x-powered-by');
app.use(cors({ origin: process.env.CORS_ORIGIN || false }));
app.use(express.json({ limit: '16kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
  next();
});
app.use(express.static(path.join(__dirname, '..', 'public'), { index: 'index.html' }));

const PORTS = [21, 22, 23, 25, 53, 80, 81, 110, 135, 139, 143, 389, 443, 445, 554, 587, 631, 993, 995, 1433, 1883, 3306, 3389, 5000, 5001, 5432, 554, 5900, 6379, 8000, 8080, 8081, 8443, 8554, 8888, 9000, 9001, 9090, 10000, 27017, 37777, 50000, 55554].filter((p, i, a) => a.indexOf(p) === i);
const TIMEOUT_MS = 900;
const MAX_HOSTS = 256;
const MAX_CONCURRENT = 24;
const MAX_PORT_CONCURRENT = 128;
const FULL_TCP_PORTS = Array.from({ length: 65535 }, (_, i) => i + 1);
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
function checkPort(ip, port, timeoutMs = TIMEOUT_MS) {
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
    const timer = setTimeout(() => finish(false), timeoutMs);
    socket.setTimeout(timeoutMs, () => finish(false));
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

async function inspectHost(ip, ports = PORTS, portConcurrency = MAX_PORT_CONCURRENT) {
  const checks = await mapLimit(ports, portConcurrency, async port => (await checkPort(ip, port, ports === FULL_TCP_PORTS ? 400 : TIMEOUT_MS)) ? port : null);
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
  service: 'IpCamHack camera inventory',
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
  const [a, b, c] = ip.split('.').map(Number);
  // Be conservative: only globally routable IPv4 addresses may be submitted
  // to the public-target geolocation and passive service-inventory endpoints.
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false; // shared address space
  if (a === 169 && b === 254) return false; // link-local
  if (a === 172 && b >= 16 && b <= 31) return false; // private
  if (a === 192 && b === 168) return false; // private
  if (a === 192 && b === 0 && c === 0) return false; // IETF protocol assignments
  if (a === 192 && b === 0 && c === 2) return false; // documentation
  if (a === 192 && b === 88 && c === 99) return false; // deprecated relay
  if (a === 198 && (b === 18 || b === 19)) return false; // benchmarking
  if (a === 198 && b === 51 && c === 100) return false; // documentation
  if (a === 203 && b === 0 && c === 113) return false; // documentation
  return true;
}

function expandPublicRange(input) {
  const range = String(input || '').trim();
  let hosts;
  if (range.includes('/')) {
    const [base, maskText, ...extra] = range.split('/');
    if (extra.length || net.isIP(base) !== 4 || !/^\d{1,2}$/.test(maskText)) {
      throw new Error('Enter a valid public IPv4 CIDR, such as your organization’s /24 range.');
    }
    const mask = Number(maskText);
    if (mask < 24 || mask > 32) throw new Error('Public CIDR must be /24 to /32 (maximum 256 addresses).');
    const count = 2 ** (32 - mask);
    const start = ipToInt(base);
    const network = (start & ((0xffffffff << (32 - mask)) >>> 0)) >>> 0;
    hosts = Array.from({ length: count }, (_, i) => intToIp((network + i) >>> 0));
  } else if (range.includes('-')) {
    const parts = range.split('-').map(s => s.trim());
    if (parts.length !== 2 || parts.some(ip => net.isIP(ip) !== 4)) {
      throw new Error('Enter two public IPv4 addresses separated by a hyphen.');
    }
    const start = ipToInt(parts[0]), end = ipToInt(parts[1]);
    if (end < start || end - start + 1 > MAX_HOSTS) throw new Error('Public range must be ascending and contain at most 256 addresses.');
    hosts = Array.from({ length: end - start + 1 }, (_, i) => intToIp((start + i) >>> 0));
  } else {
    if (net.isIP(range) !== 4) throw new Error('Enter a valid public IPv4 address, CIDR, or range.');
    hosts = [range];
  }
  if (!hosts.every(isPublicIPv4)) throw new Error('Every address must be a public IPv4 address; private and reserved ranges are rejected.');
  return hosts;
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
            countryCode: String(data.country_code || 'XX').toUpperCase(),
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
    if (req.body && req.body.fullPortScan === true && hosts.length !== 1) {
      return res.status(400).json({ error: 'Full TCP port scan (1–65535) is limited to one explicit private IPv4 host per run.' });
    }
    if (!hosts.length) return res.status(400).json({ error: 'No private addresses were found in that range.' });
  } catch (error) {
    return res.status(400).json({ error: error.message || 'Invalid range.' });
  }
  scanInProgress = true;
  try {
    const fullPortScan = req.body && req.body.fullPortScan === true;
    const results = (await mapLimit(hosts, fullPortScan ? 1 : MAX_CONCURRENT, ip => inspectHost(ip, fullPortScan ? FULL_TCP_PORTS : PORTS, MAX_PORT_CONCURRENT))).filter(Boolean);
    foundCameras = results;
    stats = { scanned: hosts.length, found: results.length, lastScanAt: new Date().toISOString() };
    return res.json({
      summary: 'Checked ' + hosts.length + ' authorized private-network address(es) across ' + (fullPortScan ? 'all 65,535 TCP ports' : PORTS.length + ' common service ports') + '; ' + results.length + ' host(s) responded on monitored ports.',
      found: results, stats
    });
  } catch (_error) {
    return res.status(500).json({ error: 'The scan failed unexpectedly. Check the local runtime and try again.' });
  } finally {
    scanInProgress = false;
  }
});

app.post('/api/scan/targets', async (req, res) => {
  if (scanInProgress) return res.status(409).json({ error: 'A scan is already in progress.' });
  const body = req.body || {};
  if (body.authorized !== true) return res.status(403).json({ error: 'Confirm you own these systems or have written permission to assess them.' });
  if (!Array.isArray(body.ips) || body.ips.length < 1 || body.ips.length > 20) {
    return res.status(400).json({ error: 'Provide 1 to 20 explicit IPv4 addresses; ranges and random targets are not accepted.' });
  }
  const ips = [...new Set(body.ips.map(v => String(v).trim()))];
  if (ips.some(ip => !isPublicIPv4(ip))) return res.status(400).json({ error: 'Only explicit public IPv4 targets are accepted by this endpoint. Use the private range scanner for LAN targets.' });
  const countries = Array.isArray(body.countries) ? [...new Set(body.countries.filter(c => /^[A-Z]{2}$/.test(c)))] .slice(0, 45) : [];
  const countryFilterStats = { selected: countries.length, matched: 0, excluded: 0, lookupFailed: 0 };
  scanInProgress = true;
  try {
    const candidates = await mapLimit(ips, 4, async ip => {
      const geo = countries.length ? await lookupGeo(ip).catch(() => null) : null;
      if (countries.length && !geo) { countryFilterStats.lookupFailed++; return null; }
      if (countries.length && !countries.includes(geo.countryCode)) { countryFilterStats.excluded++; return null; }
      if (countries.length) countryFilterStats.matched++;
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
      found: results, stats, countryFilterStats
    });
  } catch (_error) {
    return res.status(500).json({ error: 'The target assessment failed unexpectedly.' });
  } finally {
    scanInProgress = false;
  }
});

app.post('/api/scan/public-range', async (req, res) => {
  if (scanInProgress) return res.status(409).json({ error: 'A scan is already in progress.' });
  const body = req.body || {};
  if (body.authorized !== true) return res.status(403).json({ error: 'Confirm you own this public range or have written permission to assess it.' });
  let hosts;
  try {
    hosts = expandPublicRange(body.range);
  } catch (error) {
    return res.status(400).json({ error: error.message || 'Invalid public range.' });
  }
  const countries = Array.isArray(body.countries) ? [...new Set(body.countries.filter(c => /^[A-Z]{2}$/.test(c)))].slice(0, 45) : [];
  const countryFilterStats = { selected: countries.length, matched: 0, excluded: 0, lookupFailed: 0 };
  if (process.env.VERCEL && hosts.length > 8) {
    return res.status(400).json({ error: 'Hosted scans are limited to 8 explicit public IPv4 addresses per run. Run locally for ranges up to 256 addresses.' });
  }
  scanInProgress = true;
  try {
    const candidates = await mapLimit(hosts, 4, async ip => {
      let geo = null;
      if (countries.length) {
        geo = await lookupGeo(ip).catch(() => null);
        if (!geo) { countryFilterStats.lookupFailed++; return null; }
        if (!countries.includes(geo.countryCode)) { countryFilterStats.excluded++; return null; }
        countryFilterStats.matched++;
      }
      const checks = await Promise.all(PORTS.map(async port => (await checkPort(ip, port)) ? port : null));
      const openPorts = checks.filter(Boolean);
      if (!openPorts.length) return null;
      if (!geo) geo = await lookupGeo(ip).catch(() => null);
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
    stats = { scanned: hosts.length, found: results.length, lastScanAt: new Date().toISOString() };
    return res.json({
      summary: 'Checked ' + hosts.length + ' explicitly scoped, authorized public address(es); ' + results.length + ' matched the selected countries and had monitored ports open.',
      found: results, stats, countryFilterStats
    });
  } catch (_error) {
    return res.status(500).json({ error: 'The public-range assessment failed unexpectedly.' });
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
