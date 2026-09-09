const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// ========== কনফিগারেশন ==========
const PORTS = [80, 8080, 443, 554, 37777, 8000];
const DEFAULT_CREDS = [
  { user: 'admin', pass: 'admin123' },
  { user: 'admin', pass: 'admin1234' },
  { user: 'admin', pass: '12345' },
  { user: 'admin', pass: 'password' },
  { user: 'admin', pass: '123456' },
  { user: 'root', pass: '12345' },
  { user: 'user', pass: 'user' },
];
const APNIC_COUNTRIES = [
  'BD','IN','CN','JP','SG','PK','AU','NZ','VN','TH','KR','MY','PH','ID',
  'LK','NP','KH','LA','MM','BN','PG','FJ','SB','VU','WS','TO','KI','TV',
  'MH','FM','PW','NR','CK','NU','TK','WF','AS','GU','MP','VI','PR','UM',
  'HK','MO','TW'
];
const BRANDS = ['HIK Vision', 'Dahua', 'Anjhua', 'TP-Link', 'Xiaomi', 'Unknown'];
const CITIES = ['Dhaka', 'Mumbai', 'Shanghai', 'Tokyo', 'Singapore', 'Karachi', 'Sydney', 'Auckland', 'Hanoi', 'Bangkok', 'Seoul', 'Kuala Lumpur', 'Manila', 'Jakarta'];

// ========== ইন-মেমরি ডেটা স্টোর ==========
let foundCameras = [];      // সব শনাক্ত ক্যামেরা
let validCameras = [];     // ভ্যালিড ক্রেডেনশিয়াল সহ
let stats = { scanned: 0, found: 0 };

// ========== হেল্পার ফাংশন ==========
function randomIP() {
  return `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`;
}

function randomGeo() {
  const country = APNIC_COUNTRIES[Math.floor(Math.random() * APNIC_COUNTRIES.length)];
  const city = CITIES[Math.floor(Math.random() * CITIES.length)];
  return `${country} (${city})`;
}

function randomBrand() {
  return BRANDS[Math.floor(Math.random() * BRANDS.length)];
}

// ========== সিমুলেটেড ক্যামেরা স্ক্যান (Vercel-এ বাস্তব TCP সম্ভব নয়) ==========
function simulateCamera(ip, port) {
  // ১৫% সম্ভাবনায় ক্যামেরা পাবে
  if (Math.random() > 0.15) return null;

  const brand = randomBrand();
  const geo = randomGeo();
  let username = null, password = null;

  // ৩০% সম্ভাবনায় ডিফল্ট ক্রেডেনশিয়াল সঠিক হবে
  if (Math.random() < 0.30) {
    const cred = DEFAULT_CREDS[Math.floor(Math.random() * DEFAULT_CREDS.length)];
    username = cred.user;
    password = cred.pass;
  }

  return {
    ip,
    port,
    brand,
    geo,
    username,
    password
  };
}

// ========== স্ক্যান কোর (সমান্তরাল এক্সিকিউশন) ==========
async function runScanOnIPs(ipList) {
  const results = [];
  const promises = ipList.map(async (ip) => {
    for (const port of PORTS) {
      const cam = simulateCamera(ip, port);
      if (cam) {
        results.push(cam);
        foundCameras.push(cam);
        if (cam.username && cam.password) {
          validCameras.push(cam);
        }
        break; // প্রতি IP তে একটিই ক্যামেরা ধরা হবে
      }
    }
  });
  await Promise.all(promises);
  stats.scanned += ipList.length;
  stats.found += results.length;
  return results;
}

// ========== API এন্ডপয়েন্টসমূহ ==========

// ১. র্যান্ডম স্ক্যান (APNIC ৪৪ দেশ থেকে)
app.post('/api/scan/random', async (req, res) => {
  const count = 25; // প্রতি কলেই ২৫টি IP
  const ips = Array.from({ length: count }, () => randomIP());
  const found = await runScanOnIPs(ips);

  res.json({
    summary: `Scanned ${ips.length} IPs, found ${found.length} cameras.`,
    found,
    valid: validCameras,
    stats
  });
});

// ২. IP রেঞ্জ স্ক্যান (সিম্পল CIDR / হাইফেন ফরম্যাট)
app.post('/api/scan/range', async (req, res) => {
  const { range } = req.body;
  if (!range) return res.status(400).json({ error: 'Range required' });

  let ips = [];
  try {
    if (range.includes('/')) {
      // CIDR: শুধু ডেমো, প্রথম ৫টি IP নেব
      const base = range.split('/')[0];
      const parts = base.split('.');
      for (let i = 1; i <= 5; i++) {
        ips.push(`${parts[0]}.${parts[1]}.${parts[2]}.${i}`);
      }
    } else if (range.includes('-')) {
      const [start, end] = range.split('-');
      const startParts = start.split('.');
      const endParts = end.split('.');
      const sLast = parseInt(startParts[3]);
      const eLast = parseInt(endParts[3]);
      for (let i = sLast; i <= Math.min(eLast, sLast + 5); i++) {
        ips.push(`${startParts[0]}.${startParts[1]}.${startParts[2]}.${i}`);
      }
    } else {
      ips = [range];
    }
  } catch (e) {
    return res.status(400).json({ error: 'Invalid range format' });
  }

  const found = await runScanOnIPs(ips);
  res.json({
    summary: `Scanned ${ips.length} IPs from range, found ${found.length}.`,
    found,
    valid: validCameras,
    stats
  });
});

// ৩. সেভ করা ক্যামেরাগুলোর ক্রেডেনশিয়াল যাচাই (ব্রুট ফোর্স)
app.post('/api/validate', async (req, res) => {
  // যাদের ক্রেডেনশিয়াল নেই তাদের জন্য চেষ্টা
  const toValidate = foundCameras.filter(c => !c.username);
  const newlyValid = [];

  for (const cam of toValidate) {
    for (const cred of DEFAULT_CREDS) {
      // ২০% সফলতা (মক)
      if (Math.random() < 0.20) {
        cam.username = cred.user;
        cam.password = cred.pass;
        validCameras.push(cam);
        newlyValid.push(cam);
        break;
      }
    }
  }

  res.json({
    valid: newlyValid,
    stats
  });
});

// ৪. ভ্যালিড ক্যামেরার তালিকা
app.get('/api/valid/list', (req, res) => {
  res.json({ valid: validCameras, stats });
});

// ৫. ক্লিয়ার সব ডেটা
app.post('/api/clear', (req, res) => {
  foundCameras = [];
  validCameras = [];
  stats = { scanned: 0, found: 0 };
  res.json({ success: true });
});

// Vercel-এর জন্য এক্সপোর্ট
module.exports = app;
