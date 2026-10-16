const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const app = require('../api/index.js');

let server;
let baseUrl;

before(async () => {
  server = app.listen(0, '127.0.0.1');
  await new Promise((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });
  baseUrl = 'http://127.0.0.1:' + server.address().port;
});

after(async () => {
  if (server) await new Promise(resolve => server.close(resolve));
});

test('country catalog returns APNIC country codes and labels', async () => {
  const response = await fetch(baseUrl + '/api/countries');
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.countries.length, 45);
  assert.ok(body.countries.some(country => country.code === 'BD' && country.name === 'Bangladesh'));
});

test('geolocation rejects malformed IPv4 input', async () => {
  const response = await fetch(baseUrl + '/api/geo?ip=not-an-ip');
  assert.equal(response.status, 400);
  assert.match((await response.json()).error, /valid IPv4/i);
});

test('geolocation rejects private and loopback addresses before any provider request', async () => {
  for (const ip of ['192.168.1.1', '10.0.0.1', '172.16.0.1', '127.0.0.1', '169.254.1.2', '192.0.2.10']) {
    const response = await fetch(baseUrl + '/api/geo?ip=' + encodeURIComponent(ip));
    assert.equal(response.status, 400, ip + ' should be rejected');
    assert.match((await response.json()).error, /public IPv4/i);
  }
});

test('explicit public-target assessment requires an authorization confirmation', async () => {
  const response = await fetch(baseUrl + '/api/scan/targets', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ips: ['8.8.8.8'], authorized: false })
  });
  assert.equal(response.status, 403);
  assert.match((await response.json()).error, /permission|own/i);
});

test('explicit target assessment rejects private targets and oversized target lists', async () => {
  const privateResponse = await fetch(baseUrl + '/api/scan/targets', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ips: ['192.168.1.1'], authorized: true })
  });
  assert.equal(privateResponse.status, 400);

  const tooMany = Array.from({ length: 21 }, (_, i) => '8.8.' + Math.floor(i / 250) + '.' + (i + 1));
  const limitResponse = await fetch(baseUrl + '/api/scan/targets', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ips: tooMany, authorized: true })
  });
  assert.equal(limitResponse.status, 400);
  assert.match((await limitResponse.json()).error, /1 to 20/i);
});

test('hosted mode allows only bounded public scopes and still rejects private targets', async () => {
  const original = process.env.VERCEL;
  process.env.VERCEL = '1';
  try {
    const privateTarget = await fetch(baseUrl + '/api/scan/targets', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ips: ['192.168.1.1'], authorized: true })
    });
    assert.equal(privateTarget.status, 400);

    const oversizedRange = await fetch(baseUrl + '/api/scan/public-range', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ range: '8.8.8.0/28', authorized: true })
    });
    assert.equal(oversizedRange.status, 400);
    assert.match((await oversizedRange.json()).error, /limited to 8/i);
  } finally {
    if (original === undefined) delete process.env.VERCEL;
    else process.env.VERCEL = original;
  }
});
