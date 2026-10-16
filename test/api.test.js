'use strict';

const assert = require('node:assert/strict');
const { after, before, test } = require('node:test');
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
  if (!server) return;
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
});

async function get(path) {
  return fetch(baseUrl + path);
}

async function post(path, body) {
  return fetch(baseUrl + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  });
}

test('health endpoint reports a healthy service and defensive headers', async () => {
  const response = await get('/api/health');
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(response.headers.get('x-frame-options'), 'DENY');
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal((await response.json()).ok, true);
});

test('dashboard serves the JSON research-report export control', async () => {
  const response = await get('/');
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /id="exportJsonBtn"/);
  assert.match(html, /function exportJson\(/);
  assert.match(html, /exportJsonBtn.*addEventListener/s);
});

test('country catalog includes Bangladesh and stable two-letter codes', async () => {
  const response = await get('/api/countries');
  assert.equal(response.status, 200);
  const { countries } = await response.json();
  assert.ok(countries.length >= 40);
  assert.ok(countries.some(country => country.code === 'BD' && country.name === 'Bangladesh'));
  assert.ok(countries.every(country => /^[A-Z]{2}$/.test(country.code)));
});

test('geolocation rejects malformed addresses before making a provider request', async () => {
  const response = await get('/api/geo?ip=not-an-ip');
  assert.equal(response.status, 400);
  assert.match((await response.json()).error, /IPv4/i);
});

test('geolocation rejects documentation-only IP ranges', async () => {
  const response = await get('/api/geo?ip=192.0.2.10');
  assert.equal(response.status, 400);
});

test('explicit target inventory requires an authorization confirmation', async () => {
  const response = await post('/api/scan/targets', { ips: ['8.8.8.8'] });
  assert.equal(response.status, 403);
});

test('explicit target inventory rejects private addresses', async () => {
  const response = await post('/api/scan/targets', {
    ips: ['192.168.1.10'],
    authorized: true
  });
  assert.equal(response.status, 400);
});

test('explicit target inventory enforces the 20-address bound before scanning', async () => {
  const response = await post('/api/scan/targets', {
    ips: Array.from({ length: 21 }, () => '8.8.8.8'),
    authorized: true
  });
  assert.equal(response.status, 400);
});

test('private-range inventory rejects public targets before connecting', async () => {
  const response = await post('/api/scan/range', { range: '8.8.8.8' });
  assert.equal(response.status, 400);
});

test('public-range inventory rejects private address space', async () => {
  const response = await post('/api/scan/public-range', {
    range: '192.168.1.10',
    authorized: true
  });
  assert.equal(response.status, 400);
});
