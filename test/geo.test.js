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
  assert.equal(body.countries.length, 44);
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
