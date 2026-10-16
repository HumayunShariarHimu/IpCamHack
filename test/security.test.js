const test = require('node:test');
const assert = require('node:assert/strict');
const app = require('../api/index.js');

test('health endpoint reports service readiness', async () => {
  const server = app.listen(0);
  try {
    const base = 'http://127.0.0.1:' + server.address().port;
    const response = await fetch(base + '/api/health');
    assert.equal(response.status, 200);
    const data = await response.json();
    assert.equal(data.ok, true);
    assert.equal(data.version, '4.0.0');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('public IPv4 targets are rejected before any network scan', async () => {
  const server = app.listen(0);
  try {
    const response = await fetch('http://127.0.0.1:' + server.address().port + '/api/scan/range', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ range: '8.8.8.8' })
    });
    assert.equal(response.status, 400);
    assert.match((await response.json()).error, /private IPv4/i);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('oversized and invalid ranges are rejected', async () => {
  const server = app.listen(0);
  try {
    const base = 'http://127.0.0.1:' + server.address().port + '/api/scan/range';
    for (const range of ['192.168.0.0/16', '192.168.1.1-192.168.2.250', 'not-an-ip']) {
      const response = await fetch(base, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ range })
      });
      assert.equal(response.status, 400, range + ' should be rejected');
    }
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('clear endpoint resets in-memory results and stats', async () => {
  const server = app.listen(0);
  try {
    const base = 'http://127.0.0.1:' + server.address().port;
    const response = await fetch(base + '/api/clear', { method: 'POST' });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).success, true);
    const status = await (await fetch(base + '/api/status')).json();
    assert.deepEqual(status.stats, { scanned: 0, found: 0, lastScanAt: null });
    assert.deepEqual(status.results, []);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('local root route serves the dashboard', async () => {
  const server = app.listen(0);
  try {
    const response = await fetch('http://127.0.0.1:' + server.address().port + '/');
    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type') || '', /text\/html/i);
    const html = await response.text();
    assert.match(html, /IpCamHack/);
    assert.match(html, /exportBtn/);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
