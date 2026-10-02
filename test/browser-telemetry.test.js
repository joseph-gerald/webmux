'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { telemetryServer, until } = require('./support/telemetry-server.cjs');

test('telemetry: Chromium Client Hints are opt-in and a cached opt-in cannot bypass disabling collection', {
  skip: !process.env.WEBMUX_TEST_CHROME, timeout: 45000,
}, async t => {
  const s = await telemetryServer(t);
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'webmux-telemetry-chrome-'));
  const { default: puppeteer } = await import('puppeteer-core');
  let browser;
  t.after(async () => {
    if (browser) await browser.close();
    fs.rmSync(profile, { recursive: true, force: true });
  });
  browser = await puppeteer.launch({
    executablePath: process.env.WEBMUX_TEST_CHROME, headless: true, protocolTimeout: 10000,
    userDataDir: path.join(profile, 'profile'),
    env: { PATH: process.env.PATH, HOME: profile, TMPDIR: os.tmpdir(),
      XDG_CONFIG_HOME: path.join(profile, 'config'), XDG_CACHE_HOME: path.join(profile, 'cache') },
    args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-background-networking', '--disk-cache-size=1048576'],
  });
  const page = await browser.newPage();
  const cdp = await page.createCDPSession();
  await cdp.send('Network.enable');
  const urls = new Map(), sentHeaders = new Map();
  cdp.on('Network.requestWillBeSent', event => urls.set(event.requestId, event.request.url));
  // ExtraInfo contains the actual on-wire Client Hints, including headers the
  // browser adds after the ordinary requestWillBeSent/Puppeteer request event.
  cdp.on('Network.requestWillBeSentExtraInfo', event => sentHeaders.set(event.requestId,
    Object.fromEntries(Object.entries(event.headers).map(([key, value]) => [key.toLowerCase(), value]))));
  const highEntropy = ['sec-ch-ua-platform-version', 'sec-ch-ua-model', 'sec-ch-ua-full-version-list',
    'sec-ch-ua-full-version', 'sec-ch-ua-arch', 'sec-ch-ua-bitness', 'sec-ch-ua-wow64',
    'sec-ch-ua-form-factors', 'sec-ch-prefers-color-scheme', 'device-memory', 'downlink', 'ect', 'rtt'];

  async function browserRequest(label, token) {
    const url = '/api/me?telemetry=' + label;
    const result = await page.evaluate(async ({ url, token }) => {
      const response = await fetch(url, { headers: { 'x-token': token } });
      return { status: response.status, data: await response.json(), acceptCH: response.headers.get('accept-ch') };
    }, { url, token });
    assert.equal(result.status, 200);
    let headers;
    await until(() => {
      const id = [...urls].find(([, value]) => value === s.origin + url)?.[0];
      headers = sentHeaders.get(id);
      return !!headers;
    }, 'Chromium did not report on-wire request headers');
    return { ...result, sent: headers };
  }
  async function who(admin) { return (await s.request('/api/admin/who', { token: admin })).data; }
  function noDetails(data) {
    for (const row of [...data.logins, ...data.attached]) {
      assert.equal(row.ip, '127.0.0.1');
      assert.ok(row.net.headers['user-agent'], 'basic user-agent metadata remains available');
      for (const name of Object.keys(row.net.headers)) {
        assert.equal(name.startsWith('sec-ch-') || highEntropy.includes(name), false, 'unexpected collected hint: ' + name);
      }
      assert.equal(row.fp, undefined);
      assert.equal(row.intel, undefined);
    }
    assert.deepEqual(data.history, []);
    assert.equal(JSON.stringify(data).includes('historical-'), false);
  }

  await page.goto(s.origin + '/api/auth/providers?telemetry=default-navigation');
  let token = await s.login(), admin = await s.login();
  const defaults = await browserRequest('default', token);
  assert.equal(defaults.data.fingerprints, false);
  assert.equal(defaults.acceptCH, '');
  for (const name of highEntropy) assert.equal(defaults.sent[name], undefined, 'default must not request ' + name);
  // Chromium's unsolicited low-entropy hints must also be discarded.
  assert.ok(defaults.sent['sec-ch-ua']);
  noDetails(await who(admin));
  await page.evaluate(token => new Promise((resolve, reject) => {
    const socket = new WebSocket(location.origin.replace('http:', 'ws:') + '/ws?session=webmux', ['webmux', token]);
    window.telemetrySocket = socket;
    socket.onerror = () => reject(new Error('fixture WebSocket failed'));
    socket.onmessage = event => { if (event.data.startsWith('fixture-ready:')) resolve(); };
  }), token);
  const attached = await who(admin);
  assert.equal(attached.attached.length, 1);
  assert.equal(attached.attached[0].net.headers.origin, s.origin);
  noDetails(attached);
  await page.evaluate(() => new Promise(resolve => {
    window.telemetrySocket.onclose = resolve;
    window.telemetrySocket.close();
  }));

  await s.restart('1');
  await page.goto(s.origin + '/api/auth/providers?telemetry=enabled-navigation');
  token = await s.login(); admin = await s.login();
  const enabled = await browserRequest('enabled', token);
  assert.equal(enabled.data.fingerprints, true);
  assert.match(enabled.acceptCH, /sec-ch-ua-platform-version/);
  for (const name of ['sec-ch-ua-platform-version', 'sec-ch-ua-full-version-list', 'sec-ch-ua-arch', 'sec-ch-ua-bitness']) {
    assert.ok(enabled.sent[name], 'Chromium sends requested ' + name);
  }
  const optedIn = await who(admin);
  const actor = optedIn.logins.find(row => !row.you);
  assert.equal(actor.net.headers['sec-ch-ua-full-version-list'], enabled.sent['sec-ch-ua-full-version-list']);
  assert.equal(actor.net.headers['sec-ch-ua-platform-version'], enabled.sent['sec-ch-ua-platform-version']);
  assert.equal(actor.intel.city, 'historical-city');
  assert.ok(optedIn.history.some(row => row.rid === 'historical-telemetry'));

  // Keep this browser, page, and origin alive across the server restart so it
  // sends hints from the previous opt-in before seeing the disabled response.
  await s.restart();
  token = await s.login(); admin = await s.login();
  const cached = await browserRequest('cached-opt-in', token);
  assert.ok(cached.sent['sec-ch-ua-platform-version'], 'exercise actual previously enabled Client Hints');
  assert.equal(cached.data.fingerprints, false);
  assert.equal(cached.acceptCH, '');
  noDetails(await who(admin));
  await page.goto(s.origin + '/api/auth/providers?telemetry=disabled-navigation');
  const cleared = await browserRequest('cleared-opt-in', token);
  for (const name of highEntropy) assert.equal(cleared.sent[name], undefined, 'empty Accept-CH clears ' + name);
  for (const [file, text] of Object.entries(s.historicalFiles)) {
    assert.equal(fs.readFileSync(path.join(s.logDir, file), 'utf8'), text, 'historical data remains intact');
  }
});
