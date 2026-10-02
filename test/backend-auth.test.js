'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const { setTimeout: delay } = require('node:timers/promises');
const { WebSocket } = require('ws');

async function until(predicate, message) {
  const end = Date.now() + 5000;
  while (Date.now() < end) {
    if (predicate()) return;
    await delay(10);
  }
  assert.fail(message);
}

async function setup(t, env = {}, options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'webmux-backend-test-'));
  const secretFile = path.join(dir, 'private', 'secret');
  fs.writeFileSync(path.join(dir, 'fixture-marker'), 'isolated');
  const providers = path.join(dir, 'providers');
  fs.mkdirSync(providers);
  // Intentionally thin test provider exercises core rejection of malformed
  // provider results. It is created only inside the temporary test directory.
  fs.writeFileSync(path.join(providers, 'fixture.js'), `module.exports = {
    id: 'fixture', register(ctx) {
      ctx.router.post('/start', (req, res) => {
        const token = ctx.mintToken(req.body);
        if (token) ctx.setSessionCookie(res, token);
        res.status(token ? 200 : 403).json({ token, allowed: ctx.authUserAllowed(req.body.user) });
      });
    }
  };`);
  if (options.emptySecret) {
    fs.mkdirSync(path.dirname(secretFile));
    fs.writeFileSync(secretFile, ' \n');
  }
  const probe = net.createServer();
  await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  const base = 'http://127.0.0.1:' + port;
  let logs = '';
  const child = spawn(process.execPath, ['--require', path.join(__dirname, 'support/backend-terminal-fixture.cjs'), 'server.js'], {
    cwd: path.join(__dirname, '..'),
    env: {
      PATH: process.env.PATH, HOME: dir, TMPDIR: os.tmpdir(), SHELL: '/bin/sh', TERM: 'xterm-256color',
      PORT: String(port), WEBMUX_HOST: '127.0.0.1', WEBMUX_TMUX_BIN: 'webmux-test-tmux',
      WEBMUX_TMUX_SOCKET: 'webmux-backend-test-' + crypto.randomBytes(8).toString('hex'),
      WEBMUX_SECRET_FILE: secretFile, WEBMUX_STATE: path.join(dir, 'state.json'),
      WEBMUX_LOG_DIR: path.join(dir, 'logs'), WEBMUX_SEEN_IPS: path.join(dir, 'seen'),
      WEBMUX_UPLOADS: path.join(dir, 'uploads'), WEBMUX_AUTH_DIR: providers,
      WEBMUX_TEST_TERMINAL_DIR: dir, ...env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const exited = once(child, 'exit');
  child.stdout.on('data', data => { logs += data; });
  child.stderr.on('data', data => { logs += data; });
  const sockets = [];
  t.after(async () => {
    for (const ws of sockets) ws.terminate();
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await exited;
    fs.rmSync(dir, { recursive: true, force: true });
  });
  if (options.emptySecret) {
    const [code] = await exited;
    return { code, logs, dir };
  }
  await until(() => {
    assert.equal(child.exitCode, null, 'test server exited during startup: ' + logs);
    return logs.includes('webmux running on');
  }, 'test server did not start');

  async function request(url, body, token, cookie) {
    const headers = {};
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (token) headers['x-token'] = token;
    if (cookie) headers.cookie = cookie;
    const res = await fetch(base + url, {
      method: body === undefined ? 'GET' : 'POST', headers,
      body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(5000),
    });
    return { status: res.status, data: await res.json(), token: res.headers.get('x-session'), cookie: res.headers.get('set-cookie')?.split(';')[0] };
  }
  async function login() {
    const res = await request('/auth', { secret: fs.readFileSync(secretFile, 'utf8') });
    assert.equal(res.status, 200);
    return res.data.token;
  }
  async function socket(token, session = 'webmux') {
    const ws = new WebSocket(base.replace('http:', 'ws:') + '/ws?session=' + encodeURIComponent(session), ['webmux', token]);
    sockets.push(ws);
    ws.messages = [];
    ws.on('message', data => ws.messages.push(data.toString()));
    ws.closed = once(ws, 'close');
    await once(ws, 'open');
    return ws;
  }
  function events() {
    try { return fs.readFileSync(path.join(dir, 'terminal.jsonl'), 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse); }
    catch (e) { if (e.code === 'ENOENT') return []; throw e; }
  }
  function gate(session = 'slow') {
    const file = path.join(dir, 'gate-has-session-' + session);
    fs.writeFileSync(file, 'pause');
    return () => fs.rmSync(file, { force: true });
  }
  async function ready(ws) { await until(() => ws.messages.some(m => m.startsWith('fixture-ready:')), 'terminal was not attached'); }
  return { request, login, socket, ready, events, gate, dir, child };
}

test('external provider sessions require a named allowlisted user and finite positive TTL', { timeout: 10000 }, async t => {
  const s = await setup(t, { WEBMUX_AUTH_USERS: 'reader,administrator', WEBMUX_ADMIN_USERS: 'administrator' });
  for (const body of [{}, { user: null }, { user: '' }, { user: ['reader'] }, { user: {} }, { user: 'outsider' },
    { user: 'reader', ttlMs: '1000' }, { user: 'reader', ttlMs: 0 }, { user: 'reader', ttlMs: -1 }]) {
    const res = await s.request('/auth/ext/fixture/start', body);
    assert.equal(res.status, 403);
    assert.equal(res.cookie, undefined);
  }
  const reader = await s.request('/auth/ext/fixture/start', { user: 'reader', provider: 'passkey', admin: true, accountId: 'forged' });
  assert.equal(reader.status, 200);
  const me = await s.request('/api/me', undefined, reader.data.token);
  assert.equal(me.data.provider, 'fixture');
  assert.equal(me.data.admin, false);
  const exchange = await s.request('/api/auth/exchange', {}, null, reader.cookie);
  assert.equal(exchange.status, 200);
  assert.equal((await s.request('/api/auth/exchange', {}, null, reader.cookie)).status, 401);
  const admin = await s.request('/auth/ext/fixture/start', { user: 'administrator' });
  assert.equal((await s.request('/api/me', undefined, admin.data.token)).data.admin, true);
  assert.equal((await s.request('/api/me', undefined, await s.login())).data.admin, true);
});

test('explicitly empty external allowlist stays closed even when external admins are configured', { timeout: 10000 }, async t => {
  const s = await setup(t, { WEBMUX_AUTH_USERS: '', WEBMUX_ADMIN_USERS: 'administrator' });
  assert.equal((await s.request('/auth/ext/fixture/start', { user: 'administrator' })).status, 403);
});

test('logout with a still-valid rotated alias revokes the canonical ticket and its socket', { timeout: 10000 }, async t => {
  const s = await setup(t);
  const old = await s.login();
  const ws = await s.socket(old);
  await s.ready(ws);
  await delay(2050);
  const rotated = await s.request('/api/me', undefined, old);
  assert.notEqual(rotated.token, old);
  assert.equal((await s.request('/api/me', undefined, old)).status, 200);
  assert.equal((await s.request('/api/auth/logout', {}, old)).status, 200);
  await ws.closed;
  assert.equal((await s.request('/api/me', undefined, rotated.token)).status, 401);
  await until(() => s.events().some(e => e.type === 'kill'), 'logout leaked its PTY');
});

test('logout cancels pending socket admission and pending session switches', { timeout: 10000 }, async t => {
  const s = await setup(t);
  const token = await s.login();
  const release = s.gate();
  const ws = await s.socket(token, 'slow');
  await until(() => s.events().some(e => e.type === 'tmux' && e.command === 'has-session' && e.session === 'slow'), 'admission did not reach async gate');
  await s.request('/api/auth/logout', {}, token);
  await ws.closed;
  release();
  await delay(50);
  assert.equal(s.events().filter(e => e.type === 'attach').length, 0);

  const next = await s.login();
  const attached = await s.socket(next);
  await s.ready(attached);
  const releaseSwitch = s.gate('other');
  attached.send(JSON.stringify({ t: 'switch', session: 'other' }));
  await until(() => s.events().some(e => e.type === 'tmux' && e.command === 'has-session' && e.session === 'other'), 'switch did not reach async gate');
  await s.request('/api/auth/logout', {}, next);
  await attached.closed;
  releaseSwitch();
  await delay(50);
  assert.equal(s.events().filter(e => e.type === 'attach').length, 1);
  await until(() => s.events().filter(e => e.type === 'kill').length === 1, 'switch revocation leaked a PTY');
});

test('the latest reconnect and session switch win asynchronous tmux races', { timeout: 10000 }, async t => {
  const s = await setup(t);
  const token = await s.login();
  const release = s.gate();
  const old = await s.socket(token, 'slow');
  await until(() => s.events().some(e => e.command === 'has-session' && e.session === 'slow'), 'old admission did not pause');
  const current = await s.socket(token);
  await s.ready(current);
  await old.closed;
  release();
  await delay(50);
  assert.equal(s.events().filter(e => e.type === 'attach').length, 1);

  const baseline = s.events().filter(e => e.command === 'has-session' && e.session === 'slow').length;
  const releaseSwitch = s.gate();
  current.send(JSON.stringify({ t: 'switch', session: 'slow' }));
  await until(() => s.events().filter(e => e.command === 'has-session' && e.session === 'slow').length > baseline, 'old switch did not pause');
  current.send(JSON.stringify({ t: 'switch', session: 'other' }));
  await until(() => current.messages.some(m => m.includes('"switched"') && m.includes('"other"')), 'latest switch did not complete');
  releaseSwitch();
  await delay(50);
  assert.deepEqual(s.events().filter(e => e.type === 'attach').map(e => e.session), ['webmux', 'other']);
  assert.equal(current.readyState, WebSocket.OPEN);
});

test('socket expiry closes active terminals and cancels delayed admission without the minute sweep', { timeout: 10000 }, async t => {
  const s = await setup(t, { WEBMUX_AUTH_USERS: 'reader' });
  const first = await s.request('/auth/ext/fixture/start', { user: 'reader', ttlMs: 500 });
  const ws = await s.socket(first.data.token);
  await s.ready(ws);
  await ws.closed;
  assert.equal((await s.request('/api/me', undefined, first.data.token)).status, 401);
  const second = await s.request('/auth/ext/fixture/start', { user: 'reader', ttlMs: 200 });
  const release = s.gate();
  const pending = await s.socket(second.data.token, 'slow');
  await pending.closed;
  release();
  await delay(50);
  assert.equal(s.events().filter(e => e.type === 'attach').length, 1);
});

test('malformed WS messages and terminal spawn errors do not crash the process', { timeout: 10000 }, async t => {
  const s = await setup(t, { WEBMUX_FINGERPRINTS: '1' });
  const token = await s.login();
  const ws = await s.socket(token);
  await s.ready(ws);
  for (const message of [null, [], 1, { t: 'i', d: { toString: null } }, { t: 'r', cols: {}, rows: 10 },
    { t: 'focus', session: { toString: null }, name: { toString: null } },
    { t: 'fp', fp: { ua: { brands: {} } } }, { t: 'fp', fp: { webrtc: { host: {} } } },
    { t: 'fp', fp: { hardwareConcurrency: { toString: null } } },
    { t: 'switch', session: '\u0000' }]) ws.send(JSON.stringify(message));
  ws.send(JSON.stringify({ t: 'i', d: 'still-alive' }));
  await until(() => ws.messages.includes('still-alive'), 'malformed message killed the socket');
  assert.equal((await s.request('/api/me', undefined, token)).status, 200);
  fs.writeFileSync(path.join(s.dir, 'fail-spawn'), 'fail');
  const broken = await s.socket(await s.login());
  await broken.closed;
  assert.equal((await s.request('/api/me', undefined, token)).status, 200);
  assert.equal(s.child.exitCode, null);
});

test('an empty recovery-secret file fails startup instead of permitting coerced blank logins', { timeout: 10000 }, async t => {
  const s = await setup(t, {}, { emptySecret: true });
  assert.notEqual(s.code, 0);
  assert.match(s.logs, /Recovery secret file must not be empty/);
  assert.equal(fs.existsSync(path.join(s.dir, 'terminal.jsonl')), false);
});

test('invalid destructive terminal parameters cannot fall back to the default session or window zero', { timeout: 10000 }, async t => {
  const s = await setup(t);
  const token = await s.login();
  for (const index of [null, false, [], {}, -1, 0.5, 2 ** 32, '']) {
    assert.equal((await s.request('/api/kill', { session: 'webmux', index }, token)).status, 400);
  }
  for (const session of ['bad:name', '../path', 'bad\u0000name', { toString: null }, '']) {
    assert.equal((await s.request('/api/kill', { session, index: 0 }, token)).status, 400);
    assert.equal((await s.request('/api/windows', { session }, token)).status, 400);
  }
  assert.equal((await s.request('/api/rename', { index: 0, name: '\u0000' }, token)).status, 400);
  assert.equal((await s.request('/api/tmux', { command: 'new-window-unintended' }, token)).status, 403);
  assert.equal(s.events().some(e => ['kill-window', 'new-window', 'rename-window'].includes(e.command)), false);
  assert.equal((await s.request('/api/select', { session: 'webmux', index: '0' }, token)).status, 200);
});

test('telemetry: unsolicited detailed HTTP/WS headers and historical data require explicit opt-in', { timeout: 15000 }, async t => {
  const { telemetryServer } = require('./support/telemetry-server.cjs');
  const detailed = {
    'sec-ch-ua': '"telemetry-browser";v="999"', 'sec-ch-ua-mobile': '?1', 'sec-ch-ua-platform': '"telemetry-platform"',
    'sec-ch-ua-platform-version': '"999.999"', 'sec-ch-ua-model': '"telemetry-model"',
    'sec-ch-ua-full-version-list': '"telemetry-browser";v="999.999.999"', 'sec-ch-ua-full-version': '"999.999.999"',
    'sec-ch-ua-arch': '"telemetry-arch"', 'sec-ch-ua-bitness': '"64"', 'sec-ch-ua-wow64': '?0',
    'sec-ch-ua-form-factors': '"telemetry-form"', 'sec-ch-prefers-color-scheme': 'dark',
    'device-memory': '16', downlink: '9.9', ect: '4g', rtt: '50', 'save-data': 'on', 'viewport-width': '1234', dnt: '1',
    'cf-ipcity': 'telemetry-city', 'cf-ipcontinent': 'telemetry-continent', 'cf-region': 'telemetry-region',
    'cf-region-code': 'telemetry-region-code', 'cf-postal-code': 'telemetry-postcode',
    'cf-timezone': 'telemetry-timezone', 'cf-metro-code': 'telemetry-metro', 'cf-device-type': 'telemetry-device',
    'accept-language': 'telemetry-language', 'accept-encoding': 'identity', accept: 'application/json',
  };
  for (const value of [undefined, '0', '1']) {
    await t.test(value === '1' ? 'enabled' : value === '0' ? 'explicitly disabled' : 'default', async t => {
      const enabled = value === '1';
      const s = await telemetryServer(t, value);
      const headers = { ...detailed, 'user-agent': 'SecuritySession/1.0', origin: s.origin, 'cf-ray': 'security-ray', 'cf-ipcountry': 'US' };
      const token = await s.login(headers);
      const admin = await s.login();
      const me = await s.request('/api/me', { token, headers });
      assert.equal(me.data.fingerprints, enabled);
      assert.equal(!!me.headers.get('accept-ch'), enabled);
      const checkRow = row => {
        assert.ok(row, 'the active session must remain visible');
        assert.equal(row.ip, '127.0.0.1');
        assert.equal(row.net.headers['user-agent'], headers['user-agent']);
        assert.equal(row.net.headers.origin, s.origin);
        assert.equal(row.net.headers['cf-ray'], 'security-ray');
        assert.equal(row.net.country, 'US');
        for (const [name, detail] of Object.entries(detailed)) {
          assert.equal(row.net.headers[name], enabled ? detail : undefined, name + ' follows opt-in');
        }
        assert.equal(row.net.city, enabled ? detailed['cf-ipcity'] : undefined);
        assert.equal(row.net.lang, enabled ? detailed['accept-language'] : undefined);
        assert.equal(row.intel?.city, enabled ? 'historical-city' : undefined);
      };
      let who = (await s.request('/api/admin/who', { token: admin })).data;
      checkRow(who.logins.find(row => !row.you));
      await s.socket(token, headers);
      who = (await s.request('/api/admin/who', { token: admin })).data;
      checkRow(who.attached[0]);
      checkRow(who.logins.find(row => !row.you));
      assert.equal(who.history.some(row => row.rid === 'historical-telemetry'), enabled);
      for (const [file, text] of Object.entries(s.historicalFiles)) {
        assert.equal(fs.readFileSync(path.join(s.logDir, file), 'utf8'), text, 'historical data is preserved');
      }
      await s.request('/api/fp', { token, headers, body: { fp: { deviceId: 'submitted-telemetry-device' } } });
      who = (await s.request('/api/admin/who', { token: admin })).data;
      assert.equal(who.logins.find(row => !row.you).fp?.deviceId, enabled ? 'submitted-telemetry-device' : undefined);
      await until(() => fs.readFileSync(path.join(s.logDir, 'events.jsonl'), 'utf8').includes('auth_ok'), 'auth audit was not written');
      const audit = fs.readFileSync(path.join(s.logDir, 'events.jsonl'), 'utf8');
      assert.equal(audit.includes('telemetry-browser'), enabled, 'audit metadata must not bypass the opt-in');
      assert.equal(audit.includes('telemetry-language'), enabled, 'audit locale follows opt-in');
      if (!enabled) {
        assert.deepEqual(who.history, []);
        assert.equal(JSON.stringify(who).includes('historical-'), false);
        for (const [file, text] of Object.entries(s.historicalFiles)) {
          assert.equal(fs.readFileSync(path.join(s.logDir, file), 'utf8'), text, 'disabled collection must not write to historical data');
        }
      }
    });
  }
});
