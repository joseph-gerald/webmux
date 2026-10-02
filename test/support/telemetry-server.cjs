'use strict';
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

async function telemetryServer(t, fingerprints) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'webmux-telemetry-test-'));
  const logDir = path.join(dir, 'logs');
  fs.mkdirSync(logDir);
  fs.writeFileSync(path.join(dir, 'fixture-marker'), 'isolated');
  // Simulate data left by a previous opt-in. Disabling collection must hide it
  // without erasing it or importing it into new session records.
  const historicalFiles = {
    'fingerprints.jsonl': JSON.stringify({ rid: 'historical-telemetry', fp: { deviceId: 'historical-device' },
      net: { headers: { 'sec-ch-ua-model': 'historical-model' } } }) + '\n',
    'ip-intel.json': JSON.stringify({ '127.0.0.1': { city: 'historical-city', org: 'historical-org', at: Date.now() } }),
  };
  for (const [file, text] of Object.entries(historicalFiles)) fs.writeFileSync(path.join(logDir, file), text);
  const probe = net.createServer();
  await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  const origin = 'http://127.0.0.1:' + port;
  let child, exited;
  const sockets = new Set();
  async function stop() {
    for (const ws of sockets) ws.terminate();
    sockets.clear();
    if (child && child.exitCode === null && child.signalCode === null) child.kill();
    if (exited) await exited;
  }
  t.after(async () => { await stop(); fs.rmSync(dir, { recursive: true, force: true }); });
  async function restart(value) {
    await stop();
    let logs = '';
    child = spawn(process.execPath, ['--require', path.join(__dirname, 'backend-terminal-fixture.cjs'), 'server.js'], {
      cwd: path.join(__dirname, '../..'),
      env: {
        PATH: process.env.PATH, HOME: dir, TMPDIR: os.tmpdir(), SHELL: '/bin/sh', TERM: 'xterm-256color',
        PORT: String(port), WEBMUX_HOST: '127.0.0.1', WEBMUX_TMUX_BIN: 'webmux-test-tmux',
        WEBMUX_TMUX_SOCKET: 'webmux-backend-test-telemetry-' + crypto.randomBytes(8).toString('hex'),
        WEBMUX_SECRET_FILE: path.join(dir, 'secret'), WEBMUX_STATE: path.join(dir, 'state.json'),
        WEBMUX_LOG_DIR: logDir, WEBMUX_SEEN_IPS: path.join(dir, 'seen'),
        WEBMUX_UPLOADS: path.join(dir, 'uploads'), WEBMUX_AUTH_DIR: path.join(dir, 'no-providers'),
        WEBMUX_TEST_TERMINAL_DIR: dir,
        ...(value === undefined ? {} : { WEBMUX_FINGERPRINTS: value }),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    exited = once(child, 'exit');
    child.stdout.on('data', data => { logs += data; });
    child.stderr.on('data', data => { logs += data; });
    await until(() => {
      assert.equal(child.exitCode, null, 'isolated telemetry server exited: ' + logs);
      return logs.includes('webmux running on');
    }, 'isolated telemetry server did not start');
  }
  async function request(url, { body, token, headers = {} } = {}) {
    const res = await fetch(origin + url, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { ...headers, ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...(token ? { 'x-token': token } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(5000),
    });
    return { status: res.status, data: await res.json(), headers: res.headers };
  }
  async function login(headers) {
    const result = await request('/auth', { body: { secret: fs.readFileSync(path.join(dir, 'secret'), 'utf8') }, headers });
    assert.equal(result.status, 200, 'isolated telemetry login failed');
    return result.data.token;
  }
  async function socket(token, headers) {
    const ws = new WebSocket(origin.replace('http:', 'ws:') + '/ws?session=webmux', ['webmux', token], { headers });
    sockets.add(ws);
    const messages = [];
    ws.on('message', data => messages.push(data.toString()));
    await once(ws, 'open');
    await until(() => messages.some(m => m.startsWith('fixture-ready:')), 'isolated telemetry terminal did not attach');
    return ws;
  }
  await restart(fingerprints);
  return { dir, logDir, historicalFiles, origin, restart, request, login, socket };
}

module.exports = { telemetryServer, until };
