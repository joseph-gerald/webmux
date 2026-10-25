'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawn, spawnSync, execFileSync } = require('node:child_process');
const { once } = require('node:events');
const { setTimeout: delay } = require('node:timers/promises');
const { WebSocket } = require('ws');

const root = path.join(__dirname, '..');
const helper = path.join(root, 'bin/webmux-open');
const haveTmux = spawnSync('tmux', ['-V']).status === 0;

async function until(predicate, message) {
  const end = Date.now() + 5000;
  while (Date.now() < end) {
    if (predicate()) return;
    await delay(10);
  }
  assert.fail(typeof message === 'function' ? message() : message);
}

function hasRequest(text, url) {
  return text.includes('\x1b]777;webmux-open;' + Buffer.from(url).toString('base64') + '\x07');
}

test('browser helper rejects invalid URLs before touching the terminal', () => {
  for (const args of [[], ['https://example.com', 'extra'], ['javascript:alert(1)'], ['file:///tmp/file'],
    ['https://'], ['https://user:password@example.com'], ['https://example.com/\ncontrol'],
    ['https://example.com/\\path'], ['https://example.com/' + 'a'.repeat(17000)]]) {
    const result = spawnSync(process.execPath, [helper, ...args], {
      env: { PATH: process.env.PATH }, encoding: 'utf8', detached: true,
    });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /usage:|expected an http\(s\) URL/);
  }
  const noTerminal = spawnSync(process.execPath, [helper, 'https://example.com'], {
    env: { PATH: process.env.PATH }, encoding: 'utf8', detached: true,
  });
  assert.equal(noTerminal.status, 1);
  assert.match(noTerminal.stderr, /no terminal found/);
});

for (const existing of [false, true]) {
  test('browser helper reaches the WebSocket through ' + (existing ? 'an existing' : 'a new') + ' tmux daemon', {
    skip: !haveTmux, timeout: 20000,
  }, async t => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'webmux-links-test-'));
    const socket = 'webmux-links-test-' + process.pid + '-' + Date.now();
    const env = { PATH: process.env.PATH, HOME: dir, SHELL: '/bin/sh', TERM: 'xterm-256color' };
    const tmux = args => execFileSync('tmux', ['-L', socket, ...args], { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    let child, exited, ws;
    t.after(async () => {
      ws?.terminate();
      if (child && child.exitCode === null && child.signalCode === null) child.kill();
      if (exited) await exited;
      try { tmux(['kill-server']); } catch {}
      fs.rmSync(dir, { recursive: true, force: true });
    });
    if (existing) tmux(['-f', '/dev/null', 'new-session', '-d', '-s', 'webmux', '/bin/sh']);
    const probe = net.createServer();
    await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
    const port = probe.address().port;
    await new Promise(resolve => probe.close(resolve));
    const base = 'http://127.0.0.1:' + port;
    child = spawn(process.execPath, ['server.js'], {
      cwd: root,
      env: { ...env, PORT: String(port), WEBMUX_HOST: '127.0.0.1', WEBMUX_TMUX_SOCKET: socket,
        WEBMUX_SECRET_FILE: path.join(dir, 'secret'), WEBMUX_STATE: path.join(dir, 'state.json'),
        WEBMUX_LOG_DIR: path.join(dir, 'logs'), WEBMUX_SEEN_IPS: path.join(dir, 'seen'),
        WEBMUX_UPLOADS: path.join(dir, 'uploads'), WEBMUX_AUTH_DIR: path.join(dir, 'no-providers') },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    exited = once(child, 'exit');
    let logs = '';
    child.stdout.on('data', b => { logs += b; });
    child.stderr.on('data', b => { logs += b; });
    await until(() => {
      assert.equal(child.exitCode, null, logs);
      return logs.includes('webmux running on');
    }, 'test server did not start');
    const login = await fetch(base + '/auth', { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ secret: fs.readFileSync(path.join(dir, 'secret'), 'utf8') }) });
    const { token } = await login.json();
    assert.ok(token);
    ws = new WebSocket(base.replace('http:', 'ws:') + '/ws?session=webmux', ['webmux', token]);
    let output = '';
    ws.on('message', data => { if (data[0] !== 30) output += data.toString(); });
    await once(ws, 'open');
    await until(() => output.includes('\x1b['), 'tmux did not attach');
    if (existing) {
      const added = await fetch(base + '/api/windows', { method: 'POST',
        headers: { 'content-type': 'application/json', 'x-token': token }, body: JSON.stringify({ session: 'webmux' }) });
      assert.equal(added.status, 200);
    }
    // BROWSER must work even if a login profile resets PATH, and after a restart
    // against a tmux daemon whose original environment did not include it.
    const urls = ['https://example.com/browser?value=%E6%97%A5&second=2', 'https://example.com/xdg'];
    ws.send(JSON.stringify({ t: 'i', d: `"$BROWSER" '${urls[0]}'\r` }));
    await until(() => hasRequest(output, urls[0]), 'BROWSER did not forward a URL through tmux: ' + output);
    // Exercise the documented setup for shells whose /etc/profile replaces PATH.
    ws.send(JSON.stringify({ t: 'i', d: `export PATH="$(dirname "$BROWSER"):$PATH"; xdg-open '${urls[1]}' >/dev/null 2>&1\r` }));
    await until(() => hasRequest(output, urls[1]),
      () => 'xdg-open failed with redirected output: ' + output);

    // Model launchers such as Node's open package: detached, no controlling TTY,
    // and no standard streams connected to the shell. Only TMUX/PANE survive.
    const pane = tmux(['display-message', '-p', '-t', 'webmux', '#{pane_id}']);
    const serverPid = tmux(['display-message', '-p', '#{pid}']);
    const socketPath = tmux(['display-message', '-p', '#{socket_path}']);
    const detachedUrl = 'https://example.com/detached?x=1&y=2';
    const launcher = spawn(process.execPath, [helper, detachedUrl], {
      detached: true, stdio: 'ignore', env: { ...env, TMUX: `${socketPath},${serverPid},0`, TMUX_PANE: pane },
    });
    const [code] = await once(launcher, 'exit');
    assert.equal(code, 0);
    await until(() => hasRequest(output, detachedUrl),
      'detached browser launcher did not reach its originating pane');
  });
}
