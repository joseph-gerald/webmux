'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');
const { WebSocket } = require('ws');
const { createServer } = require('../webmux-win-simple/server');
const example = require('../extensions.example/auth/example-provider');

test('external-provider scaffold fails closed before mounting routes or minting tokens', () => {
  let usedContext = false;
  const ctx = new Proxy({}, { get() { usedContext = true; throw new Error('unexpected provider activity'); } });
  assert.throws(() => example.register(ctx), /implement verified login/);
  assert.equal(usedContext, false);
});

test('Windows prototype blocks cross-site and rebinding access before spawning a shell', { timeout: 10000 }, async t => {
  let spawned = 0;
  const writes = [];
  const resizes = [];
  const server = createServer({ spawn: () => {
    spawned++;
    return { onData() {}, onExit() {}, kill() {}, write: data => writes.push(data),
      resize: (cols, rows) => resizes.push([cols, rows]) };
  } });
  const sockets = [];
  t.after(async () => {
    for (const socket of sockets) socket.terminate();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  const origin = `http://127.0.0.1:${port}`;
  const socketUrl = `ws://127.0.0.1:${port}/`;

  function request(headers) {
    return new Promise((resolve, reject) => {
      http.get(origin, { headers }, res => { res.resume(); resolve(res); }).on('error', reject);
    });
  }
  assert.equal((await request({ host: `evil.example:${port}` })).statusCode, 403);
  assert.equal((await request({ origin: 'https://evil.example' })).statusCode, 403);
  const page = await request({});
  assert.equal(page.statusCode, 200);
  assert.equal(page.headers['content-security-policy'], "frame-ancestors 'none'");

  for (const headers of [
    {}, { origin: 'null' }, { origin: 'https://evil.example' },
    { origin: `http://localhost:${port}` },
    { host: `evil.example:${port}`, origin: `http://evil.example:${port}` },
  ]) {
    const ws = new WebSocket(socketUrl, { headers });
    sockets.push(ws);
    await new Promise((resolve, reject) => {
      ws.on('error', reject);
      ws.on('open', () => reject(new Error('hostile WebSocket was accepted')));
      ws.on('unexpected-response', (_req, res) => {
        res.resume();
        try { assert.equal(res.statusCode, 403); resolve(); } catch (error) { reject(error); }
      });
    });
    ws.on('error', () => {});
    ws.terminate();
  }
  assert.equal(spawned, 0);

  const ws = new WebSocket(socketUrl, { origin });
  sockets.push(ws);
  await once(ws, 'open');
  assert.equal(spawned, 1);
  for (const message of [null, 42, { type: 'input', data: {} }, { type: 'resize', cols: 1e9, rows: 24 }]) {
    ws.send(JSON.stringify(message));
  }
  ws.send('{');
  ws.send(JSON.stringify({ type: 'input', data: 'hello' }));
  ws.send(JSON.stringify({ type: 'resize', cols: 100, rows: 40 }));
  ws.ping();
  await once(ws, 'pong'); // All preceding messages have been handled.
  assert.deepEqual(writes, ['hello']);
  assert.deepEqual(resizes, [[100, 40]]);
});
