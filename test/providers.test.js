'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const express = require('express');
const { loadAuthProviders } = require('../lib/auth/providers');

test('provider loader is optional and rejects route collisions and broken plugins', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'webmux-provider-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const app = express();
  app.get('/api/me', (_req, res) => res.send('core'));
  const core = { app, express, makeCtx: (id, router) => ({ id, router }) };
  assert.deepEqual(loadAuthProviders(core, path.join(dir, 'missing')), []);
  const modules = {
    '01-valid.js': `module.exports = { id: 'example', label: 'Example', iconPath: '/icon.svg', register(ctx) { ctx.router.get('/start', (_, res) => res.send(ctx.id)); } };`,
    '02-duplicate.js': `module.exports = { id: 'example', register() { throw Error('must not register'); } };`,
    '03-collision.js': `module.exports = { id: '../api', register() {} };`,
    '04-native.js': `module.exports = { id: 'passkey', register() {} };`,
    '05-broken.js': `module.exports = { id: 'broken', register() { throw Error('missing configuration'); } };`,
    '06-valid.js': `module.exports = { id: 'another', iconPath: '//external.example/icon.svg', register() {} };`,
    '07-async.js': `module.exports = { id: 'async', async register(ctx) { ctx.router.get('/start', (_, res) => res.send('bad')); throw Error('async configuration failure'); } };`,
    '08-not-string.js': `module.exports = { id: ['coerced'], register() {} };`,
  };
  for (const [file, contents] of Object.entries(modules)) fs.writeFileSync(path.join(dir, file), contents);
  const providers = loadAuthProviders(core, dir);
  assert.deepEqual(providers.map(p => p.id), ['example', 'another']);
  assert.equal(providers[0].loginPath, '/auth/ext/example/start');
  assert.equal(providers[0].iconPath, '/auth/ext/example/icon.svg');
  assert.equal(providers[1].iconPath, null);
  const server = app.listen(0, '127.0.0.1');
  t.after(() => { server.closeAllConnections(); server.close(); });
  await new Promise(resolve => server.once('listening', resolve));
  const base = 'http://127.0.0.1:' + server.address().port;
  assert.equal(await (await fetch(base + '/api/me')).text(), 'core');
  assert.equal(await (await fetch(base + '/auth/ext/example/start')).text(), 'example');
  assert.equal((await fetch(base + '/auth/ext/async/start')).status, 404);
});
