'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { createPasskeyAuth, relyingParty } = require('../lib/auth/passkeys');
const { authenticator } = require('./support/authenticator');

async function setup(t, config = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'webmux-passkey-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'passkeys.json');
  let clock = Date.now();
  const sessions = new Map([['owner', { rid: 'owner', provider: 'secret', admin: true, mintedAt: clock }]]);
  const revoked = [], minted = [];
  const core = {
    publicUrl: 'https://mux.example.com', file, now: () => clock,
    requireToken: (req, res, next) => {
      req.auth = sessions.get(req.headers['x-token']);
      if (!req.auth) return res.status(401).json({ error: 'unauthorized' });
      next();
    },
    isAdmin: rec => rec.admin === true,
    ticketActive: rec => [...sessions.values()].includes(rec),
    mintToken: rec => {
      const token = crypto.randomBytes(32).toString('hex');
      sessions.set(token, { ...rec, rid: token, mintedAt: clock });
      minted.push(rec);
      return token;
    },
    writeTicket: (res, token) => res.set('X-Session', token),
    audit: () => {}, clientIp: () => '127.0.0.1',
    revokeCredential: id => {
      revoked.push(id);
      for (const [key, rec] of sessions) if (rec.credentialId === id) sessions.delete(key);
    },
    ...config,
  };
  const servers = [];
  t.after(() => { for (const server of servers) { server.closeAllConnections(); server.close(); } });
  async function launch() {
    const app = express();
    app.use(express.json());
    app.use('/api/auth/passkeys', createPasskeyAuth(core));
    const server = app.listen(0, '127.0.0.1');
    servers.push(server);
    await new Promise(resolve => server.once('listening', resolve));
    return 'http://127.0.0.1:' + server.address().port + '/api/auth/passkeys';
  }
  let base = await launch();
  async function request(url, body, token, cookie, origin = core.publicUrl) {
    const headers = { origin, 'content-type': 'application/json' };
    if (token) headers['x-token'] = token;
    if (cookie) headers.cookie = cookie;
    const res = await fetch(base + url, { method: body === undefined ? 'GET' : 'POST', headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const data = await res.json();
    return { status: res.status, data, cookie: res.headers.get('set-cookie')?.split(';')[0], ticket: res.headers.get('x-session') };
  }
  async function enroll(name = 'alice', admin = true, token = 'owner', key = authenticator()) {
    const flow = await request('/register/options', { username: name, admin, label: 'Laptop' }, token);
    assert.equal(flow.status, 200, JSON.stringify(flow.data));
    const response = key.register(flow.data.options);
    const result = await request('/register/verify', { requestId: flow.data.requestId, response }, token);
    assert.equal(result.status, 200, JSON.stringify(result.data));
    return { key, userHandle: flow.data.options.user.id, response, flow };
  }
  async function login(enrolled, overrides = {}) {
    const flow = await request('/login/options', {});
    const response = enrolled.key.login(flow.data.options, enrolled.userHandle, overrides);
    const body = { requestId: flow.data.requestId, response };
    return { result: await request('/login/verify', body, null, flow.cookie), body, flow };
  }
  return { request, enroll, login, file, sessions, minted, revoked,
    advance: ms => { clock += ms; }, restart: async () => { base = await launch(); } };
}

test('RP is configured explicitly; missing config disables passkeys', async t => {
  assert.equal(relyingParty('http://localhost:7070/').rpID, 'localhost');
  for (const url of ['http://example.com', 'https://example.com/path', 'https://user:pass@example.com', 'https://example.com?query=1']) {
    assert.throws(() => relyingParty(url));
  }
  const s = await setup(t, { publicUrl: '' });
  assert.equal((await s.request('/config')).data.enabled, false);
  assert.equal((await s.request('/login/options', {})).status, 503);
});

test('enrollment requires a recent authorized login and exact browser origin', async t => {
  const s = await setup(t);
  assert.equal((await s.request('/register/options', { username: 'alice' })).status, 401);
  assert.equal((await s.request('/credentials')).status, 401);
  assert.equal((await s.request('/register/options', { username: 'alice' }, 'owner', null, 'https://attacker.example')).status, 403);
  s.sessions.set('unprivileged', { rid: 'other', provider: 'external', admin: false, mintedAt: Date.now() });
  assert.equal((await s.request('/register/options', { username: 'alice' }, 'unprivileged')).status, 403);
  s.sessions.set('external-admin', { rid: 'external-admin', provider: 'external', admin: true, mintedAt: Date.now() });
  assert.equal((await s.request('/register/options', { username: 'alice' }, 'external-admin')).status, 403);
  assert.equal((await s.request('/credentials', undefined, 'external-admin')).data.canCreateUsers, false);
  s.advance(300001);
  assert.equal((await s.request('/register/options', { username: 'alice' }, 'owner')).status, 403);
});

test('real registration and signed login persist across restart; replay is rejected', async t => {
  const s = await setup(t);
  const key = await s.enroll();
  assert.equal(key.flow.data.options.authenticatorSelection.userVerification, 'required');
  assert.equal(key.flow.data.options.authenticatorSelection.residentKey, 'required');
  assert.equal(fs.statSync(s.file).mode & 0o777, 0o600);
  assert.ok(JSON.parse(fs.readFileSync(s.file)).users[0].credentials[0].publicKey);
  const first = await s.login(key);
  assert.equal(first.result.status, 200, JSON.stringify(first.result.data));
  assert.equal(first.result.ticket, first.result.data.token);
  assert.equal(s.minted[0].provider, 'passkey');
  assert.equal(s.minted[0].admin, true);
  assert.equal((await s.request('/login/verify', first.body, null, first.flow.cookie)).status, 400);
  assert.equal((await s.request('/register/verify', { requestId: key.flow.data.requestId, response: key.response }, 'owner')).status, 400);
  await s.restart();
  assert.equal((await s.login(key, { counter: 2 })).result.status, 200);
  assert.equal((await s.login(key, { counter: 2 })).result.status, 401);
  const list = await s.request('/credentials', undefined, 'owner');
  assert.equal(list.data.credentials.length, 1);
  assert.equal(list.data.credentials[0].publicKey, undefined);
  assert.equal(JSON.parse(fs.readFileSync(s.file)).users[0].credentials[0].counter, 2);
});

test('tampered assertions, wrong RP/origin/challenge/handle and missing verification cannot mint sessions', async t => {
  const s = await setup(t);
  const enrolled = await s.enroll();
  for (const overrides of [
    { tamper: true }, { origin: 'https://attacker.example' }, { rpID: 'attacker.example' },
    { challenge: 'wrong' }, { uv: false }, { crossOrigin: true }, { type: 'webauthn.create' },
  ]) {
    const attempt = await s.login(enrolled, overrides);
    assert.equal(attempt.result.status, 401, JSON.stringify(overrides));
    assert.equal((await s.request('/login/verify', attempt.body, null, attempt.flow.cookie)).status, 400);
  }
  assert.equal((await s.login({ ...enrolled, userHandle: 'wrong' })).result.status, 401);
  assert.equal((await s.login({ ...enrolled, key: authenticator() })).result.status, 401);
  assert.equal(s.minted.length, 0);
});

test('registration rejects wrong origin/challenge, unverified user and cross-origin embedding', async t => {
  const s = await setup(t);
  for (const overrides of [{ origin: 'https://attacker.example' }, { challenge: 'wrong' }, { uv: false }, { crossOrigin: true }]) {
    const flow = await s.request('/register/options', { username: 'alice' }, 'owner');
    const response = authenticator().register(flow.data.options, overrides);
    const result = await s.request('/register/verify', { requestId: flow.data.requestId, response }, 'owner');
    assert.equal(result.status, 400);
  }
  assert.equal(fs.existsSync(s.file), false);
});

test('challenges expire and bind to the initiating browser or enrollment session', async t => {
  const s = await setup(t);
  const enrolled = await s.enroll();
  const flow = await s.request('/login/options', {});
  const body = { requestId: flow.data.requestId, response: enrolled.key.login(flow.data.options, enrolled.userHandle) };
  assert.equal((await s.request('/login/verify', body, null, 'webmux_passkey=wrong')).status, 400);
  const expired = await s.request('/login/options', {});
  s.advance(300001);
  assert.equal((await s.request('/login/verify', { requestId: expired.data.requestId, response: enrolled.key.login(expired.data.options, enrolled.userHandle) }, null, expired.cookie)).status, 400);
  s.sessions.get('owner').mintedAt += 300001;
  s.sessions.set('another-admin', { rid: 'different', provider: 'secret', admin: true, mintedAt: s.sessions.get('owner').mintedAt });
  const reg = await s.request('/register/options', { username: 'bob' }, 'owner');
  assert.equal((await s.request('/register/verify', { requestId: reg.data.requestId, response: authenticator().register(reg.data.options) }, 'another-admin')).status, 400);
});

test('native users manage only their own keys, cannot elevate roles, and removal revokes sessions', async t => {
  const s = await setup(t);
  const alice = await s.enroll('alice', false);
  const bob = await s.enroll('bob', true);
  const { result: signedIn } = await s.login(alice);
  const token = signedIn.data.token;
  assert.equal((await s.request('/credentials', undefined, token)).data.credentials.length, 1);
  assert.equal((await s.request('/register/options', { username: 'bob' }, token)).status, 403);
  assert.equal((await s.request('/register/options', { username: 'new-user' }, token)).status, 403);
  assert.equal((await s.request('/credentials/delete', { id: bob.key.id }, token)).status, 404);
  const second = await s.enroll('alice', true, token);
  assert.equal((await s.login(second)).result.status, 200);
  assert.equal(s.minted.at(-1).admin, false);
  assert.equal((await s.request('/credentials/delete', { id: alice.key.id }, 'owner')).status, 200);
  assert.deepEqual(s.revoked, [alice.key.id]);
  assert.equal((await s.request('/credentials', undefined, token)).status, 401);
  assert.equal((await s.login(alice, { counter: 2 })).result.status, 401);
});

test('corrupt storage fails closed instead of erasing accounts', async t => {
  const s = await setup(t);
  await s.enroll();
  fs.writeFileSync(s.file, 'not-json');
  await assert.rejects(s.restart(), /Cannot read passkey store/);
  assert.equal(fs.readFileSync(s.file, 'utf8'), 'not-json');
});

test('invalid persisted account and credential shapes fail startup without altering the store', async t => {
  const s = await setup(t);
  await s.enroll();
  const valid = JSON.parse(fs.readFileSync(s.file));
  const cases = [
    () => null,
    db => { db.users[0] = null; },
    db => { db.users[0].id = 123; },
    db => { db.users[0].id = 'a'; },
    db => { db.users[0].username = ['alice']; },
    db => { db.users[0].admin = 'false'; },
    db => { db.users.push(structuredClone(db.users[0])); },
    db => { db.users[0].credentials.push(structuredClone(db.users[0].credentials[0])); },
    db => { db.users[0].credentials[0].publicKey = 'AAAA'; },
    db => { db.users[0].credentials[0].counter = 2 ** 32; },
    db => { db.users[0].credentials[0].transports = 'internal'; },
    db => { db.users[0].credentials[0].label = { text: 'Laptop' }; },
    db => { db.users[0].credentials[0].lastUsedAt = 'yesterday'; },
  ];
  for (const change of cases) {
    const db = structuredClone(valid);
    const result = change(db);
    const data = JSON.stringify(result === null ? null : db);
    fs.writeFileSync(s.file, data);
    await assert.rejects(s.restart(), /Invalid passkey/);
    assert.equal(fs.readFileSync(s.file, 'utf8'), data);
  }
});

test('untrusted transport metadata cannot poison persisted credentials or future enrollment', async t => {
  const s = await setup(t);
  const key = authenticator();
  const flow = await s.request('/register/options', { username: 'alice' }, 'owner');
  const response = key.register(flow.data.options);
  response.response.transports = { internal: true };
  assert.equal((await s.request('/register/verify', { requestId: flow.data.requestId, response }, 'owner')).status, 400);
  assert.equal(fs.existsSync(s.file), false);
  await s.enroll('alice', false, 'owner', key);
  await s.restart();
  assert.equal((await s.request('/register/options', { username: 'alice' }, 'owner')).status, 200);
});

test('RSA passkeys and authenticators without signature counters survive strict storage validation', async t => {
  const s = await setup(t);
  const enrolled = await s.enroll('rsa-user', false, 'owner', authenticator('RS256'));
  assert.equal((await s.login(enrolled, { counter: 0 })).result.status, 200);
  await s.restart();
  assert.equal((await s.login(enrolled, { counter: 0 })).result.status, 200);
  assert.equal(s.minted.length, 2);
});

// Pause real WebCrypto work to place revocation or another assertion inside its
// await boundary. Signatures and verifier results are never stubbed.
function pauseCrypto(t, count = 1) {
  let entered = 0, ready, release;
  const started = new Promise(resolve => { ready = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  const subtle = crypto.webcrypto.subtle;
  const digest = subtle.digest;
  t.mock.method(subtle, 'digest', async function (...args) {
    if (entered < count) {
      if (++entered === count) ready();
      await gate;
    }
    return digest.apply(this, args);
  });
  t.after(release);
  return { started, release };
}

test('an enrollment awaiting crypto cannot commit after its authorizing login is revoked', { timeout: 5000 }, async t => {
  const s = await setup(t);
  const flow = await s.request('/register/options', { username: 'alice' }, 'owner');
  const response = authenticator().register(flow.data.options);
  const gate = pauseCrypto(t);
  const verifying = s.request('/register/verify', { requestId: flow.data.requestId, response }, 'owner');
  await gate.started;
  s.sessions.delete('owner');
  gate.release();
  assert.equal((await verifying).status, 401);
  assert.equal(fs.existsSync(s.file), false);
});

test('simultaneous signed assertions cannot roll back or reuse a nonzero authenticator counter', { timeout: 5000 }, async t => {
  const s = await setup(t);
  const enrolled = await s.enroll();
  const flows = await Promise.all([s.request('/login/options', {}), s.request('/login/options', {})]);
  const gate = pauseCrypto(t, 2);
  const verifying = flows.map(flow => s.request('/login/verify', {
    requestId: flow.data.requestId, response: enrolled.key.login(flow.data.options, enrolled.userHandle),
  }, null, flow.cookie));
  await gate.started;
  gate.release();
  assert.deepEqual((await Promise.all(verifying)).map(r => r.status).sort(), [200, 401]);
  assert.equal(s.minted.length, 1);
  assert.equal(JSON.parse(fs.readFileSync(s.file)).users[0].credentials[0].counter, 1);
});

test('deleting a key while its login is awaiting crypto prevents a session from being minted', { timeout: 5000 }, async t => {
  const s = await setup(t);
  const enrolled = await s.enroll();
  const flow = await s.request('/login/options', {});
  const response = enrolled.key.login(flow.data.options, enrolled.userHandle);
  const gate = pauseCrypto(t);
  const verifying = s.request('/login/verify', { requestId: flow.data.requestId, response }, null, flow.cookie);
  await gate.started;
  assert.equal((await s.request('/credentials/delete', { id: enrolled.key.id }, 'owner')).status, 200);
  gate.release();
  assert.equal((await verifying).status, 401);
  assert.equal(s.minted.length, 0);
});

test('failed atomic storage replacement does not mint a session or advance the in-memory counter', async t => {
  const s = await setup(t);
  const enrolled = await s.enroll();
  const before = fs.readFileSync(s.file, 'utf8');
  const rename = fs.renameSync;
  const mock = t.mock.method(fs, 'renameSync', function (from, to) {
    if (to === s.file) throw new Error('simulated storage failure');
    return rename(from, to);
  });
  assert.equal((await s.login(enrolled)).result.status, 500);
  assert.equal(s.minted.length, 0);
  assert.equal(fs.readFileSync(s.file, 'utf8'), before);
  assert.deepEqual(fs.readdirSync(path.dirname(s.file)), [path.basename(s.file)]);
  mock.mock.restore();
  assert.equal((await s.login(enrolled)).result.status, 200);
});
