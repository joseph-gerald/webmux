'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const { decodeCredentialPublicKey } = require('@simplewebauthn/server/helpers');

const TTL = 5 * 60 * 1000;
const MAX_PENDING = 512;
const USERNAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const B64 = /^[A-Za-z0-9_-]+$/;
const COOKIE = 'webmux_passkey';
const TRANSPORTS = new Set(['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb']);

function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function base64(value, maxBytes) {
  return typeof value === 'string' && value.length <= Math.ceil(maxBytes * 4 / 3) &&
    B64.test(value) && Buffer.from(value, 'base64url').length <= maxBytes &&
    Buffer.from(value, 'base64url').toString('base64url') === value;
}
function transportsValid(value) {
  return value === undefined || (Array.isArray(value) && value.length <= TRANSPORTS.size &&
    value.every(t => typeof t === 'string' && TRANSPORTS.has(t)));
}
function publicKeyValid(value) {
  if (!base64(value, 4096)) return false;
  try {
    const key = decodeCredentialPublicKey(Buffer.from(value, 'base64url'));
    const bytes = n => {
      const v = key.get(n);
      if (!(v instanceof Uint8Array) || !v.length) throw new Error('Invalid key parameter');
      return Buffer.from(v).toString('base64url');
    };
    let jwk;
    if (key.get(1) === 2 && key.get(3) === -7 && key.get(-1) === 1) {
      jwk = { kty: 'EC', crv: 'P-256', x: bytes(-2), y: bytes(-3) };
    } else if (key.get(1) === 3 && key.get(3) === -257) {
      jwk = { kty: 'RSA', n: bytes(-1), e: bytes(-2) };
    } else return false;
    crypto.createPublicKey({ key: jwk, format: 'jwk' });
    return true;
  } catch { return false; }
}

function fail(status, message) {
  const error = new Error(message);
  error.status = status;
  throw error;
}

function relyingParty(publicUrl) {
  if (!publicUrl) return null;
  const url = new URL(publicUrl);
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/' ||
      (url.protocol !== 'https:' && !(url.protocol === 'http:' && url.hostname === 'localhost'))) {
    throw new Error('WEBMUX_PUBLIC_URL must be an HTTPS origin (or http://localhost for development)');
  }
  return { origin: url.origin, rpID: url.hostname, secure: url.protocol === 'https:' };
}

// Single-process store, matching webmux's in-memory session model. Disk is
// replaced atomically before updating memory; a bad file is never reset silently.
function readStore(file, rpID) {
  let db;
  try { db = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) {
    if (e.code === 'ENOENT') return { version: 1, rpID, users: [] };
    throw new Error('Cannot read passkey store: ' + e.message);
  }
  if (!object(db) || db.version !== 1 || db.rpID !== rpID || !Array.isArray(db.users) || db.users.length > 128) {
    throw new Error('Invalid passkey store or RP ID changed');
  }
  const ids = new Set(), names = new Set(), keys = new Set();
  for (const user of db.users) {
    if (!object(user) || !base64(user.id, 64) || typeof user.username !== 'string' || !USERNAME.test(user.username) ||
        typeof user.admin !== 'boolean' || !Array.isArray(user.credentials) ||
        !user.credentials.length || user.credentials.length > 10 ||
        ids.has(user.id) || names.has(user.username)) throw new Error('Invalid passkey user');
    ids.add(user.id); names.add(user.username);
    for (const key of user.credentials) {
      if (!object(key) || !base64(key.id, 1023) || !publicKeyValid(key.publicKey) ||
          !Number.isSafeInteger(key.counter) || key.counter < 0 || key.counter > 0xffffffff || keys.has(key.id) ||
          !transportsValid(key.transports) || typeof key.label !== 'string' || key.label.length > 64 ||
          !Number.isSafeInteger(key.createdAt) || key.createdAt < 0 ||
          !(key.lastUsedAt === null || (Number.isSafeInteger(key.lastUsedAt) && key.lastUsedAt >= 0)) ||
          !['singleDevice', 'multiDevice'].includes(key.deviceType) || typeof key.backedUp !== 'boolean') {
        throw new Error('Invalid passkey credential');
      }
      keys.add(key.id);
    }
  }
  return db;
}

function createPasskeyAuth(core) {
  const router = express.Router();
  const rp = relyingParty(core.publicUrl);
  const now = core.now || Date.now;
  const rpName = core.rpName || 'webmux';
  router.use((_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  router.get('/config', (_req, res) => res.json({ enabled: !!rp, rpID: rp?.rpID, rpName }));
  if (!rp) {
    router.use((_req, res) => res.status(503).json({ error: 'Set WEBMUX_PUBLIC_URL to enable passkeys' }));
    return router;
  }
  let db = readStore(core.file, rp.rpID);
  const pending = new Map();
  const limits = new Map();
  const cookieOptions = { httpOnly: true, secure: rp.secure, sameSite: 'strict', path: '/api/auth/passkeys' };

  function commit(next) {
    fs.mkdirSync(path.dirname(core.file), { recursive: true, mode: 0o700 });
    const tmp = core.file + '.' + crypto.randomBytes(8).toString('hex') + '.tmp';
    try {
      const fd = fs.openSync(tmp, 'wx', 0o600);
      try { fs.writeFileSync(fd, JSON.stringify(next) + '\n'); fs.fsyncSync(fd); }
      finally { fs.closeSync(fd); }
      fs.renameSync(tmp, core.file);
      db = next;
    } finally {
      try { fs.unlinkSync(tmp); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    }
  }

  function begin(flow) {
    for (const [id, p] of pending) if (p.expires <= now()) pending.delete(id);
    if (pending.size >= MAX_PENDING) fail(429, 'Too many pending requests; try again shortly');
    const id = crypto.randomBytes(24).toString('base64url');
    pending.set(id, { ...flow, expires: now() + TTL });
    return id;
  }

  function consume(id, type, binding) {
    const p = pending.get(id);
    pending.delete(id); // invalid attempts consume their challenge too
    if (!p || p.type !== type || p.expires <= now() || !binding || p.binding !== binding) {
      fail(400, 'Passkey request expired or already used; try again');
    }
    return p;
  }

  function route(handler) {
    return async (req, res) => {
      try { await handler(req, res); }
      catch (e) {
        core.audit('passkey_error', req, { reason: e.status ? e.message : 'storage_or_server_error' });
        if (!e.status) console.error('[passkeys]', e.message);
        res.status(e.status || 500).json({ error: e.status ? e.message : 'Passkey service unavailable' });
      }
    };
  }

  // Fetch's Origin, not Host/forwarded headers, authorizes browser mutations.
  router.use((req, res, next) => {
    if (req.method !== 'GET' && (req.headers.origin !== rp.origin || !req.is('application/json'))) {
      return res.status(403).json({ error: 'Same-origin JSON request required' });
    }
    next();
  });

  function rateLimit(req, res, next) {
    const time = now(), ip = core.clientIp(req);
    for (const [key, value] of limits) if (value.expires <= time) limits.delete(key);
    let limit = limits.get(ip);
    if (!limit) {
      if (limits.size >= 4096) return res.status(429).json({ error: 'Try again shortly' });
      limit = { count: 0, expires: time + TTL };
      limits.set(ip, limit);
    }
    if (++limit.count > 60) {
      res.set('Retry-After', String(Math.ceil((limit.expires - time) / 1000)));
      return res.status(429).json({ error: 'Too many passkey requests; try again shortly' });
    }
    next();
  }

  function recent(req, res, next) {
    if (now() - req.auth.mintedAt > TTL) {
      return res.status(403).json({ error: 'Sign in again before changing passkeys (5 minute limit)' });
    }
    next();
  }
  // External provider admins administer terminal sessions, not native identities.
  function enrollmentAdmin(req) {
    return (req.auth.provider === 'secret' || req.auth.provider === 'passkey') && core.isAdmin(req.auth);
  }
  function own(req, user) { return req.auth.provider === 'passkey' && req.auth.accountId === user.id; }
  function mayManage(req, user) { return enrollmentAdmin(req) || own(req, user); }
  function findKey(id) {
    for (const user of db.users) {
      const key = user.credentials.find(k => k.id === id);
      if (key) return { user, key };
    }
    return null;
  }
  function sameOriginResponse(response) {
    // This app does not support cross-origin embedded authentication.
    try {
      const data = JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64url').toString());
      return !data.crossOrigin && !data.topOrigin;
    } catch { return false; }
  }

  router.get('/credentials', core.requireToken, (req, res) => {
    const users = db.users.filter(u => mayManage(req, u));
    res.json({
      canCreateUsers: enrollmentAdmin(req),
      username: db.users.find(u => own(req, u))?.username || '',
      credentials: users.flatMap(u => u.credentials.map(k => ({
        id: k.id, username: u.username, admin: u.admin, label: k.label,
        createdAt: k.createdAt, lastUsedAt: k.lastUsedAt,
        current: req.auth.credentialId === k.id,
      }))),
    });
  });

  router.post('/register/options', core.requireToken, recent, rateLimit, route(async (req, res) => {
    const username = typeof req.body?.username === 'string' ? req.body.username.trim().toLowerCase() : '';
    if (!USERNAME.test(username)) fail(400, 'Username must be 1–64 letters, numbers, dots, underscores or hyphens');
    const user = db.users.find(u => u.username === username);
    if (user ? !mayManage(req, user) : !enrollmentAdmin(req)) fail(403, 'An administrator must create this account');
    if ((user?.credentials.length || 0) >= 10 || (!user && db.users.length >= 128)) fail(409, 'Passkey account limit reached');
    const userID = user?.id || crypto.randomBytes(32).toString('base64url');
    const options = await generateRegistrationOptions({
      rpName, rpID: rp.rpID, userName: username, userID: Buffer.from(userID, 'base64url'),
      attestationType: 'none', supportedAlgorithmIDs: [-7, -257], timeout: 60000,
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      excludeCredentials: (user?.credentials || []).map(k => ({ id: k.id, transports: k.transports })),
    });
    const requestId = begin({
      type: 'register', binding: req.auth.rid, challenge: options.challenge,
      userID, username, existing: !!user, admin: user ? user.admin : req.body.admin === true,
      label: typeof req.body.label === 'string' ? req.body.label.trim().slice(0, 64) || 'Passkey' : 'Passkey',
    });
    res.json({ requestId, options });
  }));

  router.post('/register/verify', core.requireToken, recent, rateLimit, route(async (req, res) => {
    const flow = consume(req.body?.requestId, 'register', req.auth.rid);
    const response = req.body?.response;
    let result;
    try {
      if (!sameOriginResponse(response)) throw new Error('cross-origin');
      result = await verifyRegistrationResponse({
        response, expectedChallenge: flow.challenge, expectedOrigin: rp.origin, expectedRPID: rp.rpID,
        requireUserVerification: true, supportedAlgorithmIDs: [-7, -257],
      });
    } catch { fail(400, 'Passkey registration verification failed'); }
    if (!result.verified) fail(400, 'Passkey registration verification failed');
    // Authorization may have been revoked while WebAuthn's crypto was awaiting.
    if (!core.ticketActive(req.auth)) fail(401, 'Sign in again before changing passkeys');
    if (flow.expires <= now() || now() - req.auth.mintedAt > TTL) fail(403, 'Sign in again before changing passkeys');
    const { credential, credentialDeviceType, credentialBackedUp } = result.registrationInfo;
    const publicKey = Buffer.from(credential.publicKey).toString('base64url');
    if (!base64(credential.id, 1023) || !publicKeyValid(publicKey) || !transportsValid(credential.transports)) {
      fail(400, 'Invalid passkey credential');
    }
    if (findKey(credential.id)) fail(409, 'Passkey already registered');
    const next = structuredClone(db);
    let user = next.users.find(u => u.username === flow.username);
    if (flow.existing ? (!user || user.id !== flow.userID || !mayManage(req, user)) : (user || !enrollmentAdmin(req))) {
      fail(409, 'Account changed; start registration again');
    }
    if (!user) {
      if (next.users.length >= 128) fail(409, 'Account limit reached');
      user = { id: flow.userID, username: flow.username, admin: flow.admin, credentials: [] };
      next.users.push(user);
    }
    if (user.credentials.length >= 10) fail(409, 'Passkey limit reached');
    user.credentials.push({
      id: credential.id, publicKey,
      counter: credential.counter, transports: credential.transports,
      deviceType: credentialDeviceType, backedUp: credentialBackedUp,
      label: flow.label, createdAt: now(), lastUsedAt: null,
    });
    commit(next);
    core.audit('passkey_registered', req, { user: user.username });
    res.json({ ok: true });
  }));

  router.post('/login/options', rateLimit, route(async (_req, res) => {
    const options = await generateAuthenticationOptions({ rpID: rp.rpID, userVerification: 'required', timeout: 60000 });
    const binding = crypto.randomBytes(32).toString('base64url');
    const requestId = begin({ type: 'login', binding, challenge: options.challenge });
    res.cookie(COOKIE, binding, { ...cookieOptions, maxAge: TTL });
    res.json({ requestId, options });
  }));

  router.post('/login/verify', rateLimit, route(async (req, res) => {
    const binding = String(req.headers.cookie || '').split(';').map(s => s.trim())
      .find(s => s.startsWith(COOKIE + '='))?.slice(COOKIE.length + 1);
    res.clearCookie(COOKIE, cookieOptions);
    const flow = consume(req.body?.requestId, 'login', binding);
    const response = req.body?.response;
    const found = findKey(response?.id);
    if (!found || response.response?.userHandle !== found.user.id) fail(401, 'Passkey login failed');
    const { user, key } = found;
    let result;
    try {
      if (!sameOriginResponse(response)) throw new Error('cross-origin');
      result = await verifyAuthenticationResponse({
        response, expectedChallenge: flow.challenge, expectedOrigin: rp.origin, expectedRPID: rp.rpID,
        requireUserVerification: true,
        credential: { id: key.id, publicKey: Buffer.from(key.publicKey, 'base64url'), counter: key.counter, transports: key.transports },
      });
    } catch { fail(401, 'Passkey login failed'); }
    if (!result.verified) fail(401, 'Passkey login failed');
    // Recheck after async crypto: deletion or another assertion may have won.
    const current = findKey(key.id);
    const count = result.authenticationInfo.newCounter;
    if (flow.expires <= now() || !current || current.user.id !== user.id || current.key.publicKey !== key.publicKey ||
        ((count > 0 || current.key.counter > 0) && count <= current.key.counter)) {
      fail(401, 'Passkey changed; sign in again');
    }
    const next = structuredClone(db);
    const saved = next.users.find(u => u.id === user.id).credentials.find(k => k.id === key.id);
    saved.counter = count;
    saved.lastUsedAt = now();
    saved.backedUp = result.authenticationInfo.credentialBackedUp;
    commit(next);
    const token = core.mintToken({
      user: current.user.username, provider: 'passkey', accountId: current.user.id,
      admin: current.user.admin, credentialId: key.id, ip: core.clientIp(req),
      ua: String(req.headers['user-agent'] || '').slice(0, 200),
    });
    if (!token) fail(403, 'Account denied');
    core.writeTicket(res, token);
    core.audit('auth_ok', req, { user: user.username, authMethod: 'passkey' });
    res.json({ token });
  }));

  router.post('/credentials/delete', core.requireToken, recent, route(async (req, res) => {
    const found = findKey(req.body?.id);
    if (!found || !mayManage(req, found.user)) fail(404, 'Passkey not found');
    const next = structuredClone(db);
    const user = next.users.find(u => u.id === found.user.id);
    user.credentials = user.credentials.filter(k => k.id !== found.key.id);
    next.users = next.users.filter(u => u.credentials.length);
    commit(next);
    core.revokeCredential(found.key.id);
    core.audit('passkey_deleted', req, { user: user.username });
    res.json({ ok: true, signedOut: req.auth.credentialId === found.key.id });
  }));

  return router;
}

module.exports = { createPasskeyAuth, relyingParty };
