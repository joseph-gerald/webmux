'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const { spawn, execFileSync } = require('child_process');
const { once } = require('events');
const { WebSocket } = require('ws');

test('browser enrolls resident passkeys, isolates native roles, and revokes deleted-key sessions', {
  skip: !process.env.WEBMUX_TEST_CHROME, timeout: 60000,
}, async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'webmux-browser-test-'));
  const socket = 'webmux-test-' + process.pid + '-' + Date.now();
  const probe = net.createServer();
  await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  const origin = 'http://localhost:' + port;
  let child, browser, logs = '';
  t.after(async () => {
    if (browser) await browser.close();
    if (child && child.exitCode === null) {
      child.kill();
      await new Promise(resolve => child.once('exit', resolve));
    }
    try { execFileSync('tmux', ['-L', socket, 'kill-server'], { stdio: 'ignore' }); } catch {}
    fs.rmSync(dir, { recursive: true, force: true });
  });
  // Deliberately omit inherited provider secrets, deployment paths and webhooks.
  child = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: {
      PATH: process.env.PATH, HOME: dir, SHELL: '/bin/sh', TERM: 'xterm-256color',
      PORT: String(port), WEBMUX_PUBLIC_URL: origin, WEBMUX_TMUX_SOCKET: socket,
      WEBMUX_SECRET_FILE: path.join(dir, '.secret'), WEBMUX_STATE: path.join(dir, 'state.json'),
      WEBMUX_LOG_DIR: path.join(dir, 'logs'), WEBMUX_SEEN_IPS: path.join(dir, 'seen'),
      WEBMUX_UPLOADS: path.join(dir, 'uploads'), WEBMUX_AUTH_DIR: path.join(dir, 'no-providers'),
    }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  await new Promise((resolve, reject) => {
    child.stdout.on('data', b => { logs += b; if (logs.includes('webmux running on')) resolve(); });
    child.stderr.on('data', b => { logs += b; });
    child.once('exit', code => reject(new Error('Server exited ' + code + '\n' + logs)));
  });
  const invalidSocket = new WebSocket(origin.replace('http:', 'ws:') + '/ws?bad=%', ['webmux']);
  const [closeCode] = await once(invalidSocket, 'close');
  assert.equal(closeCode, 4001, 'malformed unauthenticated query must not crash the server');
  const { default: puppeteer } = await import('puppeteer-core');
  browser = await puppeteer.launch({
    executablePath: process.env.WEBMUX_TEST_CHROME, headless: true, protocolTimeout: 10000,
    args: ['--no-sandbox', '--disk-cache-size=1048576'],
  });
  const page = await browser.newPage();
  // Avoid disk-cache exhaustion in constrained temporary test profiles.
  await page.setCacheEnabled(false);
  page.setDefaultTimeout(10000);
  await page.evaluateOnNewDocument(() => localStorage.setItem('webmux-bio', 'retired-cache-test'));
  const pageErrors = [];
  page.on('pageerror', e => pageErrors.push(e.message));
  async function waitForLogin() {
    await page.waitForSelector('#passkey-login', { visible: true });
  }
  let signedInToken;
  page.on('response', async res => {
    if (res.url().endsWith('/api/auth/passkeys/login/verify') && res.ok()) {
      signedInToken = (await res.json()).token;
    }
  });
  const cdp = await page.createCDPSession();
  await cdp.send('WebAuthn.enable');
  let { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
  } });
  await page.goto(origin);
  await waitForLogin();
  assert.deepEqual(await (await fetch(origin + '/api/auth/providers')).json(), []);
  await page.click('#use-secret');
  await page.type('#secret', fs.readFileSync(path.join(dir, '.secret'), 'utf8'));
  await page.keyboard.press('Enter');
  await page.waitForSelector('#app', { visible: true });
  await page.click('#app [data-passkeys]');
  await page.waitForSelector('#passkey-dialog form:not([hidden])');
  await page.type('#passkey-dialog [name=username]', 'owner');
  await page.click('#passkey-dialog [type=submit]');
  await page.waitForFunction(() => document.querySelector('.passkey-message').textContent.includes('Passkey saved'));
  const store = path.join(dir, '.webmux-passkeys.json');
  assert.equal(JSON.parse(fs.readFileSync(store)).users[0].username, 'owner');
  assert.equal(await page.evaluate(() => localStorage.getItem('webmux-bio')), null);
  await page.waitForSelector('#passkey-dialog fieldset:not([disabled])');
  await page.$eval('[name=username]', e => { e.value = '-invalid'; });
  assert.equal(await page.$eval('#passkey-dialog form', e => e.checkValidity()), false, 'account-name pattern must actually validate');
  await page.$eval('[name=username]', e => { e.value = 'member'; });
  await page.click('[name=admin]');
  await page.$eval('[name=label]', e => { e.value = 'Member key'; });
  // Cancelling a real pending WebAuthn ceremony must not leave enrollment busy
  // or allow its response to overwrite a reopened panel.
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: false });
  const offered = page.waitForResponse(r => r.url().endsWith('/register/options'));
  await page.click('#passkey-dialog [type=submit]');
  await offered;
  await page.click('.passkey-close');
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: true });
  await page.click('#app [data-passkeys]');
  await page.waitForSelector('#passkey-dialog form:not([hidden]) fieldset:not([disabled])');
  await page.$eval('[name=username]', e => { e.value = 'member'; });
  await page.click('[name=admin]');
  await page.click('#passkey-dialog [type=submit]');
  await page.waitForFunction(() => document.querySelectorAll('.passkey-row').length === 2);
  assert.equal(JSON.parse(fs.readFileSync(store)).users.find(u => u.username === 'member').admin, false);
  // Keep the resident-key chooser deterministic without logging key material.
  const memberId = JSON.parse(fs.readFileSync(store)).users.find(u => u.username === 'member').credentials[0].id;
  const virtualKeys = (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials;
  const memberKey = virtualKeys.find(k => Buffer.from(k.credentialId, 'base64').toString('base64url') === memberId);
  assert.ok(memberKey);
  await cdp.send('WebAuthn.removeCredential', { authenticatorId, credentialId: memberKey.credentialId });
  assert.equal(await page.evaluate(() => localStorage.getItem('webmux-auth-method')), 'passkey');
  await page.reload();
  assert.deepEqual(pageErrors, []);
  await waitForLogin();
  await page.click('#passkey-login');
  await page.waitForSelector('#app', { visible: true });
  assert.ok(signedInToken);
  assert.ok(JSON.parse(fs.readFileSync(store)).users[0].credentials[0].lastUsedAt);
  await page.setViewport({ width: 390, height: 844 });
  await page.click('#app [data-passkeys]');
  await page.waitForSelector('.passkey-row button');
  const currentRow = await page.$('.passkey-row');
  assert.match(await currentRow.evaluate(e => e.textContent), /owner.*admin.*current/);
  assert.equal(await page.$eval('#passkey-dialog', e => e.scrollWidth <= e.clientWidth), true);
  page.once('dialog', d => d.accept());
  await Promise.all([page.waitForNavigation(), currentRow.$eval('button', e => e.click())]);
  await waitForLogin();
  assert.equal(JSON.parse(fs.readFileSync(store)).users.length, 1);
  const revoked = await fetch(origin + '/api/me', { headers: { 'x-token': signedInToken } });
  assert.equal(revoked.status, 401);
  for (const key of virtualKeys.filter(k => k !== memberKey)) {
    await cdp.send('WebAuthn.removeCredential', { authenticatorId, credentialId: key.credentialId });
  }
  await cdp.send('WebAuthn.addCredential', { authenticatorId, credential: memberKey });
  await page.click('#passkey-login');
  await page.waitForSelector('#app', { visible: true });
  await page.click('#app [data-passkeys]');
  await page.waitForSelector('#passkey-dialog form:not([hidden])');
  assert.equal(await page.$eval('[name=username]', e => e.readOnly && e.value === 'member'), true);
  assert.equal(await page.$eval('.passkey-role', e => e.hidden), true);
  assert.equal(await page.$$eval('.passkey-row', rows => rows.length), 1);
  // A second physical authenticator can add a key to its own non-admin account.
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
  ({ authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
  } }));
  await page.$eval('[name=label]', e => { e.value = 'Second key'; });
  await page.click('#passkey-dialog [type=submit]');
  await page.waitForFunction(() => document.querySelectorAll('.passkey-row').length === 2);
  page.once('dialog', d => d.accept());
  await page.$$eval('.passkey-row', rows => rows.find(r => r.textContent.includes('Second key')).querySelector('button').click());
  await page.waitForFunction(() => document.querySelectorAll('.passkey-row').length === 1);
  assert.equal(await page.$eval('#app', e => e.hidden), false, 'removing a different key retains the current session');
  page.once('dialog', d => d.accept());
  await Promise.all([page.waitForNavigation(), page.click('.passkey-row button')]);
  await waitForLogin();
  assert.equal(JSON.parse(fs.readFileSync(store)).users.length, 0);
  assert.equal((await fetch(origin + '/api/me', { headers: { 'x-token': signedInToken } })).status, 401);
  assert.deepEqual(pageErrors, []);
});
