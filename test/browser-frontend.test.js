'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const http = require('node:http');
const express = require('express');
const { WebSocketServer } = require('ws');

// Real browser and xterm, with an in-process fake API/PTY: no tmux, credentials,
// deployment environment, or live app are used by these client regressions.
test('frontend browser regressions', {
  skip: !process.env.WEBMUX_TEST_CHROME, timeout: 90000,
}, async t => {
  const { default: puppeteer } = await import('puppeteer-core');
  const browser = await puppeteer.launch({
    executablePath: process.env.WEBMUX_TEST_CHROME, headless: true, protocolTimeout: 10000,
    args: ['--no-sandbox', '--disk-cache-size=1048576'],
  });
  t.after(() => browser.close());

  async function harness(t, { prefs = {}, deniedStorage = false, mobile = false } = {}) {
    const root = path.join(__dirname, '..');
    const state = { routes: new Map(), selected: [], authRequests: 0, providers: [], credentials: {
      canCreateUsers: true, username: '', credentials: [],
    } };
    const app = express();
    app.use(express.json());
    app.use((req, res, next) => {
      res.set('Cache-Control', 'no-store');
      const route = state.routes.get(req.method + ' ' + req.path);
      if (route) return route(req, res);
      next();
    });
    app.post('/api/auth/exchange', (_req, res) => res.status(401).json({ error: 'no handoff' }));
    app.get('/api/auth/providers', (_req, res) => res.json(state.providers));
    app.get('/api/auth/passkeys/config', (_req, res) => res.json({ enabled: true, rpID: 'localhost' }));
    app.get('/api/auth/passkeys/credentials', (_req, res) => res.json(state.credentials));
    app.post('/api/auth/logout', (_req, res) => res.json({ ok: true }));
    app.post('/auth', (_req, res) => { state.authRequests++; res.json({ token: 'browser-test-ticket' }); });
    app.get('/api/me', (_req, res) => res.json({ admin: true, fingerprints: false }));
    app.get('/api/sessions', (_req, res) => res.json({ sessions: [
      { name: 'alpha', windows: 2, attached: true }, { name: 'beta', windows: 2, attached: false },
    ] }));
    app.get('/api/windows', (_req, res) => res.json({ windows: [
      { index: 0, name: 'shell', active: true, panes: 1 },
      { index: 1, name: 'editor', active: false, panes: 1 },
    ] }));
    app.post('/api/select', (req, res) => { state.selected.push(req.body); res.json({ ok: true }); });
    for (const name of ['xterm', 'addon-fit', 'addon-web-links', 'addon-webgl', 'addon-unicode11', 'addon-image']) {
      app.use('/vendor/' + name, express.static(path.join(root, 'node_modules/@xterm', name)));
    }
    app.get('/vendor/webauthn.js', (_req, res) => res.sendFile(path.join(root,
      'node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js')));
    app.use(express.static(path.join(root, 'public')));
    const server = http.createServer(app);
    const wss = new WebSocketServer({ server });
    wss.on('connection', socket => socket.on('message', raw => {
      const msg = JSON.parse(raw);
      if (msg.t === 'switch') socket.send('\x1e' + JSON.stringify({ t: 'switched', session: msg.session }));
    }));
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const origin = 'http://localhost:' + server.address().port;
    let context;
    const errors = [];
    t.after(async () => {
      if (context) await context.close();
      for (const socket of wss.clients) socket.terminate();
      await new Promise(resolve => wss.close(resolve));
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
      assert.deepEqual(errors, [], 'no uncaught browser errors');
    });
    context = await browser.createBrowserContext();
    const page = await context.newPage();
    await page.setCacheEnabled(false);
    page.setDefaultTimeout(8000);
    page.on('pageerror', error => errors.push(error.message));
    if (mobile) await page.setViewport({ width: 390, height: 600, isMobile: true, hasTouch: true });
    await page.evaluateOnNewDocument(({ prefs, deniedStorage }) => {
      for (const [key, value] of Object.entries(prefs)) localStorage.setItem(key, value);
      if (deniedStorage) {
        for (const name of ['localStorage', 'sessionStorage']) Object.defineProperty(window, name, {
          get() { throw new DOMException('Storage disabled for this test', 'SecurityError'); },
        });
      }
      window.testInput = [];
      window.testSockets = [];
      const NativeSocket = WebSocket;
      window.WebSocket = class extends NativeSocket {
        constructor(...args) { super(...args); window.testSockets.push(this); }
        send(raw) {
          const msg = JSON.parse(raw);
          if (msg.t === 'i') window.testInput.push(msg.d);
          // app.js sends its stream preference at the end of socket startup.
          // Record that UI state, rather than racing the transport's OPEN bit.
          if (msg.t === 'stream' && !this.testAppReady) {
            this.testOpenOverlayHidden = document.querySelector('#disconnected-overlay').hidden;
            this.testAppReady = true;
          }
          super.send(raw);
        }
      };
    }, { prefs, deniedStorage });
    async function goto() {
      await page.goto(origin);
      await page.waitForSelector('#passkey-login', { visible: true });
      await page.evaluate(() => {
        const NativeTerm = Terminal;
        window.Terminal = class extends NativeTerm {
          constructor(options) { super(options); window.testTerm = this; }
        };
      });
    }
    async function login() {
      if (await page.$eval('#secret-auth', e => e.hidden)) await page.click('#use-secret');
      await page.type('#secret', 'not-a-real-secret');
      await page.keyboard.press('Enter');
      await page.waitForFunction(() => window.testSockets.some(s => s.readyState === 1 && s.testAppReady));
      await page.waitForSelector('.xterm', { visible: true });
    }
    return { page, state, origin, goto, login, wss };
  }

  async function shortcut(page) {
    await page.keyboard.down('Control');
    await page.keyboard.down('Shift');
    await page.keyboard.press('KeyP');
    await page.keyboard.up('Shift');
    await page.keyboard.up('Control');
  }

  await t.test('bad saved JSON and map formats cannot break login; font and tab memory survive', async t => {
    const h = await harness(t, { prefs: {
      'webmux-pinned': '{bad JSON', 'webmux-tab-memory': '[["beta",1],null,["invalid","x"]]',
      'webmux-fontsize': '20', 'webmux-performance': 'normal',
      'webmux-perf-prefs': '{"cursorBlink":"false","webgl":false,"mirror":"off"}',
    } });
    await h.goto();
    await h.login();
    assert.equal(await h.page.evaluate(() => window.testTerm.options.fontSize), 20);
    assert.equal(await h.page.evaluate(() => window.testTerm.options.cursorBlink), true);
    await h.page.click('.sess[data-name=beta]');
    await h.page.waitForResponse(r => r.url().endsWith('/api/select'));
    assert.deepEqual(h.state.selected.at(-1), { index: 1, session: 'beta' });
  });

  await t.test('blocked browser storage still permits mobile login and helper controls', async t => {
    const h = await harness(t, { deniedStorage: true, mobile: true });
    await h.goto();
    await h.login();
    await h.page.click('.assist-fab');
    await h.page.waitForSelector('.assist.open');
    await h.page.click('[data-act=clipboard]');
    await h.page.type('#assist-clipboard-text', 'clipboard draft');
    assert.equal(await h.page.evaluate(() => window.testInput.join('').includes('clipboard draft')), false);
    await h.page.click('[data-act=clipboard-paste]');
    await h.page.waitForFunction(() => window.testInput.join('').includes('clipboard draft'));
  });

  await t.test('overlays isolate keys, keep focus through reconnect/OSC52, and close with Escape', async t => {
    const h = await harness(t);
    await h.goto();
    // The command shortcut is inactive on the password screen.
    await h.page.click('#use-secret');
    await shortcut(h.page);
    assert.equal(await h.page.$('.palette-input'), null);
    await h.login();
    await h.page.evaluate(() => {
      window.testPrematureDisconnectHides = [];
      const overlay = document.querySelector('#disconnected-overlay');
      new MutationObserver(() => {
        const socket = window.testSockets.at(-1);
        if (overlay.hidden && socket && socket.readyState !== WebSocket.OPEN) {
          window.testPrematureDisconnectHides.push(socket.readyState);
        }
      }).observe(overlay, { attributes: true, attributeFilter: ['hidden'] });
    });
    await h.page.click('#app [data-passkeys]');
    await h.page.waitForSelector('#passkey-dialog form:not([hidden])');
    await h.page.type('[name=username]', 'form-only');
    await shortcut(h.page);
    assert.equal(await h.page.$('.palette-input'), null);
    for (const socket of h.wss.clients) socket.send('\x1b]52;c;' + Buffer.from('clipboard update').toString('base64') + '\x07');
    for (const socket of h.wss.clients) socket.close(1012, 'test reconnect');
    await h.page.waitForSelector('#disconnected-overlay', { visible: true });
    await h.page.waitForFunction(() => window.testSockets.length > 1 &&
      window.testSockets.at(-1).readyState === 1 && window.testSockets.at(-1).testAppReady);
    assert.deepEqual(await h.page.evaluate(() => window.testPrematureDisconnectHides), [],
      'an earlier connection must not hide the overlay while the current socket is disconnected');
    assert.equal(await h.page.evaluate(() => window.testSockets.at(-1).testOpenOverlayHidden), true,
      'successful socket startup must immediately dismiss the blocking disconnected overlay');
    assert.equal(await h.page.evaluate(() => document.activeElement.name), 'username');
    await h.page.type('[name=username]', '-still-form');
    await h.page.keyboard.press('Escape');
    await h.page.waitForFunction(() => !document.querySelector('#passkey-dialog').open);
    for (let i = 0; i < 3; i++) {
      await h.page.click('#perf-settings');
      await h.page.waitForSelector('.perf-overlay[open]', { visible: true });
      await h.page.keyboard.type('settings-only');
      await h.page.keyboard.press('Tab');
      assert.equal(await h.page.evaluate(() => !!document.activeElement.closest('.perf-overlay')), true);
      await h.page.keyboard.press('Escape');
      await h.page.waitForSelector('.perf-overlay', { hidden: true });
    }
    await h.page.evaluate(() => window.testTerm.focus());
    await shortcut(h.page);
    await h.page.waitForSelector('.palette-input', { visible: true });
    await h.page.type('.palette-input', 'palette-only');
    await h.page.keyboard.press('Escape');
    await h.page.waitForSelector('.confirm-overlay', { hidden: true });
    assert.deepEqual(await h.page.evaluate(() => window.testInput), []);
    await h.page.evaluate(() => window.testTerm.focus());
    await h.page.keyboard.type('terminal-input');
    assert.equal(await h.page.evaluate(() => window.testInput.join('')), 'terminal-input');
  });

  await t.test('expired passkey changes offer reauthentication and 401 credentials return to login', async t => {
    const h = await harness(t);
    h.state.routes.set('POST /api/auth/passkeys/register/options', (_req, res) =>
      res.status(403).json({ error: 'Sign in again before changing passkeys (5 minute limit)' }));
    await h.goto();
    await h.login();
    await h.page.click('#app [data-passkeys]');
    await h.page.waitForSelector('#passkey-dialog form:not([hidden])');
    await h.page.type('[name=username]', 'owner');
    await h.page.click('#passkey-dialog [type=submit]');
    await h.page.waitForSelector('.passkey-reauth', { visible: true });
    assert.match(await h.page.$eval('.passkey-message', e => e.textContent), /Sign in again/);
    await h.page.click('.passkey-reauth');
    await h.page.waitForSelector('#passkey-login', { visible: true });
    await h.login();
    h.state.routes.set('GET /api/auth/passkeys/credentials', (_req, res) => res.status(401).json({ error: 'expired' }));
    await h.page.click('#app [data-passkeys]');
    await h.page.waitForSelector('#passkey-login', { visible: true });
    assert.equal(await h.page.$eval('#passkey-dialog', e => e.open), false);
  });

  await t.test('native and external roles render usable forms; failed and late requests stay contained', async t => {
    const h = await harness(t, { mobile: true });
    h.state.credentials = { canCreateUsers: false, username: '', credentials: [] };
    h.state.routes.set('POST /api/auth/passkeys/login/options', (_req, res) => res.json({ requestId: 'test', options: {} }));
    await h.goto();
    await h.page.evaluate(() => {
      SimpleWebAuthnBrowser.startAuthentication = async () => { throw new DOMException('Cancelled', 'NotAllowedError'); };
    });
    await h.page.click('#passkey-login');
    await h.page.waitForSelector('#passkey-login-error', { visible: true });
    assert.match(await h.page.$eval('#passkey-login-error', e => e.textContent), /cancelled or timed out/);
    assert.equal(await h.page.$eval('#passkey-login', e => e.disabled), false);
    await h.login();
    await h.page.click('#app [data-passkeys]');
    await h.page.waitForFunction(() => document.querySelector('.passkey-message').textContent.includes('External accounts are separate'));
    assert.equal(await h.page.$eval('#passkey-dialog form', e => e.hidden), true);
    await h.page.click('.passkey-close');
    h.state.credentials = { canCreateUsers: false, username: 'member', credentials: [] };
    await h.page.click('#app [data-passkeys]');
    await h.page.waitForSelector('#passkey-dialog form:not([hidden])');
    assert.equal(await h.page.$eval('[name=username]', e => e.readOnly && e.value === 'member'), true);
    assert.equal(await h.page.$eval('.passkey-role', e => e.hidden), true);
    await h.page.click('.passkey-close');
    h.state.routes.set('GET /api/auth/passkeys/credentials', (_req, res) => res.status(502).type('html').send('Unavailable'));
    await h.page.click('#app [data-passkeys]');
    await h.page.waitForFunction(() => document.querySelector('.passkey-message').textContent.includes('service unavailable'));
    assert.equal(await h.page.$eval('#passkey-dialog form', e => e.hidden), true);
    await h.page.click('.passkey-close');
    let respond;
    h.state.routes.set('GET /api/auth/passkeys/credentials', (_req, res) => { respond = () => res.json({ canCreateUsers: false, username: 'stale', credentials: [] }); });
    const requested = h.page.waitForRequest(r => r.url().endsWith('/credentials'));
    await h.page.click('#app [data-passkeys]');
    await requested;
    await h.page.click('.passkey-close');
    h.state.routes.delete('GET /api/auth/passkeys/credentials');
    await h.page.click('#app [data-passkeys]');
    await h.page.waitForSelector('#passkey-dialog form:not([hidden])');
    const completed = h.page.waitForResponse(r => r.url().endsWith('/credentials'));
    respond();
    await completed;
    assert.equal(await h.page.$eval('[name=username]', e => e.value), 'member');
  });

  await t.test('rename Escape cancels without a blur-save; polls retain session drafts', async t => {
    const h = await harness(t);
    let renamed = 0;
    h.state.routes.set('POST /api/rename', (_req, res) => { renamed++; res.json({ ok: true }); });
    h.state.routes.set('POST /api/sessions/rename', (_req, res) => { renamed++; res.json({ ok: true }); });
    await h.goto();
    await h.login();
    await h.page.click('.tab', { button: 'right' });
    await h.page.click('.ctx-item');
    await h.page.waitForSelector('.tab input.rename');
    await h.page.type('.tab input.rename', 'cancelled-draft');
    await h.page.keyboard.press('Escape');
    await h.page.waitForSelector('.tab input.rename', { hidden: true });
    assert.equal(renamed, 0);
    await h.page.click('.sess.active .sess-name', { count: 2 });
    await h.page.waitForSelector('.sess-rename');
    await h.page.type('.sess-rename', 'session-draft');
    const polled = h.page.waitForResponse(r => r.url().endsWith('/api/sessions'));
    await h.page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
    await polled;
    assert.equal(await h.page.$eval('.sess-rename', e => e.value), 'session-draft');
    await h.page.keyboard.press('Escape');
    await h.page.waitForSelector('.sess-rename', { hidden: true });
    assert.equal(renamed, 0);
    assert.equal(await h.page.$eval('.sess.active .sess-name', e => e.textContent), 'alpha');
  });

  for (const scenario of [
    { name: 'preserves unselected windows when tmux renumbers; confirmation is single-use',
      alpha: ['A', 'B', 'C', 'D'], select: [0, 1], survivors: ['C', 'D'], repeat: true },
    { name: 'keeps its target session when the user switches during an awaited delete',
      alpha: ['A', 'B', 'C', 'D'], select: [0, 1], survivors: ['C', 'D'], switchSession: true },
    { name: 'handles two-digit indices and failed deletes without closing unrelated windows',
      alpha: [...'ABCDEFGHIJKL'], select: [0, 1, 2, 10], survivors: [...'BDEFGHIJL'],
      failBefore: 'B', failAfter: 'K' },
  ]) {
    await t.test('bulk close ' + scenario.name, async t => {
      const h = await harness(t);
      await h.page.setViewport({ width: 1800, height: 800 });
      const beta = ['other-A', 'other-B', 'other-C', 'other-D'];
      const sessions = new Map([['alpha', [...scenario.alpha]], ['beta', [...beta]]]);
      const attempts = [];
      let firstRequested;
      const firstRequest = new Promise(resolve => { firstRequested = resolve; });
      h.state.routes.set('GET /api/sessions', (_req, res) => res.json({ sessions:
        [...sessions].map(([name, windows]) => ({ name, windows: windows.length, attached: name === 'alpha' })),
      }));
      h.state.routes.set('GET /api/windows', (req, res) => res.json({ windows:
        sessions.get(req.query.session).map((name, index) => ({ index, name, active: index === 0, panes: 1 })),
      }));
      h.state.routes.set('POST /api/kill', (req, res) => {
        const { session, index } = req.body;
        attempts.push({ session, index });
        const windows = sessions.get(session);
        const name = windows?.[index];
        let respond;
        if (name === undefined) {
          respond = () => res.status(404).json({ error: 'no such window' });
        } else if (name === scenario.failBefore) {
          respond = () => res.status(500).json({ error: 'test delete failed before mutation' });
        } else {
          // Model tmux renumber-windows: every successful kill immediately
          // shifts higher indices down, while each window keeps its identity.
          windows.splice(index, 1);
          respond = name === scenario.failAfter
            ? () => res.status(502).type('text').send('test response lost after deletion')
            : () => res.json({ ok: true });
        }
        // Hold the first response so repeated confirmation and session switching
        // happen while the destructive operation is demonstrably still pending.
        if (attempts.length === 1) firstRequested(respond);
        else respond();
      });
      await h.goto();
      await h.login();
      await h.page.waitForSelector('.tab[data-index="' + scenario.select.at(-1) + '"]');
      await h.page.keyboard.down('Control');
      for (const index of scenario.select) await h.page.click('.tab[data-index="' + index + '"] .name');
      await h.page.keyboard.up('Control');
      await h.page.click('.bulk-btn');
      await h.page.waitForSelector('.confirm-overlay[open]', { visible: true });
      assert.equal(await h.page.$eval('.confirm-names', e => e.textContent),
        scenario.select.map(index => scenario.alpha[index]).join(', '));
      await h.page.evaluate(() => {
        const nativeFetch = window.fetch;
        window.testKillRequests = [];
        window.fetch = (url, options) => {
          if (url === '/api/kill') window.testKillRequests.push(JSON.parse(options.body));
          return nativeFetch(url, options);
        };
      });
      await h.page.click('.confirm-yes', { count: scenario.repeat ? 2 : 1 });
      const releaseFirst = await firstRequest;
      assert.equal(await h.page.evaluate(() => window.testKillRequests.length), 1,
        'only one delete may start before the first response, even after repeated confirmation');
      if (scenario.switchSession) {
        await h.page.waitForSelector('.confirm-overlay', { hidden: true });
        await h.page.click('.sess[data-name=beta]');
        await h.page.waitForSelector('.sess.active[data-name=beta]');
      }
      const refreshed = h.page.waitForResponse(r => r.url().includes('/api/windows?') &&
        attempts.length >= scenario.select.length);
      releaseFirst();
      await refreshed;
      assert.deepEqual(Object.fromEntries(sessions), { alpha: scenario.survivors, beta },
        'only selected identities in the confirmed session may be removed');
      assert.equal(attempts.length, scenario.select.length, 'each confirmed index is attempted once');
      const visible = scenario.switchSession ? beta : scenario.survivors;
      await h.page.waitForFunction(names => JSON.stringify([...document.querySelectorAll('#tabs .tab .name')]
        .map(e => e.textContent)) === JSON.stringify(names), {}, visible);
    });
  }

  await t.test('mobile long-press uses actual xterm cell dimensions', async t => {
    const h = await harness(t, { mobile: true });
    await h.goto();
    await h.login();
    await h.page.evaluate(() => new Promise(resolve => {
      window.testTerm.reset();
      window.testTerm.write('hello selection', resolve);
    }));
    await h.page.evaluate(() => {
      const term = window.testTerm;
      const rect = term.element.querySelector('.xterm-screen').getBoundingClientRect();
      const touch = new Touch({ identifier: 1, target: term.element,
        clientX: rect.left + rect.width / term.cols * 2.5,
        clientY: rect.top + rect.height / term.rows / 2 });
      term.element.dispatchEvent(new TouchEvent('touchstart', {
        bubbles: true, touches: [touch], targetTouches: [touch], changedTouches: [touch],
      }));
    });
    await h.page.waitForFunction(() => window.testTerm.getSelection() === 'hello');
  });

  await t.test('generic provider metadata, bounce guard, and network failure preserve login choices', async t => {
    const h = await harness(t, { prefs: { 'webmux-auth-method': 'example' } });
    h.state.providers = [null, { id: 'bad', loginPath: 'javascript:void(0)' }, {
      id: 'example', label: 'Example identity', loginPath: '/auth/ext/example/start', iconPath: '/favicon.svg',
    }];
    let redirects = 0;
    h.state.routes.set('GET /auth/ext/example/start', (_req, res) => { redirects++; res.redirect('/'); });
    await h.goto();
    await h.page.waitForSelector('#auth-providers a', { visible: true });
    assert.equal(redirects, 1);
    assert.equal(await h.page.$$eval('#auth-providers a', list => list.length), 1);
    assert.equal(await h.page.$eval('#auth-providers a', e => e.textContent), 'Example identity');
    h.state.routes.set('POST /auth', (req) => req.socket.destroy());
    await h.page.click('#use-secret');
    await h.page.type('#secret', 'not-a-real-secret');
    await h.page.keyboard.press('Enter');
    await h.page.waitForSelector('#auth-err', { visible: true });
    assert.equal(await h.page.$eval('#secret', e => !e.disabled && !e.value), true);
    await h.page.click('#back-to-methods');
    await h.page.waitForSelector('#auth-providers a', { visible: true });
    await h.page.evaluateOnNewDocument(() => Object.defineProperty(window, 'sessionStorage', {
      get() { throw new DOMException('Session storage disabled for this test', 'SecurityError'); },
    }));
    await h.page.reload();
    await h.page.waitForSelector('#auth-providers a', { visible: true });
    assert.equal(redirects, 1, 'auto-redirect requires a writable bounce guard');
  });

  await t.test('missing terminal dependency produces a visible reload action', async t => {
    const h = await harness(t);
    h.state.routes.set('GET /vendor/addon-fit/lib/addon-fit.js', (_req, res) => res.status(404).end());
    await h.goto();
    await h.page.click('#use-secret');
    await h.page.type('#secret', 'not-a-real-secret');
    await h.page.keyboard.press('Enter');
    await h.page.waitForSelector('#boot-reload', { visible: true });
    assert.equal(await h.page.$eval('#app', e => e.hidden), true);
    assert.equal(await h.page.evaluate(() => document.activeElement.id), 'boot-reload');
    h.state.routes.delete('GET /vendor/addon-fit/lib/addon-fit.js');
    h.state.routes.set('GET /passkeys.js', (_req, res) => res.status(404).end());
    await h.page.reload();
    await h.page.waitForSelector('#secret', { visible: true });
    await h.login();
    await h.page.click('#app [data-passkeys]');
    await h.page.waitForFunction(() => document.querySelector('#toast')?.textContent.includes('Passkey UI could not load'));
  });

  await t.test('old service workers retire their own caches and unregister', async t => {
    const h = await harness(t);
    h.state.routes.set('GET /sw.js', (_req, res) => res.type('application/javascript').set('Cache-Control', 'no-store').send(`
      self.addEventListener('install', e => e.waitUntil(self.skipWaiting()));
      self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
    `));
    await h.goto();
    await h.page.evaluate(async () => {
      await caches.open('webmux-v8');
      await caches.open('unrelated-app');
      await navigator.serviceWorker.register('/sw.js');
      await navigator.serviceWorker.ready;
    });
    h.state.routes.delete('GET /sw.js');
    const reloaded = h.page.waitForNavigation();
    await h.page.evaluate(async () => {
      const registration = await navigator.serviceWorker.getRegistration();
      void registration.update();
    });
    await reloaded;
    await h.page.waitForFunction(async () => !(await navigator.serviceWorker.getRegistration()) &&
      !(await caches.keys()).includes('webmux-v8'));
    assert.equal(await h.page.evaluate(async () => (await caches.keys()).includes('unrelated-app')), true);
  });
});
