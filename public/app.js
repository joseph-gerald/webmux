/* webmux client */
(() => {
  // Retire webmux's old offline cache; terminal sessions require a live server.
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.getRegistrations().then(async rs => {
      const ours = rs.filter(r => [r.active, r.waiting, r.installing].some(w =>
        w && new URL(w.scriptURL).pathname === '/sw.js'));
      await Promise.all(ours.map(r => r.unregister()));
      if (ours.length) location.reload();
    }).catch(() => {});
  }
  const $ = s => document.querySelector(s);
  // Storage can be unavailable (privacy settings) or contain an older format.
  // Preferences must never prevent login or terminal startup.
  function safeStorage(name) {
    return {
      getItem(key) { try { return window[name].getItem(key); } catch { return null; } },
      setItem(key, value) { try { window[name].setItem(key, value); return true; } catch { return false; } },
      removeItem(key) { try { window[name].removeItem(key); } catch {} },
    };
  }
  const localStore = safeStorage('localStorage');
  const sessionStore = safeStorage('sessionStorage');
  function savedJSON(key, fallback) {
    try { return JSON.parse(localStore.getItem(key)) ?? fallback; } catch { return fallback; }
  }
  const validIndex = n => Number.isSafeInteger(n) && n >= 0;
  function savedTabMemory() {
    const saved = savedJSON('webmux-tab-memory', []);
    const entries = Array.isArray(saved) ? saved : (saved && typeof saved === 'object' ? Object.entries(saved) : []);
    return new Map(entries.filter(e => Array.isArray(e) && typeof e[0] === 'string' && validIndex(e[1])));
  }
  // Ticket lives in this variable only. Reload drops it → login again.
  // (Clear any leftover from the old sessionStorage era.)
  sessionStore.removeItem('webmux-token');
  // Remember admin intent across the external-auth round trip. Providers always
  // redirect back to `/`, which would otherwise strip /admin and ?admin.
  function stashAdminIntent(forceNext) {
    try {
      const pathAdmin = location.pathname.replace(/\/+$/, '') === '/admin';
      const qAdmin = new URLSearchParams(location.search).has('admin');
      if (qAdmin) sessionStore.setItem('webmux-admin-q', '1');
      if (pathAdmin || (forceNext && (qAdmin || sessionStore.getItem('webmux-admin-q') === '1'))) {
        sessionStore.setItem('webmux-next', '/admin');
      }
    } catch {}
  }
  stashAdminIntent(false);
  let token = null;
  function absorbTicket(res, body) {
    const h = res && res.headers && res.headers.get('X-Session');
    if (h) token = h;
    else if (body && body.token) token = body.token;
  }
  // If we just returned from an external auth-provider login, a one-time httpOnly
  // cookie is waiting — swap it for our session ticket before the login UI decides
  // what to show. Resolves once (success or not) so the rest of boot can await it.
  const authReady = (async () => {
    if (token) return;
    try {
      const r = await fetch('/api/auth/exchange', { method: 'POST' });
      if (r.ok) {
        const body = await r.json();
        absorbTicket(r, body);
        if (token) {
          rememberAuthMethod(body.provider || 'provider');
          sessionStore.removeItem('webmux-auth-skip-auto');
        }
      }
    } catch {}
  })();
  // Start discovery immediately instead of waiting for the handoff exchange.
  // The login chooser now needs one local round trip, not two in series.
  const providersReady = token
    ? Promise.resolve([])
    : fetch('/api/auth/providers').then(r => r.json()).catch(() => []);
  let ws = null;
  let term = null;
  let fit = null;
  let windows = [];
  let sessions = [];
  let currentSession = localStore.getItem('webmux-session') || sessionStore.getItem('webmux-session') || null;
  let tabDrag = null; // active Chrome-style tab reorder / transfer
  let tabStripBusy = false; // true while drop FLIP / sync runs
  let suppressTabClick = false;
  let reconnectTimeout = null;
  let selectedTabs = new Set();
  const savedPins = savedJSON('webmux-pinned', []);
  let pinnedTabs = new Set(Array.isArray(savedPins) ? savedPins.filter(validIndex) : []);
  let recentTabs = [];
  let lastActiveTabPerSession = savedTabMemory();
  let spectatorMode = false;
  let viewOnlyAttach = false; // server-side read-only WS (?view=1)
  let watcherCount = 0;
  let watcherEyeTimer = 0;
  // ---------- battery / display prefs ----------
  // Experience-changing knobs are configurable. Silent free wins (pause when
  // hidden, coalesce paints, drop idle compositor hints) always apply.
  const PERF_KEY = 'webmux-performance'; // legacy preset key
  const PERF_PREFS_KEY = 'webmux-perf-prefs';
  const PERF_PRESETS = {
    normal:   { mirror: 'blur',  cursorBlink: true,  uiEffects: 'full',  fancyGlyphs: true,  webgl: true,  bgPaint: 'pause' },
    high:     { mirror: 'plain', cursorBlink: true,  uiEffects: 'light', fancyGlyphs: true,  webgl: true,  bgPaint: 'pause' },
    max:      { mirror: 'off',   cursorBlink: false, uiEffects: 'none',  fancyGlyphs: false, webgl: true,  bgPaint: 'pause' },
  };
  const PERF_PRESET_LABELS = { normal: 'look', high: 'balanced', max: 'battery' };

  function defaultPerfPrefs() {
    const legacy = localStore.getItem(PERF_KEY);
    if (legacy && PERF_PRESETS[legacy]) return { ...PERF_PRESETS[legacy] };
    // Desktop: full look. Mobile: max battery preservation.
    const touch = 'ontouchstart' in window || navigator.maxTouchPoints > 0;
    return { ...(touch ? PERF_PRESETS.max : PERF_PRESETS.normal) };
  }

  let perfPrefs = defaultPerfPrefs();
  const savedPerf = savedJSON(PERF_PREFS_KEY, {});
  if (savedPerf && typeof savedPerf === 'object' && !Array.isArray(savedPerf)) {
    for (const key of [...Object.keys(perfPrefs), 'stream']) {
      if (typeof savedPerf[key] === (typeof perfPrefs[key] === 'boolean' ? 'boolean' : 'string')) {
        perfPrefs[key] = savedPerf[key];
      }
    }
  }
  // clamp
  if (!['blur', 'plain', 'off'].includes(perfPrefs.mirror)) perfPrefs.mirror = 'blur';
  if (!['full', 'light', 'none'].includes(perfPrefs.uiEffects)) perfPrefs.uiEffects = 'full';
  if (!['pause', 'live'].includes(perfPrefs.bgPaint)) perfPrefs.bgPaint = 'pause';
  // Streaming fidelity: 'full' (default, lossless — every byte paints) vs
  // 'saver' (battery saver: drops repeated frames, trims stalled buffers,
  // holds big paints briefly). Lossy opts live here, never on by default.
  if (!['full', 'saver'].includes(perfPrefs.stream)) perfPrefs.stream = 'full';
  perfPrefs.cursorBlink = !!perfPrefs.cursorBlink;
  perfPrefs.fancyGlyphs = !!perfPrefs.fancyGlyphs;
  perfPrefs.webgl = perfPrefs.webgl !== false;

  let mirrorRenderSubscription = null;
  let mirrorRaf = 0;
  let pageVisible = !document.hidden;
  let perfSheetEl = null;
  let terminalBooted = false;
  let webglAddon = null;
  let webglPreserveBuf = null;
  // Drop PTY bytes until server acks session switch (avoids painting old session into new).
  let pendingSwitch = null;
  let pendingSwitchTimer = 0;

  function clearPendingSwitch() {
    pendingSwitch = null;
    if (pendingSwitchTimer) { clearTimeout(pendingSwitchTimer); pendingSwitchTimer = 0; }
  }

  function armPendingSwitch(session) {
    clearPendingSwitch();
    pendingSwitch = session;
    // If ack is lost (old server / dropped frame), ungate so the UI can't soft-lock.
    pendingSwitchTimer = setTimeout(() => {
      pendingSwitchTimer = 0;
      if (pendingSwitch !== session) return;
      pendingSwitch = null;
      clearPendingWrite();
      if (term && currentSession === session) term.reset();
      scheduleMirrorUpdate();
    }, 1500);
  }

  // Coalesce PTY writes for big redraws; interactive echoes paint ASAP.
  // (Idle hold + server batch used to stack ~16–50ms on every keystroke.)
  let pendingWrite = '';
  let writeRaf = 0;
  let writeIdleTimer = 0;
  let writeGen = 0;
  let writeMicroQueued = false;
  let lastIngestAt = 0;
  let lastWriteSig = '';
  const WRITE_CAP = 96 * 1024; // stall catch-up: keep a small tail, not hundreds of KB
  const WRITE_IDLE_HEAVY_MS = 16;
  const WRITE_DEDUP_MIN = 4096;

  function writeIdleFor(len) {
    // Full fidelity: no idle hold — coalesce via rAF/microtask only (lossless).
    if (perfPrefs.stream !== 'saver') return 0;
    if (len > 48 * 1024) return WRITE_IDLE_HEAVY_MS;
    if (len > 8 * 1024) return 8;
    return 0; // interactive: no idle hold
  }

  // Cheap signature: length + head/tail + sparse mid samples (enough to catch
  // identical fullscreen repaints without scanning 100KB+ every time).
  function writeFrameSig(s) {
    const n = s.length;
    let h = (2166136261 ^ n) >>> 0;
    const edge = Math.min(96, n);
    for (let i = 0; i < edge; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 16777619);
      h ^= s.charCodeAt(n - 1 - i);
      h = Math.imul(h, 16777619);
    }
    if (n > edge * 2) {
      const step = Math.max(1, (n / 384) | 0);
      for (let i = edge; i < n - edge; i += step) {
        h ^= s.charCodeAt(i);
        h = Math.imul(h, 16777619);
      }
    }
    return n + ':' + (h >>> 0).toString(36);
  }

  function truncateEscSafe(s, limit) {
    if (s.length <= limit) return s;
    const slice = s.slice(-limit);
    const esc = slice.indexOf('\x1b');
    if (esc > 0 && esc < 256) return slice.slice(esc);
    return slice;
  }

  function clearPendingWrite() {
    pendingWrite = '';
    lastWriteSig = '';
    writeGen++;
    writeMicroQueued = false;
    if (writeRaf) { cancelAnimationFrame(writeRaf); writeRaf = 0; }
    if (writeIdleTimer) { clearTimeout(writeIdleTimer); writeIdleTimer = 0; }
  }

  function appendPendingWrite(data) {
    pendingWrite += data;
    // Saver only: cap a stalled buffer. Truncation drops bytes (can split an
    // image/escape sequence mid-stream), so full mode never truncates.
    if (perfPrefs.stream === 'saver' && pendingWrite.length > WRITE_CAP) {
      pendingWrite = truncateEscSafe(pendingWrite, WRITE_CAP);
    }
  }

  function flushPendingWrite() {
    if (!term || !pendingWrite) return;
    const chunk = pendingWrite;
    pendingWrite = '';
    // Saver only: dedupe large identical paints. The sparse hash can collide
    // on dense output (images) and would drop whole frames — never in full mode.
    if (perfPrefs.stream === 'saver' && chunk.length >= WRITE_DEDUP_MIN) {
      const sig = writeFrameSig(chunk);
      if (sig === lastWriteSig) return;
      lastWriteSig = sig;
    }
    term.write(chunk);
  }

  function scheduleTermWrite() {
    if (!pageVisible && perfPrefs.bgPaint === 'pause') return;
    const len = pendingWrite.length;
    const idleNeed = writeIdleFor(len);

    // Tiny interactive: write this turn (microtask) — lowest latency path.
    if (len > 0 && len < 512 && idleNeed === 0) {
      if (writeIdleTimer) { clearTimeout(writeIdleTimer); writeIdleTimer = 0; }
      if (writeRaf) { cancelAnimationFrame(writeRaf); writeRaf = 0; }
      if (writeMicroQueued) return;
      writeMicroQueued = true;
      const gen = writeGen;
      queueMicrotask(() => {
        writeMicroQueued = false;
        if (gen !== writeGen) return;
        if (!pageVisible && perfPrefs.bgPaint === 'pause') return;
        flushPendingWrite();
      });
      return;
    }

    if (idleNeed > 0) {
      const since = performance.now() - lastIngestAt;
      if (since < idleNeed) {
        if (!writeIdleTimer) {
          writeIdleTimer = setTimeout(() => {
            writeIdleTimer = 0;
            scheduleTermWrite();
          }, idleNeed - since);
        }
        return;
      }
    }
    if (writeIdleTimer) { clearTimeout(writeIdleTimer); writeIdleTimer = 0; }
    if (writeRaf) return;
    writeRaf = requestAnimationFrame(() => {
      writeRaf = 0;
      if (!pageVisible && perfPrefs.bgPaint === 'pause') return;
      flushPendingWrite();
    });
  }

  function ingestOutput(data) {
    if (pendingSwitch) return; // stale bytes from previous attach — drop
    if (typeof data !== 'string') data = String(data);
    lastIngestAt = performance.now();
    appendPendingWrite(data);
    if (pageVisible || perfPrefs.bgPaint === 'live') scheduleTermWrite();
  }

  // Same-tick input coalesce: multi-char pastes / bursty IME → one WS frame.
  // Single keystrokes still leave on the next microtask (≈0 added latency).
  let pendingInput = '';
  let inputMicroQueued = false;
  function terminalUiBlocked() {
    return $('#app').hidden || !$('#auth').hidden || !!$('dialog[open], .confirm-overlay, #ctx-menu');
  }
  function editingField(target = document.activeElement) {
    return target !== term?.textarea && !!target?.closest('input, textarea, select, [contenteditable]:not([contenteditable="false"])');
  }
  function focusTerm() {
    if (!term || terminalUiBlocked() || editingField()) return;
    term.focus();
  }
  function flushInputQueue() {
    inputMicroQueued = false;
    const d = pendingInput;
    pendingInput = '';
    if (!d || !ws || ws.readyState !== 1) return;
    if (viewOnlyAttach || spectatorMode || terminalUiBlocked() || pendingSwitch) return;
    try { ws.send(JSON.stringify({ t: 'i', d })); } catch {}
  }
  function queueInput(d) {
    if (!d || viewOnlyAttach || spectatorMode || terminalUiBlocked() || pendingSwitch) return;
    pendingInput += d;
    if (inputMicroQueued) return;
    inputMicroQueued = true;
    queueMicrotask(flushInputQueue);
  }

  function handleWsControl(raw) {
    // Control frames: RS (0x1e) + JSON. Keep them out of the PTY stream.
    if (typeof raw !== 'string' || raw.charCodeAt(0) !== 0x1e) return false;
    let msg;
    try { msg = JSON.parse(raw.slice(1)); } catch { return true; }
    if (msg && msg.t === 'switched') {
      if (pendingSwitch && msg.session === pendingSwitch && msg.session === currentSession) {
        clearPendingSwitch();
        clearPendingWrite();
        // Reset only — don't replay stale buffer over the fresh attach stream.
        if (term) term.reset();
        scheduleMirrorUpdate();
      }
    } else if (msg && msg.t === 'presence') {
      if (!msg.session || msg.session === currentSession) {
        setWatcherPresence(+msg.watchers || 0);
      }
    }
    return true;
  }

  function matchedPerfPreset() {
    for (const [name, p] of Object.entries(PERF_PRESETS)) {
      if (p.mirror === perfPrefs.mirror
        && p.cursorBlink === perfPrefs.cursorBlink
        && p.uiEffects === perfPrefs.uiEffects
        && p.fancyGlyphs === perfPrefs.fancyGlyphs
        && !!p.webgl === !!perfPrefs.webgl
        && p.bgPaint === perfPrefs.bgPaint) return name;
    }
    return 'custom';
  }

  function perfSummaryLabel() {
    const preset = matchedPerfPreset();
    return preset === 'custom' ? 'custom' : (PERF_PRESET_LABELS[preset] || preset);
  }

  function savePerfPrefs() {
    localStore.setItem(PERF_PREFS_KEY, JSON.stringify(perfPrefs));
    const preset = matchedPerfPreset();
    try {
      if (preset === 'custom') localStore.removeItem(PERF_KEY);
      else localStore.setItem(PERF_KEY, preset);
    } catch {}
  }

  function scheduleMirrorUpdate() {
    if (perfPrefs.mirror === 'off' || !pageVisible || !window.updateMirror) return;
    if (mirrorRaf) return;
    mirrorRaf = requestAnimationFrame(() => {
      mirrorRaf = 0;
      if (perfPrefs.mirror === 'off' || !pageVisible) return;
      window.updateMirror();
    });
  }

  function syncMirrorSubscription() {
    const want = pageVisible && perfPrefs.mirror !== 'off' && term && window.updateMirror;
    if (!want) {
      if (mirrorRenderSubscription) { mirrorRenderSubscription.dispose(); mirrorRenderSubscription = null; }
      return;
    }
    if (!mirrorRenderSubscription) {
      mirrorRenderSubscription = term.onRender(() => scheduleMirrorUpdate());
    }
  }

  function applyTermPerfOptions() {
    if (!term) return;
    // Cursor blink keeps a timer alive even when idle — big mobile drain.
    term.options.cursorBlink = pageVisible && !!perfPrefs.cursorBlink;
    term.options.customGlyphs = !!perfPrefs.fancyGlyphs;
    term.options.rescaleOverlappingGlyphs = !!perfPrefs.fancyGlyphs;
  }

  function applyRenderer() {
    if (!term) return;
    const want = !!perfPrefs.webgl;
    // preserveDrawingBuffer is only needed so the mirror can sample the WebGL
    // canvas — keep it off otherwise (cheaper, less tear-prone).
    const wantPreserve = perfPrefs.mirror !== 'off';
    if (want && webglAddon && webglPreserveBuf !== wantPreserve) {
      try { webglAddon.dispose(); } catch {}
      webglAddon = null;
      webglPreserveBuf = null;
    }
    if (want && !webglAddon) {
      try {
        const addon = new WebglAddon.WebglAddon(wantPreserve);
        addon.onContextLoss(() => {
          try { addon.dispose(); } catch {}
          if (webglAddon === addon) {
            webglAddon = null;
            webglPreserveBuf = null;
          }
        });
        term.loadAddon(addon);
        webglAddon = addon;
        webglPreserveBuf = wantPreserve;
      } catch (e) {
        webglAddon = null;
        webglPreserveBuf = null;
        window.__webglErr = String(e);
      }
    } else if (!want && webglAddon) {
      try { webglAddon.dispose(); } catch {}
      webglAddon = null;
      webglPreserveBuf = null;
    }
  }

  function applyPerformanceMode() {
    const preset = matchedPerfPreset();
    document.body.classList.remove('perf-normal', 'perf-high', 'perf-max', 'perf-custom');
    document.body.classList.add(`perf-${preset}`);
    document.body.classList.toggle('perf-mirror-off', perfPrefs.mirror === 'off');
    document.body.classList.toggle('perf-mirror-plain', perfPrefs.mirror === 'plain');
    document.body.classList.toggle('perf-mirror-blur', perfPrefs.mirror === 'blur');
    document.body.classList.toggle('perf-fx-light', perfPrefs.uiEffects === 'light');
    document.body.classList.toggle('perf-fx-none', perfPrefs.uiEffects === 'none');
    document.body.classList.toggle('perf-fx-full', perfPrefs.uiEffects === 'full');

    const label = `battery · ${perfSummaryLabel()}`;
    const btn = $('#performance-mode');
    if (btn) btn.textContent = label;
    const barBtn = $('#perf-settings');
    if (barBtn) {
      barBtn.title = `battery & display · ${perfSummaryLabel()}`;
      barBtn.setAttribute('aria-label', `battery and display settings, ${perfSummaryLabel()}`);
    }

    const mirror = $('#mirror-canvas');
    if (mirror) {
      if (perfPrefs.mirror === 'off') {
        mirror.hidden = true;
      } else {
        mirror.hidden = false;
        if (window.resizeMirror) window.resizeMirror();
        scheduleMirrorUpdate();
      }
    }
    syncMirrorSubscription();
    applyTermPerfOptions();
    applyRenderer();
    if (pageVisible || perfPrefs.bgPaint === 'live') scheduleTermWrite();
    if (typeof paintPerfSheet === 'function') paintPerfSheet();
  }

  function setPerfPrefs(partial, { toast: doToast = false } = {}) {
    Object.assign(perfPrefs, partial);
    savePerfPrefs();
    applyPerformanceMode();
    pushStreamMode();
    if (doToast) toast(`battery: ${perfSummaryLabel()}`);
  }

  // Tell the server whether this connection wants saver-mode (lossy) streaming.
  // Server defaults to full fidelity, so this only ever opts *into* saving.
  function pushStreamMode() {
    try {
      if (ws && ws.readyState === 1) {
        ws.send(JSON.stringify({ t: 'stream', saver: perfPrefs.stream === 'saver' }));
      }
    } catch {}
  }

  function applyPerfPreset(name) {
    const p = PERF_PRESETS[name];
    if (!p) return;
    setPerfPrefs({ ...p }, { toast: true });
  }

  // Free: when the tab is backgrounded, stop blink + mirror + slow the polls.
  // Pending PTY bytes stay buffered (bgPaint=pause) and flush on return.
  function onPerfVisibility() {
    pageVisible = !document.hidden;
    applyTermPerfOptions();
    syncMirrorSubscription();
    if (pageVisible) {
      scheduleTermWrite();
      scheduleMirrorUpdate();
      if (terminalBooted) {
        refreshTabs().catch(() => {});
        refreshSessions().catch(() => {});
      }
    } else {
      if (mirrorRaf) { cancelAnimationFrame(mirrorRaf); mirrorRaf = 0; }
      if (perfPrefs.bgPaint === 'pause' && writeRaf) {
        cancelAnimationFrame(writeRaf);
        writeRaf = 0;
      }
    }
    if (typeof reschedulePolls === 'function') reschedulePolls();
  }
  document.addEventListener('visibilitychange', onPerfVisibility);

  applyPerformanceMode();

  // ---------- api ----------
  async function trySilentReauth() {
    try {
      const r = await fetch('/api/auth/exchange', { method: 'POST' });
      if (r.ok) {
        const body = await r.json();
        absorbTicket(r, body);
        return !!token;
      }
    } catch {}
    return false;
  }

  const api = async (url, body, retry = 0) => {
    const r = await fetch(url, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { 'content-type': 'application/json', 'x-token': token },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const h = r.headers.get('X-Session');
    if (h) token = h;
    if (r.status === 401) {
      // Parallel polls can race token rotation; retry before nuking the session.
      if (retry === 0) {
        await new Promise(res => setTimeout(res, 80));
        return api(url, body, 1);
      }
      if (retry === 1 && await trySilentReauth()) return api(url, body, 2);
      logout();
      throw new Error('unauthorized');
    }
    const j = await r.json();
    if (j && j.token) token = j.token;
    return j;
  };

  let loggingOut = false;
  function logout({ chooseMethod = false } = {}) {
    if (chooseMethod) {
      localStore.removeItem(AUTH_PREF);
      sessionStore.setItem('webmux-auth-skip-auto', '1');
    }
    if (loggingOut) return;
    loggingOut = true;
    // best-effort server-side revoke of session token (keepalive survives the reload)
    if (token) { fetch('/api/auth/logout', { method: 'POST', headers: { 'x-token': token }, keepalive: true }).catch(() => {}); }
    token = null;
    sessionStore.removeItem('webmux-token');
    location.reload();
  }

  // ---------- auth ----------
  let hasAuthChoices = false;
  const nativePasskeys = window.webmuxPasskeys?.init({
    getToken: () => token, absorbTicket, onLogin: start, onLogout: logout, remember: rememberAuthMethod,
  }) || { ready: Promise.resolve(false) };
  if (!window.webmuxPasskeys) {
    document.querySelectorAll('[data-passkeys]').forEach(b => b.addEventListener('click', () => toast('Passkey UI could not load. Reload to try again.')));
  }

  const AUTH_PREF = 'webmux-auth-method';
  function lastAuthMethod() {
    return localStore.getItem(AUTH_PREF) || '';
  }
  function rememberAuthMethod(id) {
    if (id) localStore.setItem(AUTH_PREF, String(id));
  }

  function showSecretAuth() {
    nativePasskeys.cancelLogin?.();
    $('#auth-methods').hidden = true;
    $('#secret-auth').hidden = false;
    $('#back-to-methods').hidden = !hasAuthChoices;
    $('#secret').focus();
  }

  function showAuthMethods() {
    if (!hasAuthChoices) return showSecretAuth();
    $('#secret').value = '';
    $('#secret-auth').hidden = true;
    $('#auth-methods').hidden = false;
    $('#auth-methods .provider-btn:not([hidden]), #use-secret')?.focus();
  }

  $('#use-secret').addEventListener('click', () => {
    rememberAuthMethod('secret');
    showSecretAuth();
  });
  $('#back-to-methods').addEventListener('click', showAuthMethods);

  async function submitSecret(secret) {
    const r = await fetch('/auth', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ secret }),
    });
    if (r.ok) {
      const body = await r.json();
      rememberAuthMethod('secret');
      sessionStore.removeItem('webmux-auth-skip-auto');
      absorbTicket(r, body);
      $('#secret').value = '';
      await start();
    } else {
      $('#auth-err').textContent = r.status === 401 || r.status === 403 ? 'Access denied.' : 'Sign-in failed. Try again.';
      $('#auth-err').hidden = false;
      $('#secret').value = '';
      const box = $('.auth-box');
      box.classList.remove('shake');
      void box.offsetWidth;
      box.classList.add('shake');
    }
  }

  $('#auth-form').addEventListener('submit', async e => {
    e.preventDefault();
    const secret = $('#secret').value.trim();
    if (!secret || $('#secret').disabled) return;
    $('#secret').disabled = true;
    $('#auth-err').hidden = true;
    try { await submitSecret(secret); }
    catch {
      $('#auth-err').textContent = 'Could not reach the server. Try again.';
      $('#auth-err').hidden = false;
    } finally {
      $('#secret').value = '';
      $('#secret').disabled = false;
      if (!$('#auth').hidden && !$('#secret-auth').hidden) $('#secret').focus();
    }
  });

  // Native passkeys, private providers and the recovery secret are peer methods.
  (async () => {
    await authReady;
    if (token) return; // already logged in — the app is about to start
    let list = await providersReady;
    const localPath = value => {
      if (typeof value !== 'string' || !value.startsWith('/')) return false;
      try { return new URL(value, location.origin).origin === location.origin; } catch { return false; }
    };
    list = Array.isArray(list) ? list.filter(p => p && typeof p.id === 'string' && localPath(p.loginPath)) : [];
    const host = $('#auth-providers');
    const last = lastAuthMethod();
    list.forEach(p => {
      const b = document.createElement('a');
      b.className = 'provider-btn';
      b.href = p.loginPath;
      b.addEventListener('click', () => {
        rememberAuthMethod(p.id || 'provider');
        stashAdminIntent(true);
      });
      b.textContent = p.label || p.id;
      if (localPath(p.iconPath)) {
        const icon = document.createElement('img');
        icon.className = 'provider-icon';
        icon.src = p.iconPath;
        icon.alt = '';
        b.prepend(icon);
      }
      host.appendChild(b);
    });
    hasAuthChoices = (await nativePasskeys.ready) || list.length > 0;
    if (token) return;
    $('#back-to-methods').hidden = !hasAuthChoices;
    // A slow discovery response must not replace a token form already in use.
    if (!$('#secret-auth').hidden) return;
    const bounced = sessionStore.getItem('webmux-auth-skip-auto') === '1';
    if (bounced) sessionStore.removeItem('webmux-auth-skip-auto');
    const pref = list.find(p => last && last === p.id);
    if (!bounced && pref && pref.loginPath && sessionStore.setItem('webmux-auth-skip-auto', '1')) {
      stashAdminIntent(true);
      location.assign(pref.loginPath);
      return;
    }
    if (last === 'secret' || !hasAuthChoices) showSecretAuth();
    else showAuthMethods();
  })();

  // ---------- clipboard ----------
  // A small, tab-lifetime history for the mobile helper. Large pastes still go
  // through in full; only the history is bounded, and none of it is persisted.
  const clipboardHistory = [];
  let refreshClipboardHistory = () => {};
  function rememberClipboard(text) {
    if (!isMobile || !text || text.length > 64 * 1024) return;
    const previous = clipboardHistory.indexOf(text);
    if (previous !== -1) clipboardHistory.splice(previous, 1);
    clipboardHistory.unshift(text);
    clipboardHistory.length = Math.min(clipboardHistory.length, 10);
    refreshClipboardHistory();
  }

  // OSC 52 copies (e.g. opencode copy-on-select) are programmatic: they fire
  // whenever the escape sequence arrives over the ws, which may be while focus
  // sits on another element — or while the whole tab is unfocused. Both make
  // navigator.clipboard reject with "Document is not focused". So: refocus the
  // terminal first; and if the *window* has no focus (nothing can write through
  // that), stash the text and flush it the instant the tab is focused again.
  let pendingCopy = null;
  function writeClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    return Promise.reject(new Error('no clipboard api'));
  }
  function copyText(text, { focusTerminal = true } = {}) {
    if (!text) return Promise.resolve(false);
    rememberClipboard(text);
    if (focusTerminal) focusTerm();
    if (!document.hasFocus()) {
      pendingCopy = text;                 // flushed by the window 'focus' handler
      toast('copied — focus this tab to sync');
      return Promise.resolve(false);
    }
    return writeClipboard(text).then(() => true, () => fallbackCopy(text));
  }
  // deferred flush: the copy landed while the tab was in the background
  window.addEventListener('focus', () => {
    if (pendingCopy == null) return;
    const t = pendingCopy; pendingCopy = null;
    writeClipboard(t).catch(() => fallbackCopy(t));
  });

  function fallbackCopy(text) {
    const active = document.activeElement;
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.readOnly = true;
    ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0;pointer-events:none';
    ($('dialog[open]') || document.body).appendChild(ta);
    ta.select();
    let copied = false;
    try { copied = document.execCommand('copy'); } catch {}
    ta.remove();
    try { active?.focus({ preventScroll: true }); } catch {}
    return copied;
  }

  // ---------- notifications (bell) ----------
  // Apps ring BEL to say "I need you" (agent finished, build done). tmux is
  // configured to pass it through for any window, so term.onBell fires even for
  // background tabs. Three escalating signals, none of which may be assumed:
  //   sound   — default ON. WebAudio, no permission needed, no asset files.
  //   title   — default ON. Free, permissionless, works when the tab is hidden.
  //   desktop — default OFF, opt-in. Most people deny the prompt, so it can
  //             never be the primary channel; permission is only ever requested
  //             from a real click on the status-bar toggle, never on load.
  const NOTIFY_KEY = 'webmux-notify';
  let notifyPrefs = { sound: true, desktop: false };
  const savedNotify = savedJSON(NOTIFY_KEY, {});
  for (const key of Object.keys(notifyPrefs)) {
    if (typeof savedNotify[key] === 'boolean') notifyPrefs[key] = savedNotify[key];
  }
  function saveNotifyPrefs() {
    localStore.setItem(NOTIFY_KEY, JSON.stringify(notifyPrefs));
  }

  // WebAudio ping, synthesised so nothing is fetched (works offline / strict CSP).
  // Browsers start the context suspended until a gesture, so resume on any input.
  let audioCtx = null;
  function primeAudio() {
    try {
      if (!audioCtx) {
        const AC = window.AudioContext || window.webkitAudioContext;
        if (!AC) return;
        audioCtx = new AC();
      }
      if (audioCtx.state === 'suspended') audioCtx.resume().catch(() => {});
    } catch {}
  }
  window.addEventListener('pointerdown', primeAudio);
  window.addEventListener('keydown', primeAudio);

  function playPing() {
    primeAudio();
    if (!audioCtx || audioCtx.state !== 'running') return;
    const t0 = audioCtx.currentTime;
    // two soft sine blips (A5 -> E6): a notification, not a klaxon
    [[880, 0], [1318.5, 0.11]].forEach(([freq, offset]) => {
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.type = 'sine';
      osc.frequency.value = freq;
      const start = t0 + offset;
      gain.gain.setValueAtTime(0.0001, start);
      gain.gain.exponentialRampToValueAtTime(0.14, start + 0.012); // fast attack
      gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.16); // soft decay
      osc.connect(gain).connect(audioCtx.destination);
      osc.start(start);
      osc.stop(start + 0.18);
    });
    // Free the audio hardware after the blip — leaving AudioContext running
    // keeps the audio pipeline awake on mobile.
    clearTimeout(playPing._suspend);
    playPing._suspend = setTimeout(() => {
      try { if (audioCtx && audioCtx.state === 'running') audioCtx.suspend(); } catch {}
    }, 400);
  }

  // title flash — the one signal that survives a hidden tab with no permissions
  const BASE_TITLE = document.title;
  let unseenBells = 0;
  let bellPulseTimer = null;
  let bellPulseIndex = null;
  let bellPulseSession = null;
  function paintTitle() {
    document.title = unseenBells ? `(${unseenBells}) ${BASE_TITLE}` : BASE_TITLE;
  }
  function clearBells() {
    if (!unseenBells) return;
    unseenBells = 0;
    paintTitle();
  }
  window.addEventListener('focus', clearBells);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) clearBells(); });

  function ringingTabs() {
    return windows.filter(w => w.bell && !w.active);
  }

  // tmux only keeps window_bell_flag for a background window. A BEL from the
  // window currently on screen therefore needs a short-lived client-side state
  // so it is still visible even while the browser and terminal are focused.
  function pulseActiveTab() {
    const active = windows.find(w => w.active);
    if (!active) return;
    bellPulseIndex = active.index;
    bellPulseSession = currentSession;
    renderTabs();
    clearTimeout(bellPulseTimer);
    bellPulseTimer = setTimeout(() => {
      bellPulseIndex = null;
      bellPulseSession = null;
      renderTabs();
    }, 2400);
  }

  function notifyDesktopBell() {
    if (!notifyPrefs.desktop || !window.Notification || Notification.permission !== 'granted') return;
    const ringing = ringingTabs();
    const where = ringing.length
      ? ringing.map(w => `${w.index} ${w.name}`).join(', ')
      : (currentSession || 'session');
    try {
      const n = new Notification('webmux', {
        body: `bell — ${where}`,
        tag: 'webmux-bell', // collapse repeats instead of stacking
        silent: notifyPrefs.sound, // don't double up with our own ping
      });
      n.onclick = () => { window.focus(); n.close(); };
    } catch {}
  }

  function onBell() {
    if (notifyPrefs.sound) playPing();
    pulseActiveTab();
    const looking = document.hasFocus() && !document.hidden;
    if (!looking) {
      unseenBells++;
      paintTitle();
    }
    // BEL itself has no window id. tmux's window_bell_flag does — pull it now
    // (and once more shortly after, in case the flag races the byte).
    const afterPaint = () => {
      const tab = $('#tabs')?.querySelector('.tab.attention');
      if (tab) tab.scrollIntoView({ inline: 'nearest', block: 'nearest' });
      if (!looking) notifyDesktopBell();
    };
    refreshTabs().then(afterPaint).catch(() => {});
    setTimeout(() => refreshTabs().then(afterPaint).catch(() => {}), 300);
  }

  // generic alert (memory pressure etc). Unlike a bell this fires even when the
  // tab is focused — the toast carries it visually, the ping carries it away
  // from the screen.
  function notifyAlert(title, body) {
    if (notifyPrefs.sound) playPing();
    if (notifyPrefs.desktop && window.Notification && Notification.permission === 'granted') {
      try {
        const n = new Notification(title, { body, tag: 'webmux-alert', silent: notifyPrefs.sound });
        n.onclick = () => { window.focus(); n.close(); };
      } catch {}
    }
  }

  // low-memory early warning — the server samples RSS per window and system
  // pressure; this fires before the OOM killer starts picking victims.
  const gb = mb => (mb / 1024).toFixed(1) + ' GB';
  let sysMem = null; // last {memTotalMB,...} from the poll

  // ---- per-tab memory badge ---------------------------------------------
  // Visibility is CSS's job (hover, or always once .warn/.crit is set) — this
  // just reports the number and the severity class.
  const fmtMem = mb => (mb >= 1024 ? (mb / 1024).toFixed(1) + 'G' : mb + 'M');
  // number and unit as separate nodes so the unit can be dimmed — makes the
  // figure itself the thing your eye lands on
  function setMemText(el, mb) {
    el.textContent = mb >= 1024 ? (mb / 1024).toFixed(1) : String(mb);
    const u = document.createElement('span');
    u.className = 'mem-u';
    u.textContent = mb >= 1024 ? 'G' : 'M';
    el.appendChild(u);
  }
  function applyMem(el, w) {
    const mb = w.mem;
    if (mb == null) { el.hidden = true; el.className = 'mem'; return; }
    const totalMB = sysMem && sysMem.memTotalMB;
    // red once one tab holds a quarter of the whole machine — that's the point
    // where the OOM killer would pick it first
    const critAt = totalMB ? totalMB / 4 : Infinity;
    el.hidden = false;
    setMemText(el, mb);
    el.classList.toggle('warn', mb >= 1024 && mb < critAt);
    el.classList.toggle('crit', mb >= critAt);
    el.title = `${fmtMem(mb)} resident`
      + (totalMB ? ` · ${Math.round((mb / totalMB) * 100)}% of ${Math.round(totalMB / 1024)}G` : '');
  }
  // bring a crashed tab back, in the directory it was working in
  async function respawnTab(w) {
    try {
      const r = await api('/api/respawn', { index: w.index, session: currentSession });
      if (r && r.error) { toast('restart failed'); return; }
      toast(r && r.cwd ? 'restarted in ' + r.cwd : 'restarted');
      await refreshTabs();
      api('/api/select', { index: w.index, session: currentSession }).then(refreshTabs);
    } catch { toast('restart failed'); }
  }

  // patch the badges on the existing DOM rather than re-rendering the tab bar:
  // keeps CSS transitions alive (so the bar glides) and never interrupts an
  // in-progress inline rename.
  function updateMemGauges() {
    for (const w of windows) {
      const el = document.querySelector(`.tab[data-index="${w.index}"] .mem`);
      if (el) applyMem(el, w);
    }
  }

  let lastMemWarn = 0;
  function checkMemPressure(sys, wins) {
    if (!sys) return;
    const tight = sys.memAvailPct <= 12 || (sys.swapTotalMB > 0 && sys.swapFreePct <= 15);
    if (!tight) { return; }
    if (Date.now() - lastMemWarn < 10 * 60 * 1000) return; // don't nag
    lastMemWarn = Date.now();
    const worst = wins.filter(w => w.mem).sort((a, b) => b.mem - a.mem)[0];
    const body = `${gb(sys.memAvailMB)} RAM free · swap ${sys.swapFreePct}% free`
      + (worst ? ` — heaviest tab: ${worst.name} (${gb(worst.mem)})` : '');
    toast('memory low — ' + body);
    notifyAlert('webmux — memory low', body);
  }

  // status-bar toggle: off -> sound -> sound+desktop -> off
  function notifyMode() {
    if (!notifyPrefs.sound && !notifyPrefs.desktop) return 'off';
    return notifyPrefs.desktop ? 'desktop' : 'sound';
  }
  function renderNotifyToggle() {
    const el = $('#status-bell');
    if (!el) return;
    const mode = notifyMode();
    el.textContent = mode === 'desktop' ? '♪+' : '♪';
    el.classList.toggle('muted', mode === 'off');
    el.title = mode === 'off' ? 'notifications off — click to enable the sound ping'
      : mode === 'sound' ? 'sound ping on — click to add desktop notifications'
      : 'sound + desktop notifications — click to turn off';
  }
  async function cycleNotify() {
    const mode = notifyMode();
    if (mode === 'off') {
      notifyPrefs.sound = true; notifyPrefs.desktop = false;
      primeAudio(); playPing(); // this click is the gesture that unlocks audio
    } else if (mode === 'sound') {
      // request permission ONLY here — inside a real user gesture, and only if
      // the user hasn't already decided (re-asking after a denial is a no-op).
      let granted = false;
      if (window.Notification) {
        if (Notification.permission === 'granted') granted = true;
        else if (Notification.permission === 'default') {
          try { granted = (await Notification.requestPermission()) === 'granted'; } catch {}
        }
      }
      if (granted) {
        notifyPrefs.desktop = true;
        toast('desktop notifications on');
      } else {
        // Desktop can't be a channel here, so the toggle degrades to a plain
        // on/off. Nobody is worse off: sound is the default-on fallback, so a
        // user who denies (or never grants) still gets pinged without doing
        // anything — they only reach silence by deliberately cycling to it.
        notifyPrefs.sound = false; notifyPrefs.desktop = false;
        toast(window.Notification && Notification.permission === 'denied'
          ? 'desktop notifications blocked by your browser — bell muted'
          : 'bell muted');
      }
    } else {
      notifyPrefs.sound = false; notifyPrefs.desktop = false;
    }
    saveNotifyPrefs();
    renderNotifyToggle();
  }

  // ---------- file upload (drag & drop and paste) ----------
  let toastTimer = null;
  function toast(msg) {
    let el = $('#toast');
    if (!el) {
      el = document.createElement('div');
      el.id = 'toast';
      document.body.appendChild(el);
    }
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), 4000);
  }

  // ---------- battery & display settings sheet ----------
  // Native modal focus handling keeps form keys and Escape out of xterm.
  function mountOverlay(overlay, onClose = () => {}) {
    document.body.appendChild(overlay);
    overlay.showModal();
    requestAnimationFrame(() => overlay.classList.add('visible'));
    let closing = false;
    const close = () => {
      if (closing) return;
      closing = true;
      overlay.classList.remove('visible');
      setTimeout(() => { overlay.close(); overlay.remove(); onClose(); }, 200);
    };
    overlay.addEventListener('cancel', e => { e.preventDefault(); close(); });
    overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
    return close;
  }

  function paintPerfSheet() {
    if (!perfSheetEl) return;
    const preset = matchedPerfPreset();
    perfSheetEl.querySelectorAll('[data-preset]').forEach(b => {
      b.classList.toggle('on', b.dataset.preset === preset);
    });
    const seg = (key, val) => {
      perfSheetEl.querySelectorAll(`[data-perf="${key}"]`).forEach(b => {
        b.classList.toggle('on', b.dataset.val === String(val));
      });
    };
    seg('mirror', perfPrefs.mirror);
    seg('cursorBlink', perfPrefs.cursorBlink ? '1' : '0');
    seg('uiEffects', perfPrefs.uiEffects);
    seg('fancyGlyphs', perfPrefs.fancyGlyphs ? '1' : '0');
    seg('webgl', perfPrefs.webgl ? '1' : '0');
    seg('bgPaint', perfPrefs.bgPaint);
    seg('stream', perfPrefs.stream || 'full');
  }

  function showPerfSettings() {
    if (perfSheetEl) { paintPerfSheet(); return; }
    const overlay = document.createElement('dialog');
    overlay.className = 'confirm-overlay perf-overlay';
    overlay.setAttribute('aria-label', 'Battery and display');
    overlay.innerHTML = `
      <div class="confirm-box perf-sheet">
        <div class="confirm-title">battery &amp; display</div>
        <p class="perf-hint">streaming is full-fidelity by default (every byte paints). saver may drop frames to save battery.</p>
        <div class="perf-presets" role="group" aria-label="presets">
          <button type="button" class="perf-chip" data-preset="normal">look</button>
          <button type="button" class="perf-chip" data-preset="high">balanced</button>
          <button type="button" class="perf-chip" data-preset="max">battery</button>
        </div>
        <div class="perf-rows">
          <div class="perf-row">
            <span class="perf-label">mirror glow</span>
            <div class="perf-seg" role="group" aria-label="mirror glow">
              <button type="button" data-perf="mirror" data-val="blur">blur</button>
              <button type="button" data-perf="mirror" data-val="plain">plain</button>
              <button type="button" data-perf="mirror" data-val="off">off</button>
            </div>
          </div>
          <div class="perf-row">
            <span class="perf-label">cursor blink</span>
            <div class="perf-seg" role="group" aria-label="cursor blink">
              <button type="button" data-perf="cursorBlink" data-val="1">on</button>
              <button type="button" data-perf="cursorBlink" data-val="0">off</button>
            </div>
          </div>
          <div class="perf-row">
            <span class="perf-label">ui polish</span>
            <div class="perf-seg" role="group" aria-label="ui polish">
              <button type="button" data-perf="uiEffects" data-val="full">full</button>
              <button type="button" data-perf="uiEffects" data-val="light">light</button>
              <button type="button" data-perf="uiEffects" data-val="none">off</button>
            </div>
          </div>
          <div class="perf-row">
            <span class="perf-label">glyph detail</span>
            <div class="perf-seg" role="group" aria-label="glyph detail">
              <button type="button" data-perf="fancyGlyphs" data-val="1">fancy</button>
              <button type="button" data-perf="fancyGlyphs" data-val="0">plain</button>
            </div>
          </div>
          <div class="perf-row">
            <span class="perf-label">renderer</span>
            <div class="perf-seg" role="group" aria-label="renderer">
              <button type="button" data-perf="webgl" data-val="1">webgl</button>
              <button type="button" data-perf="webgl" data-val="0">DOM</button>
            </div>
          </div>
          <div class="perf-row">
            <span class="perf-label">bg paint</span>
            <div class="perf-seg" role="group" aria-label="background paint">
              <button type="button" data-perf="bgPaint" data-val="pause">pause</button>
              <button type="button" data-perf="bgPaint" data-val="live">live</button>
            </div>
          </div>
          <div class="perf-row">
            <span class="perf-label">streaming</span>
            <div class="perf-seg" role="group" aria-label="streaming fidelity">
              <button type="button" data-perf="stream" data-val="full">full</button>
              <button type="button" data-perf="stream" data-val="saver">saver</button>
            </div>
          </div>
        </div>
        <div class="confirm-actions">
          <button type="button" class="confirm-btn confirm-yes perf-done">done</button>
        </div>
      </div>`;
    perfSheetEl = overlay;
    const close = mountOverlay(overlay, () => { if (perfSheetEl === overlay) perfSheetEl = null; });
    paintPerfSheet();
    overlay.querySelector('.perf-done').addEventListener('click', close);
    overlay.addEventListener('click', e => {
      const presetBtn = e.target.closest('[data-preset]');
      if (presetBtn) { applyPerfPreset(presetBtn.dataset.preset); return; }
      const knob = e.target.closest('[data-perf]');
      if (!knob) return;
      const key = knob.dataset.perf;
      const raw = knob.dataset.val;
      if (key === 'mirror') setPerfPrefs({ mirror: raw });
      else if (key === 'uiEffects') setPerfPrefs({ uiEffects: raw });
      else if (key === 'cursorBlink') setPerfPrefs({ cursorBlink: raw === '1' });
      else if (key === 'fancyGlyphs') setPerfPrefs({ fancyGlyphs: raw === '1' });
      else if (key === 'webgl') setPerfPrefs({ webgl: raw === '1' });
      else if (key === 'bgPaint') setPerfPrefs({ bgPaint: raw });
      else if (key === 'stream') setPerfPrefs({ stream: raw });
    });
  }

  // Compress only formats that usually shrink substantially. Already-compressed
  // images, videos, archives and documents go through unchanged.
  const COMPRESSIBLE_UPLOAD = /\.(txt|md|json|jsonl|csv|tsv|xml|html?|css|js|jsx|ts|tsx|svg|log|sql|py|sh|yml|yaml|toml|ini|conf)$/i;
  async function uploadBody(file) {
    if (file.size < 256 * 1024 || !COMPRESSIBLE_UPLOAD.test(file.name || '') || !('CompressionStream' in window)) {
      return { body: file, compressed: false };
    }
    try {
      const stream = file.stream().pipeThrough(new CompressionStream('gzip'));
      const compressed = await new Response(stream).blob();
      // A small saving isn't worth the CPU and transfer overhead.
      if (compressed.size < file.size * .85) return { body: compressed, compressed: true };
    } catch {}
    return { body: file, compressed: false };
  }

  // Upload over HTTP with progress reporting (XHR exposes upload.onprogress).
  async function uploadFile(file, onProgress) {
    const { body, compressed } = await uploadBody(file);
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', `/api/upload?name=${encodeURIComponent(file.name)}`);
      xhr.setRequestHeader('x-token', token);
      xhr.setRequestHeader('content-type', 'application/octet-stream');
      if (compressed) xhr.setRequestHeader('x-upload-encoding', 'gzip');
      xhr.addEventListener('load', () => {
        const h = xhr.getResponseHeader('X-Session');
        if (h) token = h;
      });
      xhr.upload.onprogress = e => {
        if (e.lengthComputable && onProgress) onProgress(Math.min(file.size, e.loaded / body.size * file.size), e.total);
      };
      xhr.onreadystatechange = () => {
        if (xhr.readyState !== 4) return;
        if (xhr.status === 401) { logout(); reject(new Error('unauthorized')); return; }
        let j = null;
        try { j = JSON.parse(xhr.responseText); } catch {}
        if (xhr.status >= 200 && xhr.status < 300 && j && j.ok) resolve(j.path);
        else reject(new Error((j && j.error) || 'upload failed'));
      };
      xhr.onerror = () => reject(new Error('network error'));
      xhr.send(body);
    });
  }

  // Upload files to the server and paste their paths at the terminal cursor.
  let dropOverlay = null, dropCounter = null, dropInk = null, dropInverse = null;
  const uploadQueue = [];
  let uploadQueueRunning = false;
  const UPLOAD_CONCURRENCY = 3;
  function ensureDropOverlay() {
    if (dropOverlay) return dropOverlay;
    dropOverlay = document.createElement('div');
    dropOverlay.className = 'drop-overlay';
    dropOverlay.style.setProperty('--drop-p', '0%');
    dropOverlay.innerHTML = `
      <div class="drop-veil" aria-hidden="true"></div>
      <div class="drop-ink" aria-hidden="true"></div>
      <div class="drop-content">
        <div class="drop-logo" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="56" height="56" fill="none" stroke="currentColor"
               stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="17 8 12 3 7 8"/>
            <line x1="12" y1="3" x2="12" y2="15"/>
          </svg>
        </div>
        <div class="drop-counter" aria-hidden="true">00.00</div>
        <div class="drop-counter drop-counter-inverse" aria-hidden="true">00.00</div>
        <div class="drop-hint">drop to upload</div>
      </div>
      <div class="drop-details" aria-hidden="true">
        <span class="drop-position"></span><span class="drop-size"></span>
        <span class="drop-filename"></span><span class="drop-speed"></span>
      </div>
    `;
    dropCounter = dropOverlay.querySelector('.drop-counter');
    dropInk = dropOverlay.querySelector('.drop-ink');
    dropInverse = dropOverlay.querySelector('.drop-counter-inverse');
    term.element.appendChild(dropOverlay);
    return dropOverlay;
  }

  function setDropProgressVisual(pct, ts = performance.now()) {
    if (!dropOverlay) return;
    const width = dropOverlay.clientWidth;
    const height = dropOverlay.clientHeight;
    if (!width || !height) return;
    const edgeX = width * Math.max(0, Math.min(100, pct)) / 100;
    const edge = Array.from({ length: 41 }, (_, i) => {
      const y = height * i / 40;
      const envelope = Math.sin(Math.PI * y / height) ** .6;
      const wave = (Math.sin(y * .032 - ts * .0021) * 5 + Math.sin(y * .067 + ts * .0014) * 2.4) * envelope;
      return `${Math.min(width + 14, Math.max(-14, edgeX + wave)).toFixed(2)}px ${y.toFixed(2)}px`;
    });
    const shape = `polygon(0 0,${edge.join(',')},0 100%)`;
    dropInk.style.clipPath = shape;
    dropInverse.style.clipPath = shape;
  }

  // smoothed big counter: the displayed value eases toward the real upload %
  // so it never jumps. Liquid fill tracks the same eased value.
  let dropTarget = 0, dropDisplay = 0, dropRaf = null, dropLast = 0, dropFinishing = false;
  const FINISH_DUR = 220;
  function setDropCounter(pct) {
    dropTarget = Math.max(0, Math.min(100, pct));
    if (!dropRaf) {
      dropRaf = requestAnimationFrame(t => { dropLast = t; tickDropCounter(t); });
    }
  }
  function resetDropCounter() {
    if (dropRaf) { cancelAnimationFrame(dropRaf); dropRaf = null; }
    dropTarget = 0; dropDisplay = 0; dropFinishing = false;
    dropOverlay.querySelectorAll('.drop-counter').forEach(el => { el.textContent = '00.00'; });
    setDropProgressVisual(0);
  }
  function tickDropCounter(ts) {
    const dt = Math.min(48, Math.max(1, ts - dropLast || 1));
    dropLast = ts;
    if (dropTarget >= 100 && !dropFinishing) { startFinishFade(); return; }
    const diff = dropTarget - dropDisplay;
    if (Math.abs(diff) < 0.005) dropDisplay = dropTarget;
    else dropDisplay += diff * Math.min(1, dt * 0.014);
    dropOverlay.querySelectorAll('.drop-counter').forEach(el => { el.textContent = dropDisplay.toFixed(2).padStart(5, '0'); });
    setDropProgressVisual(dropDisplay, ts);
    if (dropOverlay.classList.contains('uploading')) {
      dropRaf = requestAnimationFrame(tickDropCounter);
    } else {
      dropRaf = null;
    }
  }
  // upload finished: fill to 100, counter eases to 100, overlay fades out
  function startFinishFade() {
    dropFinishing = true;
    if (dropRaf) { cancelAnimationFrame(dropRaf); dropRaf = null; }
    const from = dropDisplay;
    const start = performance.now();
    if (dropOverlay) {
      dropOverlay.classList.add('finishing');
    }
    const step = now => {
      const t = Math.min(1, (now - start) / FINISH_DUR);
      const e = 1 - Math.pow(1 - t, 3);
      dropDisplay = from + (100 - from) * e;
      dropOverlay.querySelectorAll('.drop-counter').forEach(el => { el.textContent = dropDisplay.toFixed(2).padStart(5, '0'); });
      setDropProgressVisual(dropDisplay, now);
      if (t < 1) {
        requestAnimationFrame(step);
      } else {
        if (dropOverlay) dropOverlay.classList.remove('uploading', 'show', 'finishing');
        dropFinishing = false;
      }
    };
    requestAnimationFrame(step);
  }

  function startUploadingUI() {
    ensureDropOverlay();
    resetDropCounter();
    dropOverlay.classList.remove('finishing');
    dropOverlay.classList.add('uploading', 'show');
  }
  function hideUploadUI(completed = true) {
    if (dropFinishing) return; // finish fade owns dismissal
    if (completed && dropOverlay && dropOverlay.classList.contains('uploading')) {
      dropTarget = 100;
      startFinishFade();
      return;
    }
    if (dropRaf) { cancelAnimationFrame(dropRaf); dropRaf = null; }
    dropFinishing = false;
    if (dropOverlay) dropOverlay.classList.remove('uploading', 'show', 'finishing');
    setDropProgressVisual(0);
  }

  function uploadFiles(files) {
    if (!files.length) return;
    uploadQueue.push(files);
    if (uploadQueueRunning) return;
    uploadQueueRunning = true;
    void (async () => {
      startUploadingUI();
      focusTerm();
      let lastSucceeded = false;
      while (uploadQueue.length) {
        const batch = uploadQueue.shift();
        const sizeMB = bytes => (bytes / 1048576).toFixed(1);
        const positionEl = dropOverlay.querySelector('.drop-position');
        const filenameEl = dropOverlay.querySelector('.drop-filename');
        const sizeEl = dropOverlay.querySelector('.drop-size');
        const speedEl = dropOverlay.querySelector('.drop-speed');
        const total = batch.reduce((sum, f) => sum + f.size, 0);
        const progress = new Array(batch.length).fill(0);
        const results = new Array(batch.length);
        let next = 0, completed = 0, lastLoaded = 0, lastTime = performance.now(), speed = 0;
        let nextToPaste = 0;
        const pasteReady = () => {
          while (nextToPaste < batch.length && results[nextToPaste] !== undefined) {
            if (results[nextToPaste]) term.paste(results[nextToPaste]);
            nextToPaste++;
          }
        };
        const updateDetails = () => {
          const loaded = progress.reduce((sum, bytes) => sum + bytes, 0);
          const now = performance.now();
          if (now - lastTime >= 250) {
            const instant = (loaded - lastLoaded) / ((now - lastTime) / 1000);
            speed = speed ? speed * .65 + instant * .35 : instant;
            speedEl.textContent = `${sizeMB(speed)} MB/s`;
            lastLoaded = loaded;
            lastTime = now;
          }
          sizeEl.textContent = `${sizeMB(loaded)} / ${sizeMB(total)} MB`;
          setDropCounter(total ? loaded / total * 100 : 100);
        };
        positionEl.textContent = `01 / ${String(batch.length).padStart(2, '0')}`;
        filenameEl.textContent = batch[0].name || 'pasted-image.png';
        filenameEl.title = filenameEl.textContent;
        sizeEl.textContent = `0.0 / ${sizeMB(total)} MB`;
        speedEl.textContent = '0 MB/s';
        resetDropCounter();
        const worker = async () => {
          while (next < batch.length) {
            const i = next++;
            const f = batch[i];
            try {
              const p = await uploadFile(f, bytes => {
                progress[i] = Math.min(f.size, bytes);
                updateDetails();
              });
              progress[i] = f.size;
              results[i] = p;
              lastSucceeded = true;
            } catch (err) {
              results[i] = null;
              toast('upload failed: ' + err.message);
            }
            pasteReady();
            completed++;
            positionEl.textContent = `${String(Math.min(completed + 1, batch.length)).padStart(2, '0')} / ${String(batch.length).padStart(2, '0')}`;
            filenameEl.textContent = batch[Math.min(completed, batch.length - 1)].name || 'pasted-image.png';
            filenameEl.title = filenameEl.textContent;
            updateDetails();
          }
        };
        await Promise.all(Array.from({ length: Math.min(UPLOAD_CONCURRENCY, batch.length) }, worker));
        // The next queued batch starts with a fresh counter; only the final
        // batch gets the completion fade.
        if (uploadQueue.length) lastSucceeded = false;
      }
      uploadQueueRunning = false;
      hideUploadUI(lastSucceeded);
    })();
  }

  function pasteTerminalClipboard(e) {
    if (terminalUiBlocked()) return;
    const files = [...(e.clipboardData?.files || [])];
    const types = [...(e.clipboardData?.types || [])];
    // Handle the browser's actual paste payload synchronously. Dictation apps
    // such as Voquill place their transcript on the clipboard and synthesize
    // Ctrl+V / Ctrl+Shift+V / Shift+Insert; an async clipboard.read() after that
    // key event can be denied or arrive after the browser has moved focus.
    if (!files.length && !types.includes('text/plain')) return;
    e.preventDefault();
    e.stopPropagation();
    if (files.length) uploadFiles(files);
    else {
      const text = e.clipboardData.getData('text/plain');
      if (text) { rememberClipboard(text); term.paste(text); }
    }
  }

  function setupFileDrop() {
    const el = term.element;
    let depth = 0;
    const hasFiles = e => e.dataTransfer && [...e.dataTransfer.types].includes('Files');

    el.addEventListener('dragenter', e => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      depth++;
      el.classList.add('drop-active');
      ensureDropOverlay().classList.add('show');
    });
    el.addEventListener('dragover', e => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = 'copy';
    });
    el.addEventListener('dragleave', () => {
      if (--depth <= 0) {
        depth = 0;
        el.classList.remove('drop-active');
        ensureDropOverlay().classList.remove('show');
      }
    });
    el.addEventListener('drop', e => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      depth = 0;
      el.classList.remove('drop-active');
      const files = [...(e.dataTransfer.files || [])];
      const overlay = ensureDropOverlay();
      if (!files.length) { overlay.classList.remove('show'); return; }
      void uploadFiles(files);
    });

    // Capture before xterm's own paste listener so files and text use one path.
    el.addEventListener('paste', pasteTerminalClipboard, true);

    // never let the browser navigate to a file dropped outside the terminal
    window.addEventListener('dragover', e => e.preventDefault());
    window.addEventListener('drop', e => e.preventDefault());
  }

  // ---------- mobile assist controls ----------
  // Send helper keys straight to the PTY. Synthetic KeyboardEvents are
  // untrusted on mobile browsers and may be ignored by xterm's hidden textarea.
  function pressKey(o) {
    let data = '';
    if (o.ctrlKey && o.key && o.key.length === 1) {
      data = String.fromCharCode(o.key.toUpperCase().charCodeAt(0) & 31);
    } else {
      const app = !!(term.modes && term.modes.applicationCursorKeysMode);
      data = {
        Escape: '\x1b',
        Tab: '\t',
        Enter: '\r',
        Backspace: '\x7f',
        ArrowUp: app ? '\x1bOA' : '\x1b[A',
        ArrowDown: app ? '\x1bOB' : '\x1b[B',
        ArrowRight: app ? '\x1bOC' : '\x1b[C',
        ArrowLeft: app ? '\x1bOD' : '\x1b[D',
      }[o.key] || '';
    }
    if (data) queueInput(data);
  }

  // map a touch clientX/Y to a buffer cell
  function cellAt(x, y) {
    const rect = term.element.querySelector('.xterm-screen').getBoundingClientRect();
    const col = Math.max(0, Math.min(term.cols - 1, Math.floor((x - rect.left) / (rect.width / term.cols))));
    const row = Math.max(0, Math.min(term.rows - 1, Math.floor((y - rect.top) / (rect.height / term.rows))));
    return { col, row };
  }

  function selectWordAt(x, y) {
    const { col, row } = cellAt(x, y);
    const line = term.buffer.active.getLine(row);
    if (!line) return;
    const text = line.translateToString(true);
    if (col >= text.length) return;
    const re = /\S+/g;
    let m, start = col, end = col;
    while ((m = re.exec(text))) {
      if (col >= m.index && col < m.index + m[0].length) { start = m.index; end = m.index + m[0].length - 1; break; }
    }
    term.select(start, row, end - start + 1);
  }

  function setupMobileControls() {
    if (!isMobile) return;

    const host = document.createElement('div');
    host.id = 'assist';
    host.className = 'assist';
    host.innerHTML = `
      <div class="assist-backdrop"></div>
      <div class="assist-menu">
        <div class="assist-head">
          <span>terminal helper</span>
          <button class="assist-dismiss" type="button" aria-label="close helper">×</button>
        </div>
        <div class="am-grid">
          <button class="am-btn" data-k="esc">esc</button>
          <button class="am-btn" data-k="tab">tab</button>
          <button class="am-btn am-arrow" data-k="up" aria-label="up">↑</button>
          <button class="am-btn" data-k="enter">⏎</button>
          <button class="am-btn" data-k="bs">⌫</button>
          <button class="am-btn am-ctrl" data-ctrl>ctrl</button>
          <button class="am-btn am-arrow" data-k="left" aria-label="left">←</button>
          <button class="am-btn am-arrow" data-k="down" aria-label="down">↓</button>
          <button class="am-btn am-arrow" data-k="right" aria-label="right">→</button>
          <button class="am-btn am-more" data-more aria-label="more actions">•••</button>
        </div>
        <div class="am-clipboard-actions" role="group" aria-label="clipboard actions">
          <button class="am-btn am-action am-paste" type="button" data-act="paste">paste</button>
          <button class="am-btn am-action" type="button" data-act="copy">copy</button>
          <button class="am-btn am-action" type="button" data-act="clipboard"
                  aria-controls="assist-clipboard" aria-expanded="false">clipboard</button>
        </div>
        <div id="assist-clipboard" class="am-clipboard" role="region" aria-label="clipboard" hidden>
          <label for="assist-clipboard-text">clipboard text</label>
          <textarea id="assist-clipboard-text" rows="3" placeholder="Paste or type text here…"
                    autocapitalize="off" autocorrect="off" autocomplete="off" spellcheck="false"
                    aria-describedby="assist-clipboard-hint"></textarea>
          <p id="assist-clipboard-hint" class="am-clipboard-hint" role="status">Read your clipboard, or long-press the text box and choose Paste.</p>
          <div class="am-clipboard-tools">
            <button class="am-btn am-action" type="button" data-act="clipboard-read">read clipboard</button>
            <button class="am-btn am-action" type="button" data-act="clipboard-copy" disabled>copy text</button>
            <button class="am-btn am-action am-paste" type="button" data-act="clipboard-paste" disabled>paste to terminal</button>
          </div>
          <div class="am-clipboard-head">
            <span>recent in this tab</span>
            <button class="am-btn am-action" type="button" data-act="clipboard-clear" disabled>clear history</button>
          </div>
          <div class="am-clipboard-history" aria-label="recent clipboard text"></div>
        </div>
        <div class="am-letters" hidden></div>
        <div class="am-actions" hidden>
          <button class="am-btn am-action" data-act="selectall">select all</button>
          <button class="am-btn am-action am-upload" data-act="upload">upload</button>
          <button id="performance-mode" class="am-btn am-action am-performance"
                  data-act="performance">battery · balanced</button>
          <div class="am-wide-row">
            <span class="am-wide-label">width <b id="wide-val">1.0x</b></span>
            <input id="wide-slider" type="range" min="1" max="3" step="0.1" value="1" aria-label="terminal width scale">
          </div>
        </div>
      </div>
      <button class="assist-fab" aria-label="open helper controls" aria-expanded="false" title="helper controls">
        <span class="assist-symbol" aria-hidden="true">?</span>
      </button>
    `;
    document.body.appendChild(host);

    const fab = host.querySelector('.assist-fab');
    const ctrlBtn = host.querySelector('[data-ctrl]');
    const moreBtn = host.querySelector('[data-more]');
    const lettersEl = host.querySelector('.am-letters');
    const actionsEl = host.querySelector('.am-actions');
    const backdrop = host.querySelector('.assist-backdrop');
    const dismissBtn = host.querySelector('.assist-dismiss');
    const menu = host.querySelector('.assist-menu');
    const menuHandle = host.querySelector('.assist-head');
    const clipboardBtn = host.querySelector('[data-act="clipboard"]');
    const clipboardPanel = host.querySelector('.am-clipboard');
    const clipboardText = host.querySelector('#assist-clipboard-text');
    const clipboardHint = host.querySelector('#assist-clipboard-hint');
    const clipboardList = host.querySelector('.am-clipboard-history');
    const pasteBtn = host.querySelector('[data-act="paste"]');
    const readClipboardBtn = host.querySelector('[data-act="clipboard-read"]');

    function resizeHelperMenu() {
      requestAnimationFrame(() => {
        savedMenu = placeMenu(menu.offsetLeft, menu.offsetTop);
        localStore.setItem('webmux-helper-panel', JSON.stringify(savedMenu));
      });
    }

    function syncClipboardText() {
      const empty = !clipboardText.value;
      host.querySelector('[data-act="clipboard-copy"]').disabled = empty;
      host.querySelector('[data-act="clipboard-paste"]').disabled = empty;
    }
    function setClipboardText(text) {
      clipboardText.value = text;
      syncClipboardText();
    }
    clipboardText.addEventListener('input', syncClipboardText);
    // Leave native paste alone: on iOS this editable field is the reliable
    // fallback when readText is unavailable or Safari denies clipboard access.
    clipboardText.addEventListener('paste', e => {
      rememberClipboard(e.clipboardData?.getData('text/plain'));
      clipboardHint.textContent = 'Edit the text, then tap paste to terminal.';
    });

    refreshClipboardHistory = () => {
      clipboardList.replaceChildren();
      host.querySelector('[data-act="clipboard-clear"]').disabled = !clipboardHistory.length;
      if (!clipboardHistory.length) {
        const empty = document.createElement('p');
        empty.className = 'am-clipboard-hint';
        empty.textContent = 'Copied and pasted text appears here.';
        clipboardList.appendChild(empty);
      }
      for (const text of clipboardHistory) {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'am-btn am-clip';
        const preview = text.replace(/\s+/g, ' ').slice(0, 120) || '(whitespace)';
        b.textContent = preview;
        b.setAttribute('aria-label', 'load recent text: ' + preview);
        b.addEventListener('click', () => {
          setClipboardText(text);
          clipboardHint.textContent = 'Recent text loaded — edit, copy or paste it.';
          clipboardText.scrollIntoView({ block: 'nearest' });
        });
        clipboardList.appendChild(b);
      }
      if (!clipboardPanel.hidden) resizeHelperMenu();
    };

    function setClipboard(on) {
      clipboardPanel.hidden = !on;
      clipboardBtn.classList.toggle('active', on);
      clipboardBtn.setAttribute('aria-expanded', String(on));
      if (on) { setCtrl(false); setMore(false); }
      else if (document.activeElement === clipboardText) clipboardText.blur();
      resizeHelperMenu();
      if (on) requestAnimationFrame(() => clipboardText.scrollIntoView({ block: 'nearest' }));
    }

    function canPasteClipboard() {
      if (viewOnlyAttach || spectatorMode) { toast('view only — reclaim control to paste'); return false; }
      if (!ws || ws.readyState !== 1 || pendingSwitch) { toast('terminal not connected — try again'); return false; }
      return true;
    }
    function pasteClipboardText(text) {
      if (!text || !canPasteClipboard()) return;
      rememberClipboard(text);
      // Use xterm's paste path so multiline text respects bracketed paste.
      term.paste(text);
      toast('pasted');
    }

    let clipboardBusy = false;
    async function readHelperClipboard(paste = false) {
      if (clipboardBusy || (paste && !canPasteClipboard())) return;
      clipboardBusy = true;
      pasteBtn.disabled = readClipboardBtn.disabled = true;
      try {
        if (!window.isSecureContext || !navigator.clipboard?.readText) throw new Error('no clipboard read api');
        // Invoke directly from the click, before any await or focus change:
        // Safari requires transient user activation for this call.
        const text = await navigator.clipboard.readText();
        if (paste) {
          if (text) pasteClipboardText(text);
          else toast('clipboard has no text');
        } else {
          setClipboardText(text);
          rememberClipboard(text);
          clipboardHint.textContent = text ? 'Clipboard loaded — edit, copy or paste it.' : 'Clipboard has no text. You can paste or type in the text box.';
        }
      } catch {
        setClipboard(true);
        clipboardHint.textContent = 'Long-press the text box → Paste, then tap paste to terminal.';
        clipboardText.focus({ preventScroll: true });
      } finally {
        clipboardBusy = false;
        pasteBtn.disabled = readClipboardBtn.disabled = false;
      }
    }

    async function copyHelperText(text) {
      if (!text) return;
      if (await copyText(text, { focusTerminal: false })) toast('copied');
      else {
        setClipboard(true);
        setClipboardText(text);
        clipboardHint.textContent = 'Long-press the selected text and choose Copy.';
        clipboardText.focus({ preventScroll: true });
        clipboardText.select();
      }
    }

    // A-Z strip for ctrl+letter
    for (const ch of 'abcdefghijklmnopqrstuvwxyz') {
      const b = document.createElement('button');
      b.className = 'am-btn am-letter';
      b.textContent = ch.toUpperCase();
      b.addEventListener('click', () => {
        if (ctrlActive) {
          pressKey({ key: ch, code: 'Key' + ch.toUpperCase(), ctrlKey: true });
          setCtrl(false);
        }
      });
      lettersEl.appendChild(b);
    }
    let ctrlActive = false;
    function setCtrl(on) {
      ctrlActive = on;
      ctrlBtn.classList.toggle('active', on);
      lettersEl.hidden = !on;
      if (on) setClipboard(false);
      resizeHelperMenu();
    }
    let moreOpen = false;
    function setMore(on) {
      moreOpen = on;
      moreBtn.classList.toggle('active', on);
      moreBtn.setAttribute('aria-expanded', String(on));
      actionsEl.hidden = !on;
      if (on) setClipboard(false);
      resizeHelperMenu();
    }

    // width slider: 1.0x = normal, up to 3.0x wide with horizontal scroll.
    // #term grows to (100vw * scale) so fit() yields proportionally more
    // columns — wide TUIs (btop) instead of squished. 1.0x means off.
    const wideRow = host.querySelector('.am-wide-row');
    const wideSlider = host.querySelector('#wide-slider');
    const wideVal = host.querySelector('#wide-val');
    let wideFitTimer = 0;
    function applyWide(scale, save = true) {
      scale = Math.max(1, Math.min(3, +scale || 1));
      const on = scale > 1.01;
      document.body.classList.toggle('wide2x', on);
      document.body.style.setProperty('--wide-scale', String(scale));
      if (wideSlider) wideSlider.value = String(scale);
      if (wideVal) wideVal.textContent = scale.toFixed(1) + 'x';
      if (wideRow) wideRow.classList.toggle('on', on);
      if (save) localStore.setItem('webmux-wide-scale', String(scale));
      // refit after layout settles so the PTY actually grows to the new width
      clearTimeout(wideFitTimer);
      wideFitTimer = setTimeout(() => { fitSafe(); scheduleMirrorUpdate(); }, 120);
    }
    if (wideSlider) {
      wideSlider.addEventListener('input', () => applyWide(wideSlider.value));
      wideSlider.addEventListener('change', () => applyWide(wideSlider.value));
    }
    try {
      const savedScale = +(localStore.getItem('webmux-wide-scale') || 1);
      if (Number.isFinite(savedScale) && savedScale > 1.01) applyWide(savedScale, false);
      // migrate the old 2x toggle for anyone who had it on
      else if (localStore.getItem('webmux-wide2x') === '1') {
        localStore.removeItem('webmux-wide2x');
        applyWide(2);
      }
    } catch {}

    // draggable fab: drag to move, tap to toggle menu
    const fabBounds = () => {
      const barsBottom = $('#tabs')?.closest('.bar')?.getBoundingClientRect().bottom || 76;
      const pad = 12;
      return {
        minX: pad,
        maxX: Math.max(pad, window.innerWidth - fab.offsetWidth - pad),
        minY: barsBottom + 8,
        maxY: Math.max(barsBottom + 8, window.innerHeight - fab.offsetHeight - pad),
      };
    };
    const placeFab = (x, y) => {
      const b = fabBounds();
      const nx = Math.max(b.minX, Math.min(b.maxX, x));
      const ny = Math.max(b.minY, Math.min(b.maxY, y));
      fab.style.left = nx + 'px'; fab.style.top = ny + 'px';
      fab.style.right = 'auto'; fab.style.bottom = 'auto';
      return { x: nx, y: ny };
    };
    const menuBounds = () => {
      const barsBottom = $('#tabs')?.closest('.bar')?.getBoundingClientRect().bottom || 76;
      const pad = 12;
      const viewport = window.visualViewport;
      const left = viewport?.offsetLeft || 0, top = viewport?.offsetTop || 0;
      const width = viewport?.width || window.innerWidth, height = viewport?.height || window.innerHeight;
      const minY = Math.max(barsBottom + 8, top + pad);
      // Keep the editor and its actions scrollable above the iOS keyboard.
      menu.style.maxHeight = Math.max(44, top + height - minY - pad) + 'px';
      return {
        minX: left + pad,
        maxX: Math.max(left + pad, left + width - menu.offsetWidth - pad),
        minY,
        maxY: Math.max(minY, top + height - menu.offsetHeight - pad),
      };
    };
    const placeMenu = (x, y) => {
      const b = menuBounds();
      const nx = Math.max(b.minX, Math.min(b.maxX, x));
      const ny = Math.max(b.minY, Math.min(b.maxY, y));
      menu.style.left = nx + 'px'; menu.style.top = ny + 'px';
      menu.style.right = 'auto'; menu.style.bottom = 'auto';
      return { x: nx, y: ny };
    };
    let savedMenu = savedJSON('webmux-helper-panel', null);
    const positionMenu = () => {
      const f = fab.getBoundingClientRect();
      const m = { width: menu.offsetWidth, height: menu.offsetHeight };
      let pos;
      if (savedMenu && Number.isFinite(savedMenu.x) && Number.isFinite(savedMenu.y)) {
        pos = placeMenu(savedMenu.x, savedMenu.y);
      } else {
        const x = f.left + f.width / 2 > window.innerWidth / 2
          ? f.right - m.width : f.left;
        const y = f.top - m.height - 10 >= menuBounds().minY
          ? f.top - m.height - 10 : f.bottom + 10;
        pos = placeMenu(x, y);
      }
      menu.style.transformOrigin =
        `${f.left + f.width / 2 - pos.x}px ${f.top + f.height / 2 - pos.y}px`;
      return pos;
    };
    let saved = savedJSON('webmux-fab', null);
    if (saved && Number.isFinite(saved.x) && Number.isFinite(saved.y)) {
      saved = placeFab(saved.x, saved.y);
      localStore.setItem('webmux-fab', JSON.stringify(saved));
    } else {
      requestAnimationFrame(() => {
        const r = fab.getBoundingClientRect();
        const pos = placeFab(r.left, r.top);
        localStore.setItem('webmux-fab', JSON.stringify(pos));
      });
    }
    let dragging = false, didDrag = false, sx = 0, sy = 0, fx = 0, fy = 0;
    const dismissKeyboard = () => {
      if (term.textarea) term.textarea.blur();
      const active = document.activeElement;
      if (active && /^(INPUT|TEXTAREA)$/.test(active.tagName)) active.blur();
    };
    fab.addEventListener('touchstart', dismissKeyboard, { capture: true, passive: true });
    fab.addEventListener('pointerdown', e => {
      dismissKeyboard();
      dragging = true; didDrag = false;
      sx = e.clientX; sy = e.clientY;
      const r = fab.getBoundingClientRect(); fx = r.left; fy = r.top;
      try { fab.setPointerCapture(e.pointerId); } catch {}
    });
    fab.addEventListener('pointermove', e => {
      if (!dragging) return;
      const dx = e.clientX - sx, dy = e.clientY - sy;
      if (!didDrag && Math.hypot(dx, dy) < 10) return;
      didDrag = true;
      placeFab(fx + dx, fy + dy);
    });
    const stopDrag = () => {
      if (!dragging) return;
      dragging = false;
      if (didDrag) {
        const r = fab.getBoundingClientRect();
        localStore.setItem('webmux-fab', JSON.stringify({ x: r.left, y: r.top }));
      }
    };
    fab.addEventListener('pointerup', stopDrag);
    fab.addEventListener('pointercancel', stopDrag);
    let menuDragging = false, msx = 0, msy = 0, mlx = 0, mly = 0;
    menuHandle.addEventListener('pointerdown', e => {
      if (e.target.closest('.assist-dismiss')) return;
      dismissKeyboard();
      menuDragging = true;
      msx = e.clientX; msy = e.clientY;
      const r = menu.getBoundingClientRect(); mlx = r.left; mly = r.top;
      menu.classList.add('dragging');
      try { menuHandle.setPointerCapture(e.pointerId); } catch {}
      e.preventDefault();
    });
    menuHandle.addEventListener('pointermove', e => {
      if (!menuDragging) return;
      savedMenu = placeMenu(mlx + e.clientX - msx, mly + e.clientY - msy);
    });
    const stopMenuDrag = () => {
      if (!menuDragging) return;
      menuDragging = false;
      menu.classList.remove('dragging');
      if (savedMenu) localStore.setItem('webmux-helper-panel', JSON.stringify(savedMenu));
    };
    menuHandle.addEventListener('pointerup', stopMenuDrag);
    menuHandle.addEventListener('pointercancel', stopMenuDrag);
    window.addEventListener('resize', () => {
      const r = fab.getBoundingClientRect();
      const pos = placeFab(r.left, r.top);
      localStore.setItem('webmux-fab', JSON.stringify(pos));
      savedMenu = placeMenu(menu.offsetLeft, menu.offsetTop);
      localStore.setItem('webmux-helper-panel', JSON.stringify(savedMenu));
    });
    const onVisualViewport = () => { if (host.classList.contains('open')) resizeHelperMenu(); };
    window.visualViewport?.addEventListener('resize', onVisualViewport);
    window.visualViewport?.addEventListener('scroll', onVisualViewport);
    fab.addEventListener('click', () => {
      if (didDrag) { didDrag = false; return; }
      dismissKeyboard();
      const open = !host.classList.contains('open');
      if (open) {
        positionMenu();
        void menu.offsetWidth;
        host.classList.add('open');
      } else {
        host.classList.remove('open');
      }
      fab.setAttribute('aria-expanded', String(open));
    });
    const closeHelper = () => {
      if (document.activeElement === clipboardText) clipboardText.blur();
      host.classList.remove('open');
      fab.setAttribute('aria-expanded', 'false');
    };
    backdrop.addEventListener('click', closeHelper);
    dismissBtn.addEventListener('click', closeHelper);
    host.addEventListener('keydown', e => {
      if (e.key !== 'Escape') return;
      e.preventDefault();
      e.stopPropagation();
      if (!clipboardPanel.hidden) { setClipboard(false); clipboardBtn.focus(); }
      else { closeHelper(); fab.focus(); }
    });

    // hidden file input for the upload action
    let fileInput = null;
    function openFilePicker() {
      if (!fileInput) {
        fileInput = document.createElement('input');
        fileInput.type = 'file';
        fileInput.multiple = true;
        fileInput.style.display = 'none';
        document.body.appendChild(fileInput);
        fileInput.addEventListener('change', () => {
          const files = [...(fileInput.files || [])];
          fileInput.value = '';
          if (!files.length) return;
          uploadFiles(files);
        });
      }
      fileInput.click();
    }

    const KEY = {
      esc: { key: 'Escape', code: 'Escape' },
      tab: { key: 'Tab', code: 'Tab' },
      enter: { key: 'Enter', code: 'Enter' },
      bs: { key: 'Backspace', code: 'Backspace' },
      up: { key: 'ArrowUp', code: 'ArrowUp' },
      down: { key: 'ArrowDown', code: 'ArrowDown' },
      left: { key: 'ArrowLeft', code: 'ArrowLeft' },
      right: { key: 'ArrowRight', code: 'ArrowRight' },
    };

    host.addEventListener('click', e => {
      const k = e.target.closest('[data-k]');
      if (k) { const s = KEY[k.dataset.k]; if (s) pressKey(s); return; }
      if (e.target.closest('[data-ctrl]')) { setCtrl(!ctrlActive); return; }
      if (e.target.closest('[data-more]')) { setMore(!moreOpen); return; }
      const act = e.target.closest('[data-act]');
      if (act) {
        const a = act.dataset.act;
        if (a === 'copy') {
          if (term.hasSelection()) void copyHelperText(term.getSelection());
          else toast('nothing selected — long-press text to select');
        } else if (a === 'paste') {
          void readHelperClipboard(true);
        } else if (a === 'clipboard') {
          setClipboard(clipboardPanel.hidden);
        } else if (a === 'clipboard-read') {
          void readHelperClipboard();
        } else if (a === 'clipboard-copy') {
          void copyHelperText(clipboardText.value);
        } else if (a === 'clipboard-paste') {
          pasteClipboardText(clipboardText.value);
        } else if (a === 'clipboard-clear') {
          clipboardHistory.length = 0;
          refreshClipboardHistory();
        } else if (a === 'selectall') {
          term.selectAll(); toast('all selected — tap copy');
        } else if (a === 'upload') {
          openFilePicker();
        } else if (a === 'performance') {
          showPerfSettings();
        }
      }
    });

    refreshClipboardHistory();
    applyPerformanceMode();

    // ---------- selection mode ----------
    // Long-press enters a copy mode: capture-phase touch handlers own all
    // touches so the terminal stops scrolling/swiping/zooming, and dragging
    // extends a real text selection. A toolbar at the bottom does copy/done.
    const selEl = term.element;
    let selMode = false, selAnchor = null, selBar = null;
    let lpTimer = null, lpStart = null;

    function selectRange(ax, ay, bx, by) {
      const cols = term.cols;
      ax = Math.max(0, Math.min(cols - 1, ax));
      bx = Math.max(0, Math.min(cols - 1, bx));
      ay = Math.max(0, Math.min(term.rows - 1, ay));
      by = Math.max(0, Math.min(term.rows - 1, by));
      let a = ay * cols + ax;
      let b = by * cols + bx;
      if (a > b) { const t = a; a = b; b = t; }
      term.select(a % cols, Math.floor(a / cols), b - a + 1);
    }

    function showSelBar() {
      if (!selBar) {
        selBar = document.createElement('div');
        selBar.className = 'sel-bar';
        selBar.innerHTML = `
          <button class="sel-btn sel-close" aria-label="done">✕</button>
          <span class="sel-label">drag to select</span>
          <button class="sel-btn sel-copy">copy</button>`;
        selBar.querySelector('.sel-close').addEventListener('click', exitSelMode);
        selBar.querySelector('.sel-copy').addEventListener('click', () => {
          const sel = term.getSelection();
          if (sel) { copyText(sel); toast('copied'); }
          exitSelMode();
        });
        document.body.appendChild(selBar);
      }
      selBar.classList.add('show');
    }
    function hideSelBar() { if (selBar) selBar.classList.remove('show'); }

    function enterSelMode(x, y) {
      selMode = true;
      selEl.classList.add('sel-mode');
      selEl.style.touchAction = 'none';
      selAnchor = cellAt(x, y);
      selectWordAt(x, y);
      showSelBar();
    }
    function exitSelMode() {
      selMode = false;
      selEl.classList.remove('sel-mode');
      selEl.style.touchAction = '';
      selAnchor = null;
      hideSelBar();
    }

    // capture-phase: while in selection mode, block every other touch handler
    selEl.addEventListener('touchstart', e => {
      if (!selMode) return;
      e.preventDefault(); e.stopImmediatePropagation();
      const t = e.touches[0];
      selAnchor = cellAt(t.clientX, t.clientY);
      const c = selAnchor;
      selectRange(c.col, c.row, c.col, c.row);
    }, { capture: true, passive: false });

    selEl.addEventListener('touchmove', e => {
      if (!selMode) return;
      e.preventDefault(); e.stopImmediatePropagation();
      const t = e.touches[0];
      const c = cellAt(t.clientX, t.clientY);
      if (selAnchor) selectRange(selAnchor.col, selAnchor.row, c.col, c.row);
    }, { capture: true, passive: false });

    const endSelTouch = e => { if (selMode) e.stopImmediatePropagation(); };
    selEl.addEventListener('touchend', endSelTouch, { capture: true });
    selEl.addEventListener('touchcancel', endSelTouch, { capture: true });

    // long-press on the terminal -> enter selection mode
    const cancelLP = () => { if (lpTimer) { clearTimeout(lpTimer); lpTimer = null; } };
    selEl.addEventListener('touchstart', e => {
      if (e.touches.length !== 1 || host.classList.contains('open')) { cancelLP(); lpStart = null; return; }
      const t = e.touches[0];
      lpStart = { x: t.clientX, y: t.clientY };
      cancelLP();
      lpTimer = setTimeout(() => {
        lpTimer = null;
        if (!lpStart || selMode) return;
        enterSelMode(lpStart.x, lpStart.y);
      }, 450);
    }, { passive: true });
    selEl.addEventListener('touchmove', e => {
      if (lpStart && e.touches.length) {
        const t = e.touches[0];
        if (Math.hypot(t.clientX - lpStart.x, t.clientY - lpStart.y) > 12) { cancelLP(); lpStart = null; }
      }
    }, { passive: true });
    selEl.addEventListener('touchend', () => { cancelLP(); lpStart = null; });
    selEl.addEventListener('touchcancel', () => { cancelLP(); lpStart = null; });
  }

  // ---------- ctrl radial wheel (browser-blocked shortcuts) ----------
  const CTRL_WHEEL_ITEMS = [
    { key: 'n', hint: 'new' },
    { key: 't', hint: 'tab' },
    { key: 'w', hint: 'close' },
    { key: 's', hint: 'save' },
    { key: 'f', hint: 'find' },
    { key: 'p', hint: 'print' },
    { key: 'o', hint: 'open' },
    { key: 'r', hint: 'reload' },
    { key: 'l', hint: 'clear' },
    { key: 'a', hint: 'all' },
    { key: 'z', hint: 'suspend' },
    { key: 'd', hint: 'eof' },
  ];

  function setupCtrlWheel() {
    if (!term) return;
    const COUNT = CTRL_WHEEL_ITEMS.length;
    const SLICE = 360 / COUNT;
    const DEAD = 44;
    const RADIUS = 172;
    const BEAM_LEN = 72;
    const MIN_SCALE = 0.92;
    const MAX_SCALE = 1.14;
    const MAX_LIFT = 8;
    const MIN_ALPHA = 0.42;
    const MAX_ALPHA = 1;
    const PROX_SIGMA = SLICE * 1.35;
    let active = false;
    let anchorX = 0;
    let anchorY = 0;
    let selected = -1;
    let moveRaf = 0;
    let pendingX = 0;
    let pendingY = 0;

    const sectorAngle = i => i * SLICE;
    const mouseAngle = (dx, dy) => (Math.atan2(dx, -dy) * 180 / Math.PI + 360) % 360;
    const angDist = (a, b) => {
      let d = Math.abs(a - b) % 360;
      return d > 180 ? 360 - d : d;
    };
    const proximity = (mouseAng, itemAng) => {
      const d = angDist(mouseAng, itemAng);
      if (d >= PROX_SIGMA * 2) return 0;
      const t = 1 - d / (PROX_SIGMA * 1.6);
      return Math.max(0, t * t * (3 - 2 * t));
    };

    const root = document.createElement('div');
    root.className = 'ctrl-wheel';
    root.innerHTML = `
      <div class="cw-dim"></div>
      <div class="cw-hub">
        <div class="cw-beam"></div>
        <div class="cw-items"></div>
        <div class="cw-mark" aria-hidden="true">
          <div class="cw-mark-inner">
            <svg class="cw-mark-icon" viewBox="0 0 64 64" width="40" height="40">
              <rect x="8" y="8" width="48" height="48" rx="7" fill="currentColor" opacity=".15"/>
              <rect x="8" y="47" width="48" height="9" rx="4.5" fill="currentColor" opacity=".55"/>
              <text x="13" y="33" font-family="ui-monospace,monospace" font-size="22" font-weight="600" fill="currentColor">›</text>
            </svg>
            <span class="cw-mark-key"></span>
          </div>
        </div>
      </div>`;
    document.body.appendChild(root);

    let animBest = -1;

    const hub = root.querySelector('.cw-hub');
    const beam = root.querySelector('.cw-beam');
    const markEl = root.querySelector('.cw-mark');
    const markInner = root.querySelector('.cw-mark-inner');
    const markKey = root.querySelector('.cw-mark-key');
    const itemsHost = root.querySelector('.cw-items');
    beam.style.setProperty('--beam-len', BEAM_LEN + 'px');

    const itemEls = CTRL_WHEEL_ITEMS.map((item, i) => {
      const el = document.createElement('div');
      el.className = 'cw-item';
      el.style.setProperty('--a', sectorAngle(i) + 'deg');
      el.style.setProperty('--r', RADIUS + 'px');
      el.style.setProperty('--delay', (i * 14) + 'ms');
      el.textContent = `⌃${item.key.toUpperCase()}`;
      itemsHost.appendChild(el);
      return el;
    });

    function aimBeam(angle, show) {
      beam.style.setProperty('--beam', angle + 'deg');
      beam.classList.toggle('on', show);
    }

    function pulseMark(kind) {
      markInner.classList.remove('arrive');
      markKey.classList.remove('swap');
      if (!kind) return;
      const el = kind === 'swap' ? markKey : markInner;
      el.classList.remove(kind);
      void el.offsetWidth;
      el.classList.add(kind);
    }

    function setItemVisual(el, p, visible, chosen) {
      if (!visible) {
        el.style.setProperty('--s', '1');
        el.style.setProperty('--lift', '0px');
        el.style.color = 'rgba(255,255,255,0.38)';
        el.style.fontWeight = '500';
        el.classList.remove('lead');
        return;
      }
      const s = MIN_SCALE + (MAX_SCALE - MIN_SCALE) * p;
      const lift = MAX_LIFT * p;
      const alpha = MIN_ALPHA + (MAX_ALPHA - MIN_ALPHA) * p;
      el.style.setProperty('--s', s.toFixed(3));
      el.style.setProperty('--lift', lift.toFixed(1) + 'px');
      if (chosen) {
        el.style.color = 'rgba(255,255,255,1)';
        el.style.fontWeight = '700';
      } else {
        el.style.color = `rgba(255,255,255,${alpha.toFixed(3)})`;
        el.style.fontWeight = p > 0.6 ? '600' : '500';
      }
      el.classList.toggle('lead', !chosen && p > 0.75);
    }

    function resetItems() {
      itemEls.forEach(el => {
        el.classList.remove('lead', 'chosen');
        setItemVisual(el, 0, false, false);
      });
    }

    function updatePick(mx, my) {
      const dx = mx - anchorX;
      const dy = my - anchorY;
      const dist = Math.hypot(dx, dy);
      const show = dist >= DEAD;
      const angle = mouseAngle(dx, dy);
      aimBeam(angle, show);

      let best = -1;
      let bestP = 0;
      const prox = new Array(COUNT);
      for (let i = 0; i < COUNT; i++) {
        const p = show ? proximity(angle, sectorAngle(i)) : 0;
        prox[i] = p;
        if (p > bestP) { bestP = p; best = i; }
      }

      const bestChanged = show && best >= 0 && best !== animBest;
      const hadChoice = hub.classList.contains('has-choice');

      for (let i = 0; i < COUNT; i++) {
        const chosen = show && i === best;
        setItemVisual(itemEls[i], prox[i], show, chosen);
        itemEls[i].classList.toggle('chosen', chosen);
      }

      if (show && best >= 0) {
        markKey.textContent = `⌃${CTRL_WHEEL_ITEMS[best].key.toUpperCase()}`;
        if (!hadChoice) {
          hub.classList.add('has-choice');
          pulseMark('arrive');
        } else if (bestChanged) {
          pulseMark('swap');
        }
      } else if (hadChoice) {
        hub.classList.remove('has-choice');
      }
      animBest = show ? best : -1;

      const markScale = show ? 1 + bestP * 0.08 : 1;
      markEl.style.transform =
        `translate(-50%, -50%) scale(${markScale.toFixed(3)})`;

      const idx = show ? best : -1;
      if (idx !== selected) {
        selected = idx;
        hub.classList.toggle('has-pick', idx >= 0);
      }
    }

    function openWheel(x, y) {
      active = true;
      anchorX = x;
      anchorY = y;
      selected = -1;
      animBest = -1;
      hub.style.left = x + 'px';
      hub.style.top = y + 'px';
      itemEls.forEach(el => el.classList.remove('fired', 'lead'));
      hub.classList.remove('has-pick', 'has-choice', 'open');
      resetItems();
      aimBeam(0, false);
      root.classList.add('active');
      requestAnimationFrame(() => hub.classList.add('open'));
      updatePick(x, y);
    }

    function closeWheel() {
      active = false;
      selected = -1;
      hub.classList.remove('open', 'has-pick', 'has-choice');
      root.classList.remove('active');
      animBest = -1;
      resetItems();
      aimBeam(0, false);
      markEl.style.transform = '';
      markInner.classList.remove('arrive');
      markKey.classList.remove('swap');
    }

    function commit() {
      if (selected < 0) { closeWheel(); focusTerm(); return; }
      const item = CTRL_WHEEL_ITEMS[selected];
      itemEls[selected].classList.add('fired');
      pressKey({ key: item.key, code: 'Key' + item.key.toUpperCase(), ctrlKey: true });
      setTimeout(closeWheel, 160);
      focusTerm();
    }

    function onMove(e) {
      if (!active) return;
      pendingX = e.clientX;
      pendingY = e.clientY;
      if (moveRaf) return;
      moveRaf = requestAnimationFrame(() => {
        moveRaf = 0;
        updatePick(pendingX, pendingY);
      });
    }

    function onUp(e) {
      if (!active) return;
      if (e.type === 'mouseup' && e.button !== 0) return;
      commit();
    }

    function onKeyUp(e) {
      if (!active) return;
      if (e.key === 'Escape') {
        e.preventDefault();
        closeWheel();
        focusTerm();
        return;
      }
      if (e.key === 'Control') {
        e.preventDefault();
        if (selected >= 0) commit();
        else closeWheel();
        focusTerm();
      }
    }

    term.element.addEventListener('mousedown', e => {
      if (!e.ctrlKey || e.button !== 0 || e.metaKey) return;
      e.preventDefault();
      e.stopPropagation();
      openWheel(e.clientX, e.clientY);
    }, true);

    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
    document.addEventListener('keyup', onKeyUp);
  }

  // ---------- terminal ----------
  // detect mobile/touch device for smaller default font
  const isMobile = 'ontouchstart' in window || navigator.maxTouchPoints > 0;
  const savedFontSize = +(localStore.getItem('webmux-fontsize') || 0);
  const FONT_DEFAULT = isMobile ? 11 : 14;
  const FONT_MIN = 4;
  const FONT_MAX = 24;
  const defaultFontSize = (savedFontSize >= FONT_MIN && savedFontSize <= FONT_MAX)
    ? savedFontSize
    : FONT_DEFAULT;
  if (savedFontSize && (savedFontSize < FONT_MIN || savedFontSize > FONT_MAX)) {
    localStore.setItem('webmux-fontsize', String(FONT_DEFAULT));
  }
  // Wire safety only — high enough that ultrawides at ~14px don't leave gutters.
  // (Old 400-col clamp left gray empty cells on the right.)
  const MAX_TERM_COLS = 720;
  const MAX_TERM_ROWS = 200;

  function fitSafe() {
    if (!fit || !term) return;
    fit.fit();
    syncFontSizeLabel();
  }

  function wireSize() {
    return {
      cols: Math.max(20, Math.min(MAX_TERM_COLS, term?.cols || 80)),
      rows: Math.max(5, Math.min(MAX_TERM_ROWS, term?.rows || 24)),
    };
  }

  function persistFontSize() {
    if (!term) return;
    const n = Math.max(FONT_MIN, Math.min(FONT_MAX, term.options.fontSize | 0));
    term.options.fontSize = n;
    localStore.setItem('webmux-fontsize', String(n));
    syncFontSizeLabel();
  }

  function syncFontSizeLabel() {
    const el = $('#font-size-label');
    if (!el) return;
    const n = term ? (term.options.fontSize | 0) : defaultFontSize;
    el.textContent = 'A';
    el.title = `font ${n}px · click to reset`;
    el.setAttribute('aria-label', `font size ${n}px, click to reset`);
  }

  function nudgeFont(delta) {
    if (!term || !fit) return;
    const cur = term.options.fontSize | 0;
    const next = Math.max(FONT_MIN, Math.min(FONT_MAX, cur + delta));
    if (next === cur) {
      toast(next <= FONT_MIN ? `font min ${FONT_MIN}px` : `font max ${FONT_MAX}px`);
      return;
    }
    term.options.fontSize = next;
    persistFontSize();
    fit.fit(); // plain fit — never auto-bump after a manual change
    scheduleMirrorUpdate();
    focusTerm();
  }

  function resetFontSize() {
    if (!term || !fit) return;
    term.options.fontSize = FONT_DEFAULT;
    persistFontSize();
    fit.fit();
    scheduleMirrorUpdate();
    focusTerm();
  }

  function makeTerm() {
    term = new Terminal({
      cursorBlink: !!perfPrefs.cursorBlink,
      allowProposedApi: true,
      fontFamily: "'JetBrainsMonoNF', monospace",
      fontSize: defaultFontSize,
      lineHeight: 1,
      letterSpacing: 0,
      scrollback: 0,
      customGlyphs: !!perfPrefs.fancyGlyphs,
      rescaleOverlappingGlyphs: !!perfPrefs.fancyGlyphs,
      drawBoldTextInBrightColors: false,
      theme: {
        background: '#000000', foreground: '#c8cdd6',
        cursor: '#e8b15a', cursorAccent: '#0b0c0e',
        selectionBackground: 'rgba(255,255,255,0.35)',
        black: '#16181c', brightBlack: '#5c6370',
        red: '#d96c6c', brightRed: '#e89393',
        green: '#7fbf7f', brightGreen: '#a3d9a3',
        yellow: '#e8b15a', brightYellow: '#f2cd8b',
        blue: '#6f9fd8', brightBlue: '#9cbeea',
        magenta: '#b58cc9', brightMagenta: '#d0b0e0',
        cyan: '#6fbcbc', brightCyan: '#9cd6d6',
        white: '#c8cdd6', brightWhite: '#eceff4',
      },
    });
    fit = new FitAddon.FitAddon();
    term.loadAddon(fit);
    if (window.WebLinksAddon?.WebLinksAddon) term.loadAddon(new WebLinksAddon.WebLinksAddon());
    if (window.Unicode11Addon?.Unicode11Addon) {
      term.loadAddon(new Unicode11Addon.Unicode11Addon());
      term.unicode.activeVersion = '11';
    }
    // A missing addon must never prevent the terminal from starting (e.g. a
    // stale CDN 404 for a newly deployed asset).
    if (window.ImageAddon?.ImageAddon) {
      term.loadAddon(new window.ImageAddon.ImageAddon({
        enableSizeReports: true,
        pixelLimit: 4 * 1024 * 1024,
        storageLimit: 32,
        sixelSizeLimit: 8 * 1024 * 1024,
        iipSizeLimit: 8 * 1024 * 1024,
      }));
    }
    term.open($('#term'));
    // Speech-to-text / OS dictation can update xterm's hidden textarea using
    // replacement input rather than the insertText event xterm forwards. Route
    // only those unhandled edits through xterm's paste path (bracketed paste is
    // preserved); leave ordinary typing, composition and clipboard paste alone.
    if (term.textarea) {
      const textarea = term.textarea;
      let composing = false;
      textarea.addEventListener('compositionstart', () => { composing = true; });
      textarea.addEventListener('compositionend', () => { composing = false; });
      textarea.addEventListener('input', e => {
        if (composing || e.isComposing || !/^(insertReplacementText|insertFromDictation)$/.test(e.inputType)) return;
        // xterm's own input listener runs first and ignores these input types.
        // Some dictation engines provide data, others only change textarea.value.
        const text = e.data || textarea.value;
        if (!text) return;
        term.paste(text);
        textarea.value = '';
      });
    }
    applyRenderer();
    fitSafe();
    syncFontSizeLabel();

    term.onData(d => {
      if (viewOnlyAttach || spectatorMode) return;
      queueInput(d);
    });
    let lastSentSize = { cols: term.cols, rows: term.rows };
    let resizeSendTimer = 0;
    term.onResize(({ cols, rows }) => {
      updateStatusBar();
      // Debounce PTY resizes — fit storms + window-size fights look like tear.
      clearTimeout(resizeSendTimer);
      resizeSendTimer = setTimeout(() => {
        if (!ws || ws.readyState !== 1) return;
        const { cols: c, rows: r } = wireSize();
        if (c === lastSentSize.cols && r === lastSentSize.rows) return;
        lastSentSize = { cols: c, rows: r };
        ws.send(JSON.stringify({ t: 'r', cols: c, rows: r }));
      }, 80);
    });
    term.element.addEventListener('contextmenu', e => e.preventDefault());

    // cursor position tracking (no-op while status bar is CSS-hidden)
    term.onCursorMove(() => updateStatusBar());

    // --- pinch to zoom font size ---
    let pinchDist = null;
    let pinchFontSize = null;

    term.element.addEventListener('touchstart', e => {
      if (e.touches.length === 2) {
        e.preventDefault();
        const dx = e.touches[0].clientX - e.touches[1].clientX;
        const dy = e.touches[0].clientY - e.touches[1].clientY;
        pinchDist = Math.hypot(dx, dy);
        pinchFontSize = term.options.fontSize;
      }
    }, { passive: false });

    term.element.addEventListener('touchmove', e => {
      if (e.touches.length === 2 && pinchDist !== null) {
        e.preventDefault();
        const dx = e.touches[0].clientX - e.touches[1].clientX;
        const dy = e.touches[0].clientY - e.touches[1].clientY;
        const newDist = Math.hypot(dx, dy);
        const scale = newDist / pinchDist;
        const newSize = Math.round(Math.max(FONT_MIN, Math.min(FONT_MAX, pinchFontSize * scale)));
        // Font only during pinch — fit/resize on touchend (avoids redraw storms).
        if (newSize !== term.options.fontSize) term.options.fontSize = newSize;
      }
    }, { passive: false });

    term.element.addEventListener('touchend', e => {
      if (e.touches.length < 2 && pinchDist !== null) {
        persistFontSize();
        pinchDist = null;
        pinchFontSize = null;
        fitSafe();
      }
    }, { passive: true });

    // --- touch scrolling (single finger only, skips during pinch and horizontal swipe) ---
    let touchStartY = null, touchStartX = null, touchAccum = 0;
    let swipeActive = false; // shared with swipe handler below
    const SCROLL_THRESHOLD = 14 * 0.8;

    term.element.addEventListener('touchstart', e => {
      if (e.touches.length !== 1) {
        touchStartY = null;
        touchStartX = null;
        touchAccum = 0;
        return;
      }
      touchStartY = e.touches[0].clientY;
      touchStartX = e.touches[0].clientX;
      touchAccum = 0;
    }, { passive: true });

    term.element.addEventListener('touchmove', e => {
      if (e.touches.length !== 1 || touchStartY === null) return;
      // don't scroll if horizontal swipe is active
      if (swipeActive) return;
      // wide2x: let mostly-horizontal drags pan the 2x-wide terminal natively
      if (document.body.classList.contains('wide2x')) {
        const dxw = e.touches[0].clientX - touchStartX;
        const dyw = e.touches[0].clientY - touchStartY;
        if (Math.abs(dxw) > Math.abs(dyw)) return; // no preventDefault → native pan-x
      }
      e.preventDefault();
      const deltaY = touchStartY - e.touches[0].clientY;
      touchAccum += deltaY;
      touchStartY = e.touches[0].clientY;
      while (Math.abs(touchAccum) >= SCROLL_THRESHOLD) {
        const direction = touchAccum > 0 ? 1 : -1;
        touchAccum -= direction * SCROLL_THRESHOLD;
        const button = direction > 0 ? 65 : 64;
        const col = Math.round(term.cols / 2);
        const row = Math.round(term.rows / 2);
        if (ws && ws.readyState === 1) queueInput(`\x1b[<${button};${col};${row}M`);
      }
    }, { passive: false });

    term.element.addEventListener('touchend', () => { touchStartY = touchStartX = null; touchAccum = 0; }, { passive: true });
    term.element.addEventListener('touchcancel', () => { touchStartY = touchStartX = null; touchAccum = 0; }, { passive: true });

    // --- swipe left/right to switch tabs with live animation ---
    let swipeStartX = null, swipeStartY = null, swipeStartT = null;
    let swipeLocked = false;
    let swipeRaf = 0;
    let swipePending = null;
    const termEl = term.element;
    const mirrorEl = $('#mirror-canvas');
    const barsEls = document.querySelectorAll('.bar');
    const termContainer = $('#term');

    // capture the current terminal as a snapshot image for smooth transitions
    function captureTerminalSnapshot() {
      const canvases = termEl.querySelectorAll('.xterm-screen canvas');
      const xtermCanvas = canvases[canvases.length - 1];
      if (!xtermCanvas || xtermCanvas.width === 0) return null;
      try {
        const snap = document.createElement('canvas');
        snap.width = xtermCanvas.width;
        snap.height = xtermCanvas.height;
        snap.getContext('2d').drawImage(xtermCanvas, 0, 0);
        // use the canvas's CSS display size, not raw pixel size
        const cssW = xtermCanvas.style.width || (xtermCanvas.width / (window.devicePixelRatio || 1)) + 'px';
        const cssH = xtermCanvas.style.height || (xtermCanvas.height / (window.devicePixelRatio || 1)) + 'px';
        snap.style.cssText = `position:absolute;top:${termEl.offsetTop}px;left:${termEl.offsetLeft}px;width:${cssW};height:${cssH};z-index:20;pointer-events:none`;
        return snap;
      } catch (e) { return null; }
    }

    function applySwipeTransform(offset, opacity, transition) {
      const t = transition || 'none';
      const transform = offset !== null ? `translateX(${offset}px)` : '';
      const op = opacity !== null ? String(opacity) : '';
      const swiping = offset !== null;
      // Grid bg only animates while a swipe reveals it — otherwise the infinite
      // CSS animation keeps the compositor busy for nothing under an opaque term.
      document.body.classList.toggle('swipe-reveal', swiping);
      termEl.classList.toggle('xterm-swiping', swiping);
      termEl.style.transition = t;
      termEl.style.transform = transform;
      // Avoid opacity on the live WebGL/canvas node during drag — it forces
      // layer thrash / flicker. Snapshot + bars still fade.
      if (!swiping) termEl.style.opacity = '';
      else if (opacity !== null && transition && transition !== 'none') termEl.style.opacity = op;
      else termEl.style.opacity = '';
      if (mirrorEl) {
        mirrorEl.style.transition = t;
        mirrorEl.style.transform = transform;
        mirrorEl.style.opacity = op;
        mirrorEl.classList.toggle('xterm-swiping', swiping);
      }
      barsEls.forEach(bar => {
        bar.style.transition = t;
        bar.style.transform = transform;
        bar.style.opacity = op;
      });
    }

    function setSwipeTransform(offset, opacity, transition) {
      // Animated settles apply immediately; live drag is rAF-coalesced.
      if (transition && transition !== 'none') {
        if (swipeRaf) { cancelAnimationFrame(swipeRaf); swipeRaf = 0; }
        swipePending = null;
        applySwipeTransform(offset, opacity, transition);
        return;
      }
      swipePending = { offset, opacity, transition };
      if (swipeRaf) return;
      swipeRaf = requestAnimationFrame(() => {
        swipeRaf = 0;
        const p = swipePending;
        swipePending = null;
        if (p) applySwipeTransform(p.offset, p.opacity, p.transition);
      });
    }

    term.element.addEventListener('touchstart', e => {
      if (e.touches.length !== 1) {
        swipeStartX = swipeStartY = swipeStartT = null;
        swipeActive = false; swipeLocked = false;
        setSwipeTransform(null, null);
        return;
      }
      swipeStartX = e.touches[0].clientX;
      swipeStartY = e.touches[0].clientY;
      swipeStartT = Date.now();
      swipeActive = false; swipeLocked = false;
    }, { passive: true });

    term.element.addEventListener('touchmove', e => {
      if (e.touches.length !== 1 || swipeStartX === null) return;
      // wide2x: horizontal drags pan the 2x-wide terminal — don't steal them for tab swipe
      if (document.body.classList.contains('wide2x')) return;
      const dx = e.touches[0].clientX - swipeStartX;
      const dy = e.touches[0].clientY - swipeStartY;

      if (!swipeActive && !swipeLocked) {
        if (Math.abs(dx) > 15 || Math.abs(dy) > 15) {
          if (Math.abs(dx) > Math.abs(dy) * 1.5) { swipeActive = true; }
          else { swipeLocked = true; return; }
        }
        return;
      }

      if (!swipeActive) return;
      e.preventDefault();

      const activeWin = windows.find(w => w.active);
      if (!activeWin) return;
      const idx = windows.indexOf(activeWin);
      const canGoLeft = idx < windows.length - 1;
      const canGoRight = idx > 0;

      let offset = dx;
      if ((dx < 0 && !canGoLeft) || (dx > 0 && !canGoRight)) offset = dx * 0.3;

      const opacity = 1 - Math.min(Math.abs(offset) / 400, 0.4);
      setSwipeTransform(offset, opacity, 'none');
    }, { passive: false });

    term.element.addEventListener('touchend', e => {
      if (swipeStartX === null) return;
      const dx = e.changedTouches[0].clientX - swipeStartX;
      const wasActive = swipeActive;
      swipeStartX = swipeStartY = swipeStartT = null;
      swipeActive = false; swipeLocked = false;

      if (!wasActive) { setSwipeTransform(null, null); return; }

      const activeWin = windows.find(w => w.active);
      if (!activeWin) { setSwipeTransform(null, null); return; }
      const idx = windows.indexOf(activeWin);
      const threshold = 80;
      const w = window.innerWidth;

      if ((dx < -threshold && idx < windows.length - 1) || (dx > threshold && idx > 0)) {
        const goingLeft = dx < 0;
        const targetIdx = goingLeft ? idx + 1 : idx - 1;

        // capture snapshot of current terminal BEFORE switching
        const snapshot = captureTerminalSnapshot();

        // switch tab on server immediately
        windows.forEach(x => x.active = x.index === windows[targetIdx].index);
        renderTabs();
        api('/api/select', { index: windows[targetIdx].index, session: currentSession }).then(refreshTabs);
        reportFocus();

        if (snapshot) {
          // place snapshot covering the live terminal, offset by current drag position
          snapshot.style.transform = `translateX(${dx}px)`;
          snapshot.style.opacity = String(1 - Math.min(Math.abs(dx) / 400, 0.4));
          termContainer.appendChild(snapshot);

          // position live terminal (new tab) slightly off-screen in the entry direction
          const entryOffset = goingLeft ? w * 0.15 : -w * 0.15;
          setSwipeTransform(entryOffset, 0.3, 'none');

          // animate both: snapshot slides off, live terminal slides in
          requestAnimationFrame(() => {
            requestAnimationFrame(() => {
              snapshot.style.transition = 'transform .25s ease-out, opacity .25s ease-out';
              snapshot.style.transform = `translateX(${goingLeft ? -w : w}px)`;
              snapshot.style.opacity = '0';
              setTimeout(() => snapshot.remove(), 250);

              // animate live terminal to center
              setSwipeTransform(0, 1, 'transform .25s ease-out, opacity .25s ease-out');
              setTimeout(() => setSwipeTransform(null, null), 250);
            });
          });
        } else {
          // fallback: quick crossfade
          setSwipeTransform(goingLeft ? -w * 0.15 : w * 0.15, 0, 'transform .15s ease, opacity .15s ease');
          setTimeout(() => {
            setSwipeTransform(goingLeft ? w * 0.15 : -w * 0.15, 0, 'none');
            requestAnimationFrame(() => {
              requestAnimationFrame(() => {
                setSwipeTransform(0, 1, 'transform .15s ease, opacity .15s ease');
                setTimeout(() => setSwipeTransform(null, null), 150);
              });
            });
          }, 150);
        }
      } else {
        // snap back
        setSwipeTransform(0, 1, 'transform .25s ease, opacity .25s ease');
        setTimeout(() => setSwipeTransform(null, null), 250);
      }
    }, { passive: true });

    term.element.addEventListener('touchcancel', () => {
      swipeStartX = swipeStartY = swipeStartT = null;
      swipeActive = false;
      swipeLocked = false;
      setSwipeTransform(0, 1, 'transform .25s ease, opacity .25s ease');
      setTimeout(() => setSwipeTransform(null, null), 250);
    }, { passive: true });

    // BEL from any window (tmux passes it through — see server bell options)
    term.onBell(onBell);

    // OSC 52
    term.parser.registerOscHandler(52, data => {
      const idx = data.indexOf(';');
      if (idx === -1) return false;
      const b64 = data.slice(idx + 1);
      if (b64 === '?') return true;
      try { copyText(new TextDecoder().decode(Uint8Array.from(atob(b64), c => c.charCodeAt(0)))); } catch {}
      return true;
    });

    // copy/paste keybinds
    const isMac = /mac/i.test(navigator.platform);
    term.attachCustomKeyEventHandler(e => {
      if (terminalUiBlocked()) return false;
      if (e.type !== 'keydown') return true;
      const copyKey = e.code === 'KeyC' && !e.altKey && (e.metaKey || (e.ctrlKey && (e.shiftKey || term.hasSelection())));
      const pasteKey = e.code === 'KeyV' && !e.altKey && ((isMac && e.metaKey) || (!isMac && e.ctrlKey && e.shiftKey));
      const shiftInsert = e.code === 'Insert' && e.shiftKey && !e.ctrlKey && !e.altKey && !e.metaKey;
      if (copyKey) {
        e.preventDefault(); e.stopPropagation();
        if (term.hasSelection()) { copyText(term.getSelection()); term.clearSelection(); }
        return false;
      }
      // Let the browser dispatch a real paste event. Its clipboardData is
      // available synchronously (including Voquill's simulated paste), while
      // navigator.clipboard.read() may require focus or a separate permission.
      if (pasteKey || shiftInsert) return true;
      return true;
    });

    // Voquill's OS-level paste binding often sends Ctrl+V or Shift+Insert.
    // xterm handles its own Ctrl+Shift+V shortcut, but a plain Ctrl+V would
    // otherwise be forwarded as ^V to the remote shell instead of pasting.
    if (term.textarea) {
      term.textarea.addEventListener('keydown', e => {
        if ((e.code === 'KeyV' && !isMac && e.ctrlKey && !e.altKey && !e.metaKey)
          || (e.code === 'Insert' && e.shiftKey && !e.ctrlKey && !e.altKey && !e.metaKey)) {
          e.stopImmediatePropagation();
        }
      }, true);
    }

    let raf = null;
    let fitDebounce = 0;
    new ResizeObserver(() => {
      cancelAnimationFrame(raf);
      clearTimeout(fitDebounce);
      raf = requestAnimationFrame(() => {
        fitDebounce = setTimeout(() => { fitSafe(); scheduleMirrorUpdate(); }, 50);
      });
    }).observe($('#term'));

    initMirror();
    setupFileDrop();
    setupMobileControls();
    setupCtrlWheel();
  }

  // ---------- status bar ----------
  // Hidden in CSS; skip DOM work on every cursor move / resize.
  const statusBarEnabled = (() => {
    const el = $('#status-bar');
    if (!el) return false;
    try { return getComputedStyle(el).display !== 'none'; } catch { return false; }
  })();

  function updateStatusBar() {
    if (!statusBarEnabled || !term || !pageVisible) return;
    const buf = term.buffer.active;
    const cur = $('#status-cursor');
    const sz = $('#status-size');
    if (cur) cur.textContent = `${buf.cursorY + 1}:${buf.cursorX + 1}`;
    if (sz) sz.textContent = `${term.cols}×${term.rows}`;
  }

  // ---------- mirror canvas ----------
  function initMirror() {
    const mirror = $('#mirror-canvas');
    const mctx = mirror.getContext('2d', { alpha: false });
    const BARS_HEIGHT = 76;
    let cachedTermCanvas = null;

    function resizeMirror() {
      const w = mirror.parentElement.clientWidth;
      // Decorative strip — full CSS pixels are enough; retina buys little after blur.
      const dpr = 1;
      mirror.width = Math.max(1, Math.floor(w * dpr));
      mirror.height = Math.max(1, Math.floor(BARS_HEIGHT * dpr));
      mirror.style.width = w + 'px';
      mirror.style.height = BARS_HEIGHT + 'px';
      mctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      cachedTermCanvas = null; // layout change — re-resolve next paint
    }
    window.resizeMirror = resizeMirror;
    resizeMirror();
    window.addEventListener('resize', resizeMirror);

    window.updateMirror = function() {
      if (perfPrefs.mirror === 'off' || !pageVisible) return;
      const termEl = $('#term');
      if (!cachedTermCanvas || !cachedTermCanvas.isConnected) {
        const canvases = termEl.querySelectorAll('.xterm-screen canvas');
        cachedTermCanvas = canvases[canvases.length - 1] || null;
      }
      const xtermCanvas = cachedTermCanvas;
      const w = mirror.clientWidth;
      const h = BARS_HEIGHT;

      if (xtermCanvas && xtermCanvas.width > 0) {
        try {
          // capture 1/3 of the bar height from the top of the terminal,
          // then stretch it to fill the entire bar height
          const srcDpr = window.devicePixelRatio || 1;
          const srcH = Math.max(1, Math.floor((h / 3) * srcDpr));
          mctx.save();
          mctx.scale(1, -1);
          mctx.drawImage(
            xtermCanvas,
            0, 0, xtermCanvas.width, srcH,  // source: tiny strip from top
            0, -h, w, h                      // dest: stretched to fill bars
          );
          mctx.restore();
          return;
        } catch (e) {
          cachedTermCanvas = null;
        }
      }

      mctx.fillStyle = '#121226';
      mctx.fillRect(0, 0, w, h);
      const grad = mctx.createLinearGradient(0, 0, w, 0);
      grad.addColorStop(0, '#1a1a2e');
      grad.addColorStop(0.5, '#16162a');
      grad.addColorStop(1, '#121226');
      mctx.fillStyle = grad;
      mctx.fillRect(0, 0, w, h);
    };

    applyPerformanceMode();
    if (perfPrefs.mirror !== 'off') setTimeout(() => scheduleMirrorUpdate(), 500);
  }

  // ---------- websocket ----------
  function connect(opts = {}) {
    if (typeof opts.viewOnly === 'boolean') viewOnlyAttach = opts.viewOnly;
    if (reconnectTimeout) clearTimeout(reconnectTimeout);
    clearPendingSwitch();
    // Detach prior socket handlers so a ticket-reconnect close doesn't loop.
    if (ws) {
      try { ws.onopen = null; ws.onclose = null; ws.onmessage = null; ws.onerror = null; } catch {}
      try { if (ws.readyState === 0 || ws.readyState === 1) ws.close(4000, 'replaced-locally'); } catch {}
    }
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const q = new URLSearchParams();
    if (currentSession) q.set('session', currentSession);
    const sz = wireSize();
    q.set('cols', String(sz.cols));
    q.set('rows', String(sz.rows));
    if (viewOnlyAttach) q.set('view', '1');
    // Bearer via Sec-WebSocket-Protocol, never ?token= (proxy logs, Referer, HARs).
    ws = new WebSocket(`${proto}://${location.host}/ws?${q}`, ['webmux', token]);
    ws.onopen = () => {
      // The connection is usable now. A delayed hide would swallow clicks and
      // could outlive this socket, hiding a subsequent disconnect or takeover.
      $('#disconnected-overlay').hidden = true;
      hideTakeoverActions();
      const text = document.querySelector('#disconnected-overlay .disconnected-text');
      if (text) text.textContent = 'Disconnected';
      applyViewOnlyClientState();
      if (!viewOnlyAttach) focusTerm();
      updateStatusBar();
      reportFocus();
      pushFingerprint();
      pushStreamMode();
    };
    ws.onmessage = e => {
      if (handleWsControl(e.data)) return;
      ingestOutput(e.data);
    };
    ws.onclose = e => {
      clearPendingSwitch();
      $('#disconnected-overlay').hidden = false;
      $('#disconnected-overlay').style.opacity = '1';
      if (e.code === 4001) {
        hideTakeoverActions();
        trySilentReauth().then(ok => (ok ? connect() : logout()));
        return;
      }
      // Another tab took this tmux session — don't reconnect-fight.
      if (e.code === 4004) {
        showTakeoverOverlay();
        return;
      }
      hideTakeoverActions();
      reconnectTimeout = setTimeout(connect, 1200);
    };
  }

  function hideTakeoverActions() {
    const actions = $('#disconnected-actions');
    if (actions) actions.hidden = true;
  }

  function showTakeoverOverlay() {
    const text = document.querySelector('#disconnected-overlay .disconnected-text');
    if (text) text.textContent = 'Replaced by another tab of yours';
    const actions = $('#disconnected-actions');
    if (actions) actions.hidden = false;
  }

  function applyViewOnlyClientState() {
    spectatorMode = !!viewOnlyAttach;
    document.body.classList.toggle('spectator', spectatorMode);
    document.body.classList.toggle('view-only', viewOnlyAttach);
    if (term) term.options.disableStdin = spectatorMode;
    const el = $('#status-mode');
    if (el) {
      el.textContent = viewOnlyAttach ? 'view only' : (spectatorMode ? 'spectator' : 'interactive');
      el.classList.toggle('spectator', spectatorMode);
      el.title = viewOnlyAttach
        ? 'view only — you are not writing; click to reclaim interactive'
        : 'click to toggle view-only watch mode';
    }
  }

  function setWatcherPresence(n) {
    const prev = watcherCount;
    watcherCount = Math.max(0, n | 0);
    // Watchers don't need the "you're being watched" cue — the interactive party does.
    if (viewOnlyAttach) {
      hideWatcherEye();
      return;
    }
    const eye = $('#watcher-eye');
    const countEl = $('#watcher-eye-count');
    if (!eye) return;
    if (watcherCount <= 0) {
      hideWatcherEye();
      return;
    }
    if (countEl) {
      countEl.textContent = String(watcherCount);
      countEl.hidden = watcherCount < 2;
    }
    eye.hidden = false;
    eye.setAttribute('title', watcherCount === 1
      ? '1 viewer watching (view only)'
      : `${watcherCount} viewers watching (view only)`);
    eye.setAttribute('aria-label', eye.getAttribute('title'));
    // First appearance: center intro → fly to top-right (desktop needs a
    // layout flush or the left/top transition never starts).
    if (prev <= 0) {
      eye.classList.remove('docked', 'leaving');
      eye.classList.add('intro');
      void eye.offsetWidth;
      if (watcherEyeTimer) clearTimeout(watcherEyeTimer);
      watcherEyeTimer = setTimeout(() => {
        watcherEyeTimer = 0;
        requestAnimationFrame(() => {
          eye.classList.remove('intro');
          void eye.offsetWidth;
          eye.classList.add('docked');
        });
      }, 1400);
    } else if (!eye.classList.contains('intro')) {
      eye.classList.add('docked');
      eye.classList.remove('leaving');
    }
  }

  function hideWatcherEye() {
    const eye = $('#watcher-eye');
    if (!eye || eye.hidden) return;
    if (watcherEyeTimer) { clearTimeout(watcherEyeTimer); watcherEyeTimer = 0; }
    eye.classList.remove('intro');
    eye.classList.add('leaving');
    setTimeout(() => {
      eye.hidden = true;
      eye.classList.remove('docked', 'leaving', 'intro');
    }, 320);
  }

  // ---------- tabs ----------
  async function refreshTabs() {
    try {
      const q = currentSession ? '?session=' + encodeURIComponent(currentSession) : '';
      const { windows: w, sys } = await api('/api/windows' + q);
      if (sys) sysMem = sys;
      checkMemPressure(sys, w); // rides the existing 3s poll — no extra request
      const oldActive = windows.find(x => x.active)?.index;
      // Compare *structure* only. Memory moves every poll, so including it here
      // would rebuild the whole tab bar every 3s — killing the gauge's CSS
      // transitions and clobbering an open inline-rename input.
      const structure = list => JSON.stringify(list.map(
        ({ index, name, active, panes, bell, dead, deadStatus }) => [index, name, active, panes, bell, dead, deadStatus]));
      const changed = structure(w) !== structure(windows);
      windows = w; // always take the fresh data (the gauges read from it)
      if (changed) {
        const indices = new Set(w.map(x => x.index));
        selectedTabs.forEach(i => { if (!indices.has(i)) selectedTabs.delete(i); });
        const newActive = w.find(x => x.active)?.index;
        if (oldActive !== newActive && newActive !== undefined) {
          lastActiveTabPerSession.set(currentSession, newActive);
          localStore.setItem('webmux-tab-memory', JSON.stringify([...lastActiveTabPerSession]));
          recentTabs = recentTabs.filter(i => i !== newActive);
          recentTabs.unshift(newActive);
          if (recentTabs.length > 10) recentTabs.pop();
        }
        // don't rebuild mid-drag / mid-settle — that teleports the strip
        if ((!tabDrag || !tabDrag.active) && !tabStripBusy) renderTabs();
      }
      updateMemGauges(); // cheap in-place patch; animates via CSS transitions
      reportFocus();
    } catch (e) { refreshSessions().catch(() => {}); }
  }

  function reportFocus() {
    if (!ws || ws.readyState !== 1) return;
    const w = windows.find(x => x.active);
    try {
      ws.send(JSON.stringify({
        t: 'focus',
        session: currentSession || '',
        index: w ? w.index : null,
        name: w ? w.name : '',
      }));
    } catch {}
  }

  function pushFingerprint() {
    if (!token || !lastMe?.fingerprints || !window.webmuxFingerprint) return;
    window.webmuxFingerprint.collect({ stunUrls: lastMe.stunUrls || [] }).then(fp => {
      api('/api/fp', { fp }).catch(() => {});
      if (ws && ws.readyState === 1) {
        try { ws.send(JSON.stringify({ t: 'fp', fp })); } catch {}
      }
    }).catch(() => {});
  }

  function clearSessionDropTargets() {
    document.querySelectorAll('.sess.drop-target').forEach(el => el.classList.remove('drop-target'));
  }

  function hitSessionAt(x, y) {
    const stack = document.elementsFromPoint(x, y);
    for (const el of stack) {
      const sess = el.closest && el.closest('.sess');
      if (sess && sess.dataset.name && sess.dataset.name !== currentSession) return sess;
    }
    return null;
  }

  function removeTabGhost(ghost) {
    if (ghost && ghost.parentNode) ghost.remove();
  }

  function remapIndexCollection(oldToNew) {
    if (!oldToNew.size) return;
    const nextPinned = new Set();
    pinnedTabs.forEach(i => nextPinned.add(oldToNew.has(i) ? oldToNew.get(i) : i));
    pinnedTabs = nextPinned;
    localStore.setItem('webmux-pinned', JSON.stringify([...pinnedTabs]));
    const nextSel = new Set();
    selectedTabs.forEach(i => nextSel.add(oldToNew.has(i) ? oldToNew.get(i) : i));
    selectedTabs = nextSel;
    recentTabs = recentTabs.map(i => oldToNew.has(i) ? oldToNew.get(i) : i);
    if (lastActiveTabPerSession.has(currentSession)) {
      const cur = lastActiveTabPerSession.get(currentSession);
      if (oldToNew.has(cur)) {
        lastActiveTabPerSession.set(currentSession, oldToNew.get(cur));
        localStore.setItem('webmux-tab-memory', JSON.stringify([...lastActiveTabPerSession]));
      }
    }
  }

  // Patch tab nodes in place after move (tmux may renumber). Never rebuild the strip
  // here — a full renderTabs() is what made drops flash/teleport.
  async function syncTabsAfterReorder() {
    try {
      const q = currentSession ? '?session=' + encodeURIComponent(currentSession) : '';
      const { windows: w, sys } = await api('/api/windows' + q);
      if (sys) sysMem = sys;
      const nav = $('#tabs');
      const tabs = [...nav.querySelectorAll('.tab')];
      if (tabs.length !== w.length) {
        windows = w;
        renderTabs();
        return;
      }
      const namesMatch = tabs.every((tab, i) => {
        const nameEl = tab.querySelector('.name');
        return nameEl && nameEl.textContent === w[i].name;
      });
      if (!namesMatch) {
        windows = w;
        renderTabs();
        return;
      }
      const oldToNew = new Map();
      tabs.forEach((tab, i) => {
        const win = w[i];
        const oldIdx = +tab.dataset.index;
        if (oldIdx !== win.index) oldToNew.set(oldIdx, win.index);
        tab.dataset.index = String(win.index);
        const idxEl = tab.querySelector('.idx');
        if (idxEl) idxEl.textContent = win.index;
        tab.classList.toggle('active', !!win.active);
        tab.classList.toggle('dead', !!win.dead);
        const hasActivity = !!win.bell && !win.active;
        tab.classList.toggle('attention', hasActivity);
        tab.classList.toggle('selected', selectedTabs.has(win.index) || selectedTabs.has(oldIdx));
        tab.classList.toggle('pinned', pinnedTabs.has(win.index) || pinnedTabs.has(oldIdx));
      });
      remapIndexCollection(oldToNew);
      // re-apply selection/pin classes with remapped ids
      tabs.forEach((tab, i) => {
        const id = w[i].index;
        tab.classList.toggle('selected', selectedTabs.has(id));
        tab.classList.toggle('pinned', pinnedTabs.has(id));
      });
      windows = w;
      updateMemGauges();
      reportFocus();
    } catch {
      refreshTabs().catch(() => {});
    }
  }

  function measureTabRects(tabs) {
    const map = new Map();
    for (const t of tabs) map.set(t, t.getBoundingClientRect());
    return map;
  }

  // FLIP from current visual positions → post-mutate layout (smooth even mid-transition)
  function flipTabs(tabs, first, onDone) {
    for (const t of tabs) t.style.transition = 'none';
    void document.body.offsetWidth;
    let maxDx = 0;
    for (const t of tabs) {
      const f = first.get(t);
      if (!f) continue;
      const l = t.getBoundingClientRect();
      const dx = f.left - l.left;
      maxDx = Math.max(maxDx, Math.abs(dx));
      t.style.transform = Math.abs(dx) > 0.5 ? `translate3d(${dx}px,0,0)` : '';
    }
    if (maxDx < 1) {
      for (const t of tabs) {
        t.style.transition = '';
        t.style.transform = '';
      }
      if (onDone) onDone();
      return;
    }
    requestAnimationFrame(() => {
      for (const t of tabs) {
        t.style.transition = 'transform .2s cubic-bezier(.22, 1, .36, 1)';
        t.style.transform = '';
      }
      setTimeout(() => {
        for (const t of tabs) {
          t.style.transition = '';
          t.style.transform = '';
        }
        if (onDone) onDone();
      }, 210);
    });
  }

  function endTabDrag(commit) {
    if (!tabDrag) return;
    const state = tabDrag;
    tabDrag = null;
    clearTimeout(state.pressTimer);
    try { state.tab.releasePointerCapture(state.pointerId); } catch {}
    window.removeEventListener('pointermove', state.onMove);
    window.removeEventListener('pointerup', state.onUp);
    window.removeEventListener('pointercancel', state.onUp);
    clearInterval(state.scrollTimer);

    clearSessionDropTargets();
    const nav = state.nav;
    const ghost = state.ghost;
    const tabs = state.tabs.length ? state.tabs : [...nav.querySelectorAll('.tab')];
    const src = state.tab;

    const cleanupChrome = () => {
      document.body.classList.remove('tab-dragging');
      nav.classList.remove('is-reordering');
      for (const t of tabs) {
        t.classList.remove('is-drag-source', 'drag-pending');
        t.style.transform = '';
        t.style.transition = '';
        t.style.opacity = '';
      }
    };

    if (!state.active) {
      src.classList.remove('drag-pending');
      cleanupChrome();
      removeTabGhost(ghost);
      return;
    }

    suppressTabClick = true;
    setTimeout(() => { suppressTabClick = false; }, 40);

    // --- transfer ---
    if (commit && state.overSession) {
      const toSession = state.overSession;
      if (ghost) {
        ghost.style.transition = 'opacity .14s ease, transform .14s ease';
        ghost.classList.add('tab-ghost-drop');
      }
      const first = measureTabRects(tabs);
      for (const t of tabs) {
        t.style.transition = 'none';
        t.style.transform = '';
      }
      src.classList.remove('is-drag-source', 'drag-pending');
      nav.classList.remove('is-reordering');
      flipTabs(tabs.filter(t => t !== src), first, () => {
        cleanupChrome();
        removeTabGhost(ghost);
      });
      api('/api/transfer', {
        fromSession: currentSession,
        toSession,
        index: state.fromIndex,
      }).then(() => { refreshTabs(); refreshSessions(); }).catch(() => alert('Transfer failed'));
      return;
    }

    // --- reorder ---
    if (commit && state.toPos !== state.fromPos) {
      const fromPos = state.fromPos;
      const toPos = state.toPos;
      const target = tabs[toPos];
      const toIndex = target ? +target.dataset.index : state.fromIndex;

      tabStripBusy = true;

      // FIRST: where everything is on screen right now (incl. in-flight tweens)
      const first = measureTabRects(tabs);

      // MUTATE to final order with transitions forced off
      for (const t of tabs) {
        t.style.transition = 'none';
        t.style.transform = '';
      }
      if (target) {
        if (fromPos < toPos) target.after(src);
        else target.before(src);
      }
      src.classList.remove('is-drag-source', 'drag-pending');
      src.style.opacity = '0'; // stay hidden under the ghost until settle
      nav.classList.remove('is-reordering');
      document.body.classList.remove('tab-dragging');

      // Park the ghost exactly on the final slot (no fly-back animation)
      const srcLast = src.getBoundingClientRect();
      if (ghost) {
        ghost.classList.remove('tab-ghost-lift', 'tab-ghost-transfer');
        ghost.style.transition = 'none';
        ghost.style.left = srcLast.left + 'px';
        ghost.style.top = srcLast.top + 'px';
        ghost.style.transform = 'scale(1)';
        ghost.style.opacity = '1';
      }

      const finishDrop = () => {
        src.style.opacity = '';
        for (const t of tabs) {
          t.style.transition = '';
          t.style.transform = '';
          t.style.opacity = '';
        }
        removeTabGhost(ghost);
      };

      // PLAY: siblings glide from their live visual spots into final layout
      flipTabs(tabs.filter(t => t !== src), first, finishDrop);

      if (toIndex !== state.fromIndex) {
        api('/api/move', { from: state.fromIndex, to: toIndex, session: currentSession })
          .then(() => syncTabsAfterReorder())
          .catch(() => refreshTabs())
          .finally(() => { tabStripBusy = false; });
      } else {
        tabStripBusy = false;
      }
      return;
    }

    // --- cancel ---
    if (ghost) {
      const r = src.getBoundingClientRect();
      ghost.style.transition = 'left .2s cubic-bezier(.22, 1, .36, 1), top .2s cubic-bezier(.22, 1, .36, 1), transform .2s ease, opacity .2s ease';
      ghost.style.left = r.left + 'px';
      ghost.style.top = r.top + 'px';
      ghost.style.transform = 'scale(1)';
      ghost.style.opacity = '0';
    }
    const first = measureTabRects(tabs);
    for (const t of tabs) {
      t.style.transition = 'none';
      t.style.transform = '';
    }
    src.classList.remove('is-drag-source', 'drag-pending');
    nav.classList.remove('is-reordering');
    flipTabs(tabs.filter(t => t !== src), first, () => {
      cleanupChrome();
      removeTabGhost(ghost);
    });
  }

  function updateTabDragShifts(state) {
    const tabs = state.tabs;
    const from = state.fromPos;
    const to = state.toPos;
    const w = state.dragWidth;
    for (let i = 0; i < tabs.length; i++) {
      const el = tabs[i];
      if (i === from) {
        el.style.transform = '';
        continue;
      }
      let tx = 0;
      if (from < to && i > from && i <= to) tx = -w;
      else if (from > to && i >= to && i < from) tx = w;
      el.style.transform = tx ? `translate3d(${tx}px,0,0)` : '';
    }
  }

  function computeTabInsertPos(state, clientX) {
    const { fromPos, tabs } = state;
    const scrollDx = state.nav.scrollLeft - state.scrollLeft0;
    const mids = state.mids0.map(m => m - scrollDx);
    let to = fromPos;
    for (let i = 0; i < tabs.length; i++) {
      if (i === fromPos) continue;
      if (i < fromPos) {
        if (clientX < mids[i]) { to = i; break; }
      } else if (clientX > mids[i]) {
        to = i;
      }
    }
    return to;
  }

  function autoScrollTabs(state, clientX) {
    const nav = state.nav;
    const rect = nav.getBoundingClientRect();
    const edge = 36;
    let delta = 0;
    if (clientX < rect.left + edge) delta = -Math.max(2, Math.ceil((edge - (clientX - rect.left)) / 3));
    else if (clientX > rect.right - edge) delta = Math.max(2, Math.ceil((edge - (rect.right - clientX)) / 3));
    if (!delta) {
      clearInterval(state.scrollTimer);
      state.scrollTimer = null;
      state.scrollDelta = 0;
      return;
    }
    state.scrollDelta = delta;
    nav.scrollLeft += delta;
    if (!state.scrollTimer) {
      state.scrollTimer = setInterval(() => {
        if (!tabDrag || tabDrag !== state || !state.scrollDelta) {
          clearInterval(state.scrollTimer);
          state.scrollTimer = null;
          return;
        }
        nav.scrollLeft += state.scrollDelta;
        if (state.lastX != null) {
          const next = computeTabInsertPos(state, state.lastX);
          if (next !== state.toPos) {
            state.toPos = next;
            updateTabDragShifts(state);
          }
        }
      }, 16);
    }
  }

  function beginTabDrag(state, clientX, clientY) {
    if (state.active) return;
    state.active = true;
    clearTimeout(state.pressTimer);
    state.tab.classList.remove('drag-pending');
    try { navigator.vibrate?.(12); } catch {}

    const rect = state.tab.getBoundingClientRect();
    state.offsetX = clientX - rect.left;
    state.offsetY = clientY - rect.top;
    state.dragWidth = rect.width + 3;

    const tabs = [...state.nav.querySelectorAll('.tab')];
    state.tabs = tabs;
    state.fromPos = tabs.indexOf(state.tab);
    state.toPos = state.fromPos;
    state.scrollLeft0 = state.nav.scrollLeft;
    state.mids0 = tabs.map(t => {
      const r = t.getBoundingClientRect();
      return r.left + r.width / 2;
    });
    state.scrollTimer = null;
    state.fromIndex = +state.tab.dataset.index;

    const ghost = state.tab.cloneNode(true);
    ghost.classList.add('tab-ghost');
    ghost.classList.remove('drag-pending', 'is-drag-source');
    ghost.style.width = rect.width + 'px';
    ghost.style.height = rect.height + 'px';
    ghost.style.left = rect.left + 'px';
    ghost.style.top = rect.top + 'px';
    document.body.appendChild(ghost);
    requestAnimationFrame(() => ghost.classList.add('tab-ghost-lift'));
    state.ghost = ghost;

    state.nav.classList.add('is-reordering');
    state.tab.classList.add('is-drag-source');
    void state.nav.offsetWidth;
    document.body.classList.add('tab-dragging');

    try { state.tab.setPointerCapture(state.pointerId); } catch {}
  }

  function bindTabReorder(tab) {
    tab.addEventListener('pointerdown', e => {
      if (e.button !== 0 && e.pointerType === 'mouse') return;
      if (e.target.closest('.close, .respawn, .rename, input')) return;
      if (e.ctrlKey || e.metaKey) return;
      if (tabDrag || tabStripBusy) return;

      const nav = $('#tabs');
      const touch = e.pointerType === 'touch';
      const state = {
        tab,
        nav,
        fromIndex: +tab.dataset.index,
        pointerId: e.pointerId,
        startX: e.clientX,
        startY: e.clientY,
        active: false,
        pressTimer: null,
        ghost: null,
        tabs: [],
        mids0: [],
        scrollLeft0: 0,
        scrollTimer: null,
        fromPos: 0,
        toPos: 0,
        dragWidth: 0,
        offsetX: 0,
        offsetY: 0,
        overSession: null,
        lastX: null,
        touch,
        onMove: null,
        onUp: null,
      };
      tabDrag = state;
      if (touch) tab.classList.add('drag-pending');

      state.onMove = ev => {
        if (ev.pointerId !== state.pointerId) return;
        const dx = ev.clientX - state.startX;
        const dy = ev.clientY - state.startY;

        if (!state.active) {
          if (state.touch) {
            if (Math.hypot(dx, dy) > 12) {
              clearTimeout(state.pressTimer);
              tab.classList.remove('drag-pending');
              tabDrag = null;
              window.removeEventListener('pointermove', state.onMove);
              window.removeEventListener('pointerup', state.onUp);
              window.removeEventListener('pointercancel', state.onUp);
            }
            return;
          }
          if (Math.hypot(dx, dy) < 6) return;
          beginTabDrag(state, ev.clientX, ev.clientY);
        }

        if (!state.active) return;
        ev.preventDefault();

        const ghost = state.ghost;
        if (ghost) {
          ghost.style.left = (ev.clientX - state.offsetX) + 'px';
          ghost.style.top = (ev.clientY - state.offsetY) + 'px';
        }

        const sess = hitSessionAt(ev.clientX, ev.clientY);
        clearSessionDropTargets();
        if (sess) {
          sess.classList.add('drop-target');
          state.overSession = sess.dataset.name;
          state.toPos = state.fromPos;
          updateTabDragShifts(state);
          if (ghost) ghost.classList.add('tab-ghost-transfer');
          clearInterval(state.scrollTimer);
          state.scrollTimer = null;
          return;
        }
        state.overSession = null;
        if (ghost) ghost.classList.remove('tab-ghost-transfer');

        autoScrollTabs(state, ev.clientX);
        state.lastX = ev.clientX;

        const next = computeTabInsertPos(state, ev.clientX);
        if (next !== state.toPos) {
          state.toPos = next;
          updateTabDragShifts(state);
        }
      };

      state.onUp = ev => {
        if (ev.pointerId !== state.pointerId) return;
        endTabDrag(state.active);
      };

      window.addEventListener('pointermove', state.onMove, { passive: false });
      window.addEventListener('pointerup', state.onUp);
      window.addEventListener('pointercancel', state.onUp);

      if (touch) {
        state.pressTimer = setTimeout(() => {
          if (tabDrag !== state || state.active) return;
          beginTabDrag(state, state.startX, state.startY);
        }, 260);
      }
    });

    tab.addEventListener('click', e => {
      if (suppressTabClick) {
        e.preventDefault();
        e.stopImmediatePropagation();
      }
    }, true);
  }

  function renderTabs() {
    const nav = $('#tabs');
    if (nav.querySelector('input.rename')) return;
    nav.textContent = '';
    for (const w of windows) {
      const tab = document.createElement('div');
      const isPinned = pinnedTabs.has(w.index);
      // tmux owns this flag: it's raised when a background window rings BEL and
      // cleared when that window is selected. Single source of truth — no
      // client-side mirror to drift out of sync.
      const hasActivity = !!w.bell && !w.active;
      const isPulsing = currentSession === bellPulseSession && w.index === bellPulseIndex;
      tab.className = 'tab' + (w.active ? ' active' : '') + (selectedTabs.has(w.index) ? ' selected' : '')
        + (isPinned ? ' pinned' : '') + (w.dead ? ' dead' : '') + (hasActivity ? ' attention' : '')
        + (isPulsing ? ' bell-pulse' : '');
      tab.dataset.index = w.index;
      if (hasActivity) tab.title = 'bell — this tab needs attention';

      const idx = document.createElement('span');
      idx.className = 'idx';
      idx.textContent = w.index;
      const name = document.createElement('span');
      name.className = 'name';
      name.textContent = w.name;

      if (hasActivity) {
        const dot = document.createElement('span');
        dot.className = 'activity-dot';
        tab.appendChild(dot);
      }

      if (isPinned) {
        const pin = document.createElement('span');
        pin.className = 'pin-icon';
        pin.textContent = '📌';
        pin.title = 'pinned';
        tab.appendChild(pin);
      }

      const close = document.createElement('span');
      close.className = 'close';
      close.textContent = '×';
      close.title = isPinned ? 'pinned — unpin first' : 'double-click to kill';
      // live memory gauge — visible at a glance, no hover needed
      const mem = document.createElement('span');
      mem.className = 'mem';
      applyMem(mem, w);
      tab.append(idx, name, mem, close);

      // crashed tab: one-click restart, in the dir it was working in
      if (w.dead) {
        const again = document.createElement('span');
        again.className = 'respawn';
        again.textContent = '⟲';
        again.title = (w.deadStatus != null ? `exited ${w.deadStatus}` : 'crashed')
          + (w.cwd ? ` — click to restart in ${w.cwd}` : ' — click to restart');
        again.addEventListener('click', e => {
          e.stopPropagation();
          const cur = windows.find(x => x.index === +tab.dataset.index);
          if (cur) respawnTab(cur);
        });
        tab.insertBefore(again, close);
      }

      tab.addEventListener('click', e => {
        if (suppressTabClick || (tabDrag && tabDrag.active) || tabStripBusy) return;
        if (e.target === close) return;
        const index = +tab.dataset.index;
        if (e.ctrlKey || e.metaKey) {
          e.preventDefault();
          if (selectedTabs.has(index)) selectedTabs.delete(index);
          else selectedTabs.add(index);
          renderTabs();
          return;
        }
        if (selectedTabs.size > 0) { selectedTabs.clear(); renderTabs(); return; }
        windows.forEach(x => x.active = x.index === index);
        renderTabs();
        api('/api/select', { index, session: currentSession }).then(refreshTabs);
        reportFocus();
        focusTerm();
      });

      close.addEventListener('dblclick', e => {
        e.stopPropagation();
        const index = +tab.dataset.index;
        if (pinnedTabs.has(index)) return;
        api('/api/kill', { index, session: currentSession }).then(refreshTabs);
      });
      close.addEventListener('click', e => e.stopPropagation());

      tab.addEventListener('contextmenu', e => {
        e.preventDefault();
        if (tabDrag && tabDrag.tab === tab) return;
        const cur = windows.find(x => x.index === +tab.dataset.index) || w;
        showTabContextMenu(e, tab, name, cur);
      });
      tab.addEventListener('dblclick', e => {
        if (e.target === close) return;
        e.preventDefault();
        const cur = windows.find(x => x.index === +tab.dataset.index) || w;
        startRename(tab, name, cur);
      });

      bindTabReorder(tab);

      nav.appendChild(tab);
    }

    if (selectedTabs.size > 0) {
      const bulk = document.createElement('div');
      bulk.className = 'bulk-close';
      bulk.innerHTML = `<span class="bulk-label">${selectedTabs.size} selected</span><button class="bulk-btn">close</button><button class="bulk-cancel">×</button>`;
      bulk.querySelector('.bulk-btn').addEventListener('click', () => confirmBulkClose());
      bulk.querySelector('.bulk-cancel').addEventListener('click', () => { selectedTabs.clear(); renderTabs(); });
      nav.appendChild(bulk);
    }

    // scroll active tab into center of view (especially useful on mobile)
    requestAnimationFrame(() => scrollActiveTabIntoView(nav));
  }

  function scrollActiveTabIntoView(nav) {
    const activeTab = nav.querySelector('.tab.active');
    if (!activeTab) return;
    const navRect = nav.getBoundingClientRect();
    const tabRect = activeTab.getBoundingClientRect();
    const navCenter = navRect.left + navRect.width / 2;
    const tabCenter = tabRect.left + tabRect.width / 2;
    const offset = tabCenter - navCenter;
    // only scroll if the active tab is significantly off-center
    if (Math.abs(offset) > 20) {
      nav.scrollBy({ left: offset, behavior: 'smooth' });
    }
  }

  function showTabContextMenu(e, tab, nameEl, w) {
    closeContextMenu();
    const menu = document.createElement('div');
    menu.className = 'ctx-menu';
    menu.id = 'ctx-menu';
    const isPinned = pinnedTabs.has(w.index);
    const items = [
      ...(w.dead ? [{ label: 'restart here', action: () => respawnTab(w) }, { label: '─', action: null }] : []),
      { label: 'rename', action: () => startRename(tab, nameEl, w) },
      { label: isPinned ? 'unpin' : 'pin', action: () => togglePin(w.index) },
      { label: '─', action: null },
      { label: 'close', action: () => api('/api/kill', { index: w.index, session: currentSession }).then(refreshTabs), danger: true },
    ];
    for (const item of items) {
      if (item.label === '─') { const sep = document.createElement('div'); sep.className = 'ctx-sep'; menu.appendChild(sep); continue; }
      const el = document.createElement('div');
      el.className = 'ctx-item' + (item.danger ? ' danger' : '');
      el.textContent = item.label;
      el.addEventListener('click', () => { closeContextMenu(); item.action(); });
      menu.appendChild(el);
    }
    menu.style.left = Math.min(e.clientX, window.innerWidth - 160) + 'px';
    menu.style.top = e.clientY + 'px';
    document.body.appendChild(menu);
    setTimeout(() => document.addEventListener('click', closeContextMenu, { once: true }), 0);
  }

  function closeContextMenu() { const m = $('#ctx-menu'); if (m) m.remove(); }

  function togglePin(index) {
    if (pinnedTabs.has(index)) pinnedTabs.delete(index);
    else pinnedTabs.add(index);
    localStore.setItem('webmux-pinned', JSON.stringify([...pinnedTabs]));
    renderTabs();
    showToast(pinnedTabs.has(index) ? 'tab pinned' : 'tab unpinned');
  }

  function confirmBulkClose() {
    const session = currentSession;
    // tmux renumbers after each kill: remove higher indices before lower ones.
    // Freeze the confirmation's targets so later UI changes cannot redirect it.
    const indices = [...selectedTabs].sort((a, b) => b - a);
    const count = indices.length;
    const names = windows.filter(w => selectedTabs.has(w.index)).map(w => w.name).join(', ');
    showConfirm(`Close ${count} window${count > 1 ? 's' : ''}?`, names, `close ${count}`, async () => {
      selectedTabs.clear();
      for (const idx of indices) await api('/api/kill', { index: idx, session }).catch(() => {});
      refreshTabs();
    });
  }

  function showConfirm(title, subtitle, yesLabel, onYes) {
    const overlay = document.createElement('dialog');
    overlay.className = 'confirm-overlay';
    overlay.setAttribute('aria-label', title);
    overlay.innerHTML = `<div class="confirm-box"><div class="confirm-title"></div><div class="confirm-names"></div><div class="confirm-actions"><button class="confirm-btn confirm-yes"></button><button class="confirm-btn confirm-no">cancel</button></div></div>`;
    overlay.querySelector('.confirm-title').textContent = title;
    overlay.querySelector('.confirm-names').textContent = subtitle;
    overlay.querySelector('.confirm-yes').textContent = yesLabel;
    overlay.querySelector('.confirm-no').autofocus = true;
    const close = mountOverlay(overlay);
    overlay.querySelector('.confirm-no').addEventListener('click', close);
    overlay.querySelector('.confirm-yes').addEventListener('click', () => { close(); onYes(); }, { once: true });
  }

  document.addEventListener('keydown', e => {
    if (terminalUiBlocked() || editingField(e.target)) return;
    if (e.key === 'Escape' && selectedTabs.size > 0) { selectedTabs.clear(); renderTabs(); }
  });

  function startRename(tab, nameEl, w) {
    const input = document.createElement('input');
    input.className = 'rename';
    input.value = w.name;
    tab.replaceChild(input, nameEl);
    input.focus(); input.select();
    input.addEventListener('click', e => e.stopPropagation());
    input.addEventListener('dblclick', e => e.stopPropagation());
    let finished = false;
    const done = save => {
      if (finished) return;
      finished = true;
      input.replaceWith(nameEl);
      if (save && input.value.trim() && input.value.trim() !== w.name)
        api('/api/rename', { index: w.index, name: input.value.trim(), session: currentSession }).then(refreshTabs);
      else renderTabs();
    };
    input.addEventListener('keydown', e => {
      e.stopPropagation();
      if (e.key === 'Enter' || e.key === 'Escape') { e.preventDefault(); done(e.key === 'Enter'); }
    });
    input.addEventListener('blur', () => done(true));
  }

  $('#tab-add').addEventListener('click', () => { api('/api/windows', { session: currentSession }).then(refreshTabs); focusTerm(); });

  // ---------- sessions ----------
  async function refreshSessions() {
    const { sessions: s } = await api('/api/sessions');
    sessions = s;
    if (!currentSession || !sessions.some(x => x.name === currentSession)) {
      const attached = sessions.find(x => x.attached);
      currentSession = (attached || sessions[0] || { name: 'webmux' }).name;
      localStore.setItem('webmux-session', currentSession);
      sessionStore.setItem('webmux-session', currentSession);
    }
    renderSessions();
  }

  function attachCurrent() {
    windows = [];
    clearPendingWrite();
    // Gate output until the server acks the new attach — otherwise leftover
    // bytes from the previous PTY paint into the reset terminal (flash/garbage).
    if (ws && ws.readyState === 1) {
      armPendingSwitch(currentSession);
      ws.send(JSON.stringify({ t: 'switch', session: currentSession }));
      reportFocus();
    } else {
      clearPendingSwitch();
      if (term) term.reset();
      connect();
    }
    refreshTabs();
  }

  function switchSession(name) {
    if (!name || name === currentSession) return;
    currentSession = name;
    localStore.setItem('webmux-session', name);
    sessionStore.setItem('webmux-session', name);
    renderSessions();
    attachCurrent();
    const lastTab = lastActiveTabPerSession.get(name);
    if (lastTab !== undefined) setTimeout(() => api('/api/select', { index: lastTab, session: name }).then(refreshTabs), 200);
  }

  function renderSessions() {
    const nav = $('#sessions');
    if (nav.querySelector('input.rename')) return;
    nav.textContent = '';
    for (const s of sessions) {
      const el = document.createElement('div');
      el.className = 'sess' + (s.name === currentSession ? ' active' : '');
      el.dataset.name = s.name;
      const name = document.createElement('span');
      name.className = 'sess-name';
      name.textContent = s.name;
      const count = document.createElement('span');
      count.className = 'sess-count';
      count.textContent = s.windows;
      el.append(name, count);

      if (sessions.length > 1) {
        const kill = document.createElement('span');
        kill.className = 'sess-kill';
        kill.textContent = '×';
        kill.title = 'kill session';
        kill.addEventListener('click', e => {
          e.stopPropagation();
          if (!confirm(`Kill session "${s.name}"?`)) return;
          const wasCurrent = s.name === currentSession;
          api('/api/sessions/kill', { name: s.name }).then(async () => {
            if (wasCurrent) currentSession = null;
            await refreshSessions();
            if (wasCurrent) attachCurrent(); else refreshTabs();
          });
        });
        el.appendChild(kill);
      }

      el.addEventListener('click', () => {
        if (tabDrag && tabDrag.active) return;
        switchSession(s.name);
      });
      el.addEventListener('dblclick', e => {
        if (!e.target.classList.contains('sess-kill')) {
          e.preventDefault(); e.stopPropagation(); startSessionRename(el, name, s);
        }
      });
      nav.appendChild(el);
    }
  }

  function startSessionRename(el, nameEl, s) {
    const input = document.createElement('input');
    input.className = 'rename sess-rename';
    input.value = s.name;
    el.replaceChild(input, nameEl);
    input.focus(); input.select();
    input.addEventListener('click', e => e.stopPropagation());
    input.addEventListener('dblclick', e => e.stopPropagation());
    let finished = false;
    const done = save => {
      if (finished) return;
      finished = true;
      input.replaceWith(nameEl);
      const newName = input.value.trim();
      if (save && newName && newName !== s.name) {
        api('/api/sessions/rename', { oldName: s.name, newName }).then(async r => {
          if (r && r.error) { alert(r.error); renderSessions(); return; }
          if (s.name === currentSession) { currentSession = newName; localStore.setItem('webmux-session', newName); sessionStore.setItem('webmux-session', newName); }
          await refreshSessions();
        }).catch(() => renderSessions());
      } else { renderSessions(); }
    };
    input.addEventListener('keydown', e => {
      e.stopPropagation();
      if (e.key === 'Enter' || e.key === 'Escape') { e.preventDefault(); done(e.key === 'Enter'); }
    });
    input.addEventListener('blur', () => done(true));
  }

  $('#status-bell')?.addEventListener('click', cycleNotify);
  renderNotifyToggle();
  $('#perf-settings')?.addEventListener('click', showPerfSettings);
  $('#font-dec')?.addEventListener('click', () => nudgeFont(-1));
  $('#font-inc')?.addEventListener('click', () => nudgeFont(1));
  $('#font-size-label')?.addEventListener('click', resetFontSize);
  syncFontSizeLabel();
  applyPerformanceMode();

  $('#sess-add').addEventListener('click', async () => {
    const name = (prompt('New session name:') || '').trim();
    if (!name) return;
    const r = await api('/api/sessions', { name });
    if (r && r.error) { alert(r.error); return; }
    await refreshSessions();
    switchSession(name);
    focusTerm();
  });

  // ---------- shortcuts overlay ----------
  function showShortcuts() {
    const overlay = document.createElement('dialog');
    overlay.className = 'confirm-overlay';
    overlay.setAttribute('aria-label', 'Keyboard shortcuts');
    overlay.innerHTML = `<div class="confirm-box shortcuts-box"><div class="confirm-title">keyboard shortcuts</div><div class="shortcuts-grid">
      <div class="sc-key">?</div><div class="sc-desc">this overlay</div>
      <div class="sc-key">ctrl+click</div><div class="sc-desc">multi-select tabs</div>
      <div class="sc-key">escape</div><div class="sc-desc">clear selection</div>
      <div class="sc-key">dbl-click ×</div><div class="sc-desc">close tab</div>
      <div class="sc-key">dbl-click tab</div><div class="sc-desc">rename tab</div>
      <div class="sc-key">dbl-click sess</div><div class="sc-desc">rename session</div>
      <div class="sc-key">right-click</div><div class="sc-desc">context menu</div>
      <div class="sc-key">drag tab</div><div class="sc-desc">reorder / transfer</div>
      <div class="sc-key">hold tab</div><div class="sc-desc">reorder on touch</div>
      <div class="sc-key">ctrl+shift+c</div><div class="sc-desc">copy</div>
      <div class="sc-key">ctrl+shift+v</div><div class="sc-desc">paste</div>
      <div class="sc-key">ctrl+shift+p</div><div class="sc-desc">tmux command</div>
      <div class="sc-key">ctrl+tab</div><div class="sc-desc">recent tabs</div>
      <div class="sc-key">ctrl+drag</div><div class="sc-desc">radial menu for blocked shortcuts (^N ^T ^W…)</div>
      <div class="sc-key">⚡</div><div class="sc-desc">battery &amp; display settings</div>
      <div class="sc-key">swipe ←→</div><div class="sc-desc">switch tabs</div>
      <div class="sc-key">swipe ↑↓</div><div class="sc-desc">scroll</div>
    </div><div class="confirm-actions"><button class="confirm-btn confirm-no">close</button></div></div>`;
    const close = mountOverlay(overlay);
    overlay.querySelector('.confirm-no').addEventListener('click', close);
  }

  // ---------- tmux command palette ----------
  function showCommandPalette() {
    const overlay = document.createElement('dialog');
    overlay.className = 'confirm-overlay';
    overlay.setAttribute('aria-label', 'Tmux command');
    overlay.innerHTML = `<div class="confirm-box palette-box"><div class="confirm-title">tmux command</div><input class="palette-input" placeholder="split-window -h, new-window, kill-pane..." autofocus><div class="palette-hint">enter to run · esc to cancel</div></div>`;
    const close = mountOverlay(overlay);
    const input = overlay.querySelector('.palette-input');
    input.addEventListener('keydown', async e => {
      if (e.key === 'Enter') {
        e.preventDefault();
        const cmd = input.value.trim();
        close();
        if (cmd) { try { await api('/api/tmux', { command: cmd, session: currentSession }); refreshTabs(); } catch (err) { showToast('tmux error'); } }
      }
    });
  }

  // ---------- recent tabs ----------
  function showRecentTabs() {
    if (recentTabs.length === 0) return;
    const overlay = document.createElement('dialog');
    overlay.className = 'confirm-overlay';
    overlay.setAttribute('aria-label', 'Recent tabs');
    overlay.innerHTML = `<div class="confirm-box recent-box"><div class="confirm-title">recent tabs</div><div class="recent-list"></div><div class="palette-hint">click to switch · esc to cancel</div></div>`;
    const listEl = overlay.querySelector('.recent-list');
    recentTabs.slice(0, 8).forEach((idx, i) => {
      const w = windows.find(x => x.index === idx);
      if (!w) return;
      const item = document.createElement('button');
      item.type = 'button';
      item.className = `recent-item${i === 0 ? ' active' : ''}`;
      item.dataset.index = idx;
      const idxSpan = document.createElement('span');
      idxSpan.className = 'recent-idx';
      idxSpan.textContent = idx;
      const nameSpan = document.createElement('span');
      nameSpan.className = 'recent-name';
      nameSpan.textContent = w.name;
      item.appendChild(idxSpan);
      item.appendChild(nameSpan);
      listEl.appendChild(item);
    });
    const close = mountOverlay(overlay);
    overlay.querySelectorAll('.recent-item').forEach(el => {
      el.addEventListener('click', () => {
        close();
        const idx = +el.dataset.index;
        // optimistic: switch active tab immediately
        windows.forEach(x => x.active = x.index === idx);
        renderTabs();
        api('/api/select', { index: idx, session: currentSession }).then(refreshTabs);
        reportFocus();
      });
    });
  }

  // ---------- spectator / view-only mode ----------
  function toggleSpectator() {
    // Server-enforced view-only: reconnect as ro/rw so the other party gets the eye.
    if (viewOnlyAttach) {
      connect({ viewOnly: false });
      toast('interactive — reclaimed write');
      return;
    }
    if (ws && ws.readyState === 1) {
      connect({ viewOnly: true });
      toast('view only — watching, not writing');
      return;
    }
    // Offline fallback: local stdin lock only
    spectatorMode = !spectatorMode;
    document.body.classList.toggle('spectator', spectatorMode);
    if (term) term.options.disableStdin = spectatorMode;
    const el = $('#status-mode');
    if (el) {
      el.textContent = spectatorMode ? 'spectator' : 'interactive';
      el.classList.toggle('spectator', spectatorMode);
    }
    toast(spectatorMode ? 'spectator mode — read only' : 'interactive mode');
  }

  $('#status-mode').addEventListener('click', toggleSpectator);
  $('#btn-reclaim')?.addEventListener('click', () => {
    hideTakeoverActions();
    connect({ viewOnly: false });
  });
  $('#btn-view-only')?.addEventListener('click', () => {
    hideTakeoverActions();
    connect({ viewOnly: true });
  });

  // ---------- hidden admin roster ----------
  let lastMe = { admin: false, user: null };
  let adminPollTimer = 0;
  let lastWho = null;
  let adminOpenKey = '';

  function fmtDur(ms) {
    if (!Number.isFinite(ms) || ms < 0) return '·';
    const s = Math.floor(ms / 1000);
    if (s < 60) return s + 's';
    const m = Math.floor(s / 60);
    if (m < 60) return m + 'm ' + (s % 60) + 's';
    const h = Math.floor(m / 60);
    if (h < 48) return h + 'h ' + (m % 60) + 'm';
    const d = Math.floor(h / 24);
    return d + 'd ' + (h % 24) + 'h';
  }
  function shortUa(ua) {
    ua = String(ua || '');
    const os = /iPhone|iPad/.test(ua) ? 'iOS'
      : /Android/.test(ua) ? 'Android'
      : /Mac OS X/.test(ua) ? 'macOS'
      : /Windows/.test(ua) ? 'Windows'
      : /Linux/.test(ua) ? 'Linux' : '';
    const br = /Edg\//.test(ua) ? 'Edge'
      : /Chrome\//.test(ua) ? 'Chrome'
      : /Firefox\//.test(ua) ? 'Firefox'
      : /Safari\//.test(ua) ? 'Safari' : '';
    return [br, os].filter(Boolean).join(' · ') || ua.slice(0, 42);
  }
  function mk(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function fillEmpty(host, label) {
    host.textContent = '';
    host.appendChild(mk('div', 'empty', label));
  }
  function flagClass(f) {
    if (f === 'WEBRTC-LEAK' || f === 'WEBDRIVER') return 'flag leak';
    if (f === 'TZ-MISMATCH') return 'flag tz';
    if (f === 'XFF-CHAIN') return 'flag xff';
    return 'flag';
  }
  function joinVal(v) {
    if (v == null || v === '') return '·';
    if (Array.isArray(v)) return v.length ? v.join(', ') : '·';
    if (typeof v === 'object') {
      try { return JSON.stringify(v); } catch { return String(v); }
    }
    return String(v);
  }
  function kv(grid, k, v, muted) {
    if (v == null || v === '' || v === false || (Array.isArray(v) && !v.length)) return;
    grid.appendChild(mk('div', 'k', k));
    grid.appendChild(mk('div', muted ? 'v muted' : 'v', joinVal(v)));
  }
  function section(inner, title) {
    inner.appendChild(mk('h3', '', title));
    const g = mk('div', 'kv');
    inner.appendChild(g);
    return g;
  }
  function intelLine(intel) {
    if (!intel || intel.miss) return '';
    return [intel.city, intel.region, intel.countryName || intel.country, intel.org || intel.isp]
      .filter(Boolean).join(' · ');
  }
  function fillDossier(inner, row) {
    inner.textContent = '';
    const fp = row.fp || {};
    const net = row.net || {};
    const intel = row.intel || {};
    const webrtc = fp.webrtc || {};
    const flags = section(inner, 'SIGNALS');
    kv(flags, 'flags', (row.flags || []).join(' · ') || 'none');
    kv(flags, 'device', fp.deviceId);
    kv(flags, 'webdriver', fp.webdriver ? 'yes' : '');
    const netG = section(inner, 'NETWORK');
    kv(netG, 'http ip', row.httpIp || row.ip);
    kv(netG, 'peer', net.peer);
    kv(netG, 'xff hops', net.hops);
    kv(netG, 'webrtc srflx', webrtc.srflx);
    kv(netG, 'webrtc host', webrtc.host);
    kv(netG, 'webrtc relay', webrtc.relay);
    kv(netG, 'webrtc leak', row.leakIps);
    if (webrtc.error) kv(netG, 'webrtc error', webrtc.error, true);
    kv(netG, 'cf-ray', net.ray || (net.headers && net.headers['cf-ray']));
    kv(netG, 'accept-language', net.lang || (net.headers && net.headers['accept-language']));
    const geo = section(inner, 'GEO / INTEL');
    kv(geo, 'ip intel', intelLine(intel));
    kv(geo, 'asn', intel.asn);
    kv(geo, 'org', intel.org);
    kv(geo, 'isp', intel.isp);
    kv(geo, 'tz (ip)', intel.tz);
    kv(geo, 'coords', (intel.lat != null && intel.lon != null) ? (intel.lat + ', ' + intel.lon) : '');
    kv(geo, 'hosting/vpn asn', intel.hosting ? 'yes' : '');
    kv(geo, 'type', intel.type);
    if (row.leakIntel) {
      for (const [ip, inf] of Object.entries(row.leakIntel)) {
        kv(geo, 'leak ' + ip, intelLine(inf) || ip);
      }
    }
    const loc = section(inner, 'LOCALE');
    kv(loc, 'languages', fp.languages);
    kv(loc, 'language', fp.language);
    kv(loc, 'timezone', fp.timezone);
    kv(loc, 'locale', fp.locale);
    kv(loc, 'calendar', fp.calendar);
    kv(loc, 'color scheme', fp.colorScheme);
    const dev = section(inner, 'DEVICE');
    kv(dev, 'ua', fp.userAgent || row.ua, true);
    kv(dev, 'ua high-entropy', fp.ua);
    kv(dev, 'platform', fp.platform);
    kv(dev, 'vendor', fp.vendor);
    kv(dev, 'cores', fp.hardwareConcurrency);
    kv(dev, 'memory GiB', fp.deviceMemory);
    kv(dev, 'touch points', fp.maxTouchPoints);
    kv(dev, 'pointer', fp.pointer);
    kv(dev, 'screen', fp.screen && (fp.screen.w + '×' + fp.screen.h + ' @' + (fp.dpr || 1) + ' ' + (fp.screen.cd || '') + 'bit'));
    kv(dev, 'inner', fp.inner && (fp.inner.w + '×' + fp.inner.h));
    kv(dev, 'connection', fp.connection);
    kv(dev, 'media devices', fp.media);
    kv(dev, 'keyboard', fp.keyboard);
    const gpu = section(inner, 'GPU / HASHES');
    kv(gpu, 'webgl vendor', fp.webgl && (fp.webgl.unmaskedVendor || fp.webgl.vendor));
    kv(gpu, 'webgl renderer', fp.webgl && (fp.webgl.unmaskedRenderer || fp.webgl.renderer));
    kv(gpu, 'canvas', fp.canvas && fp.canvas.hash);
    kv(gpu, 'audio', fp.audio && fp.audio.hash);
    kv(gpu, 'fonts', fp.fonts);
    const hdr = section(inner, 'HEADERS');
    const headers = (net.headers) || {};
    const hdrKeys = Object.keys(headers).sort();
    if (!hdrKeys.length) kv(hdr, 'headers', 'none', true);
    for (const k of hdrKeys) kv(hdr, k, headers[k], true);
    if (row.ipHistory && row.ipHistory.length) {
      const hist = section(inner, 'IP HISTORY');
      for (const h of row.ipHistory) {
        kv(hist, h.at ? new Date(h.at).toISOString().replace('T', ' ').slice(0, 19) : 'ip', h.ip);
      }
    }
  }
  function renderAdminTable(host, rows, kind, now) {
    host.textContent = '';
    if (!rows.length) {
      fillEmpty(host, kind === 'history' ? 'no history yet' : (kind === 'attached' ? 'nobody attached' : 'no logins'));
      return;
    }
    const table = mk('table');
    const thead = mk('thead');
    const hr = mk('tr');
    const heads = kind === 'attached'
      ? ['USER', 'WHERE', 'IP', 'FLAGS', 'CONNECTED', 'IDLE', 'CLIENT']
      : kind === 'logins'
        ? ['USER', 'IP', 'FLAGS', 'AGE', 'USES', 'STATE']
        : ['WHEN', 'USER', 'IP', 'FLAGS', 'LOCALE'];
    for (const h of heads) hr.appendChild(mk('th', '', h));
    thead.appendChild(hr);
    const tb = mk('tbody');
    for (const row of rows) {
      const key = kind + ':' + (row.id || row.rid || row.ts || '');
      const tr = mk('tr', 'row' + (row.you ? ' you' : ''));
      tr.addEventListener('click', () => {
        adminOpenKey = adminOpenKey === key ? '' : key;
        if (lastWho) renderWho(lastWho);
      });
      const user = mk('td', 'user', row.user || 'token');
      user.appendChild(mk('div', 'via', String(row.via || 'secret').toUpperCase()));
      const ip = mk('td', 'ip');
      const addr = mk('span', 'ip-addr', row.httpIp || row.ip || '·');
      addr.title = row.httpIp || row.ip || '';
      ip.appendChild(addr);
      const geoBits = [row.country || (row.intel && (row.intel.city || row.intel.country)), row.intel && (row.intel.org || row.intel.isp)].filter(Boolean);
      if (geoBits.length) ip.appendChild(mk('span', 'ip-geo', geoBits.join(' · ')));
      if (row.leakIps && row.leakIps.length) {
        const leak = mk('span', 'ip-leak', 'webrtc ' + row.leakIps.join(', '));
        leak.title = 'address from STUN — often the real IP behind a VPN/proxy';
        ip.appendChild(leak);
      }
      const flags = mk('td', 'flags');
      for (const f of (row.flags || [])) flags.appendChild(mk('span', flagClass(f), f));
      if (kind === 'attached') {
        const where = mk('td', 'where');
        where.appendChild(mk('span', 'sess-name', row.session || '·'));
        where.appendChild(mk('span', 'tab-name',
          row.tabIndex == null ? '—' : (row.tabIndex + '  ' + (row.tabName || ''))));
        const conn = mk('td', '', fmtDur(now - (row.connectedAt || now)));
        conn.title = row.connectedAt ? new Date(row.connectedAt).toISOString() : '';
        const idleMs = now - (row.lastActiveAt || row.connectedAt || now);
        const idle = mk('td', idleMs < 8000 ? 'live' : 'idle', idleMs < 8000 ? 'live' : fmtDur(idleMs));
        const ua = mk('td', 'ua', shortUa(row.ua || (row.fp && row.fp.userAgent)));
        ua.title = row.ua || '';
        tr.append(user, where, ip, flags, conn, idle, ua);
      } else if (kind === 'logins') {
        const age = mk('td', '', fmtDur(now - (row.mintedAt || now)));
        age.title = row.mintedAt ? new Date(row.mintedAt).toISOString() : '';
        const uses = mk('td', '', String(row.uses || 0));
        const st = mk('td', row.attached ? 'live' : 'idle', row.attached ? 'attached' : 'idle');
        tr.append(user, ip, flags, age, uses, st);
      } else {
        const when = mk('td', '', (row.ts || '').replace('T', ' ').slice(0, 19));
        const loc = mk('td', 'ua', [row.language || (row.languages && row.languages[0]), row.timezone].filter(Boolean).join(' · ') || '·');
        tr.append(when, user, ip, flags, loc);
      }
      tb.appendChild(tr);
      if (adminOpenKey === key) {
        const dr = mk('tr', 'dossier');
        const td = mk('td');
        td.colSpan = heads.length;
        const wrap = mk('div', 'dossier-inner');
        fillDossier(wrap, row);
        td.appendChild(wrap);
        dr.appendChild(td);
        tb.appendChild(dr);
      }
    }
    table.append(thead, tb);
    host.appendChild(table);
  }
  function renderWho(data) {
    const now = Date.now();
    const attached = data.attached || [];
    const logins = data.logins || [];
    const history = (data.history || []).map(h => ({
      ...h,
      via: h.provider || (h.user ? 'external' : 'secret'),
      httpIp: h.ip,
      id: (h.rid || '') + '@' + (h.ts || ''),
    }));
    const n = attached.length;
    $('#admin-count').textContent = n + (n === 1 ? ' attached' : ' attached');
    renderAdminTable($('#admin-attached'), attached, 'attached', now);
    renderAdminTable($('#admin-tickets'), logins, 'logins', now);
    renderAdminTable($('#admin-history'), history, 'history', now);
  }
  function stopAdminPoll() {
    if (adminPollTimer) { clearInterval(adminPollTimer); adminPollTimer = 0; }
  }
  function startAdminPoll() {
    stopAdminPoll();
    const go = () => {
      api('/api/admin/who').then(d => {
        if (!d || !d.ok) { leaveAdmin(); return; }
        lastWho = d;
        renderWho(d);
      }).catch(() => { leaveAdmin(); });
    };
    go();
    adminPollTimer = setInterval(go, 2000);
  }
  function wantsAdminBtn() {
    try {
      if (new URLSearchParams(location.search).has('admin')) return true;
      return sessionStore.getItem('webmux-admin-q') === '1';
    } catch { return false; }
  }
  function showSakura() {
    const b = $('#sakura-admin');
    if (!b) return;
    // Keep the bar tidy — sakura only when ?admin is in the URL (and user is admin).
    b.hidden = !(lastMe && lastMe.admin && wantsAdminBtn());
  }
  function openAdmin() {
    $('#auth').hidden = true;
    $('#app').hidden = true;
    $('#admin').hidden = false;
    document.body.classList.add('admin-mode');
    document.title = 'webmux · who';
    try {
      history.replaceState({}, '', wantsAdminBtn() ? '/admin?admin' : '/admin');
    } catch {}
    startAdminPoll();
  }
  function leaveAdmin() {
    stopAdminPoll();
    $('#admin').hidden = true;
    document.body.classList.remove('admin-mode');
    document.title = 'webmux';
    try {
      history.replaceState({}, '', wantsAdminBtn() ? '/?admin' : '/');
    } catch {}
    showSakura();
    if (!terminalBooted) bootTerminal(lastMe).catch(showBootError);
    else {
      $('#app').hidden = false;
      try { if (term) { fitSafe(); focusTerm(); } } catch {}
    }
  }
  $('#admin-back').addEventListener('click', leaveAdmin);
  $('#sakura-admin').addEventListener('click', e => {
    e.preventDefault();
    openAdmin();
  });
  window.addEventListener('popstate', () => {
    const admin = location.pathname.replace(/\/+$/, '') === '/admin';
    if (admin && lastMe.admin) openAdmin();
    else if (!admin && !$('#admin').hidden) leaveAdmin();
  });

  // ---------- toast ----------
  function showToast(msg) {
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = msg;
    document.body.appendChild(toast);
    requestAnimationFrame(() => toast.classList.add('visible'));
    setTimeout(() => { toast.classList.remove('visible'); setTimeout(() => toast.remove(), 300); }, 2000);
  }

  // ---------- global keybinds ----------
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && $('#ctx-menu') && !$('dialog[open]')) {
      e.preventDefault(); e.stopPropagation(); closeContextMenu(); return;
    }
    if (e.defaultPrevented || e.isComposing || !terminalBooted || terminalUiBlocked() || editingField(e.target)) return;
    let action;
    if (e.key === '?' && !e.ctrlKey && !e.metaKey && !e.altKey && document.activeElement === document.body) action = showShortcuts;
    if (e.ctrlKey && e.shiftKey && e.code === 'KeyP') action = showCommandPalette;
    if (e.ctrlKey && e.code === 'Tab') action = showRecentTabs;
    if (action) { e.preventDefault(); e.stopPropagation(); action(); }
  }, true);

  // ---------- boot ----------
  function showBootError() {
    $('#auth').hidden = true;
    $('#app').hidden = true;
    $('#admin').hidden = true;
    document.body.classList.remove('admin-mode');
    $('#boot-error').hidden = false;
    $('#boot-reload').focus();
  }
  $('#boot-reload').addEventListener('click', () => location.reload());
  let terminalStarting = false;
  async function bootTerminal(me) {
    if (terminalBooted || terminalStarting) return;
    terminalStarting = true;
    $('#auth').hidden = true;
    $('#app').hidden = false;
    if (me && me.admin) showSakura();
    try {
      await Promise.all([
        document.fonts.load('400 14px "JetBrainsMonoNF"'),
        document.fonts.load('700 14px "JetBrainsMonoNF"'),
        document.fonts.load('italic 400 14px "JetBrainsMonoNF"'),
      ]);
    } catch {}
    makeTerm();
    terminalBooted = true;
    try { await refreshSessions(); } catch (e) {}
    connect();
    refreshTabs();
    startPolls();
  }

  let tabsPollTimer = 0;
  let sessionsPollTimer = 0;
  function armTabsPoll() {
    clearTimeout(tabsPollTimer);
    tabsPollTimer = setTimeout(async () => {
      try { if (terminalBooted) await refreshTabs(); } catch {}
      armTabsPoll();
    }, pageVisible ? 3000 : 30000);
  }
  function armSessionsPoll() {
    clearTimeout(sessionsPollTimer);
    sessionsPollTimer = setTimeout(async () => {
      try { if (terminalBooted) await refreshSessions(); } catch {}
      armSessionsPoll();
    }, pageVisible ? 5000 : 45000);
  }
  function reschedulePolls() {
    if (!terminalBooted) return;
    armTabsPoll();
    armSessionsPoll();
  }
  function startPolls() {
    reschedulePolls();
  }

  let starting = false;
  async function start() {
    if (starting) return;
    starting = true;
    try { await startApp(); }
    catch { showBootError(); }
    finally { starting = false; }
  }

  async function startApp() {
    $('#auth').hidden = true;
    const me = await api('/api/me');
    if (!me || typeof me.admin !== 'boolean') throw new Error('Could not load session');
    lastMe = me;
    pushFingerprint();
    let next = '';
    try {
      next = sessionStore.getItem('webmux-next') || '';
      sessionStore.removeItem('webmux-next');
    } catch {}
    // External auth always lands on `/` — put ?admin back so sakura / roster URLs stick.
    if (wantsAdminBtn()) {
      try {
        const path = location.pathname.replace(/\/+$/, '') || '/';
        const q = new URLSearchParams(location.search);
        if (!q.has('admin')) {
          history.replaceState({}, '', (path === '/admin' ? '/admin' : '/') + '?admin');
        }
      } catch {}
    }
    const pathAdmin = location.pathname.replace(/\/+$/, '') === '/admin';
    if (me.admin && (pathAdmin || next === '/admin')) {
      showSakura();
      openAdmin();
      return;
    }
    if (pathAdmin) {
      try { history.replaceState({}, '', wantsAdminBtn() ? '/?admin' : '/'); } catch {}
    }
    await bootTerminal(me);
  }

  (async () => {
    await authReady; // may have picked up a token via the provider handoff cookie
    if (token) start();
  })();
})();
