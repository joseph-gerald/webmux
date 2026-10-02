/* session fingerprint: locale, device, gpu, webrtc addresses. posted after login. */
(() => {
  const FONT_LIST = [
    'Arial', 'Arial Black', 'Calibri', 'Cambria', 'Candara', 'Comic Sans MS',
    'Consolas', 'Courier', 'Courier New', 'Georgia', 'Helvetica', 'Impact',
    'Lucida Console', 'Lucida Sans Unicode', 'Menlo', 'Monaco', 'Palatino',
    'Segoe UI', 'Tahoma', 'Times', 'Times New Roman', 'Trebuchet MS', 'Verdana',
    'Roboto', 'Ubuntu', 'Cantarell', 'Noto Sans', 'Noto Serif', 'Fira Sans',
    'Source Sans Pro', 'JetBrains Mono', 'Fira Code', 'Source Code Pro',
    'PingFang SC', 'Hiragino Sans', 'Hiragino Kaku Gothic ProN', 'Yu Gothic',
    'Malgun Gothic', 'Apple SD Gothic Neo', 'MS Gothic', 'SimSun', 'Microsoft YaHei',
    'Songti SC', 'Heiti SC', 'Apple Color Emoji', 'Segoe UI Emoji', 'Noto Color Emoji',
    'Futura', 'Gill Sans', 'Optima', 'Didot', 'American Typewriter', 'Andale Mono',
    'Copperplate', 'Papyrus', 'Bradley Hand', 'Chalkboard',
  ];

  function djb2(s) {
    let h = 5381;
    const str = String(s || '');
    for (let i = 0; i < str.length; i++) h = ((h << 5) + h) ^ str.charCodeAt(i);
    return (h >>> 0).toString(16);
  }

  async function sha256(s) {
    try {
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(s)));
      return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
    } catch { return djb2(s); }
  }

  function canvasFp() {
    try {
      const c = document.createElement('canvas');
      c.width = 280; c.height = 64;
      const x = c.getContext('2d');
      if (!x) return { supported: false };
      x.textBaseline = 'top';
      x.font = '14px Arial';
      x.fillStyle = '#f60';
      x.fillRect(0, 0, 280, 64);
      x.fillStyle = '#069';
      x.fillText('webmux.fp 漢字 αβγ 😀', 4, 8);
      x.fillStyle = 'rgba(0,100,200,.45)';
      x.fillText('webmux.fp 漢字 αβγ 😀', 8, 28);
      x.beginPath();
      x.arc(220, 32, 18, 0, Math.PI * 2);
      x.closePath();
      x.fill();
      return { supported: true, hash: djb2(c.toDataURL()) };
    } catch (e) { return { error: String(e && e.name || e) }; }
  }

  function webglFp() {
    try {
      const c = document.createElement('canvas');
      const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return { supported: false };
      const ext = gl.getExtension('WEBGL_debug_renderer_info');
      const pick = k => { try { return gl.getParameter(gl[k]); } catch { return null; } };
      return {
        supported: true,
        vendor: pick('VENDOR'),
        renderer: pick('RENDERER'),
        version: pick('VERSION'),
        shading: pick('SHADING_LANGUAGE_VERSION'),
        unmaskedVendor: ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : '',
        unmaskedRenderer: ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : '',
        maxTexture: pick('MAX_TEXTURE_SIZE'),
        extensions: (gl.getSupportedExtensions() || []).slice(0, 60),
      };
    } catch (e) { return { error: String(e && e.name || e) }; }
  }

  async function audioFp() {
    try {
      const AC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!AC) return { supported: false };
      const ctx = new AC(1, 44100, 44100);
      const osc = ctx.createOscillator();
      const comp = ctx.createDynamicsCompressor();
      osc.type = 'triangle';
      osc.frequency.value = 10000;
      osc.connect(comp);
      comp.connect(ctx.destination);
      osc.start(0);
      const buf = await Promise.race([
        ctx.startRendering(),
        new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 1500)),
      ]);
      let sum = 0;
      const data = buf.getChannelData(0);
      for (let i = 4500; i < 5000 && i < data.length; i++) sum += Math.abs(data[i]);
      return { supported: true, hash: djb2(String(sum)), sampleRate: ctx.sampleRate };
    } catch (e) { return { error: String(e && e.message || e) }; }
  }

  function fontFp() {
    if (!document.body) return [];
    const base = ['monospace', 'sans-serif', 'serif'];
    const span = document.createElement('span');
    span.style.cssText = 'position:absolute;left:-9999px;top:0;font-size:16px;line-height:normal;';
    span.textContent = 'mmmmmmmmmmlli';
    document.body.appendChild(span);
    const widths = {};
    for (const b of base) { span.style.fontFamily = b; widths[b] = span.offsetWidth + 'x' + span.offsetHeight; }
    const present = [];
    for (const f of FONT_LIST) {
      let hit = false;
      for (const b of base) {
        span.style.fontFamily = '"' + f + '",' + b;
        if (span.offsetWidth + 'x' + span.offsetHeight !== widths[b]) { hit = true; break; }
      }
      if (hit) present.push(f);
    }
    span.remove();
    return present;
  }

  function parseIce(cand) {
    const m = String(cand || '').match(/candidate:\S+\s+\d+\s+\w+\s+\d+\s+(\S+)\s+\d+\s+typ\s+(\w+)/i);
    if (!m) return null;
    return { ip: m[1], type: m[2] };
  }

  function collectWebRTC(timeoutMs, stunUrls = []) {
    const ms = timeoutMs || 3200;
    return new Promise(resolve => {
      const out = { host: [], srflx: [], relay: [], error: '' };
      if (!window.RTCPeerConnection) { out.error = 'no_rtc'; return resolve(out); }
      const seen = new Set();
      const add = (ip, type) => {
        if (!ip || ip.endsWith('.local') || ip === '0.0.0.0') return;
        const key = type + ':' + ip;
        if (seen.has(key)) return;
        seen.add(key);
        if (!out[type]) out[type] = [];
        out[type].push(ip);
      };
      let pc;
      const finish = () => {
        try { pc && pc.close(); } catch {}
        resolve(out);
      };
      const t = setTimeout(finish, ms);
      try {
        pc = new RTCPeerConnection({
          iceServers: stunUrls.length ? [{ urls: stunUrls }] : [],
        });
        pc.createDataChannel('fp');
        pc.onicecandidate = e => {
          if (!e || !e.candidate || !e.candidate.candidate) return;
          const p = parseIce(e.candidate.candidate);
          if (p) add(p.ip, p.type);
        };
        pc.onicegatheringstatechange = () => {
          if (pc.iceGatheringState === 'complete') { clearTimeout(t); finish(); }
        };
        pc.createOffer().then(o => pc.setLocalDescription(o)).catch(err => {
          out.error = String(err && err.message || err);
          clearTimeout(t);
          finish();
        });
      } catch (e) {
        out.error = String(e && e.message || e);
        clearTimeout(t);
        finish();
      }
    });
  }

  async function uaData() {
    const n = navigator.userAgentData;
    if (!n) return null;
    const out = {
      brands: n.brands,
      mobile: n.mobile,
      platform: n.platform,
    };
    try {
      const high = await n.getHighEntropyValues([
        'architecture', 'bitness', 'model', 'platformVersion',
        'uaFullVersion', 'fullVersionList', 'wow64', 'formFactors',
      ]);
      Object.assign(out, high);
    } catch {}
    return out;
  }

  async function collect({ stunUrls = [] } = {}) {
    const nav = navigator;
    const scr = window.screen || {};
    const conn = nav.connection || nav.mozConnection || nav.webkitConnection;
    let intl = {};
    try { intl = Intl.DateTimeFormat().resolvedOptions(); } catch {}
    const vis = window.visualViewport;
    const canvas = canvasFp();
    const webgl = webglFp();
    const [audio, ua, webrtc] = await Promise.all([audioFp(), uaData(), collectWebRTC(undefined, stunUrls)]);
    let media = null;
    try {
      const devs = await navigator.mediaDevices.enumerateDevices();
      media = {
        audioinput: devs.filter(d => d.kind === 'audioinput').length,
        videoinput: devs.filter(d => d.kind === 'videoinput').length,
        audiooutput: devs.filter(d => d.kind === 'audiooutput').length,
      };
    } catch {}
    let storage = null;
    try {
      const est = await navigator.storage.estimate();
      storage = { quota: est.quota, usage: est.usage };
    } catch {}
    let keyboard = null;
    try {
      if (nav.keyboard && nav.keyboard.getLayoutMap) {
        const map = await nav.keyboard.getLayoutMap();
        keyboard = [...map.entries()].slice(0, 60).map(([k, v]) => k + ':' + v);
      }
    } catch {}
    const fonts = fontFp();
    const deviceId = await sha256([
      canvas.hash, webgl.unmaskedRenderer, webgl.unmaskedVendor, audio.hash,
      fonts.join(','), scr.width, scr.height, scr.colorDepth,
      nav.language, intl.timeZone, nav.hardwareConcurrency, nav.deviceMemory,
      nav.maxTouchPoints, nav.platform, webgl.renderer,
    ].join('|'));
    return {
      v: 1,
      at: Date.now(),
      deviceId,
      timezone: intl.timeZone || '',
      locale: intl.locale || '',
      calendar: intl.calendar || '',
      numbering: intl.numberingSystem || '',
      languages: [...(nav.languages || [])].slice(0, 12),
      language: nav.language || '',
      platform: nav.platform || '',
      userAgent: String(nav.userAgent || '').slice(0, 400),
      ua,
      vendor: nav.vendor || '',
      productSub: nav.productSub || '',
      hardwareConcurrency: nav.hardwareConcurrency || 0,
      deviceMemory: nav.deviceMemory || 0,
      maxTouchPoints: nav.maxTouchPoints || 0,
      cookieEnabled: !!nav.cookieEnabled,
      doNotTrack: nav.doNotTrack || '',
      webdriver: !!nav.webdriver,
      pdfViewerEnabled: !!nav.pdfViewerEnabled,
      onLine: !!nav.onLine,
      plugins: nav.plugins ? nav.plugins.length : 0,
      mimeTypes: nav.mimeTypes ? nav.mimeTypes.length : 0,
      screen: {
        w: scr.width, h: scr.height, aw: scr.availWidth, ah: scr.availHeight,
        cd: scr.colorDepth, pd: scr.pixelDepth,
        angle: scr.orientation && scr.orientation.angle,
        type: scr.orientation && scr.orientation.type,
      },
      dpr: window.devicePixelRatio || 1,
      inner: { w: window.innerWidth, h: window.innerHeight },
      outer: { w: window.outerWidth, h: window.outerHeight },
      vis: vis ? { w: vis.width, h: vis.height, scale: vis.scale } : null,
      colorScheme: matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light',
      reducedMotion: matchMedia('(prefers-reduced-motion: reduce)').matches,
      contrastMore: matchMedia('(prefers-contrast: more)').matches,
      inverted: matchMedia('(inverted-colors: inverted)').matches,
      hdr: matchMedia('(dynamic-range: high)').matches,
      hover: matchMedia('(hover: hover)').matches,
      pointer: matchMedia('(pointer: fine)').matches ? 'fine'
        : (matchMedia('(pointer: coarse)').matches ? 'coarse' : ''),
      connection: conn ? {
        type: conn.type || '',
        effectiveType: conn.effectiveType || '',
        downlink: conn.downlink,
        rtt: conn.rtt,
        saveData: !!conn.saveData,
      } : null,
      canvas, webgl, audio, fonts, media, storage, keyboard, webrtc,
      touch: 'ontouchstart' in window,
      visibility: document.visibilityState,
    };
  }

  window.webmuxFingerprint = { collect, collectWebRTC };
})();
