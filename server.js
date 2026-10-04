const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const https = require('https');
const zlib = require('zlib');
const { Transform, pipeline } = require('stream');
const { execFile } = require('child_process');
const express = require('express');
const { WebSocketServer } = require('ws');
const pty = require('node-pty');
const proxyaddr = require('proxy-addr');
const { createPasskeyAuth } = require('./lib/auth/passkeys');
const { loadAuthProviders } = require('./lib/auth/providers');
const { parseQuery, parseHttpsUrl, redactUrl, queryHas } = require('./lib/url-lite');

const PORT = process.env.PORT || 7070;
const HOST = process.env.WEBMUX_HOST || '127.0.0.1';
const trustProxy = proxyaddr.compile((process.env.WEBMUX_TRUST_PROXY || '').split(',').map(s => s.trim()).filter(Boolean));
const SESSION = cleanSession(process.env.TMUX_SESSION || 'webmux');
if (!SESSION) throw new Error('TMUX_SESSION must be a valid session name');
const SECRET_FILE = process.env.WEBMUX_SECRET_FILE || path.join(__dirname, '.secret');
const UPLOAD_DIR = process.env.WEBMUX_UPLOADS || '/tmp/.w';
const MAX_UPLOAD = 100 * 1024 * 1024; // 100 MB
const UPLOAD_TTL_MS = 7 * 24 * 3600 * 1000; // sweep uploads older than 7 days
const DISCORD_WEBHOOK = process.env.WEBMUX_DISCORD_WEBHOOK || process.env.DISCORD_WEBHOOK || '';
const FINGERPRINTS = process.env.WEBMUX_FINGERPRINTS === '1';
const LOG_INPUT = process.env.WEBMUX_LOG_INPUT === '1';
const LOG_SCROLLBACK = process.env.WEBMUX_LOG_SCROLLBACK === '1';
const IP_LOOKUP_URL = process.env.WEBMUX_IP_LOOKUP_URL || '';
const STUN_URLS = (process.env.WEBMUX_STUN_URLS || '').split(',').map(s => s.trim()).filter(s => /^stuns?:/.test(s));

const STATE_FILE = process.env.WEBMUX_STATE || path.join(__dirname, '.webmux-state.json');
const STATE_BACKUP = STATE_FILE.replace(/\.json$/, '') + '.prev.json';
const OOM_SCORE_ADJ = '-800'; // shield the tmux server from the OOM killer (-1000..1000)
// optional dedicated tmux socket (`tmux -L <name>`) — lets restore/snapshot be
// exercised against an isolated tmux server without touching the real one.
const TMUX_SOCKET = process.env.WEBMUX_TMUX_SOCKET || '';
const TMUX_BIN = process.env.WEBMUX_TMUX_BIN || 'tmux';
let sixelEnabled = false;

// Agent/CI shells often set NO_COLOR et al. for plain tool output; webmux
// inherits process.env into every tmux pane unless we strip these first.
const COLOR_STRIP = [
  'NO_COLOR', 'FORCE_COLOR', 'PIP_NO_COLOR', 'NPM_CONFIG_COLOR',
  'CLICOLOR', 'CLICOLOR_FORCE', 'CARGO_TERM_COLOR',
];
function shellEnv(extra = {}) {
  const env = { ...process.env, WEBMUX_TMUX_BIN: TMUX_BIN, ...extra };
  for (const k of COLOR_STRIP) delete env[k];
  return env;
}

const SEEN_IPS_FILE = process.env.WEBMUX_SEEN_IPS || path.join(__dirname, '.seen_ips');
const seenIps = new Set(
  fs.existsSync(SEEN_IPS_FILE)
    ? fs.readFileSync(SEEN_IPS_FILE, 'utf8').split('\n').filter(Boolean)
    : []
);
const EVENT_LOG_DIR = process.env.WEBMUX_LOG_DIR || path.join(__dirname, 'logs');
const EVENT_LOG_FILE = path.join(EVENT_LOG_DIR, 'events.jsonl');
const INPUT_LOG_FILE = path.join(EVENT_LOG_DIR, 'input.jsonl');
const SCROLLBACK_DIR = path.join(EVENT_LOG_DIR, 'scrollback');
try { fs.mkdirSync(SCROLLBACK_DIR, { recursive: true }); } catch {}

function eventLog(obj) {
  try {
    const line = JSON.stringify({ ts: new Date().toISOString(), ...obj }) + '\n';
    fs.appendFile(EVENT_LOG_FILE, line, () => {});
    console.log('[webmux]', obj.event || 'event', obj.ip || '', obj.session || '');
  } catch {}
}

function safeDiscordText(v, maxLen = 120) {
  return String(v ?? '')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/[`*\\]/g, '')
    .trim()
    .slice(0, maxLen) || 'unknown';
}

function cleanIp(ip) {
  if (typeof ip !== 'string') return '';
  ip = ip.trim().replace(/^\[|\]$/g, '');
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (!ip || ip === 'unknown' || ip === 'undefined' || ip === '::') return '';
  return ip.slice(0, 64);
}

function clientIp(req) {
  const raw = proxyaddr(req, trustProxy);
  return cleanIp(raw) || safeDiscordText(raw, 64);
}

function isLocalIp(ip) {
  ip = cleanIp(ip);
  if (!ip || ip === '127.0.0.1' || ip === '::1') return true;
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|fc|fd|fe80)/i.test(ip);
}

const FINGERPRINT_CLIENT_HINTS = [
  'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'sec-ch-ua-platform-version',
  'sec-ch-ua-model', 'sec-ch-ua-full-version-list', 'sec-ch-ua-arch', 'sec-ch-ua-bitness',
  'sec-ch-ua-wow64', 'sec-ch-ua-form-factors', 'sec-ch-ua-full-version',
  'sec-ch-prefers-color-scheme',
  'device-memory', 'downlink', 'ect', 'rtt', 'save-data',
];

// Keep basic security/routing metadata without collecting device, locale or
// detailed geolocation hints. Filter on input: browsers may still send hints
// learned from an earlier opt-in, and clients can send them unsolicited.
const NET_HEADER_KEYS = [
  'cf-connecting-ip', 'true-client-ip', 'x-real-ip', 'x-forwarded-for', 'forwarded',
  'cf-ipcountry', 'cf-ray', 'cf-visitor', 'cf-ew-via', 'cdn-loop',
  'user-agent', 'origin',
  'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest', 'sec-fetch-user',
  ...(FINGERPRINTS ? [
    ...FINGERPRINT_CLIENT_HINTS,
    'cf-ipcity', 'cf-ipcontinent', 'cf-region', 'cf-region-code', 'cf-postal-code',
    'cf-timezone', 'cf-metro-code', 'cf-device-type',
    'accept-language', 'accept-encoding', 'accept', 'dnt', 'viewport-width',
  ] : []),
];

function captureNet(req) {
  const h = req?.headers || {};
  const headers = {};
  for (const k of NET_HEADER_KEYS) {
    const v = h[k];
    if (v == null || v === '') continue;
    headers[k] = safeDiscordText(Array.isArray(v) ? v.join(',') : v, 400);
  }
  if (h.referer || h.referrer) headers.referer = redactUrl(h.referer || h.referrer);
  const xff = String(h['x-forwarded-for'] || '');
  const hops = xff.split(',').map(s => cleanIp(s)).filter(Boolean);
  return {
    at: Date.now(),
    ip: clientIp(req),
    peer: cleanIp(req.socket?.remoteAddress),
    hops,
    country: String(h['cf-ipcountry'] || h['cf-ip-country'] || '').toUpperCase().replace(/^(XX|UNKNOWN)$/, ''),
    ray: safeDiscordText(h['cf-ray'], 48),
    ...(FINGERPRINTS ? {
      city: safeDiscordText(h['cf-ipcity'], 80),
      lang: safeDiscordText(h['accept-language'], 160),
    } : {}),
    headers,
  };
}

function reqMeta(req) {
  const net = captureNet(req);
  return {
    ip: net.ip,
    peer: net.peer,
    forwarded: (net.hops || []).join(', '),
    country: net.country,
    ray: net.ray,
    ua: safeDiscordText(req?.headers?.['user-agent'], 220),
    origin: safeDiscordText(req?.headers?.origin, 120),
    referer: (net.headers && net.headers.referer) || '',
    ...(FINGERPRINTS ? {
      lang: net.lang,
      ch: safeDiscordText(net.headers['sec-ch-ua'], 120),
    } : {}),
    method: req.method,
    url: redactUrl(req.originalUrl || req.url || ''),
  };
}

const FP_LOG_FILE = path.join(EVENT_LOG_DIR, 'fingerprints.jsonl');
const IP_INTEL_FILE = path.join(EVENT_LOG_DIR, 'ip-intel.json');
let ipIntelCache = {};
if (FINGERPRINTS) {
  try { ipIntelCache = JSON.parse(fs.readFileSync(IP_INTEL_FILE, 'utf8')); } catch { ipIntelCache = {}; }
}
function saveIpIntel() {
  try { fs.writeFileSync(IP_INTEL_FILE, JSON.stringify(ipIntelCache)); } catch {}
}

const HOSTING_RE = /amazon|aws|google cloud|\bgcp\b|azure|microsoft|digitalocean|linode|vultr|ovh|hetzner|leaseweb|choopa|psychz|m247|datacamp|cloudflare|fastly|akamai|oracle cloud|contabo|ionos|hostinger|scaleway|kamatera|buyvm|quadranet|nordvpn|mullvad|expressvpn|surfshark|proton|windscribe|cyberghost|ipvanish|tunnelbear|purevpn|\bwarp\b|tailscale|datacamp|cdn77|colocrossing|serverius|tzulo|hosting|datacenter|data center|vpn/i;

async function lookupIp(ip) {
  ip = cleanIp(ip);
  if (!ip) return null;
  if (isLocalIp(ip)) return { ip, local: true, at: Date.now() };
  const hit = ipIntelCache[ip];
  if (hit && Date.now() - (hit.at || 0) < 24 * 3600 * 1000) return hit;
  try {
    const r = await fetch(IP_LOOKUP_URL + encodeURIComponent(ip), { signal: AbortSignal.timeout(2800) });
    const j = await r.json();
    if (j && j.success !== false) {
      const conn = j.connection || {};
      const org = conn.org || conn.isp || j.org || '';
      const isp = conn.isp || '';
      const asn = conn.asn != null ? String(conn.asn) : '';
      const rec = {
        at: Date.now(),
        ip,
        type: j.type || '',
        continent: j.continent_code || j.continent || '',
        country: j.country_code || '',
        countryName: j.country || '',
        region: j.region || '',
        city: j.city || '',
        postal: j.postal || '',
        lat: j.latitude,
        lon: j.longitude,
        tz: (j.timezone && (j.timezone.id || j.timezone)) || '',
        utc: j.timezone && j.timezone.utc,
        asn,
        org,
        isp,
        domain: conn.domain || '',
        hosting: HOSTING_RE.test([org, isp, asn, conn.domain].filter(Boolean).join(' ')),
      };
      ipIntelCache[ip] = rec;
      saveIpIntel();
      return rec;
    }
  } catch {}
  const miss = { at: Date.now(), ip, miss: true };
  ipIntelCache[ip] = miss;
  return miss;
}

const intelPending = new Set();
function wantIntel(ip) {
  if (!FINGERPRINTS || !IP_LOOKUP_URL) return;
  ip = cleanIp(ip);
  if (!ip || isLocalIp(ip) || intelPending.has(ip)) return;
  const hit = ipIntelCache[ip];
  if (hit && Date.now() - (hit.at || 0) < 24 * 3600 * 1000) return;
  intelPending.add(ip);
  lookupIp(ip).finally(() => intelPending.delete(ip));
}

function clipStr(v, n) {
  if (v == null) return '';
  if (typeof v === 'number' || typeof v === 'boolean') return v;
  return String(v).slice(0, n);
}
function clipArr(a, n, inner) {
  if (!Array.isArray(a)) return [];
  return a.slice(0, n).map(x => typeof x === 'string' ? x.slice(0, inner || 80) : x);
}
function uniqIps(list) {
  const out = [];
  const seen = new Set();
  for (const raw of list || []) {
    const ip = cleanIp(raw);
    if (!ip || seen.has(ip)) continue;
    seen.add(ip);
    out.push(ip);
  }
  return out.slice(0, 16);
}

function sanitizeFp(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const webrtc = raw.webrtc && typeof raw.webrtc === 'object' ? {
    host: uniqIps(raw.webrtc.host),
    srflx: uniqIps(raw.webrtc.srflx),
    relay: uniqIps(raw.webrtc.relay),
    error: clipStr(raw.webrtc.error, 80),
  } : { host: [], srflx: [], relay: [], error: '' };
  const ua = raw.ua && typeof raw.ua === 'object' ? {
    brands: clipArr(raw.ua.brands && raw.ua.brands.map(b => (b && b.brand) + ' ' + (b && b.version)), 8, 40),
    mobile: !!raw.ua.mobile,
    platform: clipStr(raw.ua.platform, 40),
    architecture: clipStr(raw.ua.architecture, 20),
    bitness: clipStr(raw.ua.bitness, 8),
    model: clipStr(raw.ua.model, 60),
    platformVersion: clipStr(raw.ua.platformVersion, 40),
    uaFullVersion: clipStr(raw.ua.uaFullVersion, 40),
    wow64: !!raw.ua.wow64,
    formFactors: clipArr(raw.ua.formFactors, 6, 24),
    fullVersionList: clipArr(raw.ua.fullVersionList && raw.ua.fullVersionList.map(b => (b && b.brand) + ' ' + (b && b.version)), 8, 48),
  } : null;
  const webgl = raw.webgl && typeof raw.webgl === 'object' ? {
    supported: !!raw.webgl.supported,
    vendor: clipStr(raw.webgl.vendor, 80),
    renderer: clipStr(raw.webgl.renderer, 120),
    version: clipStr(raw.webgl.version, 80),
    unmaskedVendor: clipStr(raw.webgl.unmaskedVendor, 80),
    unmaskedRenderer: clipStr(raw.webgl.unmaskedRenderer, 160),
    extensions: clipArr(raw.webgl.extensions, 40, 60),
  } : null;
  return {
    v: 1,
    at: Date.now(),
    deviceId: clipStr(raw.deviceId, 64),
    timezone: clipStr(raw.timezone, 80),
    locale: clipStr(raw.locale, 40),
    calendar: clipStr(raw.calendar, 32),
    numbering: clipStr(raw.numbering, 24),
    languages: clipArr(raw.languages, 12, 24),
    language: clipStr(raw.language, 24),
    platform: clipStr(raw.platform, 64),
    userAgent: clipStr(raw.userAgent, 400),
    ua,
    vendor: clipStr(raw.vendor, 80),
    productSub: clipStr(raw.productSub, 32),
    hardwareConcurrency: Number(raw.hardwareConcurrency) || 0,
    deviceMemory: Number(raw.deviceMemory) || 0,
    maxTouchPoints: Number(raw.maxTouchPoints) || 0,
    cookieEnabled: !!raw.cookieEnabled,
    doNotTrack: clipStr(raw.doNotTrack, 16),
    webdriver: !!raw.webdriver,
    pdfViewerEnabled: !!raw.pdfViewerEnabled,
    plugins: Number(raw.plugins) || 0,
    screen: raw.screen && typeof raw.screen === 'object' ? {
      w: Number(raw.screen.w) || 0, h: Number(raw.screen.h) || 0,
      aw: Number(raw.screen.aw) || 0, ah: Number(raw.screen.ah) || 0,
      cd: Number(raw.screen.cd) || 0, pd: Number(raw.screen.pd) || 0,
      angle: raw.screen.angle, type: clipStr(raw.screen.type, 24),
    } : null,
    dpr: Number(raw.dpr) || 0,
    inner: raw.inner && typeof raw.inner === 'object' ? { w: Number(raw.inner.w) || 0, h: Number(raw.inner.h) || 0 } : null,
    outer: raw.outer && typeof raw.outer === 'object' ? { w: Number(raw.outer.w) || 0, h: Number(raw.outer.h) || 0 } : null,
    colorScheme: clipStr(raw.colorScheme, 12),
    reducedMotion: !!raw.reducedMotion,
    pointer: clipStr(raw.pointer, 12),
    hover: !!raw.hover,
    connection: raw.connection && typeof raw.connection === 'object' ? {
      type: clipStr(raw.connection.type, 24),
      effectiveType: clipStr(raw.connection.effectiveType, 16),
      downlink: raw.connection.downlink,
      rtt: raw.connection.rtt,
      saveData: !!raw.connection.saveData,
    } : null,
    canvas: raw.canvas && typeof raw.canvas === 'object' ? { hash: clipStr(raw.canvas.hash, 16), supported: raw.canvas.supported !== false } : null,
    webgl,
    audio: raw.audio && typeof raw.audio === 'object' ? { hash: clipStr(raw.audio.hash, 16), sampleRate: raw.audio.sampleRate, supported: raw.audio.supported !== false } : null,
    fonts: clipArr(raw.fonts, 50, 40),
    media: raw.media && typeof raw.media === 'object' ? {
      audioinput: Number(raw.media.audioinput) || 0,
      videoinput: Number(raw.media.videoinput) || 0,
      audiooutput: Number(raw.media.audiooutput) || 0,
    } : null,
    storage: raw.storage && typeof raw.storage === 'object' ? { quota: raw.storage.quota, usage: raw.storage.usage } : null,
    keyboard: clipArr(raw.keyboard, 40, 24),
    webrtc,
    touch: !!raw.touch,
  };
}

function mergeFp(prev, next) {
  if (!next) return prev || null;
  if (!prev) return next;
  const webrtc = {
    host: uniqIps([...(prev.webrtc && prev.webrtc.host || []), ...(next.webrtc && next.webrtc.host || [])]),
    srflx: uniqIps([...(prev.webrtc && prev.webrtc.srflx || []), ...(next.webrtc && next.webrtc.srflx || [])]),
    relay: uniqIps([...(prev.webrtc && prev.webrtc.relay || []), ...(next.webrtc && next.webrtc.relay || [])]),
    error: (next.webrtc && next.webrtc.error) || (prev.webrtc && prev.webrtc.error) || '',
  };
  return { ...prev, ...next, webrtc, at: Date.now() };
}

function dossierFlags(rec, info) {
  const fp = (info && info.fp) || (rec && rec.fp) || {};
  const intel = (rec && rec.intel) || {};
  const net = (info && info.net) || (rec && rec.net) || {};
  const httpIp = cleanIp((info && info.ip) || net.ip || (rec && (rec.lastIp || rec.ip)));
  const srflx = (fp.webrtc && fp.webrtc.srflx) || [];
  const leakIps = uniqIps(srflx).filter(ip => ip !== httpIp && !isLocalIp(ip));
  const flags = [];
  if (intel.hosting) flags.push('HOSTING');
  if (intel.local) flags.push('LOCAL');
  if (leakIps.length) flags.push('WEBRTC-LEAK');
  if ((net.hops || []).length > 1) flags.push('XFF-CHAIN');
  if (fp.webdriver) flags.push('WEBDRIVER');
  const ipTz = intel.tz || (net.headers && net.headers['cf-timezone']) || '';
  if (fp.timezone && ipTz && fp.timezone !== ipTz && !String(ipTz).startsWith(String(fp.timezone).split('/')[0] || '___')) {
    // city-level tz ids: mismatch if neither contains the other
    if (!String(ipTz).includes(String(fp.timezone)) && !String(fp.timezone).includes(String(ipTz))) {
      flags.push('TZ-MISMATCH');
    }
  }
  return { flags, httpIp, leakIps, hostIps: (fp.webrtc && fp.webrtc.host) || [] };
}

function persistFp(rec, extra = {}) {
  if (!FINGERPRINTS || !rec) return;
  try {
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      rid: rec.rid,
      user: rec.user || '',
      provider: rec.provider || 'secret',
      ip: rec.lastIp || rec.ip || '',
      deviceId: rec.fp && rec.fp.deviceId,
      flags: extra.flags || [],
      leakIps: extra.leakIps || [],
      timezone: rec.fp && rec.fp.timezone,
      language: rec.fp && rec.fp.language,
      languages: rec.fp && rec.fp.languages,
      intel: rec.intel || null,
      webrtc: rec.fp && rec.fp.webrtc,
      ua: (rec.fp && rec.fp.userAgent) || rec.ua,
      net: rec.net || null,
      fp: rec.fp || null,
    }) + '\n';
    fs.appendFile(FP_LOG_FILE, line, () => {});
  } catch {}
}

function applyFp(rec, raw, req) {
  if (!FINGERPRINTS) return rec;
  if (!rec) return rec;
  let fp;
  try { fp = sanitizeFp(raw); } catch { return rec; }
  if (!fp) return rec;
  rec.fp = mergeFp(rec.fp, fp);
  if (req) rec.net = captureNet(req);
  const httpIp = cleanIp(rec.lastIp || rec.ip);
  wantIntel(httpIp);
  for (const ip of [...(rec.fp.webrtc.srflx || []), ...(rec.fp.webrtc.host || [])]) {
    if (!isLocalIp(ip)) wantIntel(ip);
  }
  rec.intel = ipIntelCache[httpIp] || rec.intel || null;
  const { flags, leakIps } = dossierFlags(rec, null);
  const leakKey = leakIps.slice().sort().join(',');
  if (leakIps.length && rec.lastLeakKey !== leakKey) {
    rec.lastLeakKey = leakKey;
    audit('webrtc_ip_leak', req || null, {
      user: rec.user || '',
      ip: httpIp,
      leak: leakIps.join(','),
      tz: rec.fp.timezone || '',
    });
  }
  if (!rec.fpLogged || rec.fpLogged !== rec.fp.deviceId + leakKey) {
    rec.fpLogged = rec.fp.deviceId + leakKey;
    persistFp(rec, { flags, leakIps });
  }
  return rec;
}

function touchIpHistory(rec, ip) {
  ip = cleanIp(ip);
  if (!rec || !ip) return;
  if (!Array.isArray(rec.ipHistory)) rec.ipHistory = [];
  const last = rec.ipHistory[rec.ipHistory.length - 1];
  if (last && last.ip === ip) return;
  rec.ipHistory.push({ ip, at: Date.now() });
  if (rec.ipHistory.length > 16) rec.ipHistory = rec.ipHistory.slice(-16);
  wantIntel(ip);
}

function readFpHistory(n = 60) {
  if (!FINGERPRINTS) return [];
  try {
    const lines = fs.readFileSync(FP_LOG_FILE, 'utf8').trim().split('\n');
    const out = [];
    for (let i = lines.length - 1; i >= 0 && out.length < n; i--) {
      try { out.push(JSON.parse(lines[i])); } catch {}
    }
    return out;
  } catch { return []; }
}

function publicDossier(rec, info) {
  const net = (info && info.net) || (rec && rec.net) || null;
  const httpIp = cleanIp((info && info.ip) || (rec && (rec.lastIp || rec.ip)));
  const ipHistory = (rec && rec.ipHistory) || [];
  if (!FINGERPRINTS) return { httpIp, net, ipHistory };
  const fp = (info && info.fp) || (rec && rec.fp) || null;
  const intel = (rec && rec.intel) || (fp && null);
  const { flags, leakIps, hostIps } = dossierFlags(rec, info);
  const leakIntel = {};
  for (const ip of leakIps) if (ipIntelCache[ip]) leakIntel[ip] = ipIntelCache[ip];
  return {
    flags,
    leakIps,
    hostIps,
    httpIp,
    deviceId: fp && fp.deviceId,
    language: fp && fp.language,
    languages: fp && fp.languages,
    timezone: fp && fp.timezone,
    locale: fp && fp.locale,
    net,
    intel: rec && rec.intel || (httpIp && ipIntelCache[httpIp]) || intel,
    leakIntel,
    ipHistory,
    fp,
  };
}

// Discord webhook: serial queue so a burst of auth events is not dropped on 429.
const discordQueue = [];
let discordBusy = false;
function sendDiscord(content) {
  if (!DISCORD_WEBHOOK) return;
  discordQueue.push(String(content || '').slice(0, 1900));
  if (discordQueue.length > 200) discordQueue.splice(0, discordQueue.length - 200);
  pumpDiscord();
}
function pumpDiscord() {
  if (discordBusy || !discordQueue.length || !DISCORD_WEBHOOK) return;
  discordBusy = true;
  const content = discordQueue.shift();
  let url;
  try { url = parseHttpsUrl(DISCORD_WEBHOOK); } catch {
    url = null;
  }
  if (!url) {
    eventLog({ event: 'discord_webhook_error', reason: 'bad_url' });
    discordBusy = false;
    return;
  }
  const body = Buffer.from(JSON.stringify({ content, allowed_mentions: { parse: [] } }));
  const r = https.request({
    hostname: url.hostname,
    port: url.port,
    path: url.pathname + url.search,
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': body.length },
  }, res => {
    res.resume();
    if (res.statusCode === 429) {
      discordQueue.unshift(content);
      setTimeout(() => { discordBusy = false; pumpDiscord(); }, 1500);
      return;
    }
    if (res.statusCode && (res.statusCode < 200 || res.statusCode >= 300)) {
      eventLog({ event: 'discord_webhook_error', status: res.statusCode });
    }
    setTimeout(() => { discordBusy = false; pumpDiscord(); }, 350);
  });
  r.on('error', () => {
    eventLog({ event: 'discord_webhook_error', reason: 'network' });
    setTimeout(() => { discordBusy = false; pumpDiscord(); }, 1500);
  });
  r.write(body);
  r.end();
}

// Auth-class events always hit Discord (plus events.jsonl). High-frequency probes
// are Discord-rate-limited per IP so a polling tab after a kick cannot flood.
const DISCORD_ALWAYS = new Set([
  'boot', 'secret_rotated',
  'auth_ok', 'auth_fail', 'auth_lockout',
  'auth_exchange_ok', 'auth_exchange_fail', 'auth_logout',
  'auth_provider_start', 'auth_provider_ok', 'auth_provider_fail',
  'passkey_registered', 'passkey_deleted',
  'auth_user_denied',
  'ws_token_in_query', 'token_ip_change',
  'hello_visitor', 'new_ip', 'webrtc_ip_leak',
  'client_connected', 'multi_attach', 'client_disconnected',
  'all_tabs_closed', 'session_emptied',
]);
const DISCORD_COOLDOWN_MS = {
  api_unauthorized: 15000,
  ws_unauthorized: 15000,
  auth_locked: 15000,
};
const discordQuiet = new Map(); // event:ip -> lastSent
function shouldDiscord(event, ip) {
  if (DISCORD_ALWAYS.has(event)) return true;
  const cool = DISCORD_COOLDOWN_MS[event];
  if (!cool) return false;
  const key = `${event}:${ip || '?'}`;
  const last = discordQuiet.get(key) || 0;
  if (Date.now() - last < cool) return false;
  discordQuiet.set(key, Date.now());
  return true;
}

function formatDiscord(event, meta, extra) {
  const title = event.replace(/_/g, ' ').toUpperCase();
  const lines = [`**webmux ${title}**`];
  const kv = { ...meta, ...extra };
  delete kv.token; delete kv.secret; delete kv.jwt; delete kv.handoff;
  const order = [
    'ip', 'country', 'peer', 'forwarded', 'ray',
    'user', 'authMethod', 'provider', 'via', 'reason',
    'method', 'url', 'path', 'session', 'clients',
    'fails', 'offeredLen', 'mintedIp', 'ua', 'lang', 'origin', 'referer',
  ];
  const seen = new Set();
  for (const k of [...order, ...Object.keys(kv)]) {
    if (seen.has(k)) continue;
    seen.add(k);
    const v = kv[k];
    if (v == null || v === '' || v === 'unknown') continue;
    if (typeof v === 'object') continue;
    lines.push(`${k}: \`${safeDiscordText(v, 180)}\``);
  }
  lines.push(`Time: ${new Date().toISOString()}`);
  return lines.join('\n');
}

function audit(event, req, extra = {}) {
  const meta = req && req.headers ? reqMeta(req) : {};
  const payload = { event, ...meta, ...extra };
  delete payload.token; delete payload.secret; delete payload.jwt; delete payload.handoff;
  eventLog(payload);
  if (shouldDiscord(event, meta.ip || extra.ip)) sendDiscord(formatDiscord(event, meta, extra));
}

function logToDiscord(req) {
  const ip = clientIp(req);
  if (!ip || seenIps.has(ip)) return;
  seenIps.add(ip);
  fs.appendFile(SEEN_IPS_FILE, ip + '\n', () => {});
  audit('new_ip', req);
}

// ---- secret ----
let SECRET;
if (fs.existsSync(SECRET_FILE)) {
  SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim();
} else {
  SECRET = crypto.randomBytes(24).toString('base64url');
  fs.mkdirSync(path.dirname(SECRET_FILE), { recursive: true, mode: 0o700 });
  fs.writeFileSync(SECRET_FILE, SECRET, { mode: 0o600, flag: 'wx' });
}
if (!SECRET) throw new Error('Recovery secret file must not be empty');

// In-memory tickets. The browser holds the current id in a JS variable and
// sends it as `x-token` / `Authorization`. We rotate on every API call
// (`X-Session`); reload drops the JS variable → login again.
const tokens = new Map(); // sid -> rec
// oldSid -> { rec, exp }. Keep every rotated-out id until it expires so parallel
// polls (refreshTabs + refreshSessions) don't 401 each other mid-rotation.
const prevTokens = new Map();
const TICKET_DEBOUNCE_MS = 2000;
const TICKET_GRACE_MS = 30000;
// Live browser WS → metadata. Declared early so destroyTicket can revoke sockets.
const clients = new Map(); // ws -> { id, ip, session, ua, connectedAt, ... }
const pendingSockets = new Map(); // ws -> ticket, while asynchronous attachment is in flight
let clientSeq = 0;

function lookupTicket(t) {
  if (!t) return null;
  const live = tokens.get(t);
  if (live) return live;
  const prev = prevTokens.get(t);
  if (prev && prev.exp > Date.now()) return prev.rec;
  if (prev) prevTokens.delete(t);
  return null;
}
function destroyTicket(rec) {
  if (!rec) return false;
  tokens.delete(rec.sid);
  for (const [sid, p] of prevTokens) {
    if (p.rec === rec) prevTokens.delete(sid);
  }
  // Revoke live sockets for this ticket — rotated ids share the same rec.
  for (const [ws, ticket] of pendingSockets) {
    if (ticket !== rec) continue;
    try { ws.close(4001, 'ticket-revoked'); } catch {}
    try { ws.terminate(); } catch {}
  }
  for (const [ws, info] of [...clients.entries()]) {
    if (info.ticket !== rec) continue;
    try { ws.close(4001, 'ticket-revoked'); } catch {}
    try { ws.terminate(); } catch {}
  }
  return true;
}
function prunePrevTokens(now = Date.now()) {
  for (const [sid, p] of prevTokens) {
    if (p.exp <= now) prevTokens.delete(sid);
  }
}
function ticketActive(rec) {
  if (!rec || tokens.get(rec.sid) !== rec) return false;
  if (rec.exp <= Date.now() || !ticketUserAllowed(rec)) { destroyTicket(rec); return false; }
  return true;
}
function tokenValid(t) { return ticketActive(lookupTicket(t)); }
function writeTicket(res, sid) {
  if (!res || !sid) return;
  res.setHeader('X-Session', sid);
  res.setHeader('Access-Control-Expose-Headers', 'X-Session');
  res.setHeader('Cache-Control', 'no-store');
}
function rotateTicket(res, rec) {
  const now = Date.now();
  if (now - (rec.lastRotate || 0) < TICKET_DEBOUNCE_MS) {
    writeTicket(res, rec.sid);
    return rec;
  }
  const old = rec.sid;
  const neu = crypto.randomBytes(32).toString('hex');
  tokens.delete(old);
  prevTokens.set(old, { rec, exp: now + TICKET_GRACE_MS });
  rec.sid = neu;
  rec.lastRotate = now;
  tokens.set(neu, rec);
  if (prevTokens.size > 128) prunePrevTokens(now);
  writeTicket(res, neu);
  return rec;
}
function readClientToken(req) {
  const xt = req.headers['x-token'];
  if (xt) return String(xt);
  const auth = String(req.headers.authorization || '');
  if (/^bearer\s+/i.test(auth)) return auth.replace(/^bearer\s+/i, '').trim();
  return '';
}
// Optional external providers require an explicit username allowlist. Native
// accounts are enrolled locally by an administrator and have their own roles.
const AUTH_USERS = new Set(
  (process.env.WEBMUX_AUTH_USERS ?? process.env.WEBMUX_ADMIN_USERS ?? process.env.ADMIN_USERS ?? '')
    .split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
);
function authUserAllowed(user) {
  return typeof user === 'string' && !!user && AUTH_USERS.has(user.toLowerCase());
}
function ticketUserAllowed(rec) {
  return rec.provider === 'secret' || rec.provider === 'passkey' || authUserAllowed(rec.user);
}

// mint an ephemeral, revocable session token — used by secret auth & auth-provider extensions
// to bridge a login into a token requireToken/the WS handshake accept.
function mintToken({ user = null, ttlMs = 12 * 3600 * 1000, kind = 'session', ip = null, ua = null,
  provider = 'secret', accountId = null, admin = false, credentialId = null } = {}) {
  if (provider !== 'secret' && provider !== 'passkey' && !authUserAllowed(user)) return null;
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0 || !Number.isSafeInteger(Date.now() + ttlMs)) return null;
  const token = crypto.randomBytes(32).toString('hex');
  tokens.set(token, {
    sid: token,
    rid: crypto.randomBytes(8).toString('hex'),
    kind, user, provider, accountId, admin, credentialId,
    exp: Date.now() + ttlMs,
    ip: ip || null,
    ua: ua || null,
    mintedAt: Date.now(),
    lastRotate: Date.now(),
    lastIp: ip || null,
    lastAlertIp: null,
    uses: 0,
    fp: null,
    net: null,
    intel: null,
    ipHistory: ip ? [{ ip, at: Date.now() }] : [],
  });
  if (ip) wantIntel(ip);
  return token;
}
function noteTokenUse(rec, req) {
  if (!rec) return rec;
  const ip = clientIp(req);
  rec.uses++;
  rec.lastUse = Date.now();
  rec.lastIp = ip;
  rec.net = captureNet(req);
  touchIpHistory(rec, ip);
  rec.intel = FINGERPRINTS ? ipIntelCache[ip] || rec.intel || null : null;
  if (rec.ip && rec.ip !== ip && rec.lastAlertIp !== ip) {
    rec.lastAlertIp = ip;
    audit('token_ip_change', req, {
      user: rec.user || '',
      mintedIp: rec.ip,
      uses: rec.uses,
      ageSec: Math.round((Date.now() - rec.mintedAt) / 1000),
    });
  }
  return rec;
}
function revokeToken(t) {
  return destroyTicket(lookupTicket(t));
}

// one-time login handoffs: a random id (carried in the httpOnly webmux_handoff
// cookie) mapped to a real session token. Consumed on the first /api/auth/exchange
// so a replayed cookie can't re-authenticate. Short-lived.
const handoffs = new Map(); // id -> { token, exp }
const HANDOFF_TTL_MS = 60 * 1000;
function beginHandoff(sessionToken) {
  const id = crypto.randomBytes(24).toString('hex');
  handoffs.set(id, { token: sessionToken, exp: Date.now() + HANDOFF_TTL_MS });
  return id;
}
function consumeHandoff(id) {
  if (!id) return null;
  const rec = handoffs.get(id);
  handoffs.delete(id); // single-use regardless of validity
  if (!rec || rec.exp <= Date.now() || !tokenValid(rec.token)) return null;
  return rec.token;
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

// ---- tmux helpers ----
function tmux(args) {
  const full = TMUX_SOCKET ? ['-L', TMUX_SOCKET, ...args] : args;
  return new Promise((resolve, reject) => {
    execFile(TMUX_BIN, full, { env: shellEnv({ TMUX: '' }) }, (err, stdout) => {
      if (err) reject(err); else resolve(stdout);
    });
  });
}

// Reject tmux separators, path separators and control characters used by snapshots.
function cleanSession(v) {
  if (typeof v !== 'string') return '';
  const s = v.trim();
  if (!s || s.length > 64 || /[.:/\\\x00-\x1f\x7f]/.test(s)) return '';
  return s;
}

async function sessionExists(name) {
  try { await tmux(['has-session', '-t', name]); return true; }
  catch { return false; }
}

// per-session options, shared by createSession() and restoreFromSnapshot()
async function applySessionOptions(name) {
  await tmux(['set-option', '-t', name, 'mouse', 'on']);
  await tmux(['set-option', '-t', name, 'status', 'off']);
  // 20k lines/window keeps scrollback useful without making tmux a fat OOM target
  await tmux(['set-option', '-t', name, 'history-limit', '20000']);
  await tmux(['set-option', '-t', name, 'escape-time', '0']);
  await tmux(['set-option', '-t', name, 'focus-events', 'on']);
  await tmux(['set-option', '-t', name, 'renumber-windows', 'on']);
  // Multi-browser attach is collaborative (many clients share the session).
  // "latest" lets the focused client set geometry without forcing empty margins.
  await tmux(['set-option', '-t', name, 'window-size', 'latest']);
  // keep a window's pane when its program dies UNCLEANLY (crash / OOM-kill /
  // non-zero exit). A clean `exit 0` still closes the window, so deliberately
  // ephemeral tabs behave as before. A crashed pane stays visible (frozen
  // output + exit status) instead of silently vanishing, and — because the
  // window survives — the snapshot no longer overwrites it out of existence.
  await tmux(['set-option', '-t', name, 'remain-on-exit', 'failed']);
  // bell plumbing: apps ring BEL when they want attention (agent finished, job
  // done). monitor-bell raises #{window_bell_flag} so a *background* tab can be
  // marked; bell-action any + visual-bell off let the BEL byte itself through
  // to the client, so xterm.js onBell fires instantly for any window — verified
  // to propagate from non-active windows. monitor-activity stays OFF on purpose:
  // panes running agents stream output constantly, so an activity flag would be
  // permanently set and the indicator would mean nothing.
  // auto-name windows "<command> · <dir>" (e.g. "claude · rpc-proxy") so a wall
  // of identically-named agent tabs is tellable apart. These are *window*
  // options, so they must be set with -wg (global window) — setting them per
  // session only ever lands on that session's current window, and new windows
  // never inherit it. A manual rename-window turns automatic-rename off for
  // that window, so user-chosen names stick permanently (see /api/rename).
  await tmux(['set-option', '-wg', 'automatic-rename', 'on']);
  await tmux(['set-option', '-wg', 'automatic-rename-format',
    '#{pane_current_command} · #{b:pane_current_path}']);
  await tmux(['set-option', '-t', name, 'monitor-bell', 'on']);
  await tmux(['set-option', '-t', name, 'bell-action', 'any']);
  await tmux(['set-option', '-t', name, 'visual-bell', 'off']);
  // true color: advertise RGB for the outer term, let inner apps detect it
  await tmux(['set-option', '-g', 'default-terminal', 'tmux-256color']);
  await tmux(['set-option', '-s', 'terminal-overrides', 'xterm-256color:Tc']);
  await tmux(['set-option', '-sa', 'terminal-features', 'xterm-256color:RGB']);
  await tmux(['set-environment', '-t', name, 'COLORTERM', 'truecolor']);
}

async function createSession(name) {
  await tmux(['new-session', '-d', '-s', name, '-x', '220', '-y', '50']);
  await applySessionOptions(name);
}

// ---- persistence: snapshot the group/tab skeleton so it survives a tmux
// daemon death (OOM/reboot). We save session names, window names+order, and
// each window's working dir — not running programs. Restore rebuilds the
// structure and drops a fresh shell in the saved cwd.
let snapTimer = null;
function scheduleSnapshot() {
  if (snapTimer) return;
  snapTimer = setTimeout(() => { snapTimer = null; snapshot(); }, 1000);
}

// Last known working dir per window. A *dead* pane reports an empty
// pane_current_path, so without this the 15 s snapshot would overwrite a
// perfectly good directory with "" the moment a tab crashed — losing exactly
// the information needed to bring it back.
const lastCwd = new Map();       // "session:index" -> cwd
const lastCwdByName = new Map(); // "session:name"  -> cwd (survives renumbering)
function rememberCwd(session, index, name, dir) {
  if (!dir) return;
  lastCwd.set(`${session}:${index}`, dir);
  if (name) lastCwdByName.set(`${session}:${name}`, dir);
}
// renumber-windows is on, so indices shift when a window closes — keep a
// name-keyed copy too, otherwise a shift orphans the remembered directory.
function seedLastCwd() {
  for (const file of [STATE_FILE, STATE_BACKUP]) {
    try {
      for (const g of JSON.parse(fs.readFileSync(file, 'utf8'))) {
        for (const w of g.windows || []) {
          if (w.cwd && !lastCwd.has(`${g.session}:${w.index}`)) rememberCwd(g.session, w.index, w.name, w.cwd);
        }
      }
    } catch {}
  }
}

function isDir(p) {
  try { return !!p && fs.statSync(p).isDirectory(); } catch { return false; }
}

async function snapshot() {
  let out;
  try {
    out = await tmux(['list-windows', '-a', '-F',
      '#{session_name}\t#{window_index}\t#{window_active}\t#{pane_current_path}\t#{@wm_manual}\t#{window_name}']);
  } catch { return; } // tmux unreachable (e.g. just died) — never clobber the snapshot
  const map = new Map();
  for (const line of out.trim().split('\n').filter(Boolean)) {
    const [session, index, active, cwd, manual, ...nameParts] = line.split('\t');
    if (!map.has(session)) map.set(session, []);
    // keep the last good dir when the pane is dead and reports nothing
    const wname = nameParts.join('\t');
    let dir = cwd;
    if (dir) rememberCwd(session, +index, wname, dir);
    else dir = lastCwd.get(`${session}:${+index}`) || lastCwdByName.get(`${session}:${wname}`) || '';
    map.get(session).push({
      index: +index, name: wname, active: active === '1', cwd: dir,
      manual: manual === '1', // user-chosen name; auto-generated ones aren't restored verbatim
    });
  }
  const state = [...map.entries()].map(([session, windows]) => ({ session, windows }));
  if (!state.length) return; // nothing live — don't overwrite a good snapshot with empty
  try {
    const tmp = STATE_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(state));
    fs.renameSync(tmp, STATE_FILE); // atomic replace
  } catch {}
  snapshotScrollback(state);
}

function snapshotScrollback(state) {
  if (!LOG_SCROLLBACK) return;
  if (!state || !state.length) return;
  (async () => {
    for (const g of state) {
      const sess = cleanSession(g.session);
      if (!sess) continue;
      for (const w of g.windows || []) {
        const idx = +w.index;
        if (Number.isNaN(idx)) continue;
        try {
          const text = await tmux(['capture-pane', '-t', sess + ':' + idx, '-p', '-S', '-4000']);
          const safeName = String(w.name || '').replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 40);
          const file = path.join(SCROLLBACK_DIR, sess + '_' + idx + (safeName ? '_' + safeName : '') + '.txt');
          const tmp = file + '.tmp';
          fs.writeFileSync(tmp, '# ' + new Date().toISOString() + ' ' + sess + ':' + idx + ' ' + (w.name || '') + '\n' + (text || ''));
          fs.renameSync(tmp, file);
        } catch {}
      }
    }
  })().catch(() => {});
}

// crash detector: with `remain-on-exit failed`, a pane whose program dies
// uncleanly (crash / OOM-kill / non-zero exit) sticks around as a *dead* pane.
// Poll for newly-dead panes and ping Discord once each, so a silently-killed
// tab (e.g. an OOM'd process) is surfaced instead of just quietly appearing
// frozen. Deduped by pane id; ids that go away (respawned/closed) are forgotten
// so a later re-crash of the same slot alerts again.
const alertedDeadPanes = new Set();
async function checkDeadPanes() {
  let out;
  try {
    out = await tmux(['list-panes', '-a', '-F',
      '#{pane_id}\t#{pane_dead}\t#{pane_dead_status}\t#{session_name}\t#{window_index}\t#{window_name}']);
  } catch { return; } // tmux unreachable — nothing to do
  const live = new Set();
  for (const line of out.trim().split('\n').filter(Boolean)) {
    const [id, dead, status, session, index, ...nameParts] = line.split('\t');
    live.add(id);
    if (dead !== '1' || alertedDeadPanes.has(id)) continue;
    alertedDeadPanes.add(id);
    const name = safeDiscordText(nameParts.join('\t'), 80);
    const code = status === '' ? '?' : status;
    const hint = (+code === 137 || +code === 139) ? ' (likely OOM-kill / SIGKILL)' : '';
    sendDiscord(`**webmux TAB CRASHED**\nSession: \`${session}\`\nTab: \`${index}\` (\`${name}\`)\n` +
      `Exit: \`${code}\`${hint}\nTime: ${new Date().toISOString()}\n` +
      `_pane kept alive — reconnect to inspect, then respawn or close it_`);
    eventLog({ event: 'tab_crashed', session, index, name, code });
  }
  for (const id of alertedDeadPanes) if (!live.has(id)) alertedDeadPanes.delete(id);
}

// ---- memory telemetry ------------------------------------------------------
// A single fat pane can take the whole box down (a 9.7 GB process once got
// OOM-killed here and took four tabs with it). Sample per-window RSS and system
// pressure so the UI can show which tab is heavy, and warn *before* the kernel
// starts choosing victims. Sampled on the existing 15 s tick, never per-request.
let memStats = { windows: {}, sys: null, ts: 0 };

function readMeminfo() {
  try {
    const txt = fs.readFileSync('/proc/meminfo', 'utf8');
    const kb = key => {
      const m = txt.match(new RegExp('^' + key + ':\\s+(\\d+) kB', 'm'));
      return m ? +m[1] : 0;
    };
    const memTotal = kb('MemTotal'), memAvail = kb('MemAvailable');
    const swapTotal = kb('SwapTotal'), swapFree = kb('SwapFree');
    if (!memTotal) return null;
    return {
      memTotalMB: Math.round(memTotal / 1024),
      memAvailMB: Math.round(memAvail / 1024),
      memAvailPct: Math.round((memAvail / memTotal) * 100),
      swapTotalMB: Math.round(swapTotal / 1024),
      swapFreeMB: Math.round(swapFree / 1024),
      swapFreePct: swapTotal ? Math.round((swapFree / swapTotal) * 100) : 100,
    };
  } catch { return null; }
}

// resident MB for a pane: the pane process plus every descendant, since the
// interesting memory lives in what the shell spawned, not the shell itself
function rssTreeMB(pid) {
  let totalKb = 0;
  const seen = new Set();
  let frontier = [pid];
  while (frontier.length) {
    const next = [];
    for (const p of frontier) {
      if (seen.has(p)) continue;
      seen.add(p);
      try {
        const m = fs.readFileSync(`/proc/${p}/status`, 'utf8').match(/^VmRSS:\s+(\d+) kB/m);
        if (m) totalKb += +m[1];
      } catch {}
      next.push(...childrenOf(p));
    }
    frontier = next;
  }
  return Math.round(totalKb / 1024);
}

async function sampleMemory() {
  const sys = readMeminfo();
  const windows = {};
  try {
    const out = await tmux(['list-panes', '-a', '-F',
      '#{session_name}\t#{window_index}\t#{window_name}\t#{pane_pid}']);
    for (const line of out.trim().split('\n').filter(Boolean)) {
      const [session, index, wname, pid] = line.split('\t');
      const key = `${session}:${index}`;
      const cur = windows[key] || { mb: 0, name: wname };
      cur.mb += rssTreeMB(+pid); // windows can hold several panes
      windows[key] = cur;
    }
  } catch { return; }
  memStats = { windows, sys, ts: Date.now() };
  warnIfMemoryLow();
}

// fire once per cooldown while pressure lasts, naming the biggest offenders so
// the alert is actionable ("tab 3 is the 8 GB one") rather than just scary
let lastMemWarn = 0;
const MEM_WARN_COOLDOWN_MS = 10 * 60 * 1000;
function warnIfMemoryLow() {
  const s = memStats.sys;
  if (!s) return;
  const tight = s.memAvailPct <= 12 || (s.swapTotalMB > 0 && s.swapFreePct <= 15);
  if (!tight) return;
  if (Date.now() - lastMemWarn < MEM_WARN_COOLDOWN_MS) return;
  lastMemWarn = Date.now();
  const top = Object.entries(memStats.windows)
    .sort((a, b) => b[1].mb - a[1].mb).slice(0, 3)
    .map(([k, v]) => `\`${k}\` (\`${safeDiscordText(v.name, 60)}\`) — ${(v.mb / 1024).toFixed(1)} GB`).join('\n');
  sendDiscord(`**webmux MEMORY LOW**\n` +
    `RAM available: ${s.memAvailMB} MB (${s.memAvailPct}%)\n` +
    `Swap free: ${s.swapFreeMB} MB (${s.swapFreePct}%)\n` +
    `Heaviest tabs:\n${top || '_none measured_'}\n` +
    `Time: ${new Date().toISOString()}\n` +
    `_the OOM killer targets the biggest process — close or restart one before it picks_`);
}

async function restoreFromSnapshot() {
  let state;
  try { state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); }
  catch { return false; }
  if (!Array.isArray(state) || !state.length) return false;
  const home = process.env.HOME || '/';
  // fall back to $HOME if a saved dir was since deleted (tmux errors on -c <gone>)
  const dirOf = w => {
    try { if (w.cwd && fs.statSync(w.cwd).isDirectory()) return w.cwd; } catch {}
    return home;
  };
  let restored = false;
  for (const s of state) {
    const name = cleanSession(s.session);
    const windows = (Array.isArray(s.windows) ? s.windows : []).slice().sort((a, b) => a.index - b.index);
    if (!name || !windows.length) continue;
    if (await sessionExists(name)) continue; // don't stomp a session that's already live
    try {
      const first = windows[0];
      await tmux(['new-session', '-d', '-s', name, '-x', '220', '-y', '50', '-c', dirOf(first)]);
      await applySessionOptions(name);
      const idxMap = [];
      // Only re-apply names the user chose. Re-applying an auto-generated name
      // would turn automatic-rename off for that window and freeze it at a
      // stale "claude · olddir" forever.
      const restoreName = async (w, idx) => {
        if (!w.name || w.manual === false) return;
        const target = `${name}:${idx}`;
        await tmux(['rename-window', '-t', target, w.name]).catch(() => {});
        await tmux(['set-option', '-w', '-t', target, '@wm_manual', '1']).catch(() => {});
      };
      const firstIdx = (await tmux(['list-windows', '-t', name, '-F', '#{window_index}']))
        .trim().split('\n')[0];
      await restoreName(first, +firstIdx);
      idxMap.push({ w: first, idx: +firstIdx });
      for (let i = 1; i < windows.length; i++) {
        const w = windows[i];
        const idx = (await tmux(['new-window', '-t', `${name}:`, '-P', '-F', '#{window_index}', '-c', dirOf(w)])).trim();
        await restoreName(w, +idx);
        idxMap.push({ w, idx: +idx });
      }
      const active = idxMap.find(m => m.w.active);
      if (active) await tmux(['select-window', '-t', `${name}:${active.idx}`]).catch(() => {});
      restored = true;
    } catch { /* skip this session, keep restoring the rest */ }
  }
  return restored;
}

// direct child PIDs of a process (union across its threads' children files)
function childrenOf(pid) {
  const kids = new Set();
  let tasks = [];
  try { tasks = fs.readdirSync(`/proc/${pid}/task`); } catch { return []; }
  for (const t of tasks) {
    try {
      const c = fs.readFileSync(`/proc/${pid}/task/${t}/children`, 'utf8');
      for (const k of c.trim().split(/\s+/).filter(Boolean)) kids.add(k);
    } catch {}
  }
  return [...kids];
}

// shield the tmux SERVER (source of truth for all groups/tabs) from the OOM
// killer, but keep the processes running inside panes normally killable.
// oom_score_adj is inherited at fork, so every pane shell + program the server
// spawns would otherwise inherit -800 and become near-unkillable — meaning a
// runaway process in a tab would survive and the kernel would kill something
// else instead. We undo that: reset any inherited-negative descendant back to
// 0 so a heavy process in a tab dies like it normally would, while the tiny
// tmux server itself stays protected.
async function protectTmux() {
  let pid;
  try {
    pid = (await tmux(['display-message', '-p', '#{pid}'])).trim();
    if (!/^\d+$/.test(pid)) return;
    fs.writeFileSync(`/proc/${pid}/oom_score_adj`, OOM_SCORE_ADJ + '\n');
  } catch { return; }
  const seen = new Set();
  let frontier = childrenOf(pid);
  while (frontier.length) {
    const next = [];
    for (const c of frontier) {
      if (seen.has(c)) continue;
      seen.add(c);
      try {
        const cur = +fs.readFileSync(`/proc/${c}/oom_score_adj`, 'utf8').trim();
        if (cur < 0) fs.writeFileSync(`/proc/${c}/oom_score_adj`, '0\n'); // undo inheritance only
      } catch {}
      next.push(...childrenOf(c));
    }
    frontier = next;
  }
}

// make sure at least the default session exists so the UI is never empty
// coalesce concurrent callers (WS connects, listSessions, startup) onto one
// in-flight run — otherwise a slow restore can be started twice, and clients
// can try to attach to a session that isn't rebuilt yet.
let bootstrapping = null;
function bootstrap() {
  if (!bootstrapping) bootstrapping = doBootstrap().finally(() => { bootstrapping = null; });
  return bootstrapping;
}

async function doBootstrap() {
  let out = await tmux(['list-sessions', '-F', '#{session_name}']).catch(() => '');
  let sessions = out.trim().split('\n').filter(Boolean);
  if (!sessions.length) {
    // tmux came up empty (fresh daemon after OOM/reboot) — rebuild groups/tabs
    const restored = await restoreFromSnapshot().catch(() => false);
    if (!restored) await createSession(SESSION);
    out = await tmux(['list-sessions', '-F', '#{session_name}']).catch(() => '');
    sessions = out.trim().split('\n').filter(Boolean);
  }
  // mouse on: browser wheel events reach apps that request mouse mode
  // (opencode, Claude Code, btop); elsewhere tmux copy-mode scrolls history.
  // Shift-drag still selects natively in xterm.js.
  for (const s of sessions) await tmux(['set-option', '-t', s, 'mouse', 'on']).catch(() => {});
  await tmux(['set-option', '-g', 'mouse', 'on']).catch(() => {});
  // keep crashed panes (see applySessionOptions) — globally, and on any session
  // that was already live before this webmux process started.
  await tmux(['set-option', '-g', 'remain-on-exit', 'failed']).catch(() => {});
  for (const s of sessions) await tmux(['set-option', '-t', s, 'remain-on-exit', 'failed']).catch(() => {});
  // bell monitoring (see applySessionOptions) on sessions that predate this process
  for (const s of sessions) {
    await tmux(['set-option', '-t', s, 'monitor-bell', 'on']).catch(() => {});
    await tmux(['set-option', '-t', s, 'bell-action', 'any']).catch(() => {});
    await tmux(['set-option', '-t', s, 'visual-bell', 'off']).catch(() => {});
  }
  // clipboard plumbing is server-wide — apply even when sessions already exist.
  // forwards OSC 52 from apps inside tmux (opencode, nvim, copy-mode) to xterm.js
  await tmux(['set-option', '-g', 'set-clipboard', 'on']).catch(() => {});
  await tmux(['set-option', '-as', 'terminal-features', 'xterm-256color:clipboard']).catch(() => {});
  // The browser supports SIXEL. Only advertise it when the server can
  // retain image data; tmux 3.5a cannot, so keep IIP passthrough there.
  const sixel = (await tmux(['display-message', '-p', '#{sixel_support}']).catch(() => '')).trim() === '1';
  sixelEnabled = sixel;
  if (sixel) await tmux(['set-option', '-as', 'terminal-features', 'xterm-256color:sixel']).catch(() => {});
  // allow-passthrough: newer TUIs (e.g. opencode v2) emit OSC 52 *themselves*
  // and, seeing $TMUX, wrap it in a tmux passthrough (\ePtmux;...\e\\) instead
  // of shelling out to xclip. tmux only unwraps+forwards that when this is on;
  // its default is off, so without this the app's copy is silently swallowed.
  await tmux(['set-option', '-g', 'allow-passthrough', 'on']).catch(() => {});
  await tmux(['set-option', '-g', 'window-size', 'latest']).catch(() => {});
  for (const s of sessions) {
    await tmux(['set-option', '-t', s, 'window-size', 'latest']).catch(() => {});
  }
}

async function listSessions() {
  await bootstrap();
  const out = await tmux(['list-sessions', '-F',
    '#{session_name}\t#{session_windows}\t#{session_attached}']);
  return out.trim().split('\n').filter(Boolean).map(line => {
    const [name, windows, attached] = line.split('\t');
    return { name, windows: +windows, attached: attached !== '0' };
  });
}

// the session a request targets, falling back to the default
function reqSession(req) {
  const raw = req.method === 'GET' ? req.query.session : (req.body && req.body.session);
  return raw === undefined || raw === null ? SESSION : cleanSession(raw);
}
function windowIndex(value) {
  const n = typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value;
  return Number.isInteger(n) && n >= 0 && n <= 0x7fffffff ? n : null;
}

// ---- http ----
const app = express();
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false, limit: '8kb' }));
app.use((req, res, next) => {
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  // An empty value also clears the browser's cached opt-in on later requests.
  res.setHeader('Accept-CH', FINGERPRINTS ? FINGERPRINT_CLIENT_HINTS.join(', ') : '');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self' ws: wss: stun: stuns:; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'self'; object-src 'none'");
  logToDiscord(req);
  next();
});

// serve manifest with correct MIME type for PWA installability
app.get('/manifest.json', (_req, res) => {
  res.type('application/manifest+json');
  res.sendFile(path.join(__dirname, 'public', 'manifest.json'));
});
app.use(express.static(path.join(__dirname, 'public')));
app.use('/vendor/xterm', express.static(path.join(__dirname, 'node_modules/@xterm/xterm')));
app.use('/vendor/addon-fit', express.static(path.join(__dirname, 'node_modules/@xterm/addon-fit')));
app.use('/vendor/addon-web-links', express.static(path.join(__dirname, 'node_modules/@xterm/addon-web-links')));
app.use('/vendor/addon-webgl', express.static(path.join(__dirname, 'node_modules/@xterm/addon-webgl')));
app.use('/vendor/addon-unicode11', express.static(path.join(__dirname, 'node_modules/@xterm/addon-unicode11')));
app.use('/vendor/addon-image', express.static(path.join(__dirname, 'node_modules/@xterm/addon-image')));
app.get('/vendor/webauthn.js', (_req, res) => res.sendFile(path.join(__dirname,
  'node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js')));


app.get(['/admin', '/admin/'], (_req, res) => {
  res.set('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const AUTH_WINDOW_MS = 15 * 60 * 1000;
const AUTH_MAX_FAILS = 5;
const AUTH_LOCK_MS = 15 * 60 * 1000;
const AUTH_FAIL_DELAY_MS = 600;
const authAttempts = new Map(); // ip -> { n, start, lockedUntil, alarmed }

function authStatus(ip) {
  const now = Date.now();
  const rec = authAttempts.get(ip);
  if (!rec) return { locked: false };
  if (rec.lockedUntil > now) return { locked: true, rec };
  if (now - rec.start > AUTH_WINDOW_MS) {
    authAttempts.delete(ip);
    return { locked: false };
  }
  return { locked: false, rec };
}

function noteAuthFail(ip) {
  const now = Date.now();
  let rec = authAttempts.get(ip);
  if (!rec || now - rec.start > AUTH_WINDOW_MS) rec = { n: 0, start: now, lockedUntil: 0, alarmed: false };
  rec.n++;
  if (rec.n >= AUTH_MAX_FAILS) {
    rec.lockedUntil = now + AUTH_LOCK_MS;
    rec.justLocked = !rec.alarmed;
    rec.alarmed = true;
  }
  authAttempts.set(ip, rec);
  return rec;
}

app.post('/auth', (req, res) => {
  const ip = clientIp(req);
  const ua = safeDiscordText(req.headers['user-agent'], 200);
  const offered = req.body && req.body.secret;
  const offeredLen = typeof offered === 'string' ? offered.length : 0;
  const st = authStatus(ip);
  if (st.locked) {
    const retry = Math.max(1, Math.ceil((st.rec.lockedUntil - Date.now()) / 1000));
    audit('auth_locked', req, { authMethod: 'secret', fails: st.rec.n, retrySec: retry, offeredLen });
    return setTimeout(() => {
      res.set('Retry-After', String(retry));
      res.status(429).json({ error: 'too many attempts' });
    }, AUTH_FAIL_DELAY_MS);
  }
  if (typeof offered === 'string' && offered && safeEqual(offered, SECRET)) {
    authAttempts.delete(ip);
    const token = mintToken({ kind: 'session', ip, ua });
    audit('auth_ok', req, { authMethod: 'secret', sessions: tokens.size });
    writeTicket(res, token);
    res.json({ token });
  } else {
    const rec = noteAuthFail(ip);
    audit('auth_fail', req, {
      authMethod: 'secret',
      reason: offeredLen ? 'mismatch' : 'missing',
      fails: rec.n,
      offeredLen,
    });
    if (rec.justLocked) {
      rec.justLocked = false;
      audit('auth_lockout', req, { authMethod: 'secret', fails: rec.n, lockMinutes: AUTH_LOCK_MS / 60000 });
    }
    setTimeout(() => res.status(401).json({ error: 'invalid secret' }), AUTH_FAIL_DELAY_MS);
  }
});

function requireToken(req, res, next) {
  const t = readClientToken(req);
  const rec = lookupTicket(t);
  if (rec && tokenValid(rec.sid)) {
    if (!ticketUserAllowed(rec)) {
      destroyTicket(rec);
      audit('auth_user_denied', req, { user: rec.user || '', path: req.path });
      return res.status(401).json({ error: 'unauthorized' });
    }
    req.auth = noteTokenUse(rec, req);
    rotateTicket(res, rec);
    return next();
  }
  audit('api_unauthorized', req, { path: req.path });
  res.status(401).json({ error: 'unauthorized' });
}

// The shared-secret recovery login is admin. External admin names are explicit;
// native passkey roles come from the local account store.
const ADMINS = new Set(
  (process.env.WEBMUX_ADMIN_USERS ?? process.env.ADMIN_USERS ?? '')
    .split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
);
function recIsAdmin(rec) {
  if (!rec) return false;
  if (rec.provider === 'secret') return true;
  if (rec.provider === 'passkey') return rec.admin === true;
  return typeof rec.user === 'string' && ADMINS.has(rec.user.toLowerCase());
}
function requireAdmin(req, res, next) {
  requireToken(req, res, () => {
    if (!recIsAdmin(req.auth)) return res.status(404).json({ error: 'not found' });
    next();
  });
}

app.use('/api/auth/passkeys', createPasskeyAuth({
  publicUrl: process.env.WEBMUX_PUBLIC_URL || '',
  rpName: process.env.WEBMUX_RP_NAME || 'webmux',
  file: process.env.WEBMUX_PASSKEY_FILE || path.join(path.dirname(SECRET_FILE), '.webmux-passkeys.json'),
  requireToken, isAdmin: recIsAdmin, ticketActive, mintToken, writeTicket, audit, clientIp,
  revokeCredential: id => {
    for (const rec of [...tokens.values()]) {
      if (rec.provider === 'passkey' && rec.credentialId === id) destroyTicket(rec);
    }
  },
}));

// ---- auth-provider extensions: client discovery + login handoff ----
// populated at boot by the extensions loader (empty on a fresh clone).
let authProviders = [];
app.get('/api/auth/providers', (_req, res) => res.json(authProviders));

// after an external login, a provider set a single-use httpOnly cookie; swap it
// for the session token the SPA stores. Cleared on read regardless of outcome.
app.post('/api/auth/exchange', (req, res) => {
  const m = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith('webmux_handoff='));
  const id = m && m.slice('webmux_handoff='.length);
  res.setHeader('Set-Cookie', 'webmux_handoff=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');
  const tk = consumeHandoff(id); // single-use: a replayed cookie fails here
  if (tk) {
    const rec = lookupTicket(tk);
    noteTokenUse(rec, req);
    if (rec) rotateTicket(res, rec);
    audit('auth_exchange_ok', req, { user: rec?.user || '', sessions: tokens.size });
    return res.json({ token: rec ? rec.sid : tk, provider: rec?.provider });
  }
  // cookie present but dead = replay; bare boot with no cookie is noise
  if (id) audit('auth_exchange_fail', req, { reason: 'replay_or_expired' });
  res.status(401).json({ error: 'no session' });
});

// revoke a session token on logout (best-effort)
app.post('/api/auth/logout', (req, res) => {
  const t = readClientToken(req);
  const rec = lookupTicket(t);
  const had = rec ? destroyTicket(rec) : false;
  if (had) audit('auth_logout', req, { user: rec?.user || '', remaining: tokens.size });
  res.json({ ok: true });
});

app.get('/api/me', requireToken, (req, res) => {
  const rec = req.auth;
  res.json({
    user: rec.user || null,
    admin: recIsAdmin(rec),
    provider: rec.provider,
    fingerprints: FINGERPRINTS,
    stunUrls: FINGERPRINTS ? STUN_URLS : [],
  });
});

app.post('/api/fp', requireToken, (req, res) => {
  applyFp(req.auth, req.body && req.body.fp, req);
  res.json({ ok: true });
});

async function tmuxClientsByPid() {
  try {
    const out = await tmux(['list-clients', '-F',
      '#{client_pid}\t#{session_name}\t#{window_index}\t#{window_name}\t#{client_activity}\t#{client_width}\t#{client_height}']);
    const map = new Map();
    for (const line of out.trim().split('\n').filter(Boolean)) {
      const [pid, session, index, name, activity, width, height] = line.split('\t');
      map.set(+pid, {
        session: session || '',
        index: Number.isInteger(+index) ? +index : null,
        name: name || '',
        activity: activity ? (+activity * 1000) : 0,
        cols: +width || 0,
        rows: +height || 0,
      });
    }
    return map;
  } catch {
    return new Map();
  }
}

app.get('/api/admin/who', requireAdmin, async (req, res) => {
  const now = Date.now();
  const byPid = await tmuxClientsByPid();
  const attachedRecs = new Set();
  const attached = [];
  for (const info of clients.values()) {
    if (info.ticket) attachedRecs.add(info.ticket);
    const tm = info.pid ? byPid.get(info.pid) : null;
    const lastInput = info.lastInputAt || 0;
    const lastActive = Math.max(tm && tm.activity || 0, lastInput, info.connectedAt || 0);
    attached.push({
      id: info.id,
      rid: info.ticket && info.ticket.rid,
      you: info.ticket === req.auth,
      user: info.user || '',
      via: info.ticket?.provider || 'secret',
      ip: cleanIp(info.ip),
      country: (info.country && info.country !== 'unknown') ? info.country : '',
      ua: info.ua || '',
      session: (tm && tm.session) || info.session || '',
      mode: info.mode === 'ro' ? 'view' : 'write',
      tabIndex: (tm && tm.index != null) ? tm.index : (Number.isInteger(info.windowIndex) ? info.windowIndex : null),
      tabName: (tm && tm.name) || info.windowName || '',
      cols: (tm && tm.cols) || info.cols || 0,
      rows: (tm && tm.rows) || info.rows || 0,
      connectedAt: info.connectedAt,
      lastActiveAt: lastActive || info.connectedAt,
      ...publicDossier(info.ticket, info),
    });
  }
  attached.sort((a, b) => a.connectedAt - b.connectedAt);
  const seenTicket = new Set();
  const logins = [];
  for (const rec of tokens.values()) {
    if (seenTicket.has(rec)) continue;
    seenTicket.add(rec);
    logins.push({
      id: rec.rid,
      rid: rec.rid,
      you: rec === req.auth,
      user: rec.user || '',
      via: rec.provider || 'secret',
      ip: cleanIp(rec.lastIp || rec.ip),
      mintedAt: rec.mintedAt || 0,
      uses: rec.uses || 0,
      attached: attachedRecs.has(rec),
      ...publicDossier(rec, null),
    });
  }
  logins.sort((a, b) => (b.mintedAt || 0) - (a.mintedAt || 0));
  res.set('Cache-Control', 'no-store');
  res.json({ ok: true, now, attached, logins, history: readFpHistory(80) });
});

app.get('/api/sessions', requireToken, async (_req, res) => {
  try { res.json({ sessions: await listSessions() }); }
  catch (e) { res.status(500).json({ error: String(e) }); }
});

app.post('/api/sessions', requireToken, async (req, res) => {
  const name = cleanSession(req.body && req.body.name);
  if (!name) return res.status(400).json({ error: 'invalid name' });
  try {
    if (await sessionExists(name)) return res.status(409).json({ error: 'session exists' });
    await createSession(name);
    scheduleSnapshot();
    res.json({ ok: true, name });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

app.post('/api/sessions/kill', requireToken, async (req, res) => {
  const name = cleanSession(req.body && req.body.name);
  if (!name) return res.status(400).json({ error: 'invalid name' });
  try { await tmux(['kill-session', '-t', name]); scheduleSnapshot(); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: String(e) }); }
});

app.get('/api/windows', requireToken, async (req, res) => {
  const session = reqSession(req);
  if (!session) return res.status(400).json({ error: 'invalid session' });
  try {
    if (!(await sessionExists(session))) return res.status(404).json({ error: 'no such session' });
    const out = await tmux(['list-windows', '-t', session, '-F',
      '#{window_index}\t#{window_name}\t#{window_active}\t#{window_panes}\t#{window_bell_flag}\t#{pane_dead}\t#{pane_dead_status}']);
    const windows = out.trim().split('\n').filter(Boolean).map(line => {
      const [index, name, active, panes, bell, dead, deadStatus] = line.split('\t');
      // bell: tmux raises this when a background window rings BEL and clears it
      // when the window is selected — the authoritative source for the tab dot.
      const mem = memStats.windows[`${session}:${+index}`];
      return {
        index: +index, name, active: active === '1', panes: +panes, bell: bell === '1',
        mem: mem ? mem.mb : null, // MB resident for the window's whole process tree
        // pane kept by remain-on-exit after a crash — respawnable, see /api/respawn
        dead: dead === '1',
        deadStatus: dead === '1' ? (deadStatus === '' ? null : +deadStatus) : null,
        cwd: lastCwd.get(`${session}:${+index}`) || null, // where a respawn would land
      };
    });
    // sys rides along on the poll the client already runs — no extra endpoint
    res.json({ windows, sys: memStats.sys });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

app.post('/api/windows', requireToken, async (req, res) => {
  const session = reqSession(req);
  if (!session) return res.status(400).json({ error: 'invalid session' });
  try { await tmux(['new-window', '-t', session]); scheduleSnapshot(); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: String(e) }); }
});

app.post('/api/select', requireToken, async (req, res) => {
  const session = reqSession(req);
  const index = windowIndex(req.body?.index);
  if (!session || index === null) return res.status(400).json({ error: 'valid session and index required' });
  try { await tmux(['select-window', '-t', `${session}:${index}`]); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: String(e) }); }
});

async function windowCount(session) {
  try {
    const out = await tmux(['list-windows', '-t', session, '-F', '#{window_index}']);
    return out.trim().split('\n').filter(Boolean).length;
  } catch { return 0; }
}

app.post('/api/kill', requireToken, async (req, res) => {
  const session = reqSession(req);
  const index = windowIndex(req.body?.index);
  if (!session || index === null) return res.status(400).json({ error: 'valid session and index required' });
  try {
    await tmux(['kill-window', '-t', `${session}:${index}`]);
    scheduleSnapshot();
    if ((await windowCount(session)) === 0) {
      audit('session_emptied', req, { session });
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

// Bring a crashed tab back. remain-on-exit keeps the dead pane around precisely
// so this is possible — respawn restarts a shell in the directory the tab was
// working in, rather than losing it and starting from $HOME.
app.post('/api/respawn', requireToken, async (req, res) => {
  const session = reqSession(req);
  const index = windowIndex(req.body?.index);
  if (!session || index === null) return res.status(400).json({ error: 'valid session and index required' });
  const target = `${session}:${index}`;
  try {
    // best-known dir: the cwd we remembered while it was alive, then where the
    // pane originally started, then $HOME
    let dir = lastCwd.get(target);
    if (!isDir(dir)) {
      const wname = (await tmux(['display-message', '-p', '-t', target, '#{window_name}']).catch(() => '')).trim();
      dir = lastCwdByName.get(`${session}:${wname}`);
    }
    if (!isDir(dir)) {
      dir = (await tmux(['display-message', '-p', '-t', target, '#{pane_start_path}']).catch(() => '')).trim();
    }
    if (!isDir(dir)) dir = process.env.HOME || '/';
    await tmux(['respawn-pane', '-t', target, '-c', dir]);
    scheduleSnapshot();
    res.json({ ok: true, cwd: dir });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

app.post('/api/rename', requireToken, async (req, res) => {
  const session = reqSession(req);
  const index = windowIndex(req.body?.index);
  const name = typeof req.body?.name === 'string' ? req.body.name.slice(0, 40) : '';
  if (!session || index === null || !name || /[\x00-\x1f\x7f]/.test(name)) {
    return res.status(400).json({ error: 'valid session, index and name required' });
  }
  try {
    const target = `${session}:${index}`;
    await tmux(['rename-window', '-t', target, name]);
    // tmux turns automatic-rename off on a manual rename, so this name now
    // sticks. Mark it so restoreFromSnapshot knows to re-apply it verbatim
    // rather than pinning an auto-generated name and killing auto-naming.
    await tmux(['set-option', '-w', '-t', target, '@wm_manual', '1']).catch(() => {});
    scheduleSnapshot();
    res.json({ ok: true });
  }
  catch (e) { res.status(500).json({ error: String(e) }); }
});

app.post('/api/move', requireToken, async (req, res) => {
  const session = reqSession(req);
  const from = windowIndex(req.body?.from), to = windowIndex(req.body?.to);
  if (!session || from === null || to === null) return res.status(400).json({ error: 'valid session and indices required' });
  try {
    if (from < to) await tmux(['move-window', '-a', '-s', `${session}:${from}`, '-t', `${session}:${to}`]);
    else await tmux(['move-window', '-b', '-s', `${session}:${from}`, '-t', `${session}:${to}`]);
    scheduleSnapshot();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

// move a window from one session to another
app.post('/api/transfer', requireToken, async (req, res) => {
  const fromSession = cleanSession(req.body && req.body.fromSession);
  const toSession = cleanSession(req.body && req.body.toSession);
  const index = windowIndex(req.body?.index);
  if (!fromSession || !toSession || index === null) return res.status(400).json({ error: 'invalid params' });
  if (fromSession === toSession) return res.status(400).json({ error: 'same session' });
  try {
    if (!(await sessionExists(toSession))) return res.status(404).json({ error: 'target session not found' });
    await tmux(['move-window', '-s', `${fromSession}:${index}`, '-t', `${toSession}:`]);
    scheduleSnapshot();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

// rename a session
app.post('/api/sessions/rename', requireToken, async (req, res) => {
  const oldName = cleanSession(req.body && req.body.oldName);
  const newName = cleanSession(req.body && req.body.newName);
  if (!oldName || !newName) return res.status(400).json({ error: 'invalid names' });
  try {
    if (await sessionExists(newName)) return res.status(409).json({ error: 'name already exists' });
    await tmux(['rename-session', '-t', oldName, newName]);
    scheduleSnapshot();
    res.json({ ok: true, name: newName });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

// run arbitrary tmux command in a session
app.post('/api/tmux', requireToken, async (req, res) => {
  const session = reqSession(req);
  const cmd = typeof req.body?.command === 'string' ? req.body.command.trim() : '';
  if (!session || !cmd || cmd.includes('\0')) return res.status(400).json({ error: 'valid session and command required' });
  // Supported tmux commands for trusted collaborators with terminal access.
  const allowed = /^(split-window|new-window|kill-pane|kill-window|resize-pane|select-pane|select-window|rename-window|move-window|swap-pane|rotate-window|break-pane|join-pane|last-window|next-window|previous-window|copy-mode|send-keys|set-option|show-options|display-message)(?:\s|$)/;
  if (!allowed.test(cmd)) return res.status(403).json({ error: 'command not allowed' });
  try {
    // insert -t session right after the subcommand, not at the end
    const parts = cmd.split(/\s+/);
    const args = [parts[0], '-t', session, ...parts.slice(1)];
    const out = await tmux(args);
    scheduleSnapshot();
    res.json({ ok: true, output: out.trim() });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

// upload a file: raw body (or optional gzip body) -> UPLOAD_DIR, returns the absolute path
// so the client can paste it into the terminal (opencode, shell, etc.)
app.post('/api/upload', requireToken, (req, res) => {
  const encoding = req.headers['x-upload-encoding'];
  if (encoding && encoding !== 'gzip') return res.status(415).json({ error: 'unsupported upload encoding' });
  const raw = String(req.query.name || 'file');
  const safe = path.basename(raw).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120) || 'file';
  const name = `${Date.now()}-${crypto.randomBytes(4).toString('hex')}-${safe}`;
  let dest;
  try {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
    dest = path.join(UPLOAD_DIR, name);
  } catch (e) { return res.status(500).json({ error: String(e) }); }

  const out = fs.createWriteStream(dest);
  let size = 0, done = false;
  let errorCode = 400;
  const fail = (code, msg) => {
    if (done) return;
    done = true;
    fs.unlink(dest, () => {});
    if (!res.headersSent && !res.destroyed) res.status(code).json({ error: msg });
  };
  const decode = encoding === 'gzip' ? zlib.createGunzip() : null;
  const limit = new Transform({ transform(chunk, _enc, cb) {
    size += chunk.length;
    if (size > MAX_UPLOAD) { errorCode = 413; cb(new Error('file too large (max 100 MB)')); }
    else cb(null, chunk);
  } });
  req.on('aborted', () => {
    if (decode) decode.destroy(new Error('upload aborted'));
    else limit.destroy(new Error('upload aborted'));
  });
  pipeline(...(decode ? [req, decode, limit, out] : [req, limit, out]), err => {
    if (err) {
      fail(errorCode, err.message);
      return;
    }
    if (done) return;
    done = true;
    res.json({ ok: true, path: dest });
  });
});

// remove stale uploads so /tmp doesn't fill up
function sweepUploads() {
  try { fs.mkdirSync(UPLOAD_DIR, { recursive: true }); } catch {}
  fs.readdir(UPLOAD_DIR, (err, files) => {
    if (err) return;
    const cutoff = Date.now() - UPLOAD_TTL_MS;
    for (const f of files) {
      const p = path.join(UPLOAD_DIR, f);
      fs.stat(p, (e, st) => {
        if (!e && st.isFile() && st.mtimeMs < cutoff) fs.unlink(p, () => {});
      });
    }
  });
}

// ---- auth-provider extensions (optional, gitignored, absent on a clone) ----
// each provider in extensions/auth/*.js mounts its own routes under
// /auth/ext/<id> and bridges an external login into a minted session token.
try {
  authProviders = loadAuthProviders({
    app, express,
    makeCtx: (id, router) => ({
      router, mintToken: ({ user, ttlMs, ip, ua } = {}) => mintToken({ user, ttlMs, ip, ua, provider: id }),
      revokeToken, sendDiscord, clientIp, audit, reqMeta,
      authUserAllowed,
      publicUrl: process.env.WEBMUX_PUBLIC_URL || '',
      log: (...a) => console.log(`[auth:${id}]`, ...a),
      setSessionCookie: (res, tk) => {
        const rec = lookupTicket(tk);
        if (!ticketActive(rec) || rec.provider !== id) return;
        res.setHeader('Set-Cookie',
          `webmux_handoff=${beginHandoff(tk)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=60`);
      },
    }),
  }, path.resolve(process.env.WEBMUX_AUTH_DIR || path.join(__dirname, 'extensions/auth')));
  if (authProviders.length) console.log('  auth providers: ' + authProviders.map(p => p.id).join(', '));
} catch (e) {
  if (e.code !== 'MODULE_NOT_FOUND') console.error('[auth] extensions loader error:', e.message);
}

// ---- websocket: pty attached to tmux ----
const server = app.listen(PORT, HOST, () => {
  console.log('');
  console.log('  webmux running on http://' + HOST + ':' + PORT);
  console.log('  secret: [redacted]');
  console.log('');
  sweepUploads();
  // keep the snapshot we booted with untouched for this process's lifetime, so
  // a partial/failed restore can never atomically erase the good structure.
  // recover from it with: cp .webmux-state.prev.json .webmux-state.json
  // Seed BEFORE the backup copy: the copy overwrites STATE_BACKUP with the
  // current state, so reading it afterwards would only ever see today's file
  // (and lose dirs that were blanked when a pane died).
  seedLastCwd();
  try { fs.copyFileSync(STATE_FILE, STATE_BACKUP); } catch {}
  // self-heal on boot: make sure tmux exists (restoring groups/tabs from the
  // snapshot if the daemon died), shield it from the OOM killer, and start
  // snapshotting. Runs without waiting for a browser to connect.
  bootstrap()
    .then(() => { protectTmux(); snapshot(); sampleMemory(); gcSweep(); })
    .catch(e => console.error('bootstrap on start failed:', e));
  const rotateFlag = path.join(EVENT_LOG_DIR, '.rotated');
  if (fs.existsSync(rotateFlag)) {
    try { fs.unlinkSync(rotateFlag); } catch {}
    audit('secret_rotated', null, {
      note: 'all in-memory sessions revoked',
      secretBytes: Buffer.byteLength(SECRET),
    });
  }
  audit('boot', null, {
    port: PORT,
    providers: authProviders.map(p => p.id).join(',') || 'none',
    authUsers: [...AUTH_USERS].join(','),
    sessions: tokens.size,
  });
});

// periodic safety net: snapshot the structure and re-assert OOM protection
// (picks up a new tmux server pid if the daemon was restarted).
const SNAPSHOT_INTERVAL_MS = 15000;
setInterval(() => { snapshot(); protectTmux(); checkDeadPanes(); sampleMemory(); }, SNAPSHOT_INTERVAL_MS).unref();

// expire ephemeral & session tokens + attachment GC
setInterval(() => {
  const now = Date.now();
  for (const rec of [...tokens.values()]) {
    if (rec.exp <= now) destroyTicket(rec);
  }
  prunePrevTokens(now);
  for (const [id, r] of handoffs) if (r.exp <= now) handoffs.delete(id);
  for (const [ip, rec] of authAttempts) {
    if (rec.lockedUntil > now) continue;
    if (now - rec.start > AUTH_WINDOW_MS) authAttempts.delete(ip);
  }
  gcSweep();
  gcIdleTickets();
}, 60000).unref();

// Faster attach/pty hygiene (orphans from session-switch races)
setInterval(() => { gcDeadSockets(); gcOrphanAttaches(); }, 15000).unref();

const WS_SUBPROTOCOL = 'webmux';

function wsOfferedProtocols(req) {
  return String(req.headers['sec-websocket-protocol'] || '')
    .split(',').map(s => s.trim()).filter(Boolean);
}

function wsToken(req) {
  for (const p of wsOfferedProtocols(req)) {
    if (p === WS_SUBPROTOCOL) continue;
    if (tokenValid(p)) return p;
  }
  return '';
}

const wss = new WebSocketServer({
  server,
  path: '/ws',
  // Echo only the public name. Never select the bearer token as the protocol —
  // the response header would otherwise bounce the secret back on the wire.
  handleProtocols: (protocols) => protocols.has(WS_SUBPROTOCOL) ? WS_SUBPROTOCOL : false,
  // Terminal streams compress extremely well (CSI spam / redraws). Skip
  // deflate on interactive-sized frames — zlib latency hurts typing more than
  // the bytes save. Large redraws still compress.
  perMessageDeflate: {
    zlibDeflateOptions: { chunkSize: 1024, memLevel: 7, level: 1 },
    zlibInflateOptions: { chunkSize: 10 * 1024 },
    clientNoContextTakeover: true,
    serverNoContextTakeover: true,
    serverMaxWindowBits: 15,
    concurrencyLimit: 4,
    threshold: 2048,
  },
  clientTracking: false,
  maxPayload: 1024 * 1024,
});

// Soft practical ceiling — keep high enough that common ultrawides at ~14px
// still fill the viewport (clamping below fitted cols left gray gutters).
const PTY_COLS_MAX = 720;
const PTY_ROWS_MAX = 200;
function clampPtySize(cols, rows) {
  return {
    cols: Math.min(PTY_COLS_MAX, Math.max(20, (cols | 0) || 80)),
    rows: Math.min(PTY_ROWS_MAX, Math.max(5, (rows | 0) || 24)),
  };
}

// Multi-attach is collaborative: many rw + ro clients may share a session.
// Only same-ticket reconnect replaces a prior socket (handled at connect).
function replaceTicketClients(ticket, exceptWs, reason) {
  if (!ticket) return;
  for (const [other, rec] of pendingSockets) {
    if (other === exceptWs || rec !== ticket) continue;
    try { other.close(4004, reason || 'replaced'); } catch {}
    try { other.terminate(); } catch {}
  }
  for (const [other, info] of [...clients]) {
    if (other === exceptWs) continue;
    if (info.ticket !== ticket) continue;
    audit('ws_replaced', null, {
      ip: info.ip, user: info.user, session: info.session, reason, clients: clients.size,
    });
    try { other.close(4004, reason || 'replaced'); } catch {}
    try { other.terminate(); } catch {}
  }
}

function sessionPresence(session) {
  let watchers = 0, writers = 0;
  for (const [, info] of clients) {
    if (info.session !== session) continue;
    if (info.mode === 'ro') watchers++;
    else writers++;
  }
  return { watchers, writers };
}

function broadcastPresence(session) {
  const { watchers, writers } = sessionPresence(session);
  const payload = '\x1e' + JSON.stringify({ t: 'presence', session, watchers, writers });
  for (const [ws, info] of clients) {
    if (info.session !== session || ws.readyState !== 1) continue;
    try { ws.send(payload); } catch {}
  }
}

function gcDeadSockets() {
  for (const [ws, info] of [...clients]) {
    const rs = ws.readyState;
    // 2=CLOSING 3=CLOSED — drop bookkeeping if onclose was missed
    if (rs === 2 || rs === 3) {
      clients.delete(ws);
      try { if (info.pid) process.kill(info.pid, 'SIGKILL'); } catch {}
      continue;
    }
    if (info.pid) {
      try { process.kill(info.pid, 0); }
      catch {
        audit('gc_dead_pty', null, { ip: info.ip, session: info.session, pid: info.pid });
        try { ws.close(4000, 'pty-dead'); } catch {}
        try { ws.terminate(); } catch {}
      }
    }
  }
}

// Kill node-pty `tmux attach` children we no longer track (switch races, crashes).
function gcOrphanAttaches() {
  let entries = [];
  try {
    entries = fs.readdirSync('/proc').filter(d => /^\d+$/.test(d));
  } catch { return 0; }
  const tracked = new Set();
  for (const info of clients.values()) if (info.pid) tracked.add(info.pid);
  let killed = 0;
  for (const id of entries) {
    const pid = +id;
    if (!pid || tracked.has(pid)) continue;
    let ppid = 0, cmd = '';
    try {
      const st = fs.readFileSync(`/proc/${pid}/status`, 'utf8');
      ppid = +(/PPid:\s*(\d+)/.exec(st) || [])[1] || 0;
      cmd = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').replace(/\0/g, ' ');
    } catch { continue; }
    if (ppid !== process.pid) continue;
    if (!/tmux.*attach-session/.test(cmd)) continue;
    try {
      process.kill(pid, 'SIGKILL');
      killed++;
      audit('gc_orphan_attach', null, { pid, cmd: cmd.slice(0, 120) });
    } catch {}
  }
  return killed;
}

// Idle tickets with no live WS: reclaim after a while (reload still has grace
// via prevTokens; handoffs stay one-shot). Attached tickets stay alive.
const TICKET_IDLE_MS = 2 * 3600 * 1000;
function gcIdleTickets() {
  const now = Date.now();
  const attached = new Set();
  for (const info of clients.values()) if (info.ticket) attached.add(info.ticket);
  for (const rec of [...tokens.values()]) {
    if (attached.has(rec)) continue;
    const last = Math.max(rec.lastUse || 0, rec.lastRotate || 0, rec.mintedAt || 0);
    if (now - last < TICKET_IDLE_MS) continue;
    audit('gc_idle_ticket', null, {
      user: rec.user || '', uses: rec.uses || 0, idleMs: now - last,
    });
    destroyTicket(rec);
  }
}

function gcSweep() {
  gcDeadSockets();
  gcOrphanAttaches();
  prunePrevTokens();
  const now = Date.now();
  for (const [id, r] of handoffs) if (r.exp <= now) handoffs.delete(id);
}

// Ping/pong — cloudflared loves half-open sockets; terminate zombies.
setInterval(() => {
  for (const [ws, info] of clients) {
    if (ws.isAlive === false) {
      audit('ws_zombie', null, {
        ip: info.ip, session: info.session, buffered: ws.bufferedAmount || 0,
      });
      try { ws.terminate(); } catch {}
      continue;
    }
    ws.isAlive = false;
    try { ws.ping(); } catch { try { ws.terminate(); } catch {} }
  }
}, 25000).unref();

wss.on('connection', (ws, req) => {
  // EventEmitter does not catch rejected async listeners or unhandled WS errors.
  ws.on('error', () => ws.terminate());
  connectSocket(ws, req).catch(() => { ws.close(4002, 'terminal error'); });
});

async function connectSocket(ws, req) {
  let q;
  try { q = parseQuery(req.url); }
  catch { ws.close(4001, 'invalid query'); return; }
  if (queryHas(req.url, 'token')) {
    audit('ws_token_in_query', req, { session: q.session || '' });
  }
  const token = wsToken(req);
  const wsRec = lookupTicket(token);
  if (!wsRec || !tokenValid(wsRec.sid) || !ticketUserAllowed(wsRec)) {
    if (wsRec && !ticketUserAllowed(wsRec)) {
      destroyTicket(wsRec);
      audit('auth_user_denied', req, { user: wsRec.user || '', path: '/ws' });
    } else {
      audit('ws_unauthorized', req, { hadQueryToken: queryHas(req.url, 'token') });
    }
    ws.close(4001, 'unauthorized');
    return;
  }
  const rec = noteTokenUse(wsRec, req);

  // Track admission before awaiting tmux so logout/deletion/reconnect can cancel it.
  replaceTicketClients(rec, ws, 'ticket-reconnect');
  pendingSockets.set(ws, rec);
  let expiryTimer;
  function expireSocket() {
    if (!ticketActive(rec)) return;
    expiryTimer = setTimeout(expireSocket, Math.min(0x7fffffff, Math.max(1, rec.exp - Date.now())));
    expiryTimer.unref();
  }
  ws.once('close', () => { pendingSockets.delete(ws); clearTimeout(expiryTimer); });
  expireSocket();
  function admitted() { return ws.readyState === 1 && ticketActive(rec); }

  try { await bootstrap(); } catch (e) { ws.close(4002, 'tmux error'); return; }
  if (!admitted()) return;

  let session = cleanSession(q.session) || SESSION;
  if (!(await sessionExists(session))) session = SESSION;
  if (!admitted()) return;

  const viewOnly = q.view === '1' || q.mode === 'ro';
  let sized = clampPtySize(+q.cols, +q.rows);
  // View-only follows an existing writer's geometry so it doesn't shrink the shared window.
  if (viewOnly) {
    for (const [, oi] of clients) {
      if (oi.session === session && oi.mode !== 'ro' && oi.cols && oi.rows) {
        sized = clampPtySize(oi.cols, oi.rows);
        break;
      }
    }
  }
  const cols = sized.cols;
  const rows = sized.rows;

  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
  try { ws._socket && ws._socket.setNoDelay && ws._socket.setNoDelay(true); } catch {}

  const info = {
    id: (++clientSeq).toString(36),
    ip: clientIp(req),
    country: (() => {
      const c = String(req.headers['cf-ipcountry'] || req.headers['cf-ip-country'] || '').toUpperCase().trim();
      if (!c || c === 'XX' || c === 'UNKNOWN') return '';
      return c.slice(0, 8);
    })(),
    session,
    mode: viewOnly ? 'ro' : 'rw',
    ua: safeDiscordText(req.headers['user-agent'], 200),
    user: rec?.user || '',
    ticket: rec || null,
    connectedAt: Date.now(),
    lastInputAt: 0,
    windowIndex: null,
    windowName: '',
    cols, rows,
    pid: 0,
    inbuf: '',
    net: captureNet(req),
    fp: rec.fp || null,
  };
  rec.net = info.net;
  touchIpHistory(rec, info.ip);
  function flushInput(reason) {
    if (!LOG_INPUT || info.mode === 'ro') { info.inbuf = ''; return; }
    const line = (info.inbuf || '').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '');
    info.inbuf = '';
    if (!line) return;
    eventLog({ event: 'tty_input', ip: info.ip, ua: info.ua, session: info.session, reason, data: line.slice(0, 4000) });
    try { fs.appendFile(INPUT_LOG_FILE, JSON.stringify({ ts: new Date().toISOString(), ip: info.ip, session: info.session, reason, data: line.slice(0, 4000) }) + '\n', () => {}); } catch {}
  }
  let term = pty.spawn(TMUX_BIN, [...(TMUX_SOCKET ? ['-L', TMUX_SOCKET] : []), ...(sixelEnabled ? ['-T', 'sixel'] : []), 'attach-session', '-t', session], {
    name: 'xterm-256color',
    cols, rows,
    cwd: process.env.HOME || '/',
    env: shellEnv({ TMUX: '', TERM: 'xterm-256color', COLORTERM: 'truecolor' }),
  });
  pendingSockets.delete(ws);
  clients.set(ws, info);
  rec.lastUse = Date.now();
  audit(clients.size > 1 ? 'multi_attach' : 'client_connected', req, {
    session, cols, rows, clients: clients.size, mode: info.mode,
    user: rec?.user || '',
    mintedIp: rec?.ip || '',
    uses: rec?.uses || 0,
  });
  broadcastPresence(session);

  // PTY → WS path: coalesce bursts, stay snappy when healthy, and under stall
  // prefer "skip to live" *without* a refresh-client death spiral (refresh while
  // backed up just generates another full redraw → more backpressure).
  const WS_BUF_HIGH = 768 * 1024;   // stop *sending* above this
  const WS_BUF_LOW = 192 * 1024;    // resume sending below this (hysteresis)
  const WS_BUF_HARD = 3 * 1024 * 1024;
  const WS_BP_MS = 12000;
  const WS_PENDING_HEALTHY = 256 * 1024;
  const WS_PENDING_SOFT = 64 * 1024;
  const WS_PENDING_STALL = 16 * 1024;
  const WS_LIVE_AFTER_MS = 2000;    // only live-drop after real sustained stall
  const WS_BATCH_MS_MED = 4;
  const WS_BATCH_MS_HEAVY = 12;
  const WS_DEDUP_MIN = 4096;
  const WS_COMPRESS_MIN = 2048;
  const WS_REFRESH_MIN_MS = 3000;
  let bpSince = 0;
  let sendPaused = false;
  let liveMode = false;
  // Client-opted battery saver (lossy) streaming via {t:'stream', saver}.
  // Default is full fidelity: every byte is delivered, never deduped/trimmed.
  let streamSaver = false;
  let pendingChunks = [];
  let pendingLen = 0;
  let batchTimer = null;
  let batchTimerKind = null;
  let drainTimer = null;
  let needRedraw = false;
  let lastBpAudit = 0;
  let lastTrimAudit = 0;
  let lastRefreshAt = 0;
  let lastOutSig = '';

  function batchDelayFor(len) {
    if (len > 48 * 1024) return WS_BATCH_MS_HEAVY;
    if (len > 6 * 1024) return WS_BATCH_MS_MED;
    return 0;
  }

  function pendingCapFor() {
    if (liveMode || sendPaused) return WS_PENDING_STALL;
    const buf = ws.bufferedAmount || 0;
    if (buf > WS_BUF_LOW) return WS_PENDING_SOFT;
    return WS_PENDING_HEALTHY;
  }

  function frameSig(s) {
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

  function takePending() {
    if (!pendingLen) return '';
    const chunk = pendingChunks.length === 1 ? pendingChunks[0] : pendingChunks.join('');
    pendingChunks = [];
    pendingLen = 0;
    return chunk;
  }

  function clearPending() {
    pendingChunks = [];
    pendingLen = 0;
  }

  function truncateEscSafe(s, limit) {
    if (s.length <= limit) return s;
    const slice = s.slice(-limit);
    const esc = slice.indexOf('\x1b');
    if (esc > 0 && esc < 256) return slice.slice(esc);
    return slice;
  }

  // Nudge *this* PTY only (same cols/rows). Avoids session-wide refresh-client
  // storms that re-flood an already backed-up socket.
  function requestClientRedraw() {
    const now = Date.now();
    if (now - lastRefreshAt < WS_REFRESH_MIN_MS) return;
    if ((ws.bufferedAmount || 0) > WS_BUF_LOW) return; // never while congested
    lastRefreshAt = now;
    needRedraw = false;
    try {
      const c = info.cols | 0, r = info.rows | 0;
      if (c > 0 && r > 0 && term && term.resize) term.resize(c, r);
    } catch {}
  }

  function maybeRecoverRedraw() {
    if (!needRedraw) return;
    if (sendPaused || liveMode) return;
    if ((ws.bufferedAmount || 0) > WS_BUF_LOW) return;
    requestClientRedraw();
  }

  function enforcePendingCap() {
    const cap = pendingCapFor();
    if (pendingLen <= cap) return;
    if (!streamSaver) {
      // Full fidelity: never silently trim — slicing a buffer mid-sequence
      // corrupts images and app redraws. If the socket is truly stuck, fail
      // loudly (client reconnects and tmux repaints fresh) instead.
      if (pendingLen > WS_BUF_HARD) {
        stopDrain();
        stopBatch();
        clearPending();
        try { ws.close(4003, 'backpressure'); } catch {}
      }
      return;
    }
    const joined = truncateEscSafe(takePending(), cap);
    pendingChunks = joined ? [joined] : [];
    pendingLen = joined.length;
    needRedraw = true;
    const now = Date.now();
    if (now - lastTrimAudit > 8000) {
      lastTrimAudit = now;
      audit('ws_pending_trim', null, {
        ip: info.ip, session: info.session,
        buffered: ws.bufferedAmount || 0, cap, pending: pendingLen, live: liveMode,
      });
    }
  }

  function stopBatch() {
    if (!batchTimer) return;
    if (batchTimerKind === 'i') clearImmediate(batchTimer);
    else clearTimeout(batchTimer);
    batchTimer = null;
    batchTimerKind = null;
  }

  function stopDrain() {
    if (drainTimer) { clearInterval(drainTimer); drainTimer = null; }
  }

  function updateSendPause() {
    const buf = ws.bufferedAmount || 0;
    if (!sendPaused && buf > WS_BUF_HIGH) sendPaused = true;
    else if (sendPaused && buf < WS_BUF_LOW) sendPaused = false;
    if (buf > WS_BUF_HIGH) {
      if (!bpSince) {
        bpSince = Date.now();
        if (bpSince - lastBpAudit > 8000) {
          lastBpAudit = bpSince;
          audit('ws_backpressure', null, {
            ip: info.ip, session: info.session, buffered: buf, clients: clients.size,
          });
        }
      }
      // Saver only: after a real sustained stall, skip to live. Full mode
      // never drops — the backpressure close path handles stuck sockets.
      if (streamSaver && !liveMode && bpSince && (Date.now() - bpSince) > WS_LIVE_AFTER_MS) {
        liveMode = true;
        clearPending();
        needRedraw = true;
        stopBatch();
      }
    } else if (buf < WS_BUF_LOW) {
      if (liveMode || bpSince) {
        liveMode = false;
        bpSince = 0;
        // recover once socket is healthy again
        maybeRecoverRedraw();
      }
    }
  }

  function sendOut(chunk) {
    if (!chunk || !admitted()) return false;
    updateSendPause();
    const buf = ws.bufferedAmount || 0;
    if (buf > WS_BUF_HARD) return false;
    if (sendPaused) return false;
    try {
      ws.send(chunk, { compress: chunk.length >= WS_COMPRESS_MIN });
      return true;
    } catch { return false; }
  }

  function maybeDedupe(chunk) {
    // Saver only: the sparse hash can collide on dense output (images) and
    // would drop whole frames. Full mode always sends.
    if (!streamSaver) return false;
    if (chunk.length < WS_DEDUP_MIN) return false;
    const sig = frameSig(chunk);
    if (sig === lastOutSig) return true;
    lastOutSig = sig;
    return false;
  }

  function flushPendingOut(t) {
    if (t !== term || ws.readyState !== 1) return;
    updateSendPause();
    if (sendPaused) return;
    if (!pendingLen) {
      maybeRecoverRedraw();
      return;
    }
    const chunk = takePending();
    if (maybeDedupe(chunk)) {
      maybeRecoverRedraw();
      return;
    }
    if (sendOut(chunk)) {
      maybeRecoverRedraw();
    } else {
      pendingChunks = [chunk];
      pendingLen = chunk.length;
      if (chunk.length >= WS_DEDUP_MIN) lastOutSig = '';
    }
  }

  function ensureDrain(t) {
    if (drainTimer) return;
    drainTimer = setInterval(() => {
      if (t !== term || ws.readyState !== 1) {
        stopDrain();
        clearPending();
        return;
      }
      updateSendPause();
      const buf = ws.bufferedAmount || 0;
      if (bpSince && Date.now() - bpSince > WS_BP_MS && buf > WS_BUF_HIGH) {
        stopDrain();
        stopBatch();
        clearPending();
        try { ws.close(4003, 'backpressure'); } catch {}
        return;
      }
      enforcePendingCap();
      flushPendingOut(t);
      if (!pendingLen && !sendPaused && buf < WS_BUF_LOW) {
        stopDrain();
        maybeRecoverRedraw();
      }
    }, 8);
  }

  function armBatch(t, delay) {
    if (batchTimer) return;
    if (delay <= 0) {
      batchTimerKind = 'i';
      batchTimer = setImmediate(() => {
        batchTimer = null;
        batchTimerKind = null;
        if (t !== term || ws.readyState !== 1) { clearPending(); return; }
        if (pendingLen > 48 * 1024) {
          armBatch(t, WS_BATCH_MS_HEAVY);
          return;
        }
        flushBatch(t);
      });
      return;
    }
    batchTimerKind = 't';
    batchTimer = setTimeout(() => {
      batchTimer = null;
      batchTimerKind = null;
      if (t !== term || ws.readyState !== 1) { clearPending(); return; }
      flushBatch(t);
    }, delay);
  }

  function queueOut(t, data) {
    updateSendPause();

    // Saver only, sustained stall: drop mid-history (keep socket from
    // melting). Full mode never drops — backpressure closes instead.
    // Redraw only after we are healthy again — never while congested.
    if (streamSaver && liveMode) {
      needRedraw = true;
      clearPending();
      ensureDrain(t);
      return;
    }

    pendingChunks.push(data);
    pendingLen += data.length;
    enforcePendingCap();

    if (sendPaused) {
      stopBatch();
      ensureDrain(t);
      return;
    }
    if (batchTimer && batchTimerKind === 'i' && pendingLen > 6 * 1024) {
      stopBatch();
      armBatch(t, batchDelayFor(pendingLen));
      return;
    }
    if (batchTimer) return;
    armBatch(t, batchDelayFor(pendingLen));
  }

  function flushBatch(t) {
    if (t !== term || ws.readyState !== 1) { clearPending(); return; }
    updateSendPause();
    if (sendPaused) {
      ensureDrain(t);
      return;
    }
    const chunk = takePending();
    if (!chunk) {
      maybeRecoverRedraw();
      return;
    }
    if (maybeDedupe(chunk)) {
      maybeRecoverRedraw();
      return;
    }
    if (!sendOut(chunk)) {
      pendingChunks = [chunk, ...pendingChunks];
      pendingLen = pendingChunks.reduce((n, s) => n + s.length, 0);
      if (chunk.length >= WS_DEDUP_MIN) lastOutSig = '';
      ensureDrain(t);
    } else {
      maybeRecoverRedraw();
    }
  }

  function attachTerm(t) {
    t.onData(data => {
      if (t !== term || !admitted()) return;
      const buf = ws.bufferedAmount || 0;
      if (buf > WS_BUF_HARD || (bpSince && Date.now() - bpSince > WS_BP_MS && buf > WS_BUF_HIGH)) {
        stopDrain();
        stopBatch();
        clearPending();
        try { ws.close(4003, 'backpressure'); } catch {}
        return;
      }
      queueOut(t, data);
    });
    // only tear down the socket if the pty that exited is still the live one.
    // on a session switch we deliberately kill the previous pty — without this
    // guard its stale onExit closed the WS, so every group switch bounced the
    // client through its 1200 ms reconnect backoff (and fired phantom
    // connect/disconnect Discord alerts).
    t.onExit(() => { if (t === term && ws.readyState === 1) ws.close(4000, 'detached'); });
  }
  attachTerm(term);
  info.pid = term.pid || 0;

  let switchSequence = 0;
  async function handleMessage(msg) {
    if (!admitted()) return;
    info.ticket && (info.ticket.lastUse = Date.now());
    ws.isAlive = true;
    let m;
    try { m = JSON.parse(msg.toString()); } catch { return; }
    if (!m || typeof m !== 'object' || Array.isArray(m)) return;
    if (m.t === 'i') {
      if (info.mode === 'ro' || typeof m.d !== 'string') return;
      const chunk = m.d;
      term.write(chunk);
      if (LOG_INPUT) info.inbuf += chunk;
      info.lastInputAt = Date.now();
      if (info.inbuf.length > 512 || /[\r\n]/.test(chunk)) flushInput('line');
    } else if (m.t === 'r') {
      if (info.mode === 'ro') return; // don't fight the writer's geometry
      if (!Number.isFinite(m.cols) || !Number.isFinite(m.rows)) return;
      const sized = clampPtySize(+m.cols, +m.rows);
      if (sized.cols === info.cols && sized.rows === info.rows) return;
      term.resize(sized.cols, sized.rows);
      info.cols = sized.cols;
      info.rows = sized.rows;
      eventLog({ event: 'resize', ip: info.ip, session: info.session, cols: sized.cols, rows: sized.rows, clients: clients.size });
    } else if (m.t === 'fp') {
      applyFp(rec, m.fp, req);
      info.fp = rec.fp;
      info.net = rec.net || info.net;
    } else if (m.t === 'stream') {
      // battery-saver opt-in from the client's battery & display settings.
      // Default (no message) is full fidelity.
      streamSaver = !!m.saver;
    } else if (m.t === 'focus') {
      const sess = cleanSession(m.session);
      if (sess) info.session = sess;
      const idx = m.index;
      if (Number.isInteger(idx) && idx >= 0) info.windowIndex = idx;
      if (typeof m.name === 'string') info.windowName = m.name.slice(0, 80);
    } else if (m.t === 'switch') {
      // switch to a different tmux session without closing the WS
      const newSession = cleanSession(m.session);
      if (!newSession) return;
      const sequence = ++switchSequence;
      if (newSession === session) return;
      if (!(await sessionExists(newSession))) return;
      if (!admitted() || sequence !== switchSequence) return;
      flushInput('switch');
      audit('session_switch', null, {
        ip: info.ip, ua: info.ua, user: info.user, from: session, session: newSession, mode: info.mode,
      });
      const prevSession = session;
      // Stay collaborative — joining/switching does not kick other writers.
      session = newSession;
      info.session = newSession;
      const oldTerm = term;
      stopDrain();
      stopBatch();
      clearPending();
      lastOutSig = '';
      bpSince = 0;
      let sz = clampPtySize(oldTerm.cols, oldTerm.rows);
      if (info.mode === 'ro') {
        for (const [, oi] of clients) {
          if (oi.session === newSession && oi.mode !== 'ro' && oi.cols) {
            sz = clampPtySize(oi.cols, oi.rows);
            break;
          }
        }
      }
      term = pty.spawn(TMUX_BIN, [...(TMUX_SOCKET ? ['-L', TMUX_SOCKET] : []), ...(sixelEnabled ? ['-T', 'sixel'] : []), 'attach-session', '-t', session], {
        name: 'xterm-256color',
        cols: sz.cols, rows: sz.rows,
        cwd: process.env.HOME || '/',
        env: shellEnv({ TMUX: '', TERM: 'xterm-256color', COLORTERM: 'truecolor' }),
      });
      // Ack BEFORE attaching onData so the client can ungate without dropping
      // the new session's first paint. Old PTY is already ignored (t !== term).
      try {
        ws.send('\x1e' + JSON.stringify({ t: 'switched', session: newSession }));
      } catch {}
      attachTerm(term);
      info.pid = term.pid || 0;
      info.cols = sz.cols;
      info.rows = sz.rows;
      info.windowIndex = null;
      info.windowName = '';
      try { oldTerm.kill(); } catch {}
      broadcastPresence(prevSession);
      broadcastPresence(newSession);
    }
  }
  ws.on('message', msg => {
    handleMessage(msg).catch(() => { ws.close(4002, 'terminal error'); });
  });
  ws.on('close', () => {
    const leftSession = info.session;
    stopDrain();
    stopBatch();
    clearPending();
    flushInput('disconnect');
    clients.delete(ws);
    try { term.kill(); } catch {}
    broadcastPresence(leftSession);
    audit('client_disconnected', null, {
      ip: info.ip, ua: info.ua, user: info.user, session: leftSession, mode: info.mode, clients: clients.size,
    });
    if (clients.size === 0) {
      audit('all_tabs_closed', null, {
        ip: info.ip, ua: info.ua, user: info.user, session: leftSession,
      });
    }
  });
}
