'use strict';
// URL/query helpers shared by the server and optional provider extensions.

function httpsOrigin(raw) {
  const url = parseHttpsUrl(raw);
  if (!url) throw new Error('URL must be https without credentials');
  return url.origin;
}

function decodeQueryComp(s) {
  return decodeURIComponent(String(s).replace(/\+/g, ' '));
}

function parseQuery(input) {
  const s = String(input || '');
  const q = s.includes('?') ? s.slice(s.indexOf('?') + 1).split('#')[0] : '';
  const out = Object.create(null);
  if (!q) return out;
  for (const part of q.split('&')) {
    if (!part) continue;
    const eq = part.indexOf('=');
    const k = decodeQueryComp(eq >= 0 ? part.slice(0, eq) : part);
    const v = decodeQueryComp(eq >= 0 ? part.slice(eq + 1) : '');
    if (k) out[k] = v;
  }
  return out;
}

function appendQuery(base, params) {
  const start = String(base).replace(/#.*$/, '');
  const parts = [];
  for (const [k, v] of Object.entries(params)) {
    if (v == null) continue;
    parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(String(v)));
  }
  if (!parts.length) return start;
  return start + (start.includes('?') ? '&' : '?') + parts.join('&');
}

function parseHttpsUrl(raw) {
  if (typeof raw !== 'string' || /[\\\x00-\x20\x7f]/.test(raw)) return null;
  try {
    const url = new URL(raw);
    if (url.protocol !== 'https:' || url.username || url.password || !/^https:\/\//i.test(raw)) return null;
    return {
      origin: url.origin, hostname: url.hostname.replace(/^\[|\]$/g, ''),
      port: url.port || undefined, pathname: url.pathname, search: url.search,
    };
  } catch { return null; }
}


function redactUrl(raw) {
  const s = String(raw || '');
  return s.replace(/([?&#])([^=&#]+)=([^&#]*)/g, (part, sep, key) => {
    let decoded;
    try { decoded = decodeQueryComp(key); }
    catch { return `${sep}${key}=[redacted]`; }
    return /token|secret|handoff|password|passwd|jwt|code/i.test(decoded) ? `${sep}${key}=[redacted]` : part;
  });
}

function queryHas(input, key) {
  return Object.prototype.hasOwnProperty.call(parseQuery(input), key);
}

function queryGet(input, key, fallback) {
  const q = parseQuery(input);
  return q[key] != null ? q[key] : fallback;
}

module.exports = {
  httpsOrigin, parseQuery, appendQuery, parseHttpsUrl, redactUrl, queryHas, queryGet,
};
