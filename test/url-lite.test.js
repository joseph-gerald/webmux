'use strict';
const assert = require('assert');
const {
  httpsOrigin, parseQuery, appendQuery, parseHttpsUrl, redactUrl, queryHas, queryGet,
} = require('../lib/url-lite');

assert.strictEqual(httpsOrigin('https://mux.example.com'), 'https://mux.example.com');
assert.strictEqual(httpsOrigin('https://mux.example.com/foo'), 'https://mux.example.com');
assert.throws(() => httpsOrigin('http://mux.example.com'));
assert.throws(() => httpsOrigin('https://user:password@mux.example.com'));
assert.strictEqual(httpsOrigin('https://MUX.example.com:8443/foo'), 'https://mux.example.com:8443');

const q = parseQuery('/ws?session=webmux&cols=240&rows=46&token=secret');
assert.strictEqual(q.session, 'webmux');
assert.strictEqual(q.cols, '240');
assert.strictEqual(q.token, 'secret');
assert.strictEqual(queryHas('/ws?token=1', 'token'), true);
assert.strictEqual(queryHas('/ws?session=x', 'token'), false);
assert.strictEqual(queryGet('/ws?session=webmux', 'session', ''), 'webmux');

const auth = appendQuery('https://auth.example.com/', {
  callback: 'https://mux.example.com/auth/ext/example/callback?response_mode=form_post',
  amr: 'passkey',
});
assert.ok(auth.includes('callback=https%3A%2F%2Fmux.example.com'));
assert.ok(auth.includes('amr=passkey'));

const wh = parseHttpsUrl('https://discord.com/api/webhooks/123/abc?wait=true');
assert.strictEqual(wh.hostname, 'discord.com');
assert.strictEqual(wh.pathname, '/api/webhooks/123/abc');
assert.strictEqual(wh.search, '?wait=true');
assert.strictEqual(parseHttpsUrl('https://localhost:8443/path').hostname, 'localhost');
assert.strictEqual(parseHttpsUrl('https://localhost:8443/path').port, '8443');
assert.strictEqual(parseHttpsUrl('https://[::1]:8443/path').hostname, '::1');
for (const url of ['https://user:pass@example.com', 'https://example.com:bad/', 'https://example.com\\@other.example/', 'https://example.com/\npath', 'http://example.com/']) {
  assert.strictEqual(parseHttpsUrl(url), null);
}

assert.ok(redactUrl('/auth?token=abc&user=h').includes('token=[redacted]'));
assert.strictEqual(redactUrl('/auth?%74oken=hidden&%63ode=hidden&user=h'), '/auth?%74oken=[redacted]&%63ode=[redacted]&user=h');
assert.strictEqual(redactUrl('/auth?%ZZ=hidden#access_token=hidden'), '/auth?%ZZ=[redacted]#access_token=[redacted]');
assert.throws(() => parseQuery('/ws?session=%'));
assert.strictEqual(Object.getPrototypeOf(parseQuery('/ws?__proto__=x')), null);

console.log('url-lite.test.js: ok');
