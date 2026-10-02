# webmux auth-provider extensions

Drop-in external login providers for webmux. Native server-verified passkeys and
the built-in recovery secret are available without any extensions. Configured
providers appear alongside them.

Providers live in `extensions/auth/*.js`. **`extensions/` is gitignored**, keeping
local providers out of ordinary Git adds. This
`extensions.example/` directory is the committed template.

## Quick start

```sh
mkdir -p extensions/auth
cp -n extensions.example/auth/example-provider.js extensions/auth/my-provider.js
# implement your provider's verified login flow in that file
# set WEBMUX_AUTH_USERS to the external usernames allowed into this terminal
# restart webmux with your process manager, or run npm start
```

The example is a **disabled scaffold**, not a working identity service. Its
`register()` throws until you implement the provider-specific protocol. Setting
environment variables alone cannot enable it.

The public loader (`lib/auth/providers.js`) scans `extensions/auth/*.js` on boot
(override the directory with `WEBMUX_AUTH_DIR`) and mounts each valid provider at
`/auth/ext/<id>`. A provider that fails to load, has the wrong shape, or throws in
`register()` is skipped with a log line — it never breaks startup. With no
`extensions/` dir at all, the app runs exactly as before.

## Provider module shape

```js
module.exports = {
  id: 'myprovider',          // required. URL-safe; namespaces routes + the client button
  label: 'Sign in',          // optional. Button text (default: id)
  kind: 'oauth',             // optional. Client hint: 'oauth' | 'secret' | 'custom'
  iconPath: '/icon.svg',     // optional. Mount this asset on ctx.router as well
  register(ctx) { /* mount your routes synchronously on ctx.router */ },
};
```

`loginPath` is **not** something you export — the core derives it as
`/auth/ext/<id>/start` and hands it to the client.

`register(ctx)` must be synchronous; a returned Promise causes the provider to
be skipped. Route handlers may be asynchronous.

## The `ctx` object passed to `register(ctx)`

| Field | What it is |
|---|---|
| `ctx.router` | An `express.Router()` the core mounts at `/auth/ext/<id>`. Add your `/start`, `/callback`, etc. here. You cannot shadow the app's static files, `/ws`, or `/api/*`. |
| `ctx.mintToken({ user, ttlMs, ip, ua })` | Returns a random, revocable session token (default TTL 12h). `user` must be a nonempty, allowlisted string; `ttlMs`, if supplied, must be a positive safe integer in milliseconds whose expiry is also a safe integer. Invalid inputs return `null`. The loader records the provider ID automatically. |
| `ctx.authUserAllowed(user)` | Checks the configured external username allowlist. No usernames are allowed by default. |
| `ctx.revokeToken(token)` | Invalidates a previously minted token. |
| `ctx.setSessionCookie(res, token)` | Sets the single-use `webmux_handoff` cookie (HttpOnly, Secure, SameSite=Strict, 60s). The SPA reads it via `POST /api/auth/exchange`. |
| `ctx.publicUrl` | `WEBMUX_PUBLIC_URL` (e.g. `https://app.example.com`). Build redirect/callback URLs from this — **never** from `req.headers.host`. |
| `ctx.clientIp(req)` | The caller's IP; forwarded headers are accepted only from `WEBMUX_TRUST_PROXY`. |
| `ctx.sendDiscord(msg)` | Optional: post a message to the configured webhook (login events, etc.). |
| `ctx.log(...args)` | Prefixed console logger. |

## How a login completes (the handoff)

webmux's SPA holds a bearer token only in memory and sends it as the
`x-token` header and as a `Sec-WebSocket-Protocol` value on `/ws` — never as
`?token=` on the WebSocket URL. After an external login, get that token
into the browser like this:

1. In your `/callback`, verify the credential and the single-use state binding
   it to the initiating browser, then `const t = ctx.mintToken({ user })`.
2. If `t` is null, reject the login. Otherwise call `ctx.setSessionCookie(res, t)`
   then `res.redirect(303, ctx.publicUrl + '/')`.
3. The SPA boots and calls `POST /api/auth/exchange`, which swaps the one-time
   cookie for `{ token, provider }`. Reloading requires a new login.

## Rules & gotchas

- **Build callback/redirect URLs from `ctx.publicUrl` only.** Trusting the Host
  header lets an attacker turn your `/start` redirect into an open redirect.
- **Require HTTPS.** The handoff cookie is `Secure`; set `WEBMUX_PUBLIC_URL` to an
  `https://` origin.
- **Fail closed.** If required env vars are missing, `throw` in `register()` — the
  loader will skip the provider instead of mounting a half-configured one.
- **Use your identity service's supported verifier/client.** Validate signatures,
  issuer, audience, expiry and replay protection. Bind callbacks to the browser
  with single-use state; use PKCE for OAuth authorization-code flows. Do not
  pass bearer credentials in redirect URLs or log them.
- **Keep secrets in env**, not in the provider file, so even your gitignored copy
  carries no literal secrets.

## Env vars

- `WEBMUX_PUBLIC_URL` — required by any redirect-based provider (the app's public
  https origin).
- `WEBMUX_AUTH_USERS` — comma-separated external usernames allowed to log in.
- `WEBMUX_ADMIN_USERS` — comma-separated external usernames with admin access.
  These roles govern terminal management. Native account/key management requires
  the recovery secret or a native passkey account; native roles are stored locally.
- All other configuration is provider-specific.

See `example-provider.js` for the scaffold and a session-handoff example.
