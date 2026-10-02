# webmux

A browser terminal backed by tmux. Persistent sessions, tabs, uploads, mobile
controls and built-in passkey login.

## Setup

You need **Node.js 22.12+**, **tmux 3.3+**, Python 3 and a C/C++ build toolchain.
Linux is the primary platform. On Debian/Ubuntu, install the system dependencies
with `sudo apt install tmux python3 build-essential` after installing Node.js.

### 1. Install and start

From the repository directory:

```sh
npm ci
WEBMUX_PUBLIC_URL=http://localhost:7070 npm start
```

Open **http://localhost:7070** on the same machine.

Installing on a server? Use the [HTTPS setup below](#https-on-a-server) before
registering a passkey. Passkeys are tied to the hostname you choose.

### 2. First login

The first start generates a recovery secret. In another terminal, in the same
repository directory, read it:

```sh
cat .secret
```

Choose **Sign in with token**, paste the secret and press Enter.

### 3. Add your passkey

1. Click the key button in the top bar: **Manage passkeys**.
2. Enter an account name and a name for the key. Keep **Administrator** checked
   for your owner account.
3. Click **Add passkey** and complete your device's prompt.
4. Reload and choose **Sign in with passkey**.

Passkeys are verified by the server and work with supported devices, password
managers and security keys. Keep the recovery secret for lost-device recovery.
If your login is over five minutes old, reload and sign in again before adding
or removing keys.

## HTTPS on a server

Point your domain at the server. Install [Caddy](https://caddyserver.com/docs/install)
on that server and make ports **80 and 443** reachable. Replace
`terminal.example.com` below with your domain.

Start webmux with its public URL:

```sh
WEBMUX_PUBLIC_URL=https://terminal.example.com \
WEBMUX_TRUST_PROXY=loopback \
npm start
```

Add this to `/etc/caddy/Caddyfile`:

```caddyfile
terminal.example.com {
    reverse_proxy 127.0.0.1:7070
}
```

Reload Caddy with `sudo systemctl reload caddy`, then open your HTTPS URL and
follow **First login** and **Add your passkey** above. Caddy handles HTTPS and
WebSockets; webmux listens on loopback.

To keep webmux running in the background and across reboots, follow the
[PM2 setup](docs/configuration.md#run-with-pm2).

## Useful details

- Run webmux as the OS user whose shell you want. All signed-in users share that
  account and its tmux workspace.
- Back up `.secret`, `.webmux-passkeys.json` and `.webmux-state.json`.
- Native auth works out of the box; external providers are optional, private
  modules. See the [provider guide](extensions.example/auth/README.md).
- [Configuration and recovery](docs/configuration.md) · [Clipboard support](CLIPBOARD.md).

## Tests

```sh
npm test
```

Tests require Git for the private-file exclusion check. Include the
browser/passkey flow by supplying a Chrome or Chromium executable:

```sh
WEBMUX_TEST_CHROME=/path/to/chrome npm test
```

CI runs this browser flow on Node.js 22.12 and 24, using an isolated tmux socket
and temporary account/state files.

## License

[ISC](LICENSE). Bundled fonts have separate [licenses and source notices](public/fonts/NOTICE.md);
vendored xterm.js files use [MIT](webmux-win-simple/public/XTERM-LICENSE.txt).
