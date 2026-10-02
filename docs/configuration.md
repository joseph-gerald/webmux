# Configuration and recovery

See the [README](../README.md) for first-time setup.

## Run with PM2

From the repository directory, with Node.js and the app dependencies installed:

```sh
npm install --global pm2
cp -n ecosystem.config.example.cjs ecosystem.config.cjs
```

In the local `ecosystem.config.cjs`, set these entries in `env`, using your HTTPS
hostname. This keeps the settings in place across restarts:

```js
WEBMUX_PUBLIC_URL: 'https://terminal.example.com',
WEBMUX_TRUST_PROXY: 'loopback',
```

Then start the service:

```sh
pm2 start ecosystem.config.cjs
pm2 save
pm2 startup
```

Run the command printed by `pm2 startup` to finish enabling startup on boot.
Use the same OS user for webmux and PM2. The template runs one process, as
required by the session and passkey store design.

`ecosystem.config.cjs` is ignored by Git. Put deployment-specific environment
values in its `env` section. To apply configuration or source changes:

```sh
pm2 restart ecosystem.config.cjs --update-env
pm2 save
```

`pm2 logs webmux` shows server logs. A webmux restart requires users to sign in
again; running tmux sessions continue separately.

## Environment variables

Set these in your shell or process manager. The app does not automatically load
`.env` files. Default paths are in the project unless stated otherwise. Relative
paths supplied through the environment resolve from the process's working directory.

| Variable | Default / purpose |
| --- | --- |
| `PORT` | `7070` |
| `WEBMUX_HOST` | `127.0.0.1`; listener address |
| `WEBMUX_PUBLIC_URL` | Exact HTTPS origin, or `http://localhost:PORT` for development. Native passkeys are disabled when unset. |
| `WEBMUX_RP_NAME` | `webmux`; displayed by the authenticator |
| `WEBMUX_SECRET_FILE` | `.secret`; recovery secret |
| `WEBMUX_PASSKEY_FILE` | `.webmux-passkeys.json` beside the secret |
| `WEBMUX_STATE` | `.webmux-state.json`; tmux layout and working directories |
| `WEBMUX_TMUX_BIN` | `tmux` from `PATH` |
| `WEBMUX_TMUX_SOCKET` | Optional isolated tmux socket name (`tmux -L`) |
| `TMUX_SESSION` | `webmux`; initial session name |
| `WEBMUX_UPLOADS` | `/tmp/.w`; uploaded files, up to 100 MB each |
| `WEBMUX_LOG_DIR` | `logs/`; event logs and optional telemetry |
| `WEBMUX_SEEN_IPS` | `.seen_ips`; previously seen client addresses |
| `WEBMUX_TRUST_PROXY` | Empty by default. Comma-separated trusted proxy IPs/subnets, or `loopback` for a local proxy. Only these peers may supply forwarded client IPs. |
| `WEBMUX_DISCORD_WEBHOOK` | Optional event webhook; disabled when unset |
| `WEBMUX_AUTH_DIR` | `extensions/auth`; optional private external providers |
| `WEBMUX_AUTH_USERS` | External-provider username allowlist; empty by default |
| `WEBMUX_ADMIN_USERS` | External-provider admin usernames; empty by default |

Native account names and roles are stored locally and do not depend on external
provider allowlists. `WEBMUX_AUTH_USERS` falls back to the configured external
admin list when unset. Legacy `ADMIN_USERS` and `DISCORD_WEBHOOK` environment
aliases are supported.

## Passkeys and recovery

The recovery secret and native administrators can enroll accounts and manage
all keys. Regular native accounts can add/remove their own keys. External-provider
administrators manage terminals only. Roles are set when an account is created;
adding a key to an existing account does not change its role. Removing a key
revokes its sessions and terminal sockets. Removing the last key removes the
account. Key changes require a login from the last five minutes.

Passkeys use server-verified WebAuthn: single-use, five-minute challenges; exact
origin and RP checks; required user verification; signature and counter checks.
The server stores public keys and account roles. Session tickets stay in memory;
reloading the browser requires a new login.

**Lost a passkey?** Sign in with the recovery secret, remove the lost key and
enroll a replacement. With the default paths, read the secret using `cat .secret`
on the server. If `WEBMUX_SECRET_FILE` is set, read that file instead.

**Changing hostname, including localhost → a real domain?** Existing passkeys
stay bound to the original hostname. Set `WEBMUX_PASSKEY_FILE` to a new file
outside the repository, restart, sign in with the recovery secret and enroll
keys on the new hostname. Keep the original store if the old installation is
still needed. Reusing it with a different RP ID causes startup to fail.

**Backups:** keep the recovery secret, passkey store and tmux layout state.
The default secret and passkey store are owner-readable only and Git-ignored.
If you customize their paths, keep them outside the public source tree.
A corrupt passkey store fails startup rather than silently resetting accounts;
restore a valid backup for that hostname.

## Optional diagnostics

Session/security events are logged locally. Detailed collection is opt-in:

- `WEBMUX_FINGERPRINTS=1`: device fingerprint collection after login and detailed
  browser Client Hints.
- `WEBMUX_STUN_URLS`: comma-separated STUN URLs for optional WebRTC address
  collection. No external STUN services are configured by default.
- `WEBMUX_IP_LOOKUP_URL`: optional IP lookup URL prefix using an ipwho.is-shaped
  JSON response. The client IP is appended. Requires fingerprints enabled.
- `WEBMUX_LOG_INPUT=1`: raw terminal input logging, including entered secrets.
- `WEBMUX_LOG_SCROLLBACK=1`: terminal scrollback snapshots.

These are disabled on a fresh installation.

## Other tools

- [Clipboard support](../CLIPBOARD.md): OSC 52 setup.
- `bin/webmux-img`: image display; requires `timg`, and ImageMagick for GIFs.
- `bin/build-tmux-sixel [output-path]`: optional patched SIXEL tmux build;
  installs to `~/.local/bin/webmux-tmux` by default. Requires curl, tar, patch,
  make, sha256sum, a C compiler, libevent and ncurses headers. On Debian/Ubuntu:
  `sudo apt install curl patch build-essential libevent-dev libncurses-dev bison`.
  The tmux 3.7c download is checksum-pinned; `WEBMUX_TMUX_ARCHIVE` can point to
  an offline copy of that release archive. Set `WEBMUX_TMUX_BIN` to the absolute
  path of the resulting binary. Existing tmux servers keep their old executable;
  use a new `WEBMUX_TMUX_SOCKET` to try the build in a separate workspace.
- [Windows prototype](../webmux-win-simple/README.md): separate, local-only,
  unauthenticated PowerShell terminal.
