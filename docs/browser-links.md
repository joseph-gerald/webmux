# Opening browser links

HTTP(S) URLs and labeled OSC 8 hyperlinks in the terminal open in a new tab in
the browser running webmux. Applications can call the usual browser openers;
webmux provides URL-only `xdg-open`, `sensible-browser`, `x-www-browser`,
`gnome-open`, `kde-open`, `exo-open`, and `gio open` shims, plus the standalone
`webmux-open` helper.

```sh
"$BROWSER" 'https://example.com'
```

webmux adds its `bin` directory to the environment's `PATH` and defaults
`BROWSER` to the absolute path of `bin/webmux-open`. Apps that respect `BROWSER`
(including Python's `webbrowser` module) use this bridge automatically. A
`BROWSER` configured in the server environment takes precedence. Libraries that
shell out to `xdg-open` or `gio open` instead also work because those names
resolve to the shims in `bin`.

For agents and daemons that start with a PATH that does not include webmux's
`bin`, install the shims system-wide:

```sh
sudo /path/to/webmux/bin/install-browser-shims /usr/local/bin
```

They are URL-only: non-URL arguments are rejected rather than passed to a
desktop browser.

To use the launchers by name when your login profile resets `PATH`:

```sh
# With the default webmux BROWSER:
export PATH="$(dirname "$BROWSER"):$PATH"
webmux-open 'https://example.com'
xdg-open 'https://example.com'
```

## Existing shells

After updating webmux, restart its server and reload the page. New panes inherit
the browser setup; already-running shells and apps retain their old environment.
In an existing shell, or if your shell startup files replace `PATH`, run:

```sh
# Replace /path/to/webmux with your installation directory.
export PATH="/path/to/webmux/bin:$PATH"
export BROWSER="/path/to/webmux/bin/webmux-open"
```

Restart the terminal application after exporting these variables. Applications
with their own browser command setting can use the absolute helper path. Programs
that insist on `/usr/bin/xdg-open` bypass the `PATH` wrapper; configure their
browser command or `BROWSER` setting instead.

## Browser behavior

- Program-issued links are confirmed first: a full-screen prompt names the tab
  you are viewing and its group, then shows the destination URL. **Open link**
  launches it and **Not now** dismisses it. Plain URLs and labeled OSC 8
  hyperlinks that you click yourself open immediately.
- Up to ten distinct requests are queued and shown in turn. Requests travel only
  through the pane that made them, so a link from another group never appears
  here.
- A request goes through the originating pane. Keep that pane visible and a
  webmux browser attached when an application launches a link. Detached browser
  launcher subprocesses use `TMUX_PANE` to find the originating terminal.
- Automatic requests are ignored by view-only and spectator clients. They can
  still click terminal hyperlinks themselves.
- Links open on your browser's machine. `localhost` points to that machine;
  remote development servers and OAuth callbacks may need an SSH port forward
  or a reachable URL.
- The helper accepts HTTP(S) URLs up to 16 KB, without embedded credentials.
  Local files and other URL schemes are not handled by the wrapper.

## Protocol

The helper writes `OSC 777 ; webmux-open ; BASE64_URL BEL`, with the URL encoded
as UTF-8 before base64. Under tmux it wraps the OSC in DCS passthrough, escaping
each inner ESC byte. webmux enables `allow-passthrough on` for its tmux server.
The request uses the existing terminal connection; it needs no HTTP credentials
or additional listener.

For labeled OSC 8 links, native tmux hyperlink forwarding requires a tmux version
that supports it (3.4+); plain URL detection and the helper also work on 3.3.
