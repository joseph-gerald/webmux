# Clipboard support

webmux handles OSC 52 clipboard writes from terminal applications. Use HTTPS
(or localhost) and keep the browser tab focused. Browser clipboard permissions
still apply.

The server enables tmux's `set-clipboard on`, the `clipboard` terminal feature
and `allow-passthrough on`. This supports both plain OSC 52 and sequences wrapped
in tmux passthrough. Applications with native OSC 52 support need no shim.

## Headless clipboard shim

Some applications copy by running `xclip`, `xsel` or `wl-copy`. Without an X11 or
Wayland display, use the following **stdin-copy-only** aliases in that terminal.
They write OSC 52 to its controlling TTY and do not provide clipboard reads.

Install in a dedicated directory under your own account:

```sh
mkdir -p "$HOME/.local/lib/webmux-clipboard"
cat > "$HOME/.local/lib/webmux-clipboard/osc52-copy" <<'EOF'
#!/bin/sh
case " $* " in
  *" -o "*|*" -out "*|*" --output "*|*" --paste "*)
    echo 'This shim supports stdin copy only' >&2
    exit 1
    ;;
esac
b64=$(base64 | tr -d '\n')
printf '\033]52;c;%s\033\\' "$b64" > /dev/tty
EOF
chmod 755 "$HOME/.local/lib/webmux-clipboard/osc52-copy"
for name in xclip xsel wl-copy; do
  ln -sfn osc52-copy "$HOME/.local/lib/webmux-clipboard/$name"
done
export PATH="$HOME/.local/lib/webmux-clipboard:$PATH"
```

Start the application from that shell so it inherits this `PATH`. This avoids
replacing system clipboard utilities. Test inside a webmux terminal:

```sh
printf 'hello from webmux' | xclip -selection clipboard -i
```

Paste into another application to confirm the text arrived. To test OSC 52
without installing the shim:

```sh
printf '\033]52;c;aGVsbG8=\007'
```

## Troubleshooting

- **The application says it copied, but nothing arrives:** restart it after
  setting `PATH`; some applications cache which clipboard tools are installed.
- **The shim works but native OSC 52 does not:** the application may use tmux
  passthrough. Check `tmux show-options -gv allow-passthrough` from the affected
  pane. webmux sets it to `on` for its tmux server.
- **Copy only works in a focused tab:** this is a browser restriction. webmux
  retries pending clipboard writes when the window regains focus; permissions
  may still require a user gesture.
- **`/dev/tty` fails:** the shim needs a controlling terminal. Run it inside a
  webmux pane, rather than cron or a detached script.

This affects copying from applications; pasting still uses the terminal's
normal paste controls.
