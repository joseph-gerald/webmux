# Windows prototype

A separate, local-only PowerShell terminal. It has **no authentication**; every
connection shares one shell under your Windows account. Use the main Linux
server for authenticated remote access.

Requires Windows 10/11, Node.js 22.12+ and PowerShell. If `node-pty` must compile
locally, its build needs Python and Visual Studio C++ build tools; see the
[node-pty instructions](https://github.com/microsoft/node-pty#windows).

From this directory:

```powershell
npm ci
npm start
```

Open `http://127.0.0.1:3000`. `PORT` changes the port and `WEBMUX_SHELL` selects a
different shell executable. The listener is fixed to `127.0.0.1`; Host and
WebSocket Origin checks reject other websites. Do not expose it through a
reverse proxy or port forward. Local processes can still access it.

The shell persists while this Node process is running. Refreshing the page
reattaches and replays recent output. There is no tmux or native passkey support.

Code uses the parent project's [ISC license](../LICENSE). The copied xterm.js
bundles use [MIT](public/XTERM-LICENSE.txt); `npm ci` refreshes bundles and notices
from the locked dependencies.
