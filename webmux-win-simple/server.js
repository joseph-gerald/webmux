// Local-only, unauthenticated Windows prototype. One PowerShell session is
// shared by connections; refreshing reattaches and replays recent output.

const http = require("http");
const path = require("path");
const express = require("express");
const { WebSocketServer } = require("ws");
const pty = require("node-pty");

const HOST = "127.0.0.1";
const BUFFER_LIMIT = 256 * 1024;

function createServer({ spawn = pty.spawn } = {}) {
  const app = express();
  const server = http.createServer(app);
  const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });
  const clients = new Set();
  let term = null;
  let buffer = "";

  function localOrigin(req) {
    const suffix = req.socket.localPort === 80 ? "" : `:${req.socket.localPort}`;
    const host = req.headers.host;
    if (host !== `localhost${suffix}` && host !== `${HOST}${suffix}`) return null;
    return `http://${host}`;
  }

  app.use((req, res, next) => {
    // A loopback bind alone does not prevent DNS rebinding or hostile websites.
    const origin = localOrigin(req);
    if (!origin || (req.headers.origin && req.headers.origin !== origin)) {
      return res.status(403).send("Local origin required");
    }
    res.setHeader("Content-Security-Policy", "frame-ancestors 'none'");
    res.setHeader("X-Frame-Options", "DENY");
    next();
  });
  app.use(express.static(path.join(__dirname, "public")));

  server.on("upgrade", (req, socket, head) => {
    const origin = localOrigin(req);
    if (req.url !== "/" || !origin || req.headers.origin !== origin) {
      socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws));
  });

  function broadcast(data) {
    buffer = (buffer + data).slice(-BUFFER_LIMIT);
    const msg = JSON.stringify({ type: "data", data });
    for (const ws of clients) {
      if (ws.readyState === ws.OPEN) ws.send(msg);
    }
  }

  function spawnShell() {
    term = spawn(process.env.WEBMUX_SHELL || "powershell.exe", [], {
      name: "xterm-256color",
      cols: 80,
      rows: 24,
      cwd: process.env.USERPROFILE || process.cwd(),
      env: process.env,
      useConpty: true,
    });
    term.onData(broadcast);
    term.onExit(({ exitCode }) => {
      term = null;
      broadcast(`\r\n\x1b[90m[shell exited with code ${exitCode} — restart it by refreshing, or type anything]\x1b[0m\r\n`);
    });
  }

  function dimension(value) {
    return Number.isInteger(value) && value >= 1 && value <= 500;
  }

  wss.on("connection", (ws) => {
    clients.add(ws);
    ws.on("error", () => {});
    ws.on("close", () => clients.delete(ws));
    try {
      if (!term) spawnShell();
    } catch {
      ws.close(1011, "Could not start shell");
      return;
    }
    if (buffer) ws.send(JSON.stringify({ type: "data", data: buffer }));

    ws.on("message", (msg) => {
      let m;
      try { m = JSON.parse(msg); } catch { return; }
      if (!m || typeof m !== "object") return;
      if (m.type === "input" && typeof m.data === "string") {
        try {
          if (!term) {
            spawnShell();
            return; // Drop the keystroke that triggered the respawn.
          }
          term.write(m.data);
        } catch { ws.close(1011, "Shell unavailable"); }
      } else if (m.type === "resize" && dimension(m.cols) && dimension(m.rows)) {
        if (!term) return;
        try { term.resize(m.cols, m.rows); } catch {}
      }
    });
  });

  server.on("close", () => {
    wss.close();
    if (term) { try { term.kill(); } catch {} }
  });
  return server;
}

if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("PORT must be 1–65535");
  createServer().listen(port, HOST, () => {
    console.log(`webmux-win-simple running at http://127.0.0.1:${port}`);
  });
}

module.exports = { createServer };
