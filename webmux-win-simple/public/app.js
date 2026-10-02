/* global Terminal, FitAddon, WebLinksAddon */
(() => {
  const term = new Terminal({
    cursorBlink: true,
    fontFamily: "'Cascadia Mono', Consolas, 'Courier New', monospace",
    fontSize: 14,
    theme: { background: "#0c0c0c" },
    scrollback: 5000,
    windowsMode: true, // treat \r\n properly for ConPTY output
  });

  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.loadAddon(new WebLinksAddon.WebLinksAddon());
  term.open(document.getElementById("terminal"));

  let ws;

  function send(obj) {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
  }

  function connect() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${proto}://${location.host}`);

    ws.onopen = () => {
      term.reset(); // server replays the scrollback buffer; start clean
      fit.fit();
      send({ type: "resize", cols: term.cols, rows: term.rows });
      term.focus();
    };

    ws.onmessage = (e) => {
      const m = JSON.parse(e.data);
      if (m.type === "data") term.write(m.data);
      else if (m.type === "exit") term.write(`\r\n\x1b[90m[process exited with code ${m.code}]\x1b[0m\r\n`);
    };

    ws.onclose = () => {
      term.write("\r\n\x1b[90m[connection lost — reconnecting…]\x1b[0m\r\n");
      setTimeout(connect, 1000);
    };
  }

  term.onData((data) => send({ type: "input", data }));

  window.addEventListener("resize", () => {
    fit.fit();
    send({ type: "resize", cols: term.cols, rows: term.rows });
  });

  connect();
})();
