'use strict';
// Preloaded only in isolated backend test children. Both terminal boundaries are
// replaced, so these tests never start, query, or signal an actual tmux server.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const { EventEmitter } = require('node:events');
const dir = process.env.WEBMUX_TEST_TERMINAL_DIR;
assert.ok(dir && fs.existsSync(path.join(dir, 'fixture-marker')));
assert.match(process.env.WEBMUX_TMUX_SOCKET, /^webmux-backend-test-/);

function record(event) {
  fs.appendFileSync(path.join(dir, 'terminal.jsonl'), JSON.stringify(event) + '\n');
}
function argumentsFor(bin, args) {
  assert.equal(bin, 'webmux-test-tmux');
  assert.deepEqual(args.slice(0, 2), ['-L', process.env.WEBMUX_TMUX_SOCKET]);
  return args.slice(2);
}

require('node:child_process').execFile = (bin, full, _options, callback) => {
  const args = argumentsFor(bin, full);
  const command = args[0];
  const session = args[args.indexOf('-t') + 1];
  record({ type: 'tmux', command, session });
  const gate = path.join(dir, 'gate-' + command + '-' + String(session).replace(/[^a-z-]/g, '_'));
  const started = Date.now();
  function complete() {
    if (fs.existsSync(gate) && Date.now() - started < 5000) return setTimeout(complete, 10);
    let output = '';
    if (command === 'list-sessions') output = 'webmux\nslow\nother\n';
    if (command === 'has-session' && !['webmux', 'slow', 'other'].includes(session)) {
      callback(new Error('no such fixture session'), '');
      return;
    }
    callback(null, output);
  }
  setImmediate(complete);
};

let sequence = 0;
const pty = {
  spawn(bin, full, options) {
    const args = argumentsFor(bin, full);
    if (fs.existsSync(path.join(dir, 'fail-spawn'))) throw new Error('simulated PTY spawn failure');
    const session = args[args.indexOf('-t') + 1];
    const id = ++sequence;
    const events = new EventEmitter();
    let closed = false;
    record({ type: 'attach', id, session });
    setImmediate(() => { if (!closed) events.emit('data', `fixture-ready:${id}:${session}`); });
    return {
      pid: 0, cols: options.cols, rows: options.rows,
      onData(fn) { events.on('data', fn); },
      onExit(fn) { events.on('exit', fn); },
      write(data) {
        if (closed) throw new Error('PTY closed');
        record({ type: 'write', id, data });
        events.emit('data', data);
      },
      resize(cols, rows) { this.cols = cols; this.rows = rows; },
      kill() {
        if (closed) return;
        closed = true;
        record({ type: 'kill', id });
        events.emit('exit');
      },
    };
  },
};
const load = Module._load;
Module._load = function (id, ...rest) {
  return id === 'node-pty' ? pty : load.call(this, id, ...rest);
};
