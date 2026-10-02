'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

test('public Git checkout excludes private deployment files, runtime state and backups', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'webmux-packaging-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.copyFileSync(path.join(__dirname, '../.gitignore'), path.join(dir, '.gitignore'));
  // Only this temporary fixture gets Git metadata, never the working tree.
  const env = { PATH: process.env.PATH, HOME: dir, TMPDIR: os.tmpdir(),
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
  execFileSync('git', ['init', '--quiet', dir], { env });
  const privatePaths = [
    '.secret', '.secret.bak', '.secret.tmp', '.webmux-passkeys.json',
    '.webmux-passkeys.json.tmp', '.webmux-state.json', '.webmux-state.prev.json',
    '.webmux-state.json.tmp', '.seen_ips', '.env', '.env.production',
    'extensions/auth/local-provider.js', 'extensions/test/private.test.js',
    'ecosystem.config.cjs', 'ecosystem.config.cjs.old', 'logs/events.jsonl',
    'npm-debug.log', 'server.js.bak', 'server.js.bak.1', 'core', 'core.123',
    'node_modules/example/index.js', 'webmux-win-simple/node_modules/example/index.js',
  ];
  const publicPaths = ['ecosystem.config.example.cjs', '.env.example',
    'extensions.example/auth/example-provider.js', 'public/fonts/OFL.txt'];
  const ignored = execFileSync('git', ['check-ignore', '--stdin'], {
    cwd: dir, env, encoding: 'utf8', input: [...privatePaths, ...publicPaths].join('\n') + '\n',
  }).trim().split('\n');
  assert.deepEqual(ignored, privatePaths);
});
