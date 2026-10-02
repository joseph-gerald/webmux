'use strict';
const fs = require('fs');
const path = require('path');

// The loader is public; implementation, routes and assets of optional providers
// live entirely in the configured private directory.
function loadAuthProviders(core, dir) {
  let files;
  try { files = fs.readdirSync(dir); }
  catch (e) { if (e.code === 'ENOENT') return []; throw e; }
  const loaded = [];
  const ids = new Set(['passkey', 'secret']);
  for (const file of files.filter(f => f.endsWith('.js')).sort()) {
    try {
      const mod = require(path.resolve(dir, file));
      if (!mod || typeof mod.id !== 'string' || !/^[a-z][a-z0-9_-]{0,39}$/.test(mod.id) || ids.has(mod.id) || typeof mod.register !== 'function') {
        throw new Error('provider needs a unique URL-safe id and register(ctx)');
      }
      const base = `/auth/ext/${mod.id}`;
      const descriptor = {
        id: mod.id, label: typeof mod.label === 'string' && mod.label ? mod.label : mod.id,
        kind: typeof mod.kind === 'string' && mod.kind ? mod.kind : 'custom',
        loginPath: base + '/start',
        iconPath: typeof mod.iconPath === 'string' && /^\/[a-zA-Z0-9/_-]+\.(svg|png)$/.test(mod.iconPath) ? base + mod.iconPath : null,
      };
      const router = core.express.Router();
      const result = mod.register(core.makeCtx(mod.id, router));
      if (result && typeof result.then === 'function') {
        Promise.resolve(result).catch(() => {});
        throw new Error('register(ctx) must mount routes synchronously');
      }
      core.app.use(base, router);
      ids.add(mod.id);
      loaded.push(descriptor);
      console.log(`[auth] loaded provider "${mod.id}"`);
    } catch (e) { console.error(`[auth] skipped ${file}:`, e.message); }
  }
  return loaded;
}

module.exports = { loadAuthProviders };
