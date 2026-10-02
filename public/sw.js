// Retire the old offline shell. Keep this URL so installed workers can update
// even when they are still serving an old copy of app.js.
self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(key => key.startsWith('webmux-')).map(key => caches.delete(key)));
    await self.registration.unregister();
    const clients = await self.clients.matchAll({ type: 'window' });
    await Promise.all(clients.map(client => client.navigate(client.url)));
  })());
});
