// Garde l'app en cache pour qu'elle marche sans Internet. Les images ne passent jamais ici.
const V = 'coffre-v2';
const FICHIERS = ['./', 'index.html', 'app.js?v=2', 'style.css?v=2', 'manifest.webmanifest', 'icone-180.png', 'icone-512.png'];
self.addEventListener('install', e => { e.waitUntil(caches.open(V).then(c => c.addAll(FICHIERS))); self.skipWaiting(); });
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(k => Promise.all(k.filter(x => x !== V).map(x => caches.delete(x)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== location.origin) return;
  e.respondWith(caches.match(e.request, { ignoreSearch: u.pathname.endsWith('/') }).then(r => r || fetch(e.request)));
});
