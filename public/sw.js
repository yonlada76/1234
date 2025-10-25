// sw.js
const CACHE_STATIC = 'sports-static-v5';
const PRECACHE = [
  '/',
  '/offline.html',
  '/css/style.css',
  '/icons/icon-192.png',
  '/icons/icon-512.png'
];

self.addEventListener('install', (e) => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE_STATIC).then(c => c.addAll(PRECACHE)));
});

self.addEventListener('activate', (e) => {
  self.clients.claim();
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_STATIC).map(k => caches.delete(k)))
    )
  );
});

function isAPI(req){ return new URL(req.url).pathname.startsWith('/api/'); }
function isNav(req){ return req.mode === 'navigate' || (req.headers.get('accept')||'').includes('text/html'); }
function isStatic(req){ return /\.(css|js|png|jpg|jpeg|svg|webp|woff2?)$/i.test(new URL(req.url).pathname); }

self.addEventListener('fetch', (e) => {
  const req = e.request;

  if (isAPI(req)) {
    e.respondWith(fetch(req).catch(() =>
      new Response(JSON.stringify({ error: 'offline' }), {status:503, headers:{'Content-Type':'application/json'}})
    ));
    return;
  }

  if (isNav(req)) {
    e.respondWith(
      fetch(req).then(res => {
        const copy = res.clone();
        caches.open(CACHE_STATIC).then(c => c.put(req, copy)).catch(()=>{});
        return res;
      }).catch(() => caches.match(req).then(m => m || caches.match('/offline.html')))
    );
    return;
  }

  if (isStatic(req)) {
    e.respondWith(
      caches.match(req).then(m => m || fetch(req).then(res => {
        const copy = res.clone();
        caches.open(CACHE_STATIC).then(c => c.put(req, copy)).catch(()=>{});
        return res;
      }))
    );
    return;
  }

  e.respondWith(
    fetch(req).catch(() => caches.match(req).then(m => m || caches.match('/offline.html')))
  );
});
