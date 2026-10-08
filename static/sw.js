// sw.js - ClassRoot Service Worker for PWA
const CACHE_NAME = 'classroot-v1';
const STATIC_ASSETS = [
    '/',
    '/index.html',
    '/common.css',
    '/mainpage.css',
    '/galene.css',
    '/manifest.json'
];

self.addEventListener('install', (event) => {
    self.skipWaiting();
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            return cache.addAll(STATIC_ASSETS).catch(() => {});
        })
    );
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) => {
            return Promise.all(
                keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
            );
        }).then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', (event) => {
    // Only cache GET requests for static assets; bypass WebSocket and API
    if (event.request.method !== 'GET' || event.request.url.includes('/ws') || event.request.url.includes('/api/')) {
        return;
    }
    event.respondWith(
        fetch(event.request).catch(() => caches.match(event.request))
    );
});
