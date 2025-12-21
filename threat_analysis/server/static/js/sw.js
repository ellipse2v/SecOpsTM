// Service Worker for Threat Model Full GUI Offline Support
const CACHE_NAME = 'threat-model-offline-cache-v1';

// Liste des ressources à mettre en cache pour un fonctionnement offline
const urlsToCache = [
    '/',
    '/full',
    '/static/js/sw.js',
    '/static/js/lib/mxgraph.min.js',
    '/static/js/lib/split.min.js',
    '/static/js/lib/svg-pan-zoom.min.js',
    '/static/css/styles.css',
    '/static/resources/icons/actor.png',
    '/static/resources/icons/server.png',
    '/static/resources/icons/web-server.png',
    '/static/resources/icons/database.png',
    '/static/resources/icons/firewall.png',
    '/static/resources/icons/data.png',
    '/static/resources/icons/boundary.png',
    '/static/js/lib/css/common.css',
    '/static/js/lib/resources/graph.txt',
    '/static/js/lib/resources/graph_fr.txt',
    '/static/js/lib/resources/editor.txt',
    '/static/js/lib/resources/editor_fr.txt',
    '/static/js/lib/split.min.js.map',
    '/static/js/lib/images/expanded.gif'
];

// Installation du Service Worker
self.addEventListener('install', function(event) {
    console.log('Service Worker: Installing...');
    
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(function(cache) {
                console.log('Service Worker: Caching resources');
                return cache.addAll(urlsToCache);
            })
            .then(function() {
                console.log('Service Worker: All resources cached');
                return self.skipWaiting(); // Force the waiting service worker to become active
            })
            .catch(function(error) {
                console.error('Service Worker: Failed to cache resources:', error);
            })
    );
});

// Activation du Service Worker
self.addEventListener('activate', function(event) {
    console.log('Service Worker: Activating...');
    
    // Suppression des anciens caches
    event.waitUntil(
        caches.keys().then(function(cacheNames) {
            return Promise.all(
                cacheNames.map(function(cacheName) {
                    if (cacheName !== CACHE_NAME) {
                        console.log('Service Worker: Deleting old cache:', cacheName);
                        return caches.delete(cacheName);
                    }
                })
            );
        })
        .then(function() {
            console.log('Service Worker: Ready to handle fetches');
            return self.clients.claim(); // Take control of all clients
        })
    );
});

// Interception des requêtes
self.addEventListener('fetch', function(event) {
    // Ignorer les requêtes qui ne sont pas GET
    if (event.request.method !== 'GET') {
        return;
    }
    
    event.respondWith(
        caches.match(event.request)
            .then(function(cachedResponse) {
                // Retourner la réponse en cache si disponible
                if (cachedResponse) {
                    console.log('Service Worker: Serving from cache:', event.request.url);
                    return cachedResponse;
                }
                
                // Sinon, faire la requête réseau et mettre en cache la réponse
                console.log('Service Worker: Fetching from network:', event.request.url);
                return fetch(event.request)
                    .then(function(response) {
                        // Vérifier si la réponse est valide
                        if (!response || response.status !== 200 || response.type !== 'basic') {
                            return response;
                        }
                        
                        // Cloner la réponse pour la mettre en cache
                        const responseToCache = response.clone();
                        
                        caches.open(CACHE_NAME)
                            .then(function(cache) {
                                cache.put(event.request, responseToCache);
                                console.log('Service Worker: Cached new resource:', event.request.url);
                            });
                        
                        return response;
                    });
            })
            .catch(function(error) {
                console.error('Service Worker: Fetch failed:', error);
                // Retourner une réponse de fallback si disponible
                return caches.match('/offline.html') || 
                       new Response('You are offline and this resource is not cached.', {
                           status: 408,
                           statusText: 'Offline'
                       });
            })
    );
});

// Gestion des messages (pour la communication avec la page)
self.addEventListener('message', function(event) {
    if (event.data && event.data.type === 'SKIP_WAITING') {
        self.skipWaiting();
    }
});

console.log('Service Worker: Loaded and ready');