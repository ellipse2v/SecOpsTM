// Register Service Worker for offline-only mode
if ('serviceWorker' in navigator) {
    window.addEventListener('load', function() {
        navigator.serviceWorker.register('/static/js/sw.js').then(function(registration) {
            console.log('ServiceWorker registration successful - Offline mode activated');
        }, function(err) {
            console.log('ServiceWorker registration failed: ', err);
        });
    });
}