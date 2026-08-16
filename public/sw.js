// Service worker minimal : sert uniquement a rendre l'application "installable"
// sur l'ecran d'accueil du telephone (Android/Chrome). Il ne fait pas de cache
// hors-ligne pour l'instant, afin de toujours servir les toutes dernieres donnees.
self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', () => {
  // Laisse passer toutes les requetes normalement (pas de cache).
});
