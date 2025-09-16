// Verifica se o navegador suporta Service Worker
if ('serviceWorker' in navigator) {

  // Quando a página termina de carregar...
  window.addEventListener('load', () => {
    // ...registra o arquivo sw.js, que fica em /static/sw.js
    navigator.serviceWorker.register('/static/sw.js');
  });

}
