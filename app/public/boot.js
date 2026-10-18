(function () {
  var russian = (navigator.language || "").toLowerCase().indexOf("ru") === 0;
  var dark = !window.matchMedia || window.matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.lang = russian ? "ru" : "en";
  document.documentElement.dataset.theme = dark ? "dark" : "light";

  window.addEventListener("DOMContentLoaded", function () {
    var message = document.getElementById("startup-message");
    if (message) message.textContent = russian ? "Запуск…" : "Starting…";
  });

  window.addEventListener("error", function () {
    var message = document.getElementById("startup-message");
    if (message) {
      message.textContent = russian
        ? "Ошибка запуска. Перезапустите приложение."
        : "Startup error. Restart the application.";
    }
  });
})();
