import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { api } from "./api/backend";
import { AppErrorBoundary } from "./components/AppErrorBoundary";
import { AppProvider } from "./store";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/layout.css";
import "./styles/components.css";

// Disable the browser context menu and zoom gestures that make the app feel like a web page.
window.addEventListener("contextmenu", (e) => {
  const el = e.target as HTMLElement;
  if (!el.closest("input, textarea, .selectable")) e.preventDefault();
});

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <AppErrorBoundary>
      <AppProvider>
        <App />
      </AppProvider>
    </AppErrorBoundary>
  </React.StrictMode>,
);

// Record readiness only after React has committed and WebView2 has had two
// animation frames to paint. Packaged-launch tests use this signal to catch
// the Store-only blank-window regression.
window.requestAnimationFrame(() => {
  window.requestAnimationFrame(() => {
    void api.frontendReady().catch(console.error);
  });
});
