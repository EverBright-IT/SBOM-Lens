import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { registerSW } from 'virtual:pwa-register';
import { openHostPush } from './app/ingest';
import { host, IS_VSCODE } from './host';
import { App } from './ui/App';
import './index.css';

// Offline support on the web; updates activate silently on the next visit.
// A webview has no service-worker lifecycle (the PWA is disabled there).
if (!IS_VSCODE) registerSW({ immediate: true });

// Files the host pushes in (VS Code). Registering also signals readiness.
host.onPush((files) => void openHostPush(files));

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
