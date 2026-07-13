import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { registerSW } from 'virtual:pwa-register';
import { IS_VSCODE } from './app/brand';
import { ingestBuffers } from './app/ingest';
import { host, setHost } from './host/adapter';
import { createVscodeHost } from './host/vscodeHost';
import { webHost } from './host/webHost';
import { App } from './ui/App';
import { initTheme } from './ui/theme';
import './index.css';

// The host seam must exist before anything renders or fetches. IS_VSCODE is
// a build-time constant, so the unused host implementation tree-shakes away.
setHost(IS_VSCODE ? createVscodeHost() : webHost);
host().onIngestMessage((files) => void ingestBuffers(files));
initTheme();

// Offline support; updates activate silently on the next visit. A webview
// has no service-worker lifecycle (the PWA plugin is disabled there).
if (!IS_VSCODE) registerSW({ immediate: true });

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
