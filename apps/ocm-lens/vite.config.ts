import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { VitePWA } from 'vite-plugin-pwa';

// OCM Lens 2.0 is a plain standalone app: no flavor modes, no build-time
// branching. base './' keeps the build relocatable (subpath hosts, and later
// the VS Code webview, where a <base href> is injected).
export default defineConfig({
  base: './',
  plugins: [
    react(),
    tailwindcss(),
    // Offline support: once visited, a deployment keeps working without
    // network — analyzing a delivery never needed a server anyway. The demo
    // delivery (.tar) is precached with the app shell.
    VitePWA({
      registerType: 'autoUpdate',
      manifest: {
        name: 'OCM Lens',
        short_name: 'OCM Lens',
        description:
          'Understand an OCM delivery: component versions, artifacts, completeness, signatures.',
        start_url: '.',
        display: 'standalone',
        // indigo-600 — the OCM Lens accent (see src/index.css).
        theme_color: '#4f46e5',
        background_color: '#ffffff',
        icons: [{ src: 'favicon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' }],
      },
      workbox: { globPatterns: ['**/*.{js,css,html,svg,png,json,tar}'] },
    }),
  ],
});
