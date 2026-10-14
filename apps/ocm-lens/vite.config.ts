import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { VitePWA } from 'vite-plugin-pwa';

// Two builds from one app: the web build (mode production) and the VS Code
// webview build (mode vscode -> dist-vscode). base './' keeps both
// relocatable (subpath hosts; the webview injects a <base href>).
export default defineConfig(({ mode }) => {
  const vscode = mode === 'vscode';
  return {
    base: './',
    plugins: [
      react(),
      tailwindcss(),
      // Offline support: once visited, a deployment keeps working without
      // network - analyzing a delivery never needed a server anyway. The demo
      // delivery (.tar) is precached with the app shell. A webview has no
      // service-worker lifecycle, so the PWA is disabled there.
      VitePWA({
        disable: vscode,
        registerType: 'autoUpdate',
        manifest: {
          name: 'OCM Lens',
          short_name: 'OCM Lens',
          description:
            'Understand an OCM delivery: component versions, artifacts, completeness, signatures.',
          start_url: '.',
          display: 'standalone',
          // indigo-600 - the OCM Lens accent (see src/index.css).
          theme_color: '#4f46e5',
          background_color: '#ffffff',
          icons: [{ src: 'favicon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' }],
        },
        workbox: { globPatterns: ['**/*.{js,css,html,svg,png,json,tar}'] },
      }),
    ],
    build: {
      target: 'es2022',
      outDir: vscode ? 'dist-vscode' : 'dist',
    },
    worker: {
      format: 'es' as const,
      // The webview instantiates the worker from a Blob (webview resource
      // URLs are cross-origin for workers), so the worker must be one file.
      rollupOptions: { output: { inlineDynamicImports: true } },
    },
    optimizeDeps: {
      // Source-linked workspace package - let Vite transform its TS directly.
      exclude: ['@sbomlens/core'],
    },
  };
});
