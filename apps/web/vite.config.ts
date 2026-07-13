import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { VitePWA } from 'vite-plugin-pwa';

// base './' keeps the build relocatable: GitLab/GitHub Pages subpaths,
// Docker at root, any static file server — and a VS Code webview, where the
// extension injects a <base href> pointing at the bundled assets.
export default defineConfig(({ mode }) => {
  const vscode = mode === 'vscode' || mode === 'vscode-ocm';
  const ocm = mode === 'ocm' || mode === 'vscode-ocm';
  return {
    base: './',
    plugins: [
      react(),
      tailwindcss(),
      // Offline support: everything is precached (app, examples, catalog), so a
      // once-visited deployment keeps working without network — SBOM analysis
      // never needs to talk to a server anyway. Inside a webview there is no
      // service-worker lifecycle, so the PWA is disabled there.
      VitePWA({
        disable: vscode,
        registerType: 'autoUpdate',
        manifest: ocm
          ? {
              name: 'OCM Lens',
              short_name: 'OCM Lens',
              description:
                'A fast, minimal viewer for Open Component Model component versions and deliveries.',
              start_url: '.',
              display: 'standalone',
              theme_color: '#0284c7',
              background_color: '#ffffff',
              icons: [
                { src: 'favicon-ocm.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' },
              ],
            }
          : {
              name: 'SBOM Lens',
              short_name: 'SBOM Lens',
              description:
                'A fast, minimal viewer for SPDX SBOMs — including cascading document hierarchies.',
              start_url: '.',
              display: 'standalone',
              theme_color: '#0284c7',
              background_color: '#ffffff',
              icons: [{ src: 'favicon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' }],
            },
        workbox: {
          globPatterns: ['**/*.{js,css,html,svg,json,spdx,yaml,tar}'],
          maximumFileSizeToCacheInBytes: 5 * 1024 * 1024,
        },
      }),
    ],
    build: {
      target: 'es2022',
      outDir: vscode ? (ocm ? 'dist-vscode-ocm' : 'dist-vscode') : ocm ? 'dist-ocm' : 'dist',
    },
    worker: {
      format: 'es' as const,
      // The webview instantiates the worker from a Blob (vscode-resource URLs
      // are cross-origin for workers), so the worker must be a single file.
      rollupOptions: { output: { inlineDynamicImports: true } },
    },
    optimizeDeps: {
      // Source-linked workspace package — let Vite transform its TS directly.
      exclude: ['@sbomlens/core'],
    },
  };
});
