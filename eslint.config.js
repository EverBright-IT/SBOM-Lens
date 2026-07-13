import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';
import globals from 'globals';

export default tseslint.config(
  {
    ignores: [
      '**/dist',
      '**/dist-vscode',
      '**/dist-ocm',
      '**/dist-vscode-ocm',
      'coverage',
      'node_modules',
      'apps/vscode/media',
      'apps/vscode/out',
      'apps/vscode-ocm/media',
      'apps/vscode-ocm/out',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: { globals: { ...globals.browser } },
  },
  {
    files: ['apps/web/src/**/*.tsx', 'apps/web/src/app/**/*.ts'],
    plugins: { 'react-hooks': reactHooks },
    rules: {
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
    },
  },
  {
    // packages/core is framework-agnostic: no React, no state libs, no app/ui/worker
    // imports, no DOM globals. This fence keeps it extractable as a library.
    files: ['packages/core/src/**/*.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['react', 'react-dom', 'react/*', 'react-dom/*', 'zustand', 'zustand/*', '@tanstack/*', 'clsx'],
              message: '@sbomlens/core must stay framework-free.',
            },
            {
              group: ['**/app/**', '**/ui/**', '**/worker/**'],
              message: '@sbomlens/core must not depend on app, ui, or worker layers.',
            },
          ],
        },
      ],
      'no-restricted-globals': [
        'error',
        'window',
        'document',
        'navigator',
        'localStorage',
        'sessionStorage',
      ],
    },
  },
  {
    // Storage goes through the HostAdapter (src/host/**) so the app works in
    // hosts without web storage (VS Code webview).
    files: ['apps/web/src/**/*.{ts,tsx}'],
    ignores: ['apps/web/src/host/**'],
    rules: {
      'no-restricted-globals': [
        'error',
        { name: 'localStorage', message: 'Use host().readPref/persistPref instead.' },
        { name: 'sessionStorage', message: 'Use host().secretGet/secretSet instead.' },
      ],
    },
  },
  {
    files: [
      'apps/*/scripts/**/*.mjs',
      'packages/*/scripts/**/*.mjs',
      'apps/vscode/esbuild.mjs',
      'apps/vscode-ocm/esbuild.mjs',
    ],
    languageOptions: { globals: { ...globals.node } },
  },
  {
    // Extensions and the shared shell run in the Node extension host, not a browser.
    files: [
      'apps/vscode/src/**/*.ts',
      'apps/vscode-ocm/src/**/*.ts',
      'packages/vscode-shell/src/**/*.ts',
    ],
    languageOptions: { globals: { ...globals.node } },
  },
);
