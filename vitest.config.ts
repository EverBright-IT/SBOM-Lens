import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'core',
          root: 'packages/core',
          environment: 'node',
          include: ['src/**/*.test.ts'],
          setupFiles: ['./src/test-setup.ts'],
        },
      },
      {
        test: {
          name: 'web',
          root: 'apps/web',
          environment: 'node',
          include: ['src/**/*.test.ts'],
          setupFiles: ['../../packages/core/src/test-setup.ts'],
        },
      },
      {
        test: {
          name: 'vscode-shell',
          root: 'packages/vscode-shell',
          environment: 'node',
          include: ['src/**/*.test.ts'],
          // The registry tests run packed CTFs through the real delivery
          // walker, which needs the YAML parser registered.
          setupFiles: ['../../packages/core/src/test-setup.ts'],
        },
      },
    ],
  },
});
