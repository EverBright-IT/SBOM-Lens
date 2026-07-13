import { build } from 'esbuild';

// One self-contained CommonJS file; the vsix ships zero runtime dependencies.
await build({
  entryPoints: ['src/extension.ts'],
  bundle: true,
  platform: 'node',
  format: 'cjs',
  target: 'node18',
  external: ['vscode'],
  outfile: 'out/extension.js',
  sourcemap: true,
});
console.log('out/extension.js written');
