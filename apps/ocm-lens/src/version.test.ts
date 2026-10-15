import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { APP_VERSION } from './version';

/**
 * OCM Lens versions independently (2.x) of the monorepo's 0.x lockstep.
 * The lockstep release command (`npm version <v> --workspaces`) bumps EVERY
 * workspace, this one included; this test is what stops that from shipping.
 *
 * Fix after a lockstep bump: `git checkout -- apps/ocm-lens/package.json
 * apps/vscode-ocm/package.json`, then `npm install --package-lock-only`. Bump
 * OCM Lens explicitly when it releases itself: both package.json files and
 * its CHANGELOG (the UI reads the version from package.json).
 */
describe('OCM Lens version line', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
    version: string;
  };

  it('stays on the independent 2.x line', () => {
    expect(
      pkg.version,
      'apps/ocm-lens was bumped by the 0.x lockstep release - see the header of src/version.test.ts for the fix',
    ).toMatch(/^2\./);
  });

  it('matches the version the UI displays', () => {
    expect(APP_VERSION).toBe(pkg.version);
  });

  it('is the version the VS Code extension ships (one product, one number)', () => {
    const extension = JSON.parse(
      readFileSync(new URL('../../vscode-ocm/package.json', import.meta.url), 'utf8'),
    ) as { version: string };
    expect(
      extension.version,
      'apps/vscode-ocm bundles OCM Lens 2.x - keep its version equal to apps/ocm-lens',
    ).toBe(pkg.version);
  });
});
