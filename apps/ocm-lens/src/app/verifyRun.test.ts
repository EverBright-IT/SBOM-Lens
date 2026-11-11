import { readFileSync } from 'node:fs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { bundleFromDescriptors } from '@sbomlens/core/ocm';
import { useAppStore } from './store';
import { runVerification } from './verifyRun';

/**
 * A signed root vouches for the component versions it references only
 * through the reference digests in its descriptor. The descriptors here are
 * what the real `ocm` CLI (v0.54.0) wrote: a root signed with the committed
 * test key, the child it references, and a child of the same name and
 * version with other content that `ocm transfer --overwrite` put in its
 * place afterwards, no key involved. `ocm verify` rejects the root over the
 * swapped delivery ("calculated reference digest ... mismatches existing
 * digest"); the Verify view must not call it valid either.
 */

const prefs = vi.hoisted(() => new Map<string, string>());

vi.mock('../host', () => ({
  host: {
    readPref: (key: string) => prefs.get(key) ?? null,
    persistPref: (key: string, value: string) => void prefs.set(key, value),
  },
}));

function fixture(name: string): string {
  return readFileSync(
    new URL(`../../../../packages/core/fixtures/ocm/${name}`, import.meta.url),
    'utf8',
  );
}

const publicKey = fixture('keys/test-rsa.pub.pem');

/** Open the descriptors as one delivery and run the Verify view's check. */
async function verify(descriptors: string[], pastedKey?: string) {
  const { bundle } = await bundleFromDescriptors(
    'delivery',
    descriptors.map((name) => ({ fileName: name, text: fixture(`reference-digest/${name}`) })),
  );
  useAppStore.setState({
    delivery: {
      bundle: bundle!,
      extracted: [],
      sbomAnalyses: {},
      sbomPackages: {},
      vexSources: [],
      diagnostics: [],
    },
    verification: null,
  });
  await runVerification(pastedKey);
  return useAppStore.getState().verification!.entries;
}

beforeEach(() => {
  prefs.clear();
});

describe('runVerification over a signed root and what it references', () => {
  it('calls the signature valid while the referenced component version is the signed one', async () => {
    expect(await verify(['root.yaml', 'child.yaml'], publicKey)).toEqual([
      { cvId: 'example.org/root@1.0.0', name: 'reference-test', verdict: 'valid', keyLabel: 'pasted key' },
    ]);
  });

  it('calls it invalid once the referenced component version was swapped', async () => {
    const entries = await verify(['root.yaml', 'child-swapped.yaml'], publicKey);
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      cvId: 'example.org/root@1.0.0',
      verdict: 'invalid',
      keyLabel: 'pasted key',
    });
    expect(entries[0]!.reason).toContain('example.org/child@1.0.0');
  });

  it('judges a pinned key the same way and names it', async () => {
    prefs.set('ocmlens.trustedKeys', JSON.stringify([{ label: 'release', pem: publicKey }]));
    expect(await verify(['root.yaml', 'child.yaml'])).toMatchObject([
      { verdict: 'valid', keyLabel: 'release' },
    ]);
    expect(await verify(['root.yaml', 'child-swapped.yaml'])).toMatchObject([
      { verdict: 'invalid', keyLabel: 'release' },
    ]);
  });

  it('does not call it valid when the swapped one is delivered next to the signed one', async () => {
    for (const order of [
      ['root.yaml', 'child.yaml', 'child-swapped.yaml'],
      ['root.yaml', 'child-swapped.yaml', 'child.yaml'],
    ]) {
      expect(await verify(order, publicKey)).toMatchObject([{ verdict: 'invalid' }]);
    }
  });

  it('is unverifiable, not valid, when the referenced component version is not delivered', async () => {
    const entries = await verify(['root.yaml'], publicKey);
    expect(entries).toMatchObject([{ verdict: 'unverifiable', keyLabel: 'pasted key' }]);
    expect(entries[0]!.reason).toContain('not in this delivery');
  });
});
