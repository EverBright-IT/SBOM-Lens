import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
// @ts-expect-error — plain-JS fixture builder without type declarations
import { buildDemoDeliveryCtf } from '../../../scripts/generate-ocm-fixtures.mjs';
import { digestSummary } from '../../ocm/report';
import { verifyRawSignatures } from '../../ocm/verify';
import { readOcmBundle } from './bundle';

/**
 * The OCM Lens 2.0 demo delivery is a showcase AND a regression net: one
 * bundle exhibiting every verdict the product gives. These tests pin its
 * facts — if the demo stops telling its story, CI says so.
 */

function fixtureBytes(name: string): Uint8Array {
  return new Uint8Array(readFileSync(new URL(`../../../fixtures/${name}`, import.meta.url)));
}

describe('ecme demo delivery', () => {
  it('matches a fresh generator run byte-for-byte', () => {
    expect(fixtureBytes('ocm/ecme-delivery.ctf.tar')).toEqual(new Uint8Array(buildDemoDeliveryCtf()));
  });

  it('exhibits the full showcase: 3 levels, diamond, signed CV, mismatch, external, SBOMs', async () => {
    const result = await readOcmBundle('ecme-delivery.ctf.tar', fixtureBytes('ocm/ecme-delivery.ctf.tar'));
    const bundle = result.bundle!;

    expect(bundle.componentVersions.map((cv) => cv.id).sort()).toEqual([
      'ecme.org/base@0.9.0',
      'ecme.org/observability@1.4.0',
      'ecme.org/platform@2.0.0',
      'ecme.org/webstack@2.1.0',
    ]);
    expect(bundle.roots).toEqual(['ecme.org/platform@2.0.0']);
    // The diamond: base is referenced by platform AND observability.
    expect(bundle.shared).toEqual(['ecme.org/base@0.9.0']);

    // Three levels: platform -> observability -> base.
    const platform = bundle.componentVersions.find((cv) => cv.name === 'ecme.org/platform')!;
    const obs = bundle.componentVersions.find((cv) => cv.name === 'ecme.org/observability')!;
    expect(platform.references.find((r) => r.name === 'observability')?.target).toBe(
      'ecme.org/observability@1.4.0',
    );
    expect(obs.references[0]!.target).toBe('ecme.org/base@0.9.0');

    // Completeness: everything transported except the external gateway image.
    expect(bundle.completeness).toMatchObject({
      transported: 6,
      external: 1,
      broken: 0,
      unknown: 0,
      unresolvedRefs: 0,
      airGapReady: false,
    });

    // Integrity: one deliberate mismatch (obs-config). obs-sbom declares no
    // digest at all, which yields NO verdict (not 'unchecked' — that means
    // declared but not checkable).
    const digests = digestSummary(bundle);
    expect(digests.match).toBe(4);
    expect(digests.mismatch).toEqual([{ cvId: 'ecme.org/observability@1.4.0', artifact: 'obs-config' }]);
    expect(digests.unchecked).toBe(0);

    // Two embedded SBOMs, both extracted and linked.
    const sboms = bundle.componentVersions.flatMap((cv) => cv.resources).filter((r) => r.sbom);
    expect(sboms.map((r) => r.name).sort()).toEqual(['obs-sbom', 'webstack-sbom']);
    expect(result.extracted).toHaveLength(2);

    // The signed CV came from the real ocm CLI v0.13.0 (LocalBlob/v1 access
    // spelling included) and verifies against the committed test public key.
    const webstack = bundle.componentVersions.find((cv) => cv.name === 'ecme.org/webstack')!;
    expect(webstack.signatures?.map((s) => s.name)).toEqual(['ecme-release']);
    expect(webstack.resources.every((r) => r.transport === 'transported')).toBe(true);
    const pem = new TextDecoder().decode(fixtureBytes('ocm/keys/test-rsa.pub.pem'));
    const verdicts = await verifyRawSignatures(webstack.raw, pem);
    expect(verdicts).toEqual([{ name: 'ecme-release', verdict: 'valid', digestMatch: true }]);
  });
});
