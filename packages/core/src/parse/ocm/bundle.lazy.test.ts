import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
// @ts-expect-error — plain-JS test/fixture helper without type declarations
import { writeTar } from '../../../scripts/tar-writer.mjs';
import { acceptanceReport, digestSummary } from '../../ocm/report';
import { bufferSource } from '../../util/bytesource';
import { readOcmBundle } from './bundle';
import { digestDeliveryBlob } from './extract';

/**
 * Lazy digests: past the eager-hash budget, unmaterialized blobs open with
 * digestCheck 'pending' instead of a load-time full-byte read — and the
 * deferred verdicts are computable on demand with identical semantics.
 */

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

const GOOD = 'A'.repeat(200 * 1024);
const BAD = 'B'.repeat(180 * 1024);
const GOOD_HASH = sha256(GOOD);
const BAD_STORED_HASH = sha256(BAD);
const BAD_DECLARED = 'f'.repeat(64); // deliberately wrong

function lazyCtf(): Uint8Array {
  const cd = `meta:
  schemaVersion: v2
component:
  name: ecme.org/bulk
  version: 1.0.0
  provider: ECME Corp
  sources: []
  resources:
    - name: good-blob
      version: 1.0.0
      type: blob
      relation: local
      access:
        type: localBlob
        localReference: sha256.${GOOD_HASH}
      digest:
        hashAlgorithm: SHA-256
        normalisationAlgorithm: genericBlobDigest/v1
        value: "${GOOD_HASH}"
    - name: bad-blob
      version: 1.0.0
      type: blob
      relation: local
      access:
        type: localBlob
        localReference: sha256.${BAD_STORED_HASH}
      digest:
        hashAlgorithm: SHA-256
        normalisationAlgorithm: genericBlobDigest/v1
        value: "${BAD_DECLARED}"
  componentReferences: []
`;
  const cdDigest = `sha256:${'a'.repeat(64)}`;
  const manifestDigest = `sha256:${'b'.repeat(64)}`;
  const manifest = JSON.stringify({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    layers: [
      { mediaType: 'application/vnd.ocm.software.component-descriptor.v2+yaml', digest: cdDigest, size: cd.length },
      { mediaType: 'application/octet-stream', digest: `sha256:${GOOD_HASH}`, size: GOOD.length },
      { mediaType: 'application/octet-stream', digest: `sha256:${BAD_STORED_HASH}`, size: BAD.length },
    ],
  });
  const index = JSON.stringify({
    schemaVersion: 1,
    artifacts: [{ repository: 'component-descriptors/ecme.org/bulk', tag: '1.0.0', digest: manifestDigest }],
  });
  return new Uint8Array(
    writeTar([
      { name: 'artifact-index.json', bytes: index },
      { name: `blobs/${manifestDigest.replace(':', '.')}`, bytes: manifest },
      { name: `blobs/${cdDigest.replace(':', '.')}`, bytes: cd },
      { name: `blobs/sha256.${GOOD_HASH}`, bytes: GOOD },
      { name: `blobs/sha256.${BAD_STORED_HASH}`, bytes: BAD },
    ]),
  );
}

/** Blobs stay index-only (above 1 KB), descriptors materialize. */
const UNMATERIALIZED = { materializeEntryMax: 1024 };

describe('lazy digest checking', () => {
  it('defers past the eager-hash budget and reports it everywhere', async () => {
    const { bundle } = await readOcmBundle('bulk.ctf.tar', lazyCtf(), {
      ...UNMATERIALIZED,
      eagerHashBudget: 0,
    });
    const cv = bundle!.componentVersions[0]!;
    expect(cv.resources.map((r) => r.blob?.digestCheck)).toEqual(['pending', 'pending']);
    expect(bundle!.digestsDeferred).toEqual({ blobs: 2, bytes: GOOD.length + BAD.length });
    expect(bundle!.issues.some((d) => d.code === 'BUNDLE_DIGESTS_DEFERRED')).toBe(true);

    const digests = digestSummary(bundle!);
    expect(digests.pending).toBe(2);
    expect(digests.mismatch).toHaveLength(0); // deferred ≠ judged

    const { markdown, json } = acceptanceReport({
      bundle: bundle!,
      toolVersion: '2.0.0-test',
      generatedAt: '2026-10-14T12:00:00Z',
    });
    expect(markdown).toContain('2 deferred (not checked in this run)');
    expect(markdown).toContain('were deferred at load and NOT checked in this run');
    expect((json.digests as { pending: number }).pending).toBe(2);
  });

  it('keeps eager verdicts when the budget covers the blobs (default path)', async () => {
    const { bundle } = await readOcmBundle('bulk.ctf.tar', lazyCtf(), UNMATERIALIZED);
    const cv = bundle!.componentVersions[0]!;
    const byName = new Map(cv.resources.map((r) => [r.name, r.blob?.digestCheck]));
    expect(byName.get('good-blob')).toBe('match');
    expect(byName.get('bad-blob')).toBe('mismatch');
    expect(bundle!.digestsDeferred).toBeUndefined();
  });

  it('computes deferred verdicts on demand with identical semantics', async () => {
    const source = bufferSource(lazyCtf());
    const good = await digestDeliveryBlob(source, `sha256.${GOOD_HASH}`, {
      hashAlgorithm: 'SHA-256',
      normalisationAlgorithm: 'genericBlobDigest/v1',
      value: GOOD_HASH,
    });
    const bad = await digestDeliveryBlob(source, `sha256.${BAD_STORED_HASH}`, {
      hashAlgorithm: 'SHA-256',
      normalisationAlgorithm: 'genericBlobDigest/v1',
      value: BAD_DECLARED,
    });
    expect(good).toBe('match');
    expect(bad).toBe('mismatch');
    expect(await digestDeliveryBlob(source, 'sha256.missing', { value: 'x' })).toBe('unchecked');
    expect(await digestDeliveryBlob(source, `sha256.${GOOD_HASH}`, undefined)).toBeUndefined();
  });

  it('spends the budget: small bundles keep full verdicts under the default', async () => {
    // The committed delivery fixture is far below the default budget and
    // must behave exactly as before the lazy mode existed.
    const { readFileSync } = await import('node:fs');
    const bytes = new Uint8Array(
      readFileSync(new URL('../../../fixtures/ocm/delivery.ctf.tar', import.meta.url)),
    );
    const { bundle } = await readOcmBundle('delivery.ctf.tar', bytes);
    expect(bundle!.digestsDeferred).toBeUndefined();
    expect(digestSummary(bundle!).pending).toBe(0);
  });
});
