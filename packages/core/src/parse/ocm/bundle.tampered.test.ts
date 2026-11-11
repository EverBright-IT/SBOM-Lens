import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
// @ts-expect-error — plain-JS test/fixture helper without type declarations
import { writeTar } from '../../../scripts/tar-writer.mjs';
import type { OcmBundle } from '../../model/ocm-bundle';
import type { DigestSummary } from '../../ocm/report';
import { acceptanceReport, digestSummary, digestVerdict } from '../../ocm/report';
import { bufferSource } from '../../util/bytesource';
import { readOcmBundle } from './bundle';
import { digestDeliveryBlob } from './extract';

/**
 * A blob swapped after signing never reads as intact. Regression for the
 * digest check that failed open: an unmaterialized blob whose stored bytes
 * begin with the gzip magic and do not hash to the declared value came back
 * 'unchecked', and "no mismatch counted" was reported as "all match" — also
 * while digests were deferred or not computable. The ocm CLI rejects the
 * same delivery.
 */

const hash = (algorithm: string, bytes: Uint8Array | string) =>
  createHash(algorithm).update(bytes).digest('hex');

const INTACT = 'intact';
const INTACT_HASH = hash('sha256', INTACT);

/** The blob as signed: gzip magic, then filler. Past the cap below. */
const SIGNED = new Uint8Array(16 * 1024).fill(0x41);
SIGNED.set([0x1f, 0x8b]);
const SIGNED_HASH = hash('sha256', SIGNED);
/** As delivered: one byte flipped in place; name, size and descriptor unchanged. */
const TAMPERED = new Uint8Array(SIGNED);
TAMPERED[TAMPERED.length / 2] = 0x42;

const SHA256 = { hashAlgorithm: 'SHA-256', value: SIGNED_HASH };
const SHA512 = { hashAlgorithm: 'SHA-512', value: hash('sha512', SIGNED) };

function tamperedCtf(declared: { hashAlgorithm: string; value: string }): Uint8Array {
  const cd = `meta:
  schemaVersion: v2
component:
  name: ecme.org/swapped
  version: 1.0.0
  provider: ECME Corp
  sources: []
  resources:
    - name: intact
      version: 1.0.0
      type: blob
      relation: local
      access:
        type: localBlob
        localReference: sha256.${INTACT_HASH}
      digest:
        hashAlgorithm: SHA-256
        normalisationAlgorithm: genericBlobDigest/v1
        value: "${INTACT_HASH}"
    - name: payload
      version: 1.0.0
      type: blob
      relation: local
      access:
        type: localBlob
        localReference: sha256.${SIGNED_HASH}
      digest:
        hashAlgorithm: ${declared.hashAlgorithm}
        normalisationAlgorithm: genericBlobDigest/v1
        value: "${declared.value}"
  componentReferences: []
`;
  const cdDigest = `sha256:${'a'.repeat(64)}`;
  const manifestDigest = `sha256:${'b'.repeat(64)}`;
  const manifest = JSON.stringify({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    layers: [
      { mediaType: 'application/vnd.ocm.software.component-descriptor.v2+yaml', digest: cdDigest, size: cd.length },
      { mediaType: 'application/octet-stream', digest: `sha256:${INTACT_HASH}`, size: INTACT.length },
      { mediaType: 'application/octet-stream', digest: `sha256:${SIGNED_HASH}`, size: TAMPERED.length },
    ],
  });
  const index = JSON.stringify({
    schemaVersion: 1,
    artifacts: [{ repository: 'component-descriptors/ecme.org/swapped', tag: '1.0.0', digest: manifestDigest }],
  });
  return new Uint8Array(
    writeTar([
      { name: 'artifact-index.json', bytes: index },
      { name: `blobs/${manifestDigest.replace(':', '.')}`, bytes: manifest },
      { name: `blobs/${cdDigest.replace(':', '.')}`, bytes: cd },
      { name: `blobs/sha256.${INTACT_HASH}`, bytes: INTACT },
      { name: `blobs/sha256.${SIGNED_HASH}`, bytes: TAMPERED },
    ]),
  );
}

/** The payload stays index-only (past 4 KB); descriptors and the small blob materialize. */
const UNMATERIALIZED = { materializeEntryMax: 4096 };

const report = (bundle: OcmBundle) =>
  acceptanceReport({ bundle, toolVersion: '2.3.0-test', generatedAt: '2026-11-11T12:00:00Z' }).markdown;

describe('a blob swapped after signing', () => {
  it('is a mismatch when it was never materialized, gzip magic or not', async () => {
    const { bundle } = await readOcmBundle('swapped.ctf.tar', tamperedCtf(SHA256), UNMATERIALIZED);
    const blobs = new Map(bundle!.componentVersions[0]!.resources.map((r) => [r.name, r.blob]));
    expect(blobs.get('payload')!.notInspected).toBe(true); // premise: the indexed path
    expect(blobs.get('intact')!.digestCheck).toBe('match');
    expect(blobs.get('payload')!.digestCheck).toBe('mismatch');

    const digests = digestSummary(bundle!);
    expect(digests.mismatch.map((m) => m.artifact)).toEqual(['payload']);
    expect(digestVerdict(digests)).toBe('mismatch');
    expect(report(bundle!)).toContain('**1 MISMATCH(ES)**');
  });

  it('is a mismatch when its digest is checked on demand', async () => {
    const verdict = await digestDeliveryBlob(bufferSource(tamperedCtf(SHA256)), `sha256.${SIGNED_HASH}`, {
      ...SHA256,
      normalisationAlgorithm: 'genericBlobDigest/v1',
    });
    expect(verdict).toBe('mismatch');
  });

  it('never reads as "all match" while its check is deferred', async () => {
    const { bundle } = await readOcmBundle('swapped.ctf.tar', tamperedCtf(SHA256), {
      ...UNMATERIALIZED,
      eagerHashBudget: 0,
    });
    const digests = digestSummary(bundle!);
    expect(digests).toMatchObject({ match: 1, mismatch: [], pending: 1 });
    expect(digestVerdict(digests)).toBe('incomplete');
    expect(report(bundle!)).toContain('**NOT ALL CHECKED** — 1 of 2 declared digest(s) match');
    expect(report(bundle!)).not.toContain('All 1 declared digest(s) match');
  });

  it('never reads as "all match" when its digest is not computable', async () => {
    const { bundle } = await readOcmBundle('swapped.ctf.tar', tamperedCtf(SHA512), UNMATERIALIZED);
    const digests = digestSummary(bundle!);
    expect(digests).toMatchObject({ match: 1, mismatch: [], unchecked: 1 });
    expect(digestVerdict(digests)).toBe('incomplete');
    expect(report(bundle!)).toContain('**NOT ALL CHECKED** — 1 of 2 declared digest(s) match');
    expect(report(bundle!)).not.toContain('All 1 declared digest(s) match');
  });
});

describe('digestVerdict', () => {
  const summary = (over: Partial<DigestSummary>): DigestSummary => ({
    checked: 0,
    match: 0,
    mismatch: [],
    unchecked: 0,
    pending: 0,
    pendingBytes: 0,
    ...over,
  });

  it('is "match" only when every declared digest was checked and matched', () => {
    expect(digestVerdict(summary({}))).toBe('none');
    expect(digestVerdict(summary({ checked: 2, match: 2 }))).toBe('match');
    expect(digestVerdict(summary({ checked: 2, match: 2, unchecked: 1 }))).toBe('incomplete');
    expect(digestVerdict(summary({ checked: 2, match: 2, pending: 1 }))).toBe('incomplete');
    expect(digestVerdict(summary({ unchecked: 1 }))).toBe('incomplete');
    expect(digestVerdict(summary({ pending: 1 }))).toBe('incomplete');
    expect(
      digestVerdict(summary({ checked: 2, match: 1, mismatch: [{ cvId: 'a@1', artifact: 'x' }], pending: 1 })),
    ).toBe('mismatch');
  });
});
