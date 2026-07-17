import { describe, expect, it } from 'vitest';
// @ts-expect-error — plain-JS test/fixture helper without type declarations
import { writeTar } from '../../../scripts/tar-writer.mjs';
import { loadFixture } from '../../test-fixtures';
import { blobSource, bufferSource } from '../../util/bytesource';
import { readTarFrom } from '../../util/tar';
import { readOcmDeliveryFrom } from './archive';

/**
 * Large-delivery behaviour: blobs past the materialization cap are indexed
 * instead of loaded, keep a REAL digest verdict (hashed incrementally off
 * the source), and never cost the walker a descriptor. Tiny caps stand in
 * for multi-GB reality so the tests stay fast; the caps are the only
 * difference to production.
 */

const TINY = { materializeEntryMax: 1024, materializeTotalMax: 64 * 1024 };

const text = (s: string) => new TextEncoder().encode(s);

describe('readTarFrom — selective materialization', () => {
  it('indexes oversized entries without loading them', async () => {
    const big = new Uint8Array(4096).fill(7);
    const tar: Uint8Array = writeTar([
      { name: 'small.txt', bytes: 'hello' },
      { name: 'blobs/sha256.big', bytes: big },
    ]);
    const { entries, diagnostics } = await readTarFrom(bufferSource(tar), TINY);
    const small = entries.find((e) => e.name === 'small.txt')!;
    const indexed = entries.find((e) => e.name === 'blobs/sha256.big')!;
    expect(small.bytes).not.toBeNull();
    expect(indexed.bytes).toBeNull();
    expect(indexed.size).toBe(4096);
    expect(tar.subarray(indexed.offset, indexed.offset + 5)).toEqual(big.subarray(0, 5));
    expect(diagnostics.some((d) => d.code === 'ARCHIVE_BLOBS_INDEXED')).toBe(true);
  });

  it('stops materializing when the total budget is spent, but keeps indexing', async () => {
    const entriesIn = Array.from({ length: 5 }, (_, i) => ({
      name: `blobs/sha256.${'0'.repeat(63)}${i}`,
      bytes: new Uint8Array(512).fill(i + 1),
    }));
    const tar: Uint8Array = writeTar(entriesIn);
    const { entries } = await readTarFrom(bufferSource(tar), { materializeEntryMax: 1024, materializeTotalMax: 1024 });
    expect(entries).toHaveLength(5); // nothing dropped
    expect(entries.filter((e) => e.bytes !== null).length).toBe(2); // 2 x 512 fit the budget
  });
});

describe('readOcmDeliveryFrom — component archive with oversized blobs', () => {
  async function archiveWith(declared: string[], payload: Uint8Array, media = 'application/octet-stream') {
    const cd = [
      'meta:',
      '  schemaVersion: v2',
      'component:',
      '  name: acme.org/large',
      '  version: 1.0.0',
      '  provider: ACME',
      '  componentReferences: []',
      '  sources: []',
      '  resources:',
      '    - name: big-artifact',
      '      version: 1.0.0',
      '      type: blob',
      '      relation: local',
      '      access:',
      '        type: localBlob',
      '        localReference: sha256.cafe',
      `        mediaType: ${media}`,
      ...declared,
    ].join('\n');
    const tar: Uint8Array = writeTar([
      { name: 'component-descriptor.yaml', bytes: cd },
      { name: 'blobs/sha256.cafe', bytes: payload },
    ]);
    return readOcmDeliveryFrom('large.tar', bufferSource(tar), TINY);
  }

  const declaredSha256 = (value: string) => [
    '      digest:',
    '        hashAlgorithm: SHA-256',
    '        normalisationAlgorithm: genericBlobDigest/v1',
    `        value: "${value}"`,
  ];

  it('keeps the descriptor, marks the blob notInspected, and the digest verdict is real (match)', async () => {
    const payload = new Uint8Array(8192).fill(0x42);
    const sha = await sha256HexOf(payload);
    const result = await archiveWith(declaredSha256(sha), payload);
    expect(result.documents).toHaveLength(1);
    const blob = result.documents[0]!.document.elements.find((e) => e.name === 'big-artifact')!.ocm!.blob!;
    expect(blob.notInspected).toBe(true);
    expect(blob.size).toBe(8192);
    expect(blob.previews).toBeUndefined();
    expect(blob.digestCheck).toBe('match');
  });

  it('a tampered oversized blob is a real mismatch', async () => {
    const payload = new Uint8Array(8192).fill(0x42);
    const result = await archiveWith(declaredSha256('9'.repeat(64)), payload);
    const blob = result.documents[0]!.document.elements.find((e) => e.name === 'big-artifact')!.ocm!.blob!;
    expect(blob.digestCheck).toBe('mismatch');
    const mismatch = result.documents[0]!.diagnostics.find((d) => d.code === 'OCM_DIGEST_MISMATCH');
    expect(mismatch).toBeDefined();
  });

  it('a gzip-stored oversized blob that does not match stays unchecked (either-or rule)', async () => {
    // Incompressible payload: constant bytes would gzip BELOW the cap and
    // take the materialized path instead of the indexed one under test.
    const noise = new Uint8Array(8192);
    let state = 7;
    for (let i = 0; i < noise.length; i++) {
      state = (state * 1103515245 + 12345) & 0x7fffffff;
      noise[i] = state & 0xff;
    }
    const payload = await compress(noise);
    expect(payload.byteLength).toBeGreaterThan(TINY.materializeEntryMax); // premise
    const result = await archiveWith(declaredSha256('9'.repeat(64)), payload, 'application/gzip');
    expect(result.documents[0]!.document.elements.find((e) => e.name === 'big-artifact')!.ocm!.blob!.digestCheck).toBe('unchecked');
  });

  it('a sha512-declared oversized blob stays unchecked (incremental hash is sha256-only)', async () => {
    const payload = new Uint8Array(8192).fill(0x42);
    const result = await archiveWith(
      [
        '      digest:',
        '        hashAlgorithm: SHA-512',
        '        normalisationAlgorithm: genericBlobDigest/v1',
        `        value: "${'a'.repeat(128)}"`,
      ],
      payload,
    );
    expect(result.documents[0]!.document.elements.find((e) => e.name === 'big-artifact')!.ocm!.blob!.digestCheck).toBe('unchecked');
  });

  it('an SBOM resource past the cap is still fetched and extracted in full', async () => {
    const spdx = loadFixture('minimal.spdx.json');
    expect(spdx.length).toBeGreaterThan(TINY.materializeEntryMax); // premise of the test
    const cd = [
      'meta:',
      '  schemaVersion: v2',
      'component:',
      '  name: acme.org/withsbom',
      '  version: 1.0.0',
      '  provider: ACME',
      '  componentReferences: []',
      '  sources: []',
      '  resources:',
      '    - name: the-sbom',
      '      version: 1.0.0',
      '      type: sbom',
      '      relation: local',
      '      access:',
      '        type: localBlob',
      '        localReference: sha256.beef',
      '        mediaType: application/spdx+json',
    ].join('\n');
    const tar: Uint8Array = writeTar([
      { name: 'component-descriptor.yaml', bytes: cd },
      { name: 'blobs/sha256.beef', bytes: text(spdx) },
    ]);
    const result = await readOcmDeliveryFrom('sbom.tar', bufferSource(tar), TINY);
    expect(result.extracted).toHaveLength(1);
    expect(new TextDecoder().decode(result.extracted[0]!.bytes)).toBe(spdx);
  });
});

describe('readOcmDeliveryFrom — CTF with an oversized artifact set', () => {
  it('walks the set through a source window: descriptor found, big layer verified unmaterialized', async () => {
    const bigLayer = new Uint8Array(8192).fill(0x0c);
    const bigSha = await sha256HexOf(bigLayer);
    const cd = [
      'meta:',
      '  schemaVersion: v2',
      'component:',
      '  name: acme.org/bundled',
      '  version: 2.0.0',
      '  provider: ACME',
      '  componentReferences: []',
      '  sources: []',
      '  resources:',
      '    - name: huge-image',
      '      version: 2.0.0',
      '      type: ociImage',
      '      relation: local',
      '      access:',
      '        type: localBlob',
      `        localReference: sha256.${bigSha}`,
      '        mediaType: application/octet-stream',
      '      digest:',
      '        hashAlgorithm: SHA-256',
      '        normalisationAlgorithm: genericBlobDigest/v1',
      `        value: "${bigSha}"`,
    ].join('\n');
    const cdSha = await sha256HexOf(text(cd));
    const manifest = JSON.stringify({
      layers: [
        { mediaType: 'application/vnd.ocm.software.component-descriptor.v2+yaml', digest: `sha256:${cdSha}` },
        { mediaType: 'application/octet-stream', digest: `sha256:${bigSha}`, size: bigLayer.byteLength },
      ],
    });
    const setTar: Uint8Array = writeTar([
      { name: 'artifact-set-descriptor.json', bytes: manifest },
      { name: `blobs/sha256.${cdSha}`, bytes: cd },
      { name: `blobs/sha256.${bigSha}`, bytes: bigLayer },
    ]);
    const setSha = await sha256HexOf(setTar);
    const ctf: Uint8Array = writeTar([
      { name: 'artifact-index.json', bytes: JSON.stringify({ artifacts: [{ repository: 'acme.org/bundled', tag: '2.0.0', digest: `sha256:${setSha}` }] }) },
      { name: `blobs/sha256.${setSha}`, bytes: setTar },
    ]);

    // The set itself exceeds the cap, so the nested tar is walked through a
    // window; inside it the big layer exceeds the cap again.
    const result = await readOcmDeliveryFrom('bundle.ctf', bufferSource(ctf), TINY);
    expect(result.documents).toHaveLength(1);
    expect(result.documents[0]!.document.name).toBe('acme.org/bundled');
    const blob = result.documents[0]!.document.elements.find((e) => e.name === 'huge-image')!.ocm!.blob!;
    expect(blob.notInspected).toBe(true);
    expect(blob.digestCheck).toBe('match');
  });

  it('reads identically through a Blob handle (the browser path)', async () => {
    const payload = new Uint8Array(8192).fill(0x42);
    const sha = await sha256HexOf(payload);
    const cd = [
      'meta:',
      '  schemaVersion: v2',
      'component:',
      '  name: acme.org/viablob',
      '  version: 1.0.0',
      '  provider: ACME',
      '  componentReferences: []',
      '  sources: []',
      '  resources:',
      '    - name: big-artifact',
      '      version: 1.0.0',
      '      type: blob',
      '      relation: local',
      '      access:',
      '        type: localBlob',
      `        localReference: sha256.${sha}`,
      '        mediaType: application/octet-stream',
      '      digest:',
      '        hashAlgorithm: SHA-256',
      '        normalisationAlgorithm: genericBlobDigest/v1',
      `        value: "${sha}"`,
    ].join('\n');
    const tar: Uint8Array = writeTar([
      { name: 'component-descriptor.yaml', bytes: cd },
      { name: `blobs/sha256.${sha}`, bytes: payload },
    ]);
    const result = await readOcmDeliveryFrom('blob.tar', blobSource(new Blob([new Uint8Array(tar)])), TINY);
    expect(result.documents).toHaveLength(1);
    const blob = result.documents[0]!.document.elements.find((e) => e.name === 'big-artifact')!.ocm!.blob!;
    expect(blob.notInspected).toBe(true);
    expect(blob.digestCheck).toBe('match');
  });
});

async function sha256HexOf(input: Uint8Array | string): Promise<string> {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : new Uint8Array(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes.buffer as ArrayBuffer);
  let hex = '';
  for (const byte of new Uint8Array(digest)) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

async function compress(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([new Uint8Array(bytes)]).stream().pipeThrough(new CompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
