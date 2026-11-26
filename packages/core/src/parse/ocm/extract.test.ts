import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bufferSource } from '../../util/bytesource';
import { sniffContainer } from '../../util/binary';
import { asString, isRecord } from '../../util/narrow';
import { readOcmBundle } from './bundle';
// @ts-expect-error - plain-JS test/fixture helper without type declarations
import { writeTar } from '../../../scripts/tar-writer.mjs';
import { digestDeliveryBlob, extractDeliveryBlob } from './extract';

function fixtureBytes(name: string): Uint8Array {
  return new Uint8Array(readFileSync(new URL(`../../../fixtures/${name}`, import.meta.url)));
}

describe('extractDeliveryBlob', () => {
  it('pulls a blob back out of a nested artifact set, byte-sized as indexed', async () => {
    const bytes = fixtureBytes('ocm/delivery.ctf.tar');
    const { bundle } = await readOcmBundle('delivery.ctf.tar', bytes);
    const webstack = bundle!.componentVersions.find((cv) => cv.name === 'acme.org/webstack')!;
    const chart = webstack.resources.find((r) => r.name === 'webstack-chart')!;
    const ref = asString(isRecord(chart.access?.raw) ? chart.access.raw.localReference : undefined)!;

    const result = await extractDeliveryBlob(bufferSource(bytes), ref);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.bytes.byteLength).toBe(chart.blob!.size);
      // The chart blob is itself a tar (helm chart content).
      expect(sniffContainer(result.bytes)).toBe('tar');
    }
  });

  it('finds top-level component-archive blobs too', async () => {
    const bytes = fixtureBytes('ocm/component-archive.tar');
    const { bundle } = await readOcmBundle('component-archive.tar', bytes);
    const cv = bundle!.componentVersions[0]!;
    const withBlob = cv.resources.find((r) => r.transport === 'transported')!;
    const ref = asString(isRecord(withBlob.access?.raw) ? withBlob.access.raw.localReference : undefined)!;
    const result = await extractDeliveryBlob(bufferSource(bytes), ref);
    expect(result.ok).toBe(true);
  });

  it('answers not-found honestly', async () => {
    const bytes = fixtureBytes('ocm/delivery.ctf.tar');
    const result = await extractDeliveryBlob(bufferSource(bytes), `sha256.${'0'.repeat(64)}`);
    expect(result).toEqual({ ok: false, reason: 'not-found' });
  });
});

describe('extractDeliveryBlob returns only bytes the declared digest vouches for', () => {
  const sha256 = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
  const encoder = new TextEncoder();

  /** One tar, entries in exactly the given order (writeTar sorts, and duplicates must stay ordered). */
  function orderedTar(entries: { name: string; bytes: Uint8Array | string }[]): Uint8Array {
    const parts = entries.map((entry) => {
      const single: Uint8Array = writeTar([entry]);
      return single.subarray(0, single.length - 1024); // drop the end-of-archive blocks
    });
    const total = parts.reduce((n, p) => n + p.length, 0) + 1024;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return out;
  }

  const GENUINE = encoder.encode('the artifact as signed and shipped');
  const TAMPERED = encoder.encode('the artifact swapped by somebody else');
  const DIGEST = sha256(GENUINE);
  const DECLARED = { hashAlgorithm: 'SHA-256', normalisationAlgorithm: 'genericBlobDigest/v1', value: DIGEST };
  const REF = `sha256:${DIGEST}`;
  const cdText = `meta:
  schemaVersion: v2
component:
  name: acme.org/dup
  version: 1.0.0
  provider: ACME Corp
  sources: []
  componentReferences: []
  resources:
    - name: payload
      version: 1.0.0
      type: blob
      relation: local
      access:
        type: localBlob
        localReference: ${REF}
        mediaType: application/octet-stream
      digest:
        hashAlgorithm: SHA-256
        normalisationAlgorithm: genericBlobDigest/v1
        value: ${DIGEST}
`;
  const archiveWith = (first: Uint8Array, last: Uint8Array) =>
    orderedTar([
      { name: 'component-descriptor.yaml', bytes: cdText },
      { name: `blobs/sha256.${DIGEST}`, bytes: first },
      { name: `blobs/sha256.${DIGEST}`, bytes: last },
    ]);

  it('hands out the genuine bytes when a tampered copy of the same name comes first', async () => {
    const bytes = archiveWith(TAMPERED, GENUINE);
    const { bundle, diagnostics } = await readOcmBundle('dup.tar', bytes);
    // The walk uses the last entry of a name and calls it intact, and says the name is doubled.
    expect(bundle!.componentVersions[0]!.resources[0]!.blob?.digestCheck).toBe('match');
    expect(diagnostics.map((d) => d.code)).toContain('ARCHIVE_DUPLICATE_ENTRY');
    const result = await extractDeliveryBlob(bufferSource(bytes), REF, DECLARED);
    expect(result).toEqual({ ok: true, bytes: GENUINE });
  });

  it('refuses, rather than guessing, when nothing says which copy is meant', async () => {
    const result = await extractDeliveryBlob(bufferSource(archiveWith(TAMPERED, GENUINE)), REF);
    expect(result).toEqual({ ok: false, reason: 'ambiguous' });
  });

  it('refuses bytes that do not match the declared digest', async () => {
    const bytes = orderedTar([
      { name: 'component-descriptor.yaml', bytes: cdText },
      { name: `blobs/sha256.${DIGEST}`, bytes: TAMPERED },
    ]);
    expect(await extractDeliveryBlob(bufferSource(bytes), REF, DECLARED)).toEqual({ ok: false, reason: 'mismatch' });
  });

  it('judges every copy on demand: one copy that does not match is a mismatch', async () => {
    const bytes = archiveWith(GENUINE, TAMPERED);
    expect(await digestDeliveryBlob(bufferSource(bytes), REF, DECLARED)).toBe('mismatch');
  });

  it('keeps a top-level entry from standing in for the verified blob of a nested artifact set', async () => {
    const fixture = fixtureBytes('ocm/delivery.ctf.tar');
    const { bundle } = await readOcmBundle('delivery.ctf.tar', fixture);
    const webstack = bundle!.componentVersions.find((cv) => cv.name === 'acme.org/webstack')!;
    const chart = webstack.resources.find((r) => r.name === 'webstack-chart')!;
    expect(chart.blob?.digestCheck).toBe('match');
    const ref = asString(isRecord(chart.access?.raw) ? chart.access.raw.localReference : undefined)!;
    const declared = chart.raw.digest as Record<string, unknown>;
    const genuine = await extractDeliveryBlob(bufferSource(fixture), ref, declared);
    expect(genuine.ok).toBe(true);

    // The same CTF with one more top-level entry under the chart's name, other bytes.
    const end = fixture.length - 1024;
    expect(fixture.subarray(end).every((b) => b === 0)).toBe(true);
    const extra = orderedTar([{ name: `blobs/${ref.replace(':', '.')}`, bytes: TAMPERED }]);
    const forged = new Uint8Array(end + extra.length);
    forged.set(fixture.subarray(0, end), 0);
    forged.set(extra, end);

    const result = await extractDeliveryBlob(bufferSource(forged), ref, declared);
    expect(result.ok).toBe(true);
    if (result.ok && genuine.ok) expect(sha256(result.bytes)).toBe(sha256(genuine.bytes));
  });
});
