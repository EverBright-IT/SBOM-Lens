import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bufferSource } from '../../util/bytesource';
import { sniffContainer } from '../../util/binary';
import { asString, isRecord } from '../../util/narrow';
import { readOcmBundle } from './bundle';
import { extractDeliveryBlob } from './extract';

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
