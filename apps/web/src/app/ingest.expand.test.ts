import { readFileSync } from 'node:fs';
import { parseDocument, sha1Hex, sniffContainer } from '@sbomlens/core';
import { readOcmDelivery } from '@sbomlens/core/ocm';
import { beforeEach, describe, expect, it } from 'vitest';
import type { HostAdapter } from '../host/adapter';
import { setHost } from '../host/adapter';
import type { ParseJobRequest, ParseJobResponse } from '../worker/protocol';
import { ingestBuffers } from './ingest';
import { useAppStore } from './store';

/** Fake worker that runs the REAL worker logic: sniff → expand or parse. */
class ExpandingFakeWorker {
  onmessage: ((event: { data: ParseJobResponse }) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  postMessage(request: ParseJobRequest): void {
    void (async () => {
      const bytes = new Uint8Array(request.buffer!);
      const container = sniffContainer(bytes);
      if (container === 'gzip' || container === 'tar') {
        const delivery = await readOcmDelivery(request.fileName, bytes);
        this.onmessage?.({
          data: {
            id: request.id,
            ok: true,
            kind: 'expanded',
            fileName: request.fileName,
            documents: delivery.documents,
            extracted: delivery.extracted.map((e) => ({
              fileName: e.fileName,
              buffer: new Uint8Array(e.bytes).buffer as ArrayBuffer,
            })),
            diagnostics: delivery.diagnostics,
          },
        });
        return;
      }
      const sha1 = await sha1Hex(request.buffer!);
      const text = new TextDecoder().decode(request.buffer!);
      const { document, diagnostics } = parseDocument({
        fileName: request.fileName,
        text,
        sha1,
        byteSize: request.buffer!.byteLength,
      });
      this.onmessage?.({
        data: {
          id: request.id,
          ok: true,
          kind: 'document',
          fileName: request.fileName,
          sha1,
          byteSize: request.buffer!.byteLength,
          text,
          document,
          diagnostics,
        },
      });
    })();
  }
  terminate(): void {}
}

const fakeHost: HostAdapter = {
  kind: 'web',
  caps: { catalog: false },
  fetchDocument: async () => ({ ok: false }),
  readPref: () => null,
  persistPref: () => {},
  secretGet: async () => null,
  secretSet: async () => {},
  exportFile: () => {},
  openExternal: () => {},
  createWorker: () => new ExpandingFakeWorker() as unknown as Worker,
  onIngestMessage: () => {},
};

function ctfBuffer(): ArrayBuffer {
  const bytes = readFileSync(
    new URL('../../../../packages/core/fixtures/ocm/delivery.ctf.tar', import.meta.url),
  );
  return new Uint8Array(bytes).buffer as ArrayBuffer;
}

describe('delivery archives through ingest', () => {
  beforeEach(() => {
    setHost(fakeHost);
    useAppStore.getState().actions.clearAll();
  });

  it('loads a CTF as one linked batch: CDs + extracted SBOM, resolved edges', async () => {
    const added = await ingestBuffers([{ fileName: 'delivery.ctf.tar', buffer: ctfBuffer() }]);
    const state = useAppStore.getState();
    expect(added).toHaveLength(3); // platform CD + webstack CD + extracted SPDX
    expect(state.ws.documents.size).toBe(3);
    expect(state.parsing.active).toBe(0);

    let resolved = 0;
    for (const resolution of state.ws.resolutions.values()) {
      if (resolution.status === 'resolved') resolved++;
    }
    expect(resolved).toBe(2); // componentReference (namespace) + sbom blob (checksum)

    // Blob inspection summaries survive the worker roundtrip structurally —
    // capped previews and the digest verdicts, never the raw bytes.
    const webstack = [...state.ws.documents.values()].find((d) => d.document.name === 'acme.org/webstack')!;
    const blobOf = (name: string) => webstack.document.elements.find((e) => e.name === name)?.ocm?.blob;
    expect(blobOf('webstack-chart')).toMatchObject({ kind: 'helm-chart', digestCheck: 'match' });
    expect(blobOf('runtime-config')).toMatchObject({ kind: 'yaml', digestCheck: 'mismatch' });
    expect(blobOf('dashboards-image')?.oci?.layers).toHaveLength(2);
    expect(blobOf('gateway-image')).toBeUndefined();
  });

  it('re-dropping the same delivery dedupes by content', async () => {
    await ingestBuffers([{ fileName: 'delivery.ctf.tar', buffer: ctfBuffer() }]);
    const again = await ingestBuffers([{ fileName: 'delivery-copy.ctf.tar', buffer: ctfBuffer() }]);
    expect(again).toHaveLength(0);
    expect(useAppStore.getState().ws.documents.size).toBe(3);
  });

  it('reports corrupt archives as failures without documents', async () => {
    const junk = new Uint8Array(1024);
    junk.set([0x1f, 0x8b], 0); // gzip magic, invalid stream
    await ingestBuffers([{ fileName: 'broken.tgz', buffer: junk.buffer as ArrayBuffer }]);
    const state = useAppStore.getState();
    expect(state.ws.documents.size).toBe(0);
    expect(state.failures.length).toBeGreaterThan(0);
    expect(state.parsing.active).toBe(0);
  });
});
