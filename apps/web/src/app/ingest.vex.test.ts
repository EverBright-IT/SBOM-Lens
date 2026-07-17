import { parseDocument, sha1Hex } from '@sbomlens/core';
import { beforeEach, describe, expect, it } from 'vitest';
import type { HostAdapter } from '../host/adapter';
import { setHost } from '../host/adapter';
import type { ParseJobRequest, ParseJobResponse } from '../worker/protocol';
import { ingestBuffers } from './ingest';
import { useAppStore } from './store';

/**
 * The VEX overlay through the real ingest funnel: sniffed before the
 * worker, committed to the store, and re-matched when SBOMs load later.
 */

class FakeWorker {
  onmessage: ((event: { data: ParseJobResponse }) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  postMessage(request: ParseJobRequest): void {
    void (async () => {
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
  createWorker: () => new FakeWorker() as unknown as Worker,
  onIngestMessage: () => {},
};

const SBOM = [
  'SPDXVersion: SPDX-2.3',
  'SPDXID: SPDXRef-DOCUMENT',
  'DocumentName: vex-app',
  'DocumentNamespace: https://example.org/spdxdocs/vex-app',
  'PackageName: web-frontend',
  'SPDXID: SPDXRef-P0',
  'PackageVersion: 2.0.0',
  'PackageDownloadLocation: NOASSERTION',
  'ExternalRef: PACKAGE-MANAGER purl pkg:npm/acme-web@2.0.0',
].join('\n');

const VEX = JSON.stringify({
  '@context': 'https://openvex.dev/ns/v0.2.0',
  '@id': 'vex-1',
  timestamp: '2026-03-01T00:00:00Z',
  statements: [
    { vulnerability: 'CVE-2026-1111', products: ['pkg:npm/acme-web@2.0.0'], status: 'affected' },
  ],
});

function buf(text: string): ArrayBuffer {
  const bytes = new TextEncoder().encode(text);
  return bytes.buffer.slice(0, bytes.byteLength) as ArrayBuffer;
}

describe('VEX through the ingest funnel', () => {
  beforeEach(() => {
    setHost(fakeHost);
    useAppStore.getState().actions.clearAll();
  });

  it('consumes VEX before the worker and matches SBOMs loaded later', async () => {
    // VEX first: it never reaches the parser, and nothing matches yet.
    const added = await ingestBuffers([{ fileName: 'acme.openvex.json', buffer: buf(VEX) }]);
    expect(added).toEqual([]);
    expect(useAppStore.getState().vex.documents).toHaveLength(1);
    expect(useAppStore.getState().vex.findings.size).toBe(0);

    // SBOM second: the overlay recomputes on the workspace swap.
    await ingestBuffers([{ fileName: 'app.spdx', buffer: buf(SBOM) }]);
    const { vex, ws } = useAppStore.getState();
    expect(vex.findings.size).toBe(1);
    const [findings] = [...vex.findings.values()];
    expect(findings![0]).toMatchObject({ vulnerability: 'CVE-2026-1111', status: 'affected' });
    expect(ws.documents.size).toBe(1);
  });

  it('re-adding the same VEX id replaces it, and clearAll drops the overlay', async () => {
    await ingestBuffers([{ fileName: 'app.spdx', buffer: buf(SBOM) }]);
    await ingestBuffers([{ fileName: 'acme.openvex.json', buffer: buf(VEX) }]);
    const updated = JSON.parse(VEX) as { statements: { status: string }[] };
    updated.statements[0]!.status = 'fixed';
    await ingestBuffers([{ fileName: 'acme2.openvex.json', buffer: buf(JSON.stringify(updated)) }]);

    const { vex, actions } = useAppStore.getState();
    expect(vex.documents).toHaveLength(1); // same @id replaced, not duplicated
    expect([...vex.findings.values()][0]![0]!.status).toBe('fixed');

    actions.clearAll();
    expect(useAppStore.getState().vex.documents).toHaveLength(0);
    expect(useAppStore.getState().vex.findings.size).toBe(0);
  });
});
