import { parseDocument, sha1Hex } from '@sbomlens/core';
import { beforeEach, describe, expect, it } from 'vitest';
import type { HostAdapter } from '../host/adapter';
import { setHost } from '../host/adapter';
import type { ParseJobRequest, ParseJobResponse } from '../worker/protocol';
import { ingestBuffers } from './ingest';
import { useAppStore } from './store';

/**
 * CSAF through the real ingest funnel: prescreened by the csaf_version
 * marker, sniffed before the worker, committed to the shared VEX overlay,
 * and re-matched when the SBOM loads later — the same path OpenVEX takes.
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
  'DocumentName: csaf-app',
  'DocumentNamespace: https://example.org/spdxdocs/csaf-app',
  'PackageName: openssl',
  'SPDXID: SPDXRef-P0',
  'PackageVersion: 3.0.9',
  'PackageDownloadLocation: NOASSERTION',
  'ExternalRef: PACKAGE-MANAGER purl pkg:apk/alpine/openssl@3.0.9',
].join('\n');

const CSAF = JSON.stringify({
  document: {
    csaf_version: '2.0',
    category: 'csaf_vex',
    publisher: { category: 'vendor', name: 'ACME' },
    tracking: { id: 'ACME-CSAF-1', version: '1', current_release_date: '2026-05-01T00:00:00Z' },
  },
  product_tree: {
    full_product_names: [
      {
        product_id: 'CSAFPID-1',
        name: 'openssl',
        product_identification_helper: { purl: 'pkg:apk/alpine/openssl@3.0.9' },
      },
    ],
  },
  vulnerabilities: [{ cve: 'CVE-2026-40711', product_status: { known_affected: ['CSAFPID-1'] } }],
});

function buf(text: string): ArrayBuffer {
  const bytes = new TextEncoder().encode(text);
  return bytes.buffer.slice(0, bytes.byteLength) as ArrayBuffer;
}

describe('CSAF through the ingest funnel', () => {
  beforeEach(() => {
    setHost(fakeHost);
    useAppStore.getState().actions.clearAll();
  });

  it('consumes CSAF before the worker and matches SBOMs loaded later', async () => {
    const added = await ingestBuffers([{ fileName: 'acme.csaf.json', buffer: buf(CSAF) }]);
    expect(added).toEqual([]);
    const doc = useAppStore.getState().vex.documents[0];
    expect(doc?.format).toBe('csaf');
    expect(useAppStore.getState().vex.findings.size).toBe(0);

    await ingestBuffers([{ fileName: 'app.spdx', buffer: buf(SBOM) }]);
    const { vex } = useAppStore.getState();
    expect(vex.findings.size).toBe(1);
    expect([...vex.findings.values()][0]![0]).toMatchObject({
      vulnerability: 'CVE-2026-40711',
      status: 'affected',
    });
  });

  it('lets CSAF and OpenVEX overlays coexist on the same package', async () => {
    const openvex = JSON.stringify({
      '@context': 'https://openvex.dev/ns/v0.2.0',
      '@id': 'ov-1',
      timestamp: '2026-05-02T00:00:00Z',
      statements: [
        { vulnerability: 'CVE-2026-99999', products: ['pkg:apk/alpine/openssl@3.0.9'], status: 'fixed' },
      ],
    });
    await ingestBuffers([{ fileName: 'app.spdx', buffer: buf(SBOM) }]);
    await ingestBuffers([{ fileName: 'acme.csaf.json', buffer: buf(CSAF) }]);
    await ingestBuffers([{ fileName: 'acme.openvex.json', buffer: buf(openvex) }]);

    const { vex } = useAppStore.getState();
    expect(vex.documents).toHaveLength(2);
    const findings = [...vex.findings.values()][0]!;
    // Different CVEs from the two formats both land on openssl.
    expect(findings.map((f) => f.vulnerability).sort()).toEqual(['CVE-2026-40711', 'CVE-2026-99999']);
  });
});
