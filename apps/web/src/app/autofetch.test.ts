import { parseDocument, sha1Hex } from '@sbomlens/core';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { HostAdapter } from '../host/adapter';
import { setHost } from '../host/adapter';
import type { ParseJobRequest, ParseJobResponse } from '../worker/protocol';
import { fetchAllReferences } from './autofetch';
import { initCatalog, loadCatalogSource } from './catalog';
import { ingestBuffers, ingestUrl } from './ingest';
import { useAppStore } from './store';

/**
 * The reference cascade through the real ingest path. Its promise: what a
 * server answers for one URL never decides which other hosts get contacted.
 * A fetched document pulls in references on its own origin only; reaching
 * another host takes a click on a placeholder the user can see.
 */

/** Stands in for the parse worker: same protocol, real core parser. */
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

/** What each URL answers; every other URL is a 404. */
let served: Record<string, ArrayBuffer>;
let requested: string[];

const fakeHost: HostAdapter = {
  kind: 'web',
  caps: { catalog: true },
  async fetchDocument(url) {
    requested.push(url);
    const bytes = served[url];
    return bytes ? { ok: true, bytes: bytes.slice(0) } : { ok: false, status: 404, statusText: 'Not Found' };
  },
  readPref: () => null,
  persistPref: () => {},
  secretGet: async () => null,
  secretSet: async () => {},
  exportFile: () => {},
  openExternal: () => {},
  createWorker: () => new FakeWorker() as unknown as Worker,
  onIngestMessage: () => {},
};

/**
 * A small SPDX document whose package depends on something in each reference,
 * so every reference is structural and always a fetch candidate. The namespace
 * is the URL the document is served from: a fetched document resolves the
 * reference that named it.
 */
function spdx(namespace: string, refs: string[] = []): ArrayBuffer {
  const document = {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: namespace,
    documentNamespace: namespace,
    creationInfo: { created: '2026-01-01T00:00:00Z', creators: ['Tool: test'] },
    externalDocumentRefs: refs.map((uri, i) => ({
      externalDocumentId: `DocumentRef-${i}`,
      spdxDocument: uri,
    })),
    packages: [
      { SPDXID: 'SPDXRef-Package', name: 'pkg', versionInfo: '1.0.0', downloadLocation: 'NOASSERTION' },
    ],
    relationships: [
      {
        spdxElementId: 'SPDXRef-DOCUMENT',
        relationshipType: 'DESCRIBES',
        relatedSpdxElement: 'SPDXRef-Package',
      },
      ...refs.map((_, i) => ({
        spdxElementId: 'SPDXRef-Package',
        relationshipType: 'DEPENDS_ON',
        relatedSpdxElement: `DocumentRef-${i}:SPDXRef-Package`,
      })),
    ],
  };
  return new TextEncoder().encode(JSON.stringify(document)).buffer as ArrayBuffer;
}

function serve(url: string, refs: string[] = []): void {
  served[url] = spdx(url, refs);
}

describe('fetchAllReferences', () => {
  beforeEach(() => {
    setHost(fakeHost);
    useAppStore.getState().actions.clearAll();
    useAppStore.setState({ toasts: [] }); // clearAll keeps them; each case starts quiet
    served = {};
    requested = [];
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('keeps a catalog source that loads on start on the hosts the catalog names', async () => {
    // Nobody clicked anything here. The vendor's answer names a third host,
    // and that alone must not make the browser contact it.
    const catalog = {
      sources: [
        {
          label: 'Vendor root',
          urls: ['https://vendor.test/root.spdx.json'],
          loadOnStart: true,
          resolveRefs: true,
        },
      ],
    };
    serve('https://vendor.test/root.spdx.json', [
      'https://vendor.test/child.spdx.json',
      'https://third.test/x.spdx.json',
    ]);
    serve('https://vendor.test/child.spdx.json');
    serve('https://third.test/x.spdx.json');

    const realFetch = globalThis.fetch;
    globalThis.fetch = (async () => new Response(JSON.stringify(catalog))) as typeof fetch;
    try {
      await initCatalog();
    } finally {
      globalThis.fetch = realFetch;
    }
    // initCatalog does not wait for its sources; the cascade's closing toast marks the end.
    await vi.waitFor(() =>
      expect(useAppStore.getState().toasts.some((t) => t.message.startsWith('Fetched '))).toBe(true),
    );

    expect(requested).toEqual(['https://vendor.test/root.spdx.json', 'https://vendor.test/child.spdx.json']);
    // The reference stays a placeholder, and the user is told why.
    expect(useAppStore.getState().toasts.at(-1)?.message).toContain('1 on another host not followed');
  });

  it('lets only the first round after a click reach other hosts', async () => {
    // "Fetch all" covers the placeholders on screen. What the fetched
    // documents reference in turn is the answering server's choice.
    serve('https://a.test/one.spdx.json', ['https://a.test/two.spdx.json', 'https://third.test/x.spdx.json']);
    serve('https://a.test/two.spdx.json');
    serve('https://third.test/x.spdx.json');
    await ingestBuffers([
      { fileName: 'local.spdx.json', buffer: spdx('urn:test:local', ['https://a.test/one.spdx.json']) },
    ]);

    const summary = await fetchAllReferences();
    expect(requested).toEqual(['https://a.test/one.spdx.json', 'https://a.test/two.spdx.json']);
    expect(summary).toMatchObject({ fetched: 2, failed: [], held: 1 });

    // The held-back placeholder is on screen now, so the next click covers it.
    await fetchAllReferences();
    expect(requested.slice(2)).toEqual(['https://third.test/x.spdx.json']);
  });

  it('does not follow references of documents the catalog source did not load', async () => {
    // A `?url=` deep link opens next to the catalog on start. Its document
    // must not steer the catalog's cascade, not even to a catalog host.
    serve('https://link.test/doc.spdx.json', ['https://vendor.test/picked-by-the-link.spdx.json']);
    serve('https://vendor.test/root.spdx.json');
    serve('https://vendor.test/picked-by-the-link.spdx.json');
    await ingestUrl('https://link.test/doc.spdx.json', { useStoredToken: false });

    await loadCatalogSource({ label: 'Vendor', urls: ['https://vendor.test/root.spdx.json'], resolveRefs: true });

    expect(requested).toEqual(['https://link.test/doc.spdx.json', 'https://vendor.test/root.spdx.json']);
  });

  it('compares origins the way fetch resolves the URLs', async () => {
    vi.stubGlobal('location', { href: 'https://lens.test/app/' });
    serve('sboms/root.spdx.json', [
      'sboms/child.spdx.json', // relative: the app's own origin, like the root
      'https://lens.test/app/sboms/absolute.spdx.json', // the same origin, spelled out
      '//third.test/x.spdx.json', // scheme-relative is another host
      '/\\third.test/y.spdx.json', // and so is this, to a browser
      'http://lens.test/app/sboms/plain.spdx.json', // same host without TLS
      'https://lens.test:8443/sboms/port.spdx.json', // same host, another port
    ]);
    serve('sboms/child.spdx.json');
    serve('https://lens.test/app/sboms/absolute.spdx.json');

    await loadCatalogSource({ label: 'Local', urls: ['sboms/root.spdx.json'], resolveRefs: true });

    expect(requested).toEqual([
      'sboms/root.spdx.json',
      'sboms/child.spdx.json',
      'https://lens.test/app/sboms/absolute.spdx.json',
    ]);
  });

  it('lets a second catalog source join the cascade that is already running', async () => {
    serve('https://a.test/root.spdx.json', ['https://a.test/child.spdx.json']);
    serve('https://a.test/child.spdx.json');
    serve('https://b.test/root.spdx.json', ['https://b.test/child.spdx.json', 'https://a.test/other.spdx.json']);
    serve('https://b.test/child.spdx.json');

    await Promise.all([
      loadCatalogSource({ label: 'A', urls: ['https://a.test/root.spdx.json'], resolveRefs: true }),
      loadCatalogSource({ label: 'B', urls: ['https://b.test/root.spdx.json'], resolveRefs: true }),
    ]);

    // Both trees assemble, and b.test still cannot name a path on a.test.
    expect([...requested].sort()).toEqual([
      'https://a.test/child.spdx.json',
      'https://a.test/root.spdx.json',
      'https://b.test/child.spdx.json',
      'https://b.test/root.spdx.json',
    ]);
  });
});
