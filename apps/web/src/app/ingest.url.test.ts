import { parseDocument, sha1Hex } from '@sbomlens/core';
import { loadFixture } from '@sbomlens/core/test-fixtures';
import { beforeEach, describe, expect, it } from 'vitest';
import type { FetchDocumentResult, HostAdapter } from '../host/adapter';
import { setHost } from '../host/adapter';
import type { ParseJobRequest, ParseJobResponse } from '../worker/protocol';
import { ingestUrl } from './ingest';
import { useAppStore } from './store';
import { rememberToken } from './tokens';

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

let fetchResult: FetchDocumentResult;
const fetchedWith: { url?: string; headers?: Record<string, string> } = {};
const secrets = new Map<string, string>();

/** The host the page's fetch reaches: it resolves against the page, as webHost does. */
const reachedHost = (url: string) => new URL(url, 'https://lens.example/app/').host;

const fakeHost: HostAdapter = {
  kind: 'web',
  caps: { catalog: false },
  async fetchDocument(url, headers) {
    fetchedWith.url = url;
    fetchedWith.headers = headers;
    return fetchResult;
  },
  readPref: () => null,
  persistPref: () => {},
  secretGet: async (key) => secrets.get(key) ?? null,
  secretSet: async (key, value) => {
    if (value === null) secrets.delete(key);
    else secrets.set(key, value);
  },
  exportFile: () => {},
  openExternal: () => {},
  createWorker: () => new FakeWorker() as unknown as Worker,
  onIngestMessage: () => {},
};

describe('ingestUrl through the host adapter', () => {
  beforeEach(() => {
    setHost(fakeHost);
    useAppStore.getState().actions.clearAll();
    secrets.clear();
  });

  it('maps a network-level failure to the CORS hint', async () => {
    fetchResult = { ok: false };
    const result = await ingestUrl('https://registry.example.org/a.spdx');
    expect(result.ok).toBe(false);
    expect(result.message).toContain('CORS');
  });

  it('maps 401 to the token hint and keeps the status visible', async () => {
    fetchResult = { ok: false, status: 401, statusText: 'Unauthorized' };
    const result = await ingestUrl('https://registry.example.org/a.spdx');
    expect(result.ok).toBe(false);
    expect(result.message).toContain('401');
    expect(result.message).toContain('access token');
  });

  it('reports plain HTTP errors without the token hint', async () => {
    fetchResult = { ok: false, status: 404, statusText: 'Not Found' };
    const result = await ingestUrl('https://registry.example.org/a.spdx');
    expect(result.ok).toBe(false);
    expect(result.message).toContain('404');
    expect(result.message).not.toContain('access token');
  });

  it('parses fetched bytes and lands the document in the workspace', async () => {
    const bytes = new TextEncoder().encode(loadFixture('minimal.spdx'));
    fetchResult = { ok: true, bytes: bytes.buffer as ArrayBuffer };
    const result = await ingestUrl('https://registry.example.org/downloads/minimal.spdx');
    expect(result.ok).toBe(true);
    expect(result.documentId).toBeTruthy();
    const ws = useAppStore.getState().ws;
    expect(ws.documents.size).toBe(1);
    expect(ws.documents.get(result.documentId!)?.source.fileName).toBe('minimal.spdx');
  });

  it('returns the existing document id for duplicate content', async () => {
    const bytes = new TextEncoder().encode(loadFixture('minimal.spdx'));
    fetchResult = { ok: true, bytes: bytes.buffer.slice(0) };
    const first = await ingestUrl('https://registry.example.org/one.spdx');
    fetchResult = { ok: true, bytes: bytes.buffer.slice(0) };
    const second = await ingestUrl('https://registry.example.org/two.spdx');
    expect(second.ok).toBe(true);
    expect(second.documentId).toBe(first.documentId);
    expect(useAppStore.getState().ws.documents.size).toBe(1);
  });

  // A URL in the page's own scheme without `//` is a host to `new URL`, but a
  // relative path to the page's fetch: the token would go to our own origin.
  it.each(['https:registry-a.test/x', 'https:/registry-a.test/x', 'https:\\registry-a.test/x'])(
    'sends a stored token only to the host it was stored for: %s',
    async (url) => {
      await rememberToken('https://registry-a.test/', { scheme: 'bearer', value: 'stored-secret' });
      fetchResult = { ok: false, status: 404, statusText: 'Not Found' };
      await ingestUrl(url);
      expect(fetchedWith.headers).toEqual({ Authorization: 'Bearer stored-secret' });
      expect(reachedHost(fetchedWith.url!)).toBe('registry-a.test');
    },
  );

  it('keeps a relative URL relative and sends no token with it', async () => {
    await rememberToken('https://registry-a.test/', { scheme: 'bearer', value: 'stored-secret' });
    fetchResult = { ok: false, status: 404, statusText: 'Not Found' };
    await ingestUrl('examples/minimal.spdx');
    expect(fetchedWith.url).toBe('examples/minimal.spdx');
    expect(fetchedWith.headers).toEqual({});
  });
});
