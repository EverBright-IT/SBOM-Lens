import { parseDocument, sha1Hex } from '@sbomlens/core';
import { loadFixture } from '@sbomlens/core/test-fixtures';
import { beforeEach, describe, expect, it } from 'vitest';
import type { FetchDocumentResult, HostAdapter } from '../host/adapter';
import { setHost } from '../host/adapter';
import type { ParseJobRequest, ParseJobResponse } from '../worker/protocol';
import { openDeepLinks } from './deepLink';
import { useAppStore } from './store';

/**
 * The behaviour a deep link promises, through the real ingest path: documents
 * open, failures are said out loud, and a link someone else sent never spends
 * the recipient's stored credentials.
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

let fetchResult: FetchDocumentResult;
const fetched: { urls: string[]; headers: (Record<string, string> | undefined)[] } = {
  urls: [],
  headers: [],
};

const fakeHost: HostAdapter = {
  kind: 'web',
  caps: { catalog: false },
  async fetchDocument(url, headers) {
    fetched.urls.push(url);
    fetched.headers.push(headers);
    return fetchResult;
  },
  readPref: () => null,
  persistPref: () => {},
  secretGet: async () => 'stored-secret-token',
  secretSet: async () => {},
  exportFile: () => {},
  openExternal: () => {},
  createWorker: () => new FakeWorker() as unknown as Worker,
  onIngestMessage: () => {},
};

function ok(fixture: string): FetchDocumentResult {
  const bytes = new TextEncoder().encode(loadFixture(fixture)).buffer as ArrayBuffer;
  return { ok: true, bytes };
}

describe('openDeepLinks', () => {
  beforeEach(() => {
    setHost(fakeHost);
    useAppStore.getState().actions.clearAll();
    useAppStore.setState({ toasts: [] }); // clearAll keeps them; each case starts quiet
    fetched.urls = [];
    fetched.headers = [];
  });

  it('opens the document a link names', async () => {
    fetchResult = ok('minimal.spdx.json');
    await openDeepLinks('?url=https://acme.example/minimal.spdx.json');
    expect(fetched.urls).toEqual(['https://acme.example/minimal.spdx.json']);
    expect(useAppStore.getState().ws.documents.size).toBe(1);
  });

  it('opens several, in the order the link lists them', async () => {
    fetchResult = ok('minimal.spdx.json');
    await openDeepLinks('?url=https://acme.example/a.spdx.json&url=https://acme.example/b.spdx.json');
    expect(fetched.urls).toEqual(['https://acme.example/a.spdx.json', 'https://acme.example/b.spdx.json']);
  });

  it('never attaches a stored token, however tempting the host', async () => {
    // The whole point: a link someone sent must not spend your credentials.
    fetchResult = ok('minimal.spdx.json');
    await openDeepLinks('?url=https://registry.example.org/private.spdx.json');
    // secretGet would hand out a token here; the deep link must not ask for one.
    expect(Object.keys(fetched.headers[0] ?? {})).toEqual([]);
  });

  it('fetches nothing at all for a rejected scheme', async () => {
    fetchResult = ok('minimal.spdx.json');
    await openDeepLinks('?url=javascript:alert(1)');
    expect(fetched.urls).toEqual([]);
    expect(useAppStore.getState().toasts.some((t) => t.kind === 'error')).toBe(true);
  });

  it('does nothing, quietly, without a url parameter', async () => {
    fetchResult = ok('minimal.spdx.json');
    await openDeepLinks('?theme=dark');
    expect(fetched.urls).toEqual([]);
    expect(useAppStore.getState().toasts).toEqual([]);
  });

  it('names the host when a fetch fails', async () => {
    fetchResult = { ok: false, status: 404, statusText: 'Not Found' };
    await openDeepLinks('?url=https://acme.example/gone.spdx.json');
    const toast = useAppStore.getState().toasts.at(-1);
    expect(toast?.kind).toBe('error');
    expect(toast?.message).toContain('acme.example');
    expect(toast?.message).toContain('404');
  });

  it('offers the dialog when the source wants authentication', async () => {
    // Attaching a credential stays a deliberate act: the dialog opens
    // prefilled instead of the link quietly retrying with a token.
    fetchResult = { ok: false, status: 401, statusText: 'Unauthorized' };
    await openDeepLinks('?url=https://registry.example.org/private.spdx.json');
    const state = useAppStore.getState();
    expect(state.urlDialogOpen).toBe(true);
    expect(state.urlDialogPrefill).toBe('https://registry.example.org/private.spdx.json');
  });

  it('stops at the first authentication prompt instead of stacking dialogs', async () => {
    fetchResult = { ok: false, status: 403, statusText: 'Forbidden' };
    await openDeepLinks('?url=https://acme.example/a.json&url=https://acme.example/b.json');
    expect(fetched.urls).toEqual(['https://acme.example/a.json']);
  });

  it('keeps going after a plain failure', async () => {
    fetchResult = { ok: false, status: 500, statusText: 'Server Error' };
    await openDeepLinks('?url=https://acme.example/a.json&url=https://acme.example/b.json');
    expect(fetched.urls).toHaveLength(2);
  });
});
