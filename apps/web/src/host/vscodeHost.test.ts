import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { IngestPush } from './adapter';
import type { HostToWebviewMessage, WebviewToHostMessage } from './vscode-protocol';
import { createVscodeHost } from './vscodeHost';

/**
 * Drives the webview side of the bridge with a faked acquireVsCodeApi and
 * window message events — request/response correlation must hold.
 */

const sent: WebviewToHostMessage[] = [];
const fakeApi = { postMessage: (m: WebviewToHostMessage) => void sent.push(m) };

function reply(message: HostToWebviewMessage) {
  window.dispatchEvent(new MessageEvent('message', { data: message }));
}

// happy-dom/node: vitest node env has no window — build a minimal event target.
beforeEach(() => {
  sent.length = 0;
  if (typeof window === 'undefined') {
    const target = new EventTarget();
    Object.assign(globalThis, {
      window: Object.assign(target, { }),
      MessageEvent:
        globalThis.MessageEvent ??
        class extends Event {
          data: unknown;
          constructor(type: string, init?: { data?: unknown }) {
            super(type);
            this.data = init?.data;
          }
        },
    });
  }
});

describe('vscodeHost bridge correlation', () => {
  it('resolves fetchDocument with the matching id and converts bytes', async () => {
    const host = createVscodeHost(fakeApi);
    const first = host.fetchDocument('https://example.org/a.spdx', { 'PRIVATE-TOKEN': 't' });
    const second = host.fetchDocument('https://example.org/b.spdx');

    const [reqA, reqB] = sent.filter((m) => m.type === 'fetchUrl') as Array<
      Extract<WebviewToHostMessage, { type: 'fetchUrl' }>
    >;
    expect(reqA!.headers).toEqual({ 'PRIVATE-TOKEN': 't' });

    // Answer out of order — correlation must hold.
    reply({ type: 'fetchResult', id: reqB!.id, ok: false, status: 404, statusText: 'Not Found' });
    reply({ type: 'fetchResult', id: reqA!.id, ok: true, bytes: new TextEncoder().encode('hi') });

    const b = await second;
    expect(b).toEqual({ ok: false, status: 404, statusText: 'Not Found' });
    const a = await first;
    expect(a.ok).toBe(true);
    if (a.ok) expect(new TextDecoder().decode(a.bytes)).toBe('hi');
  });

  it('correlates secretGet answers and posts secretSet fire-and-forget', async () => {
    const host = createVscodeHost(fakeApi);
    const pending = host.secretGet('sbomlens.token.example.org');
    const req = sent.find((m) => m.type === 'secretGet') as Extract<
      WebviewToHostMessage,
      { type: 'secretGet' }
    >;
    reply({ type: 'secretValue', id: req.id, value: '{"scheme":"bearer","value":"x"}' });
    expect(await pending).toContain('bearer');

    await host.secretSet('sbomlens.token.example.org', null);
    expect(sent.at(-1)).toEqual({
      type: 'secretSet',
      key: 'sbomlens.token.example.org',
      value: null,
    });
  });

  it('delivers host-pushed files to the ingest callback as ArrayBuffers', () => {
    const host = createVscodeHost(fakeApi);
    const received: IngestPush[] = [];
    host.onIngestMessage((files) => received.push(...files));
    expect(sent.at(-1)).toEqual({ type: 'ready' });

    reply({
      type: 'ingestFiles',
      files: [{ fileName: 'a.spdx', bytes: new TextEncoder().encode('SPDX') }],
    });
    expect(received).toHaveLength(1);
    const first = received[0]!;
    expect(first.fileName).toBe('a.spdx');
    if (!('buffer' in first)) throw new Error('expected a buffer push');
    expect(new TextDecoder().decode(first.buffer)).toBe('SPDX');
  });

  it('fetches ingestUris into Blob pushes and degrades failures to empty buffers', async () => {
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL) =>
      String(url).includes('big.ctf')
        ? ({ ok: true, blob: async () => new Blob([new Uint8Array([1, 2, 3])]) } as Response)
        : ({ ok: false, status: 404 } as Response)) as typeof fetch;
    try {
      const host = createVscodeHost(fakeApi);
      const batches: IngestPush[][] = [];
      host.onIngestMessage((files) => batches.push(files));
      reply({
        type: 'ingestUris',
        files: [
          { fileName: 'big.ctf', uri: 'https://resource.test/big.ctf' },
          { fileName: 'gone.ctf', uri: 'https://resource.test/gone.ctf' },
        ],
      });
      await vi.waitFor(() => expect(batches).toHaveLength(1));
      const [ok, failed] = batches[0]!;
      if (!('blob' in ok!)) throw new Error('expected a blob push');
      expect(ok.fileName).toBe('big.ctf');
      expect(ok.blob.size).toBe(3);
      if (!('buffer' in failed!)) throw new Error('expected a buffer fallback');
      expect(failed.buffer.byteLength).toBe(0);
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it('passes the compare intent through to the ingest callback', () => {
    const host = createVscodeHost(fakeApi);
    const opts: Array<{ compare?: boolean } | undefined> = [];
    host.onIngestMessage((_files, o) => opts.push(o));

    const files = [{ fileName: 'a.ctf', bytes: new Uint8Array([1]) }];
    reply({ type: 'ingestFiles', files });
    reply({ type: 'ingestFiles', files, compare: true });
    expect(opts).toEqual([undefined, { compare: true }]);
  });

  it('reads prefs from the injected snapshot and echoes writes', () => {
    (globalThis as Record<string, unknown>).__SBOMLENS_PREFS__ = { 'sbomlens.sidebar': '400' };
    const host = createVscodeHost(fakeApi);
    expect(host.readPref('sbomlens.sidebar')).toBe('400');
    host.persistPref('sbomlens.map', 'closed');
    expect(host.readPref('sbomlens.map')).toBe('closed');
    expect(sent.at(-1)).toEqual({ type: 'persistPref', key: 'sbomlens.map', value: 'closed' });
    delete (globalThis as Record<string, unknown>).__SBOMLENS_PREFS__;
  });
});
