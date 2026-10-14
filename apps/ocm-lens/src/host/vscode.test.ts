import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { HostToWebviewMessage, WebviewToHostMessage } from '@sbomlens/web/vscode-protocol';
import type { HostPushFile } from './types';
import { createVscodeHost } from './vscode';

/**
 * Drives the webview side of the OCM Lens 2.0 host with a faked
 * acquireVsCodeApi and window message events.
 */

const sent: WebviewToHostMessage[] = [];
const fakeApi = { postMessage: (m: WebviewToHostMessage) => void sent.push(m) };

function hostSays(message: HostToWebviewMessage) {
  window.dispatchEvent(new MessageEvent('message', { data: message }));
}

beforeEach(() => {
  sent.length = 0;
  if (typeof window === 'undefined') {
    Object.assign(globalThis, {
      window: new EventTarget(),
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

describe('VS Code host', () => {
  it('signals ready when the app registers for pushes, and turns pushed bytes into Blobs', async () => {
    const host = createVscodeHost(fakeApi);
    const received: HostPushFile[][] = [];
    host.onPush((files) => received.push(files));
    expect(sent).toEqual([{ type: 'ready' }]);

    hostSays({ type: 'ingestFiles', files: [{ fileName: 'demo.ctf', bytes: new Uint8Array([1, 2, 3]) }] });
    expect(received).toHaveLength(1);
    expect(received[0]![0]!.fileName).toBe('demo.ctf');
    expect(new Uint8Array(await received[0]![0]!.blob.arrayBuffer())).toEqual(new Uint8Array([1, 2, 3]));
  });

  it('fetches large-file URIs into Blobs and degrades failures to empty files', async () => {
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL) =>
      String(url).includes('big.ctf')
        ? ({ ok: true, blob: async () => new Blob([new Uint8Array(5)]) } as Response)
        : ({ ok: false, status: 404 } as Response)) as typeof fetch;
    try {
      const host = createVscodeHost(fakeApi);
      const received: HostPushFile[][] = [];
      host.onPush((files) => received.push(files));
      hostSays({
        type: 'ingestUris',
        files: [
          { fileName: 'big.ctf', uri: 'https://resource.test/big.ctf' },
          { fileName: 'gone.ctf', uri: 'https://resource.test/gone.ctf' },
        ],
      });
      await vi.waitFor(() => expect(received).toHaveLength(1));
      expect(received[0]!.map((f) => [f.fileName, f.blob.size])).toEqual([
        ['big.ctf', 5],
        ['gone.ctf', 0],
      ]);
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it('reads prefs from the injected snapshot and persists writes through the bridge', () => {
    (globalThis as Record<string, unknown>).__SBOMLENS_PREFS__ = { 'ocmlens.trustedKeys': '[]' };
    try {
      const host = createVscodeHost(fakeApi);
      expect(host.readPref('ocmlens.trustedKeys')).toBe('[]');
      host.persistPref('ocmlens.trustedKeys', '[{"label":"ecme"}]');
      expect(host.readPref('ocmlens.trustedKeys')).toBe('[{"label":"ecme"}]');
      expect(sent.at(-1)).toEqual({ type: 'persistPref', key: 'ocmlens.trustedKeys', value: '[{"label":"ecme"}]' });
    } finally {
      delete (globalThis as Record<string, unknown>).__SBOMLENS_PREFS__;
    }
  });

  it('saves through the host as bytes, text included (webviews cannot download)', () => {
    const host = createVscodeHost(fakeApi);
    host.saveFile('report.md', 'text/markdown', '# Report');
    host.saveFile('chart.tar', 'application/x-tar', new Uint8Array([7, 7]));
    const exports = sent.filter((m) => m.type === 'exportBytes') as Extract<
      WebviewToHostMessage,
      { type: 'exportBytes' }
    >[];
    expect(exports.map((m) => m.fileName)).toEqual(['report.md', 'chart.tar']);
    expect(new TextDecoder().decode(exports[0]!.bytes)).toBe('# Report');
    expect(exports[1]!.bytes).toEqual(new Uint8Array([7, 7]));
  });
});
