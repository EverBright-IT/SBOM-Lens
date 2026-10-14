import workerUrl from '../worker/bundle.worker.ts?worker&url';
import type { HostToWebviewMessage, WebviewToHostMessage } from '@sbomlens/web/vscode-protocol';
import type { Host, HostPushFile } from './types';

interface VsCodeApi {
  postMessage(message: WebviewToHostMessage): void;
}

declare function acquireVsCodeApi(): VsCodeApi;

/**
 * Injected by the shared extension shell (packages/vscode-shell, see
 * buildWebviewHtml) so synchronous pref reads work before any message.
 */
const PREFS_GLOBAL = '__SBOMLENS_PREFS__';

/**
 * The VS Code webview host. Prefs persist in the extension's globalState
 * (the shell snapshots `ocmlens.*` keys into the page, which is how pinned
 * keys carry over from 1.x), saves go through a native save dialog
 * (webviews cannot download), and the bundle worker is instantiated from a
 * Blob because the webview CSP only allows `worker-src blob:`.
 */
export function createVscodeHost(api: VsCodeApi = acquireVsCodeApi()): Host {
  const prefs: Record<string, string> =
    ((globalThis as Record<string, unknown>)[PREFS_GLOBAL] as Record<string, string> | undefined) ?? {};
  let pushCallback: ((files: HostPushFile[]) => void) | null = null;

  window.addEventListener('message', (event: MessageEvent<HostToWebviewMessage>) => {
    const message = event.data;
    if (!message || typeof message !== 'object') return;
    if (message.type === 'ingestFiles') {
      pushCallback?.(
        message.files.map((f) => ({
          fileName: f.fileName,
          blob: new Blob([f.bytes.slice().buffer as ArrayBuffer]),
        })),
      );
    } else if (message.type === 'ingestUris') {
      // Large files arrive as webview-resource URIs: fetched into Blobs
      // (Chromium spills large blobs to disk), streamed by the worker.
      void (async () => {
        const files = await Promise.all(
          message.files.map(async (f): Promise<HostPushFile> => {
            try {
              const response = await fetch(f.uri);
              if (!response.ok) throw new Error(`${response.status}`);
              return { fileName: f.fileName, blob: await response.blob() };
            } catch {
              // An empty file surfaces as a visible "could not be opened".
              return { fileName: f.fileName, blob: new Blob([]) };
            }
          }),
        );
        pushCallback?.(files);
      })();
    }
  });

  return {
    kind: 'vscode',

    createWorker() {
      return createBlobWorkerProxy(new URL(workerUrl, document.baseURI).href);
    },

    readPref(key) {
      return prefs[key] ?? null;
    },

    persistPref(key, value) {
      prefs[key] = value;
      api.postMessage({ type: 'persistPref', key, value });
    },

    saveFile(fileName, _mime, data) {
      const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
      api.postMessage({ type: 'exportBytes', fileName, bytes });
    },

    onPush(callback) {
      pushCallback = callback;
      api.postMessage({ type: 'ready' });
    },
  };
}

/**
 * Synchronous Worker facade over an async Blob instantiation: messages posted
 * before the real worker exists are queued and flushed once it does. Same
 * mechanism as the 1.x webview host (apps/web/src/host/vscodeHost.ts).
 */
function createBlobWorkerProxy(absoluteUrl: string): Worker {
  let real: Worker | null = null;
  let queue: Array<[unknown, Transferable[] | undefined]> = [];
  const proxy = {
    onmessage: null as Worker['onmessage'],
    onerror: null as Worker['onerror'],
    postMessage(message: unknown, transfer?: Transferable[]) {
      if (real) real.postMessage(message, transfer ?? []);
      else queue.push([message, transfer]);
    },
    terminate() {
      real?.terminate();
      queue = [];
    },
  };
  void (async () => {
    const response = await fetch(absoluteUrl);
    if (!response.ok) throw new Error(`worker asset: ${response.status}`);
    const blob = await response.blob();
    real = new Worker(URL.createObjectURL(blob), { type: 'module' });
    real.onmessage = (e) => proxy.onmessage?.call(real as Worker, e);
    real.onerror = (e) => proxy.onerror?.call(real as Worker, e);
    for (const [message, transfer] of queue) real.postMessage(message, transfer ?? []);
    queue = [];
  })().catch(() => {
    proxy.onerror?.call(
      proxy as unknown as Worker,
      new ErrorEvent('error', { message: 'Failed to load the bundle worker.' }),
    );
  });
  return proxy as unknown as Worker;
}
