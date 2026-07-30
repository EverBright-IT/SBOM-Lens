import workerUrl from '../worker/parse.worker.ts?worker&url';
import { HAS_DELIVERIES } from '../app/brand';
import type { HostAdapter, IngestPush, IngestPushOptions, OcmRegistryPort } from './adapter';
import type { HostToWebviewMessage, WebviewToHostMessage } from './vscode-protocol';
import { PREFS_GLOBAL } from './vscode-protocol';

interface VsCodeApi {
  postMessage(message: WebviewToHostMessage): void;
}

declare function acquireVsCodeApi(): VsCodeApi;

/**
 * The VS Code webview host. Network, secrets, prefs, and file export are
 * bridged to the extension host via postMessage (which also makes URL
 * fetches CORS-free); the parse worker is instantiated from a Blob because
 * webview resource URLs are cross-origin for workers.
 */
export function createVscodeHost(api: VsCodeApi = acquireVsCodeApi()): HostAdapter {
  let nextId = 1;
  const pendingFetches = new Map<
    number,
    (r: { ok: boolean; status?: number; statusText?: string; bytes?: Uint8Array }) => void
  >();
  const pendingSecrets = new Map<number, (value: string | null) => void>();
  const pendingOcmVersions = new Map<number, (r: { ok: boolean; versions?: string[]; error?: string }) => void>();
  const pendingOcmResolves = new Map<number, (r: { ok: boolean; skippedLayers?: number; error?: string }) => void>();
  let ingestCallback: ((files: IngestPush[], opts?: IngestPushOptions) => void) | null = null;

  // Sync pref reads come from the snapshot the extension injects into the page.
  const prefs: Record<string, string> =
    ((globalThis as Record<string, unknown>)[PREFS_GLOBAL] as Record<string, string>) ?? {};

  window.addEventListener('message', (event: MessageEvent<HostToWebviewMessage>) => {
    const message = event.data;
    if (!message || typeof message !== 'object') return;
    switch (message.type) {
      case 'ingestFiles':
        ingestCallback?.(
          message.files.map((f) => ({
            fileName: f.fileName,
            buffer: f.bytes.buffer.slice(
              f.bytes.byteOffset,
              f.bytes.byteOffset + f.bytes.byteLength,
            ) as ArrayBuffer,
          })),
          message.compare ? { compare: true } : undefined,
        );
        break;
      case 'ingestUris':
        // Fetch each webview-resource URI into a Blob. Chromium spills large
        // blobs to disk, and the worker reads them via slice() — the bytes
        // never exist as one buffer. CSP already allows connect-src to the
        // webview resource origin.
        void (async () => {
          const entries: IngestPush[] = await Promise.all(
            message.files.map(async (f) => {
              try {
                const response = await fetch(f.uri);
                if (!response.ok) throw new Error(`${response.status}`);
                return { fileName: f.fileName, blob: await response.blob() };
              } catch {
                // An empty buffer surfaces as a visible per-file parse
                // failure; there is no toast channel this far down.
                return { fileName: f.fileName, buffer: new ArrayBuffer(0) };
              }
            }),
          );
          ingestCallback?.(entries);
        })();
        break;
      case 'fetchResult':
        pendingFetches.get(message.id)?.(message);
        pendingFetches.delete(message.id);
        break;
      case 'secretValue':
        pendingSecrets.get(message.id)?.(message.value);
        pendingSecrets.delete(message.id);
        break;
      case 'ocmVersions':
        pendingOcmVersions.get(message.id)?.(message);
        pendingOcmVersions.delete(message.id);
        break;
      case 'ocmResolved':
        pendingOcmResolves.get(message.id)?.(message);
        pendingOcmResolves.delete(message.id);
        break;
    }
  });

  // Build-time constant: the SBOM flavor compiles the port away entirely.
  const ocmRegistry: OcmRegistryPort | undefined = HAS_DELIVERIES
    ? {
        listVersions(registry, component) {
          return new Promise((resolve) => {
            const id = nextId++;
            pendingOcmVersions.set(id, resolve);
            api.postMessage({ type: 'ocmListVersions', id, registry, component });
          });
        },
        resolve(registry, component, version) {
          return new Promise((resolve) => {
            const id = nextId++;
            pendingOcmResolves.set(id, resolve);
            api.postMessage({ type: 'ocmResolve', id, registry, component, version });
          });
        },
      }
    : undefined;

  return {
    kind: 'vscode',
    caps: { catalog: false },
    ...(ocmRegistry ? { ocmRegistry } : {}),

    fetchDocument(url, headers = {}) {
      return new Promise((resolve) => {
        const id = nextId++;
        pendingFetches.set(id, (r) => {
          if (!r.ok || !r.bytes) {
            resolve({ ok: false, status: r.status, statusText: r.statusText });
            return;
          }
          resolve({
            ok: true,
            bytes: r.bytes.buffer.slice(
              r.bytes.byteOffset,
              r.bytes.byteOffset + r.bytes.byteLength,
            ) as ArrayBuffer,
          });
        });
        api.postMessage({ type: 'fetchUrl', id, url, headers });
      });
    },

    readPref(key) {
      return prefs[key] ?? null;
    },
    persistPref(key, value) {
      prefs[key] = value;
      api.postMessage({ type: 'persistPref', key, value });
    },

    secretGet(key) {
      return new Promise((resolve) => {
        const id = nextId++;
        pendingSecrets.set(id, resolve);
        api.postMessage({ type: 'secretGet', id, key });
      });
    },
    async secretSet(key, value) {
      api.postMessage({ type: 'secretSet', key, value });
    },

    exportFile(fileName, mime, text) {
      api.postMessage({ type: 'exportFile', fileName, mime, text });
    },

    openExternal(url) {
      api.postMessage({ type: 'openExternal', url });
    },

    createWorker() {
      return createBlobWorkerProxy(new URL(workerUrl, document.baseURI).href);
    },

    onIngestMessage(callback) {
      ingestCallback = callback;
      api.postMessage({ type: 'ready' });
    },
  };
}

/**
 * Synchronous Worker facade over an async Blob instantiation: messages
 * posted before the real worker exists are queued and flushed once it does.
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
      new ErrorEvent('error', { message: 'Failed to load the parse worker.' }),
    );
  });
  return proxy as unknown as Worker;
}
