import type { Diagnostic } from '@sbomlens/core';
import type { HostPushFile } from '../host';
import { host } from '../host';
import type { BundleWalkOptions, DigestCheckRequest, WorkerRequest, WorkerResponse } from '../worker/protocol';
import type { ArtifactRef, SourceRef } from './store';
import { useAppStore } from './store';

/** File → worker → store. One worker, jobs correlated by id. */

let worker: Worker | null = null;
let nextId = 1;
interface Pending {
  resolve: (response: WorkerResponse) => void;
  onProgress?: (done: number, total: number) => void;
}
const pending = new Map<number, Pending>();

function getWorker(): Worker {
  if (worker) return worker;
  worker = host.createWorker();
  worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
    const entry = pending.get(event.data.id);
    if (!entry) return;
    if (event.data.kind === 'digests-progress') {
      entry.onProgress?.(event.data.done, event.data.total);
      return; // not final — keep the correlation alive
    }
    pending.delete(event.data.id);
    entry.resolve(event.data);
  };
  return worker;
}

/** Omit that distributes over the request union (plain Omit collapses it). */
type RequestInput = WorkerRequest extends infer T ? (T extends WorkerRequest ? Omit<T, 'id'> : never) : never;

function run(
  request: RequestInput,
  transfer?: Transferable[],
  onProgress?: (done: number, total: number) => void,
): Promise<WorkerResponse> {
  return new Promise((resolve) => {
    const id = nextId++;
    pending.set(id, { resolve, ...(onProgress ? { onProgress } : {}) });
    getWorker().postMessage({ ...request, id } as WorkerRequest, transfer ?? []);
  });
}

/** Re-acquire the delivery bytes for a follow-up worker job. */
async function jobSource(): Promise<{ blob?: Blob; buffer?: ArrayBuffer } | null> {
  const { sourceRef } = useAppStore.getState();
  if (!sourceRef) return null;
  if (sourceRef.kind === 'blob') return { blob: sourceRef.blob };
  const fetched = await fetch(sourceRef.url);
  if (!fetched.ok) return null;
  return { buffer: await fetched.arrayBuffer() };
}

/** `extra` carries findings from before the worker (files the host could not read). */
async function commit(
  fileName: string,
  response: WorkerResponse,
  sourceRef: SourceRef | null,
  extra: Diagnostic[] = [],
): Promise<void> {
  if (response.kind !== 'bundle') return;
  const { actions } = useAppStore.getState();
  const diagnostics = [...extra, ...response.diagnostics];
  if (response.bundle) {
    actions.loadSucceeded({ bundle: response.bundle, extracted: response.extracted, diagnostics }, sourceRef);
  } else {
    actions.loadFailed(fileName, diagnostics);
  }
}

async function openBlobWith(
  fileName: string,
  blob: Blob,
  options: BundleWalkOptions | undefined,
  extra: Diagnostic[],
): Promise<void> {
  const { actions } = useAppStore.getState();
  actions.loadStarted(fileName);
  // The worker streams archives from the Blob via slice() (disk-backed for
  // picked files and large pushed files alike).
  await commit(
    fileName,
    await run({ kind: 'bundle', fileName, blob, ...(options ? { options } : {}) }),
    { kind: 'blob', blob },
    extra,
  );
}

/** Open one delivery (CTF/component archive/.tgz or a bare descriptor). */
export async function openBlob(fileName: string, blob: Blob, options?: BundleWalkOptions): Promise<void> {
  await openBlobWith(fileName, blob, options, []);
}

/** Open a file the user picked or dropped. */
export async function openFile(file: File, options?: BundleWalkOptions): Promise<void> {
  await openBlob(file.name, file, options);
}

/**
 * Files pushed by the host (VS Code: custom editor, folder, workspace scan,
 * registry, deep link). One file opens as itself; several descriptors become
 * ONE bundle; with archives among them, the first archive opens - OCM Lens
 * shows one delivery at a time, and the worker says so.
 */
export async function openHostPush(files: HostPushFile[]): Promise<void> {
  if (files.length === 0) return;
  const readable = files.filter((f): f is Extract<HostPushFile, { blob: Blob }> => f.blob !== undefined);
  const unreadable: Diagnostic[] = files.flatMap((f) =>
    f.error === undefined
      ? []
      : [
          {
            severity: 'error' as const,
            code: 'HOST_FILE_UNREADABLE',
            message: `VS Code could not hand ${f.fileName} to OCM Lens (${f.error}). Check that the file still exists and is readable, then open it again.`,
          },
        ],
  );
  const { actions } = useAppStore.getState();
  if (readable.length === 0) {
    actions.loadFailed(files.length === 1 ? files[0]!.fileName : `${files.length} files`, unreadable);
    return;
  }
  if (readable.length === 1) {
    await openBlobWith(readable[0]!.fileName, readable[0]!.blob, undefined, unreadable);
    return;
  }
  const label = `${readable.length} files`;
  actions.loadStarted(label);
  const response = await run({ kind: 'open-many', files: readable });
  const source =
    response.kind === 'bundle' && response.sourceIndex !== undefined ? readable[response.sourceIndex] : undefined;
  await commit(label, response, source ? { kind: 'blob', blob: source.blob } : null, unreadable);
}

/** Open a delivery served next to the app (demo, or the `?open=` dev hook). */
export async function openFromUrl(url: string, options?: BundleWalkOptions): Promise<void> {
  const fileName = url.split('/').pop() ?? url;
  const { actions } = useAppStore.getState();
  actions.loadStarted(fileName);
  try {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const buffer = await response.arrayBuffer();
    await commit(
      fileName,
      await run({ kind: 'bundle', fileName, buffer, ...(options ? { options } : {}) }, [buffer]),
      { kind: 'url', url },
    );
  } catch (error) {
    actions.loadFailed(fileName, [
      { severity: 'error', code: 'URL_UNAVAILABLE', message: `Could not load ${url}: ${String(error)}` },
    ]);
  }
}

export const DEMO_FILE = 'ecme-delivery.ctf.tar';

/** The bundled demo delivery — one click to a populated dashboard. */
export async function openDemo(): Promise<void> {
  await openFromUrl(`examples/${DEMO_FILE}`);
}

/**
 * Pull one blob back out of the opened delivery (download-on-demand). The
 * viewer never holds blob bytes; the archive is re-read from its source.
 */
export async function extractBlob(localReference: string): Promise<Uint8Array | null> {
  const { delivery } = useAppStore.getState();
  const source = await jobSource();
  if (!source || !delivery) return null;
  const response = await run(
    { kind: 'extract', fileName: delivery.bundle.fileName, localReference, ...source },
    source.buffer ? [source.buffer] : [],
  );
  return response.kind === 'extract' ? response.bytes : null;
}

/**
 * Run the deferred digest checks — all pending ones, or an explicit subset.
 * Verdicts land in the store; progress feeds the caller's UI.
 */
export async function runDigestChecks(
  targets?: ArtifactRef[],
  onProgress?: (done: number, total: number) => void,
): Promise<boolean> {
  const { delivery, actions } = useAppStore.getState();
  if (!delivery) return false;
  const wanted =
    targets &&
    new Set(targets.map((t) => `${t.cvId}\u0000${t.role}\u0000${t.index}`));
  const checks: DigestCheckRequest[] = [];
  for (const cv of delivery.bundle.componentVersions) {
    const collect = (role: 'resource' | 'source', artifacts: typeof cv.resources) => {
      artifacts.forEach((artifact, index) => {
        if (artifact.blob?.digestCheck !== 'pending') return;
        if (wanted && !wanted.has(`${cv.id}\u0000${role}\u0000${index}`)) return;
        const access = artifact.access?.raw ?? {};
        const localReference =
          typeof access.localReference === 'string'
            ? access.localReference
            : typeof access.filename === 'string'
              ? access.filename
              : null;
        const declared = artifact.raw.digest;
        if (!localReference || typeof declared !== 'object' || declared === null) return;
        checks.push({
          cvId: cv.id,
          role,
          index,
          localReference,
          declared: declared as Record<string, unknown>,
        });
      });
    };
    collect('resource', cv.resources);
    collect('source', cv.sources);
  }
  if (checks.length === 0) return true;

  const source = await jobSource();
  if (!source) return false;
  const response = await run(
    { kind: 'digests', fileName: delivery.bundle.fileName, checks, ...source },
    source.buffer ? [source.buffer] : [],
    onProgress,
  );
  if (response.kind !== 'digests') return false;
  actions.applyDigestResults(response.results);
  return true;
}
