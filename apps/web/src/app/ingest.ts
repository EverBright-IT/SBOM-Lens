import type { DocumentId, LoadedDocument } from '@sbomlens/core';
import {
  MAX_CSAF_BYTES,
  MAX_VEX_BYTES,
  buildIndexes,
  parseCsaf,
  parseOpenVex,
  sniffCsaf,
  sniffProfile,
  sniffVex,
} from '@sbomlens/core';
import { host } from '../host/adapter';
import type { ParseJobRequest, ParseJobResponse } from '../worker/protocol';
import { HAS_DELIVERIES } from './brand';
import { useAppStore } from './store';
import { importProfileText, withinProfileSizeCap } from './profiles';
import { authHeaders, tokenForUrl } from './tokens';

/**
 * Files and URLs → parse worker → workspace. One worker, jobs queued FIFO;
 * only index building (single-digit ms) happens on the UI thread.
 */

let worker: Worker | null = null;
let nextJobId = 1;
const pending = new Map<number, { resolve: (r: ParseJobResponse) => void }>();

function getWorker(): Worker {
  if (worker) return worker;
  worker = host().createWorker();
  worker.onmessage = (event: MessageEvent<ParseJobResponse>) => {
    const job = pending.get(event.data.id);
    pending.delete(event.data.id);
    job?.resolve(event.data);
  };
  worker.onerror = () => {
    // Worker died: fail everything in flight and start fresh next time.
    for (const [id, job] of pending) {
      job.resolve({ id, ok: false, fileName: '(unknown)', error: 'Parse worker crashed.' });
    }
    pending.clear();
    worker?.terminate();
    worker = null;
  };
  return worker;
}

function parseInWorker(fileName: string, payload: ArrayBuffer | Blob): Promise<ParseJobResponse> {
  return new Promise((resolve) => {
    const id = nextJobId++;
    pending.set(id, { resolve });
    // A Blob is a handle, not bytes: it clones structurally (cheap) while
    // the worker reads it from disk-backed storage via slice(). Buffers
    // keep transferring as before.
    const request: ParseJobRequest =
      payload instanceof Blob ? { id, fileName, blob: payload } : { id, fileName, buffer: payload };
    getWorker().postMessage(request, payload instanceof Blob ? [] : [payload]);
  });
}

/**
 * Parse one entry off-thread; report failures; no workspace mutation yet.
 * Delivery archives come back pre-expanded: the contained component
 * descriptors are already mapped, the extracted SPDX blobs re-enter this
 * same path (depth-capped — archives inside archives are consumed inside
 * the walker, never re-dispatched).
 */
async function parseEntry(
  fileName: string,
  payload: ArrayBuffer | Blob,
  depth = 0,
): Promise<LoadedDocument[]> {
  const { actions } = useAppStore.getState();
  const response = await parseInWorker(fileName, payload);
  actions.parsingDone();

  if (!response.ok) {
    actions.recordFailure({
      fileName: response.fileName,
      diagnostics: [{ severity: 'error', code: 'PARSE_CRASH', message: response.error }],
    });
    actions.toast(`${response.fileName}: ${response.error}`, 'error');
    return [];
  }

  if (response.kind === 'expanded') {
    if (response.diagnostics.length > 0) {
      actions.recordFailure({ fileName: response.fileName, diagnostics: response.diagnostics });
    }
    const docs: LoadedDocument[] = response.documents.map((d) => ({
      document: d.document,
      indexes: buildIndexes(d.document),
      source: { fileName: d.fileName, byteSize: d.byteSize, sha1: d.sha1, text: d.text },
    }));
    if (response.documents.length === 0 && response.extracted.length === 0) {
      const reason = response.diagnostics[0]?.message ?? 'Empty archive.';
      actions.toast(`${response.fileName}: ${reason}`, 'error');
      return docs;
    }
    if (depth >= 1) return docs;
    actions.parsingBegin(response.extracted.length);
    const nested = await Promise.all(
      response.extracted.map((entry) => parseEntry(entry.fileName, entry.buffer, depth + 1)),
    );
    return [...docs, ...nested.flat()];
  }

  if (!response.document) {
    actions.recordFailure({ fileName: response.fileName, diagnostics: response.diagnostics });
    const reason = response.diagnostics[0]?.message ?? 'Unrecognized format.';
    actions.toast(`${response.fileName}: ${reason}`, 'error');
    return [];
  }

  return [
    {
      document: response.document,
      indexes: buildIndexes(response.document),
      source: {
        fileName: response.fileName,
        byteSize: response.byteSize,
        sha1: response.sha1,
        text: response.text,
      },
    },
  ];
}

/**
 * Content-sniff for compliance profiles and OpenVEX documents BEFORE the
 * worker: this is the one funnel all byte paths share (file picker/drop via
 * ingestFiles, the VS Code push channel, and — via its own call —
 * ingestUrl), so overlays import the same way everywhere. Consumed entries
 * never reach the parse worker or the parsing counters.
 *
 * Cost discipline: profiles decode at most 64 KB, and a VEX candidate is
 * pre-screened with a raw byte scan for the openvex.dev marker (UTF-8
 * makes the ASCII substring byte-stable), so ordinary SBOM drops are never
 * text-decoded on the UI thread just to be ruled out.
 */
function siftOverlays(entries: ReadonlyArray<IngestEntry>): IngestEntry[] {
  const sboms: IngestEntry[] = [];
  for (const entry of entries) {
    if ('buffer' in entry && entry.buffer.byteLength <= MAX_OVERLAY_BYTES) {
      const smallEnoughForProfile = withinProfileSizeCap(entry.buffer.byteLength);
      const vexCandidate = hasVexMarker(entry.buffer);
      const csafCandidate = hasCsafMarker(entry.buffer);
      if (smallEnoughForProfile || vexCandidate || csafCandidate) {
        const text = new TextDecoder().decode(entry.buffer);
        if (smallEnoughForProfile) {
          const sniff = sniffProfile(text);
          if (sniff.isProfile) {
            importProfileText(entry.fileName, text, 'imported');
            continue;
          }
        }
        if (vexCandidate) {
          const vexSniff = sniffVex(text);
          if (vexSniff.isVex) {
            importVexRaw(entry.fileName, vexSniff.raw);
            continue;
          }
        }
        if (csafCandidate) {
          const csafSniff = sniffCsaf(text);
          if (csafSniff.isCsaf) {
            importCsafRaw(entry.fileName, csafSniff.raw);
            continue;
          }
        }
      }
    }
    sboms.push(entry);
  }
  return sboms;
}

/** The overlay pre-filter accepts anything up to the largest overlay cap. */
const MAX_OVERLAY_BYTES = Math.max(MAX_VEX_BYTES, MAX_CSAF_BYTES);

const VEX_MARKER = new TextEncoder().encode('openvex.dev');
const CSAF_MARKER = new TextEncoder().encode('csaf_version');

/** OpenVEX prescreen: raw byte scan, cheap enough to run on every drop. */
function hasVexMarker(buffer: ArrayBuffer): boolean {
  return bufferContains(buffer, VEX_MARKER);
}

/** CSAF prescreen: the mandatory `csaf_version` key, byte-scanned. */
function hasCsafMarker(buffer: ArrayBuffer): boolean {
  return bufferContains(buffer, CSAF_MARKER);
}

/** Boyer-Moore-free substring scan over raw bytes — no decode needed. */
function bufferContains(buffer: ArrayBuffer, marker: Uint8Array): boolean {
  const bytes = new Uint8Array(buffer);
  const first = marker[0]!;
  let from = 0;
  while (true) {
    const i = bytes.indexOf(first, from);
    if (i === -1 || i + marker.length > bytes.length) return false;
    let match = true;
    for (let j = 1; j < marker.length; j++) {
      if (bytes[i + j] !== marker[j]) {
        match = false;
        break;
      }
    }
    if (match) return true;
    from = i + 1;
  }
}

/** Parse + commit one OpenVEX document; findings recompute in the store. */
function importVexRaw(fileName: string, raw: unknown): void {
  commitVexDoc(fileName, parseOpenVex(fileName, raw), 'VEX');
}

/** Parse + commit one CSAF document; it flows through the same overlay. */
function importCsafRaw(fileName: string, raw: unknown): void {
  commitVexDoc(fileName, parseCsaf(fileName, raw), 'CSAF');
}

function commitVexDoc(
  fileName: string,
  doc: ReturnType<typeof parseOpenVex>,
  label: 'VEX' | 'CSAF',
): void {
  const { actions } = useAppStore.getState();
  if (doc.diagnostics.length > 0) {
    actions.recordFailure({ fileName, diagnostics: doc.diagnostics });
  }
  const { matched } = actions.addVexDocument(doc);
  const n = doc.statements.length;
  actions.toast(
    `${label} loaded: ${n} statement${n === 1 ? '' : 's'}, ${matched} package${matched === 1 ? '' : 's'} matched`,
    matched > 0 ? 'success' : 'info',
  );
}

/**
 * Parses all entries in the worker, then commits them as ONE workspace
 * change — loading a 70-file cascade folder is a single resolution recompute
 * and a single render wave instead of 70.
 */
export type IngestEntry =
  | { fileName: string; buffer: ArrayBuffer }
  | { fileName: string; blob: Blob };

export async function ingestBuffers(entries: ReadonlyArray<IngestEntry>): Promise<DocumentId[]> {
  const sbomEntries = siftOverlays(entries);
  if (sbomEntries.length === 0) return [];
  const { actions } = useAppStore.getState();
  actions.parsingBegin(sbomEntries.length);
  const parsed = await Promise.all(
    sbomEntries.map((e) => parseEntry(e.fileName, 'buffer' in e ? e.buffer : e.blob)),
  );
  const loaded = parsed.flat();
  const { added, duplicates } = actions.addLoadedBatch(loaded);
  if (duplicates > 0) {
    actions.toast(
      `${duplicates} file${duplicates === 1 ? ' was' : 's were'} already loaded (same content)`,
      'info',
    );
  }
  return added;
}

// Archive extensions only make sense where deliveries do — the SPDX-only
// product would just hand a tarball to a parser that cannot read it.
const ACCEPTED_FILE = HAS_DELIVERIES
  ? /\.(spdx|json|yaml|yml|rdf|tar|tgz|gz|ctf)$/i
  : /\.(spdx|json|yaml|yml|rdf)$/i;
// These never buffer up front: the worker streams them via Blob.slice().
const DELIVERY_FILE = /\.(tar|tgz|gz|ctf)$/i;
const SKIP_HINT = HAS_DELIVERIES
  ? 'not .spdx/.json/.yaml or a .tar/.tgz delivery'
  : 'not .spdx/.json/.yaml';

export async function ingestFiles(files: ReadonlyArray<File>): Promise<DocumentId[]> {
  const accepted = files.filter((f) => ACCEPTED_FILE.test(f.name));
  const skipped = files.length - accepted.length;
  if (skipped > 0) {
    useAppStore
      .getState()
      .actions.toast(`Skipped ${skipped} file${skipped === 1 ? '' : 's'} (${SKIP_HINT})`, 'info');
  }
  const entries = await Promise.all(
    accepted.map(async (f): Promise<IngestEntry> =>
      HAS_DELIVERIES && DELIVERY_FILE.test(f.name)
        ? { fileName: f.name, blob: f }
        : { fileName: f.name, buffer: await f.arrayBuffer() },
    ),
  );
  return ingestBuffers(entries);
}

/** Recursively collects files from a drop that may contain directories. */
export async function ingestDataTransfer(dataTransfer: DataTransfer): Promise<void> {
  const files: File[] = [];
  const entries: FileSystemEntry[] = [];
  for (const item of dataTransfer.items) {
    const entry = item.webkitGetAsEntry?.();
    if (entry) entries.push(entry);
    else {
      const file = item.getAsFile();
      if (file) files.push(file);
    }
  }
  for (const entry of entries) {
    await collectEntry(entry, files, 0);
  }
  await ingestFiles(files);
}

function collectEntry(entry: FileSystemEntry, out: File[], depth: number): Promise<void> {
  if (depth > 10) return Promise.resolve();
  if (entry.isFile) {
    return new Promise((resolve) => {
      (entry as FileSystemFileEntry).file((file) => {
        out.push(file);
        resolve();
      }, () => resolve());
    });
  }
  if (entry.isDirectory) {
    const reader = (entry as FileSystemDirectoryEntry).createReader();
    return new Promise((resolve) => {
      const readBatch = () => {
        reader.readEntries(async (batch) => {
          if (batch.length === 0) {
            resolve();
            return;
          }
          for (const child of batch) await collectEntry(child, out, depth + 1);
          readBatch(); // readEntries returns at most ~100 entries per call
        }, () => resolve());
      };
      readBatch();
    });
  }
  return Promise.resolve();
}

export interface UrlIngestResult {
  ok: boolean;
  message?: string;
  documentId?: DocumentId;
}

export async function ingestUrl(url: string): Promise<UrlIngestResult> {
  const { actions } = useAppStore.getState();
  const result = await host().fetchDocument(url, authHeaders(await tokenForUrl(url)));
  if (!result.ok) {
    if (result.status === undefined) {
      return {
        ok: false,
        message:
          'Could not fetch: the server likely blocks cross-origin requests (CORS) or is unreachable. ' +
          'Download the file and drop it here instead.',
      };
    }
    const hint =
      result.status === 401 || result.status === 403
        ? ' The server requires authentication. Add an access token for this host.'
        : '';
    return {
      ok: false,
      message: `Server answered ${result.status} ${result.statusText ?? ''}`.trimEnd() + `.${hint}`,
    };
  }
  const buffer = result.bytes;
  if (buffer.byteLength <= MAX_OVERLAY_BYTES) {
    const text = new TextDecoder().decode(buffer);
    if (withinProfileSizeCap(buffer.byteLength)) {
      const sniff = sniffProfile(text);
      if (sniff.isProfile) {
        const imported = importProfileText(url, text, 'imported');
        return imported.ok
          ? { ok: true }
          : { ok: false, message: 'The fetched file is an invalid compliance profile.' };
      }
    }
    const vexSniff = sniffVex(text);
    if (vexSniff.isVex) {
      importVexRaw(url, vexSniff.raw);
      return { ok: true };
    }
    const csafSniff = sniffCsaf(text);
    if (csafSniff.isCsaf) {
      importCsafRaw(url, csafSniff.raw);
      return { ok: true };
    }
  }
  const pathName = (() => {
    try {
      return new URL(url, globalThis.location?.href).pathname;
    } catch {
      return url;
    }
  })();
  const fileName = decodeURIComponent(pathName.split('/').pop() || 'document.spdx');
  actions.parsingBegin(1);
  const loaded = await parseEntry(fileName, buffer);
  if (loaded.length === 0) {
    return { ok: false, message: 'The fetched file did not parse as SPDX.' };
  }
  const { added } = useAppStore.getState().actions.addLoadedBatch(loaded);
  // Duplicate content: hand back the already-loaded document's id.
  const documentId =
    added[0] ?? useAppStore.getState().ws.bySha1.get(loaded[0]!.source.sha1) ?? loaded[0]!.document.id;
  return { ok: true, documentId };
}
