import type { Diagnostic } from '@sbomlens/core';
import type { OcmBundle } from '@sbomlens/core/ocm';

/**
 * Main thread ↔ bundle worker. Archives stream through a ByteSource, so a
 * multi-GB CTF never exists as one buffer and its bytes never reach the UI
 * thread; only the structured model, the (small, capped) extracted SBOMs,
 * and explicitly requested blobs cross back.
 */

interface JobSource {
  fileName: string;
  /** Exactly one of blob/buffer is set. Blobs stream; buffers are sniffed. */
  blob?: Blob;
  buffer?: ArrayBuffer;
}

/** Structured-clone-safe subset of DeliveryWalkOptions. */
export interface BundleWalkOptions {
  eagerHashBudget?: number;
  materializeEntryMax?: number;
}

export interface DigestCheckRequest {
  cvId: string;
  role: 'resource' | 'source';
  index: number;
  localReference: string;
  /** The artifact's verbatim digest node. */
  declared: Record<string, unknown>;
}

export interface DigestCheckResult {
  cvId: string;
  role: 'resource' | 'source';
  index: number;
  verdict: 'match' | 'mismatch' | 'unchecked';
}

export type WorkerRequest =
  | ({ kind: 'bundle'; id: number; options?: BundleWalkOptions } & JobSource)
  /** Pull one blob back out of the delivery (download-on-demand). */
  | ({ kind: 'extract'; id: number; localReference: string } & JobSource)
  /** Check deferred digests on demand; progress per blob. */
  | ({ kind: 'digests'; id: number; checks: DigestCheckRequest[] } & JobSource);

export type WorkerResponse =
  | {
      kind: 'bundle';
      id: number;
      bundle: OcmBundle | null;
      extracted: { fileName: string; bytes: Uint8Array }[];
      diagnostics: Diagnostic[];
    }
  | { kind: 'extract'; id: number; bytes: Uint8Array | null; reason?: string }
  | { kind: 'digests-progress'; id: number; done: number; total: number }
  | { kind: 'digests'; id: number; results: DigestCheckResult[] };
