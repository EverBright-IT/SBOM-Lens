import type { Diagnostic } from '@sbomlens/core';
import type { VexDocument } from '@sbomlens/core';
import type { OcmBundle, SbomAnalysis, SbomPackageList } from '@sbomlens/core/ocm';

/**
 * Main thread ↔ bundle worker. Archives stream through a ByteSource, so a
 * multi-GB CTF never exists as one buffer and its bytes never reach the UI
 * thread; only the structured model, the (small, capped) extracted SBOMs
 * with their analysis summaries, and explicitly requested blobs cross back.
 * Parsed SBOM documents never leave the worker whole: the package views get
 * package lists without files and raw JSON.
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
  /**
   * Bytes of SBOM text the app analyses right after opening; the rest waits
   * for "Analyse now". Read by the app, never sent to the walk.
   */
  sbomBudget?: number;
}

/** One extracted SBOM to analyse on demand. */
export interface SbomAnalysisItem {
  sha1: string;
  fileName: string;
  bytes: Uint8Array;
}

/** A VEX or CSAF document to read: bytes the reader added, or a blob of the delivery. */
export type VexReadItem = { key: string; fileName: string } & (
  | { bytes: Uint8Array }
  | { localReference: string }
);

export type VexReadResult = { document: VexDocument } | { reason: string };

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
  | ({ kind: 'digests'; id: number; checks: DigestCheckRequest[] } & JobSource)
  /**
   * Several host-pushed files at once (folder, workspace scan): descriptors
   * merge into one bundle; with archives among them the first archive opens.
   */
  | { kind: 'open-many'; id: number; files: { fileName: string; blob: Blob }[] }
  /** Analyse extracted SBOMs (after opening, and on demand); progress per SBOM. */
  | { kind: 'sbom-analyze'; id: number; items: SbomAnalysisItem[] }
  /** Read the package lists of analysed SBOMs (when the package views need them); progress per SBOM. */
  | { kind: 'sbom-packages'; id: number; items: SbomAnalysisItem[] }
  /** Read VEX and CSAF documents; blobs of the delivery come from the source. */
  | { kind: 'vex-read'; id: number; items: VexReadItem[]; blob?: Blob; buffer?: ArrayBuffer };

export type WorkerResponse =
  | {
      kind: 'bundle';
      id: number;
      bundle: OcmBundle | null;
      extracted: { fileName: string; bytes: Uint8Array }[];
      diagnostics: Diagnostic[];
      /** open-many: which pushed file is the opened archive (re-read source). */
      sourceIndex?: number;
    }
  | { kind: 'extract'; id: number; bytes: Uint8Array | null; reason?: string }
  | { kind: 'digests-progress'; id: number; done: number; total: number }
  | { kind: 'digests'; id: number; results: DigestCheckResult[] }
  | { kind: 'sbom-progress'; id: number; done: number; total: number }
  | { kind: 'sbom-analyze'; id: number; analyses: Record<string, SbomAnalysis> }
  /** By SHA-1; null where the SBOM gave no package list. */
  | { kind: 'sbom-packages'; id: number; lists: Record<string, SbomPackageList | null> }
  | { kind: 'vex-read'; id: number; results: Record<string, VexReadResult> }
  /** The worker died (crash, out of memory); every pending job gets this. */
  | { kind: 'error'; id: number; message: string };
