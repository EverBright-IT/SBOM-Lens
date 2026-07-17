import type { SbomElement } from '../model/document';
import type { ElementId } from '../model/ids';
import type { WorkspaceState } from '../workspace/workspace';

/**
 * Delivery acceptance: does what was actually delivered match what the SBOM
 * says? The SPDX-side counterpart to the OCM blob-digest check. An SBOM
 * describes files with checksums; this recomputes the delivered bytes'
 * digests (off-thread, in the worker) and compares them file by file —
 * match, mismatch (tampered or corrupt), missing (described but not
 * delivered), or unverifiable (no checksum to check against). Delivered
 * files the SBOM never mentions are surfaced as extras.
 *
 * The bytes never reach this module: hashing happens where the bytes are,
 * and only the resulting digests cross the thread boundary. Like every other
 * overlay, the verdict is derived, never written into the document model.
 */

/** A delivered file, already hashed off-thread. Carries digests, not bytes. */
export interface DeliveredFile {
  /** Path as delivered, relative to the delivery root (e.g. "src/app.js"). */
  path: string;
  size: number;
  /** Algorithm (uppercase, e.g. "SHA1", "SHA256") → lowercase hex digest. */
  digests: Record<string, string>;
}

export type AcceptanceVerdict = 'match' | 'mismatch' | 'missing' | 'unverifiable';

export interface FileAcceptance {
  elementId: ElementId;
  /** The SBOM's file name for this element. */
  path: string;
  verdict: AcceptanceVerdict;
  /** The algorithm that decided a match/mismatch (the strongest shared one). */
  algorithm?: string;
  /** Declared digest from the SBOM (present for match/mismatch). */
  declared?: string;
  /** Recomputed digest of the delivered bytes (present for match/mismatch). */
  actual?: string;
  /** Why a pair could not be verified. */
  reason?: string;
}

export interface ExtraFile {
  path: string;
  size: number;
}

export interface AcceptanceReport {
  /** One entry per file element across every loaded SBOM. */
  files: FileAcceptance[];
  /** Delivered files that matched no SBOM file, sorted by path. */
  extra: ExtraFile[];
  summary: {
    match: number;
    mismatch: number;
    missing: number;
    unverifiable: number;
    extra: number;
    /** File elements considered across the workspace. */
    total: number;
  };
}

/** Strongest first: the verdict uses the strongest algorithm both sides share. */
const ALGORITHM_STRENGTH = ['SHA512', 'SHA384', 'SHA256', 'SHA3-512', 'SHA3-256', 'SHA1', 'MD5'];

/**
 * The set of algorithms worth recomputing for a delivery: every algorithm
 * any file element in the workspace actually declares. The worker hashes
 * delivered files for exactly these, so nothing is computed that no file
 * could be checked against.
 */
export function deliveryAlgorithms(ws: WorkspaceState): string[] {
  const algorithms = new Set<string>();
  for (const loaded of ws.documents.values()) {
    for (const element of loaded.document.elements) {
      if (element.kind !== 'file') continue;
      for (const checksum of element.checksums ?? []) algorithms.add(normalizeAlgorithm(checksum.algorithm));
    }
  }
  return [...algorithms];
}

/** Whether the workspace has any file element with a checksum to check. */
export function hasVerifiableFiles(ws: WorkspaceState): boolean {
  for (const loaded of ws.documents.values()) {
    for (const element of loaded.document.elements) {
      if (element.kind === 'file' && (element.checksums?.length ?? 0) > 0) return true;
    }
  }
  return false;
}

/**
 * Match delivered files against the workspace's file inventory by path, then
 * decide each verdict by digest. Deterministic for identical inputs; the
 * order of `files` follows document then element order, `extra` is sorted.
 */
export function checkDelivery(ws: WorkspaceState, delivered: readonly DeliveredFile[]): AcceptanceReport {
  const deliveredByPath = new Map<string, DeliveredFile>();
  for (const file of delivered) deliveredByPath.set(normalizePath(file.path), file);
  const claimed = new Set<string>();

  const files: FileAcceptance[] = [];
  for (const loaded of ws.documents.values()) {
    for (const element of loaded.document.elements) {
      if (element.kind !== 'file') continue;
      const key = normalizePath(element.name);
      const match = deliveredByPath.get(key);
      if (!match) {
        files.push({ elementId: element.id, path: element.name, verdict: 'missing' });
        continue;
      }
      claimed.add(key);
      files.push(verdictFor(element, match));
    }
  }

  const extra: ExtraFile[] = delivered
    .filter((file) => !claimed.has(normalizePath(file.path)))
    .map((file) => ({ path: file.path, size: file.size }))
    .sort((a, b) => a.path.localeCompare(b.path));

  const summary = {
    match: files.filter((f) => f.verdict === 'match').length,
    mismatch: files.filter((f) => f.verdict === 'mismatch').length,
    missing: files.filter((f) => f.verdict === 'missing').length,
    unverifiable: files.filter((f) => f.verdict === 'unverifiable').length,
    extra: extra.length,
    total: files.length,
  };
  return { files, extra, summary };
}

function verdictFor(element: SbomElement, delivered: DeliveredFile): FileAcceptance {
  const declared = element.checksums ?? [];
  if (declared.length === 0) {
    return { elementId: element.id, path: element.name, verdict: 'unverifiable', reason: 'no checksum in the SBOM' };
  }
  for (const algorithm of ALGORITHM_STRENGTH) {
    const checksum = declared.find((c) => normalizeAlgorithm(c.algorithm) === algorithm);
    const actual = delivered.digests[algorithm];
    if (!checksum || actual === undefined) continue;
    const declaredHex = checksum.value.toLowerCase();
    return actual.toLowerCase() === declaredHex
      ? { elementId: element.id, path: element.name, verdict: 'match', algorithm, declared: declaredHex, actual }
      : { elementId: element.id, path: element.name, verdict: 'mismatch', algorithm, declared: declaredHex, actual };
  }
  return {
    elementId: element.id,
    path: element.name,
    verdict: 'unverifiable',
    reason: 'no checksum algorithm shared with the delivery',
  };
}

/** SPDX file names carry a leading "./"; delivery paths may carry "/". */
function normalizePath(path: string): string {
  return path.replace(/^\.?\/+/, '').replace(/\\/g, '/');
}

/** Uppercase, hyphen-collapsed: "sha-256" and "SHA256" both become "SHA256". */
function normalizeAlgorithm(algorithm: string): string {
  const upper = algorithm.toUpperCase();
  return upper.startsWith('SHA3-') ? upper : upper.replace(/-/g, '');
}
