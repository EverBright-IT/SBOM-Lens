import type { Diagnostic, SbomDocument } from '@sbomlens/core';

export interface ParseJobRequest {
  id: number;
  fileName: string;
  /** Transferred, not cloned. Exactly one of buffer/blob is set. */
  buffer?: ArrayBuffer;
  /**
   * Delivery archives ride as a Blob/File handle instead: Blob storage is
   * disk-backed, so a multi-GB delivery reaches the worker without ever
   * existing as one buffer. The worker reads it through slice().
   */
  blob?: Blob;
  /**
   * When set, this is a delivery-acceptance HASH job, not a parse: the worker
   * digests the bytes for these algorithms and returns the digests only — the
   * delivered bytes never cross back to the UI thread.
   */
  hashAlgorithms?: string[];
}

/** A component descriptor pre-parsed inside an archive expansion. */
export interface ExpandedDocument {
  fileName: string;
  sha1: string;
  byteSize: number;
  text: string;
  document: SbomDocument;
  diagnostics: Diagnostic[];
}

export type ParseJobResponse =
  | {
      id: number;
      ok: true;
      kind: 'document';
      fileName: string;
      sha1: string;
      byteSize: number;
      text: string;
      document: SbomDocument | null;
      diagnostics: Diagnostic[];
    }
  | {
      id: number;
      ok: true;
      /** Delivery archive: pre-parsed CDs + extracted SPDX candidates. */
      kind: 'expanded';
      fileName: string;
      documents: ExpandedDocument[];
      /** Transferred back; each entry re-enters the normal parse path. */
      extracted: { fileName: string; buffer: ArrayBuffer }[];
      diagnostics: Diagnostic[];
    }
  | {
      id: number;
      ok: true;
      /** Delivery-acceptance hash job: digests of the delivered bytes only. */
      kind: 'digest';
      fileName: string;
      byteSize: number;
      /** Algorithm (uppercase) → lowercase hex; a subset of what was asked. */
      digests: Record<string, string>;
    }
  | { id: number; ok: false; fileName: string; error: string };
