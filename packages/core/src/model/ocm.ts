/**
 * OCM-native extension data. The SPDX-shaped base model stays the shared
 * substrate; everything the Open Component Model adds beyond it (labels,
 * access specs, signatures, repository contexts, identities) rides in
 * optional `ocm` attachments on document/element/reference. Presence of
 * `ocm` gates all OCM-specific UI — SPDX parsers never touch these.
 */

export interface OcmLabel {
  name: string;
  /** Verbatim label value — objects render pretty-printed. */
  value: unknown;
  /** Labels with `signing: true` are part of the signed payload. */
  signing?: boolean;
  version?: string;
}

/** The OCM digest triple (hash + normalization + value). */
export interface OcmDigest {
  hashAlgorithm?: string;
  normalisationAlgorithm?: string;
  value?: string;
}

export interface OcmSignatureInfo {
  name?: string;
  digest?: OcmDigest;
  algorithm?: string;
  /** Signature value, typically hex — truncated in the UI, copyable. */
  value?: string;
  mediaType?: string;
  issuer?: string;
}

export interface OcmRepositoryContext {
  type?: string;
  baseUrl?: string;
  subPath?: string;
  componentNameMapping?: string;
}

export interface OcmAccessInfo {
  type?: string;
  /** The full access node, verbatim — rendered as key/value rows. */
  raw: Record<string, unknown>;
}

/** Extra data on an OCM component-descriptor document. */
export interface OcmDocumentExt {
  schemaVersion: string;
  provider?: { name?: string; labels?: OcmLabel[] };
  labels?: OcmLabel[];
  repositoryContexts?: OcmRepositoryContext[];
  signatures?: OcmSignatureInfo[];
}

/** One previewable text pulled out of a delivery blob (hard-capped). */
export interface OcmBlobPreview {
  name: string;
  text: string;
  truncated?: boolean;
}

export interface OcmOciLayerInfo {
  digest?: string;
  size?: number;
  mediaType?: string;
}

/**
 * What a localBlob resource physically contains, inspected inside the
 * worker. Only these capped summaries cross the thread boundary; the raw
 * blob bytes never leave the parse worker.
 */
export interface OcmBlobInfo {
  /** Stored size in the delivery (before any gunzip). */
  size: number;
  mediaType?: string;
  kind: 'text' | 'json' | 'yaml' | 'binary' | 'tar' | 'helm-chart' | 'oci-artifact';
  /** True when the blob was stored gzip-compressed. */
  compressed?: boolean;
  /**
   * Result of checking the declared OCM digest against the actual bytes.
   * Only explicit genericBlobDigest/v1 and ociArtifactDigest/v1 are
   * computed — anything else stays 'unchecked' rather than risking a wrong
   * verdict. Absent when the resource declares no digest.
   */
  digestCheck?: 'match' | 'mismatch' | 'unchecked';
  previews?: OcmBlobPreview[];
  files?: { name: string; size: number }[];
  filesTruncated?: boolean;
  oci?: { layers: OcmOciLayerInfo[] };
}

/** Extra data on a component/resource/source element. */
export interface OcmElementExt {
  role: 'component' | 'resource' | 'source';
  /** Artifact type verbatim (ociImage, helmChart, sbom, …). */
  type?: string;
  relation?: string;
  extraIdentity?: Record<string, string>;
  access?: OcmAccessInfo;
  digest?: OcmDigest;
  labels?: OcmLabel[];
  /** Present only when the artifact's bytes travel inside a loaded delivery. */
  blob?: OcmBlobInfo;
}

/** Extra data on a componentReference-backed external document ref. */
export interface OcmReferenceExt {
  componentName?: string;
  digest?: OcmDigest;
  extraIdentity?: Record<string, string>;
  labels?: OcmLabel[];
}
