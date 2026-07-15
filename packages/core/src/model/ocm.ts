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
}

/** Extra data on a componentReference-backed external document ref. */
export interface OcmReferenceExt {
  componentName?: string;
  digest?: OcmDigest;
  extraIdentity?: Record<string, string>;
  labels?: OcmLabel[];
}
