import type { Diagnostic } from './diagnostics';
import type {
  OcmAccessInfo,
  OcmBlobInfo,
  OcmDigest,
  OcmLabel,
  OcmRepositoryContext,
  OcmSignatureInfo,
} from './ocm';

/**
 * The OCM-native bundle model: what a delivery IS, in the spec's own
 * vocabulary — component versions aggregated by reference, artifacts with
 * access specifications, a flat content-addressed blob store. This is the
 * data model of OCM Lens 2.0; nothing here knows about SPDX documents.
 *
 * Spec grounding (ocm-spec, 2026-10): aggregation is logical, by identity
 * (componentName + version), with no depth limit — a CTF materializes "the
 * complete closure" as a flat set of component versions. The spec is silent
 * on cycles and diamonds, so the graph here records both explicitly instead
 * of assuming a tree.
 */

/** Stable in-bundle id for a component version: `name@version`. */
export type OcmCvId = string;

export function ocmCvId(name: string, version: string): OcmCvId {
  return `${name}@${version}`;
}

/**
 * Where an artifact's bytes live relative to this bundle — the transport
 * dimension (by-value vs. by-reference) that decides air-gap fitness:
 * - `transported`: a localBlob whose bytes are in the archive.
 * - `external`: a known remote access type (ociArtifact, github, s3, ...);
 *   deploying from this bundle needs network.
 * - `broken`: declared as localBlob but the referenced blob is missing.
 * - `none`: no access specification at all.
 * - `unknown`: an access type this viewer cannot classify.
 */
export type OcmTransport = 'transported' | 'external' | 'broken' | 'none' | 'unknown';

export interface OcmArtifactSbom {
  format: 'spdx' | 'cyclonedx';
  /** File name of the extracted SBOM (also its entry in `extracted`). */
  fileName: string;
  size: number;
  sha1: string;
  /** Media type for saving the file, from content detection. */
  contentType: string;
  /** Index into OcmBundleResult.extracted for download/handoff. */
  extractedIndex: number;
}

export interface OcmArtifact {
  role: 'resource' | 'source';
  name: string;
  version?: string;
  /** Artifact type (ociImage, helmChart, blob, ...); SOURCE types for sources. */
  type?: string;
  relation?: string;
  extraIdentity?: Record<string, string>;
  access?: OcmAccessInfo;
  digest?: OcmDigest;
  labels?: OcmLabel[];
  /** Inspection summary when the bytes are in the bundle (worker-side). */
  blob?: OcmBlobInfo;
  /**
   * The resource declares itself an SBOM (type sbom/spdx/cyclonedx/cdx or
   * an SBOM media type), whether or not its bytes could be extracted: an
   * external or unreadable SBOM still counts as declared.
   */
  isSbom?: boolean;
  /** Present when this artifact carries an embedded SBOM that was extracted. */
  sbom?: OcmArtifactSbom;
  /** Human-usable location derived from the access spec (image ref, URL, ...). */
  location?: string;
  transport: OcmTransport;
  /** Verbatim artifact node from the descriptor. */
  raw: Record<string, unknown>;
}

export interface OcmRef {
  name: string;
  componentName: string;
  version: string;
  extraIdentity?: Record<string, string>;
  digest?: OcmDigest;
  labels?: OcmLabel[];
  /** In-bundle resolution; undefined = the target is not in this bundle. */
  target?: OcmCvId;
  /** True when following this edge would close a reference cycle. */
  cyclic?: boolean;
}

export interface OcmCv {
  id: OcmCvId;
  name: string;
  version: string;
  /** Descriptor schema: "v2" | "v3alpha1" (best-effort). */
  schemaVersion: string;
  provider?: { name?: string; labels?: OcmLabel[] };
  creationTime?: string;
  labels?: OcmLabel[];
  repositoryContexts?: OcmRepositoryContext[];
  signatures?: OcmSignatureInfo[];
  resources: OcmArtifact[];
  sources: OcmArtifact[];
  references: OcmRef[];
  /**
   * Verbatim parsed descriptor root — the source view, and the exact input
   * signature verification normalizes (never a re-serialization).
   */
  raw: Record<string, unknown>;
  serialization: 'json' | 'yaml';
  text: string;
  sha1: string;
  byteSize: number;
  fileName: string;
  /** Per-CV findings: structural lint, mapping notes, digest mismatches. */
  diagnostics: Diagnostic[];
}

export interface OcmBlobStat {
  /** Canonical digest spelling (`sha256:<hex>`). */
  digest: string;
  size: number;
  mediaType?: string;
  /** Component versions whose descriptor references this blob. */
  referencedBy: OcmCvId[];
}

export interface OcmCompleteness {
  /** Resource counts by transport class (sources are provenance, not gated). */
  transported: number;
  external: number;
  broken: number;
  unknown: number;
  none: number;
  /** References whose target component version is not in this bundle. */
  unresolvedRefs: number;
  /**
   * True when deploying from this bundle alone needs no network: every
   * resource is transported (or has no content) and the reference closure
   * is complete.
   */
  airGapReady: boolean;
}

export interface OcmBundle {
  fileName: string;
  /**
   * How the delivery is organized — CTF index, component archive, or a bare
   * component descriptor opened without a container.
   */
  layout: 'ctf' | 'component-archive' | 'descriptor';
  /** Whether the container arrived gzip-compressed (.tgz). */
  compressed: boolean;
  archiveSize: number;
  componentVersions: OcmCv[];
  /** CVs no in-bundle reference points at — the entry points of the delivery. */
  roots: OcmCvId[];
  /** CVs referenced by more than one in-bundle reference (diamonds). */
  shared: OcmCvId[];
  completeness: OcmCompleteness;
  /**
   * Present when load-time digest checking was deferred for some blobs
   * (large delivery): how many and how many bytes. Running the checks
   * (Verify view / digestDeliveryBlob) shrinks this toward absence.
   */
  digestsDeferred?: { blobs: number; bytes: number };
  /** Unique blobs by digest, largest first. */
  blobs: OcmBlobStat[];
  /** Bytes saved by content-addressed dedup (shared blobs stored once). */
  dedupSavedBytes: number;
  /** Bundle-level findings (index problems, cycles, unresolved refs, ...). */
  issues: Diagnostic[];
}

export interface OcmBundleResult {
  /** Null when the archive held no component descriptors at all. */
  bundle: OcmBundle | null;
  /** Extracted embedded SBOMs, for download or hand-off to SBOM Lens. */
  extracted: { fileName: string; bytes: Uint8Array }[];
  /** Archive-level diagnostics (fatal parse problems land here). */
  diagnostics: Diagnostic[];
}
