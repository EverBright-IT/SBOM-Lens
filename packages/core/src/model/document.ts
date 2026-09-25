import type { DocumentId, ElementId } from './ids';
import type { Diagnostic } from './diagnostics';
import type { OcmDocumentExt, OcmElementExt, OcmReferenceExt } from './ocm';

export type Serialization = 'json' | 'yaml' | 'tag-value' | 'xml';

export interface SpecInfo {
  model: 'spdx-2' | 'spdx-3' | 'cyclonedx' | 'ocm';
  /** Raw version string, e.g. "SPDX-2.3". */
  version: string;
  serialization: Serialization;
}

export interface Checksum {
  /** Uppercase, e.g. "SHA1", "SHA256". */
  algorithm: string;
  /** Lowercase hex. */
  value: string;
}

/** `ExternalDocumentRef: DocumentRef-X <uri> SHA1:<hash>` */
export interface ExternalDocumentRef {
  docRef: string;
  uri: string;
  checksum?: Checksum;
  /** OCM componentReference extras (digest, extraIdentity, labels). */
  ocm?: OcmReferenceExt;
}

/**
 * One side of a relationship. External refs carry the `DocumentRef-X` prefix;
 * a bare `DocumentRef-X` without an element part occurs in the wild.
 */
export type ElementRef =
  | { kind: 'local'; spdxId: string }
  | { kind: 'external'; docRef: string; spdxId: string | null }
  | { kind: 'special'; value: 'NOASSERTION' | 'NONE' };

export interface Relationship {
  from: ElementRef;
  /** Uppercase-normalized. Open set: non-standard types occur in real documents. */
  type: string;
  to: ElementRef;
  comment?: string;
}

/**
 * Lossless passthrough of everything the source said about an element,
 * for the detail/source views. JSON keeps a pointer into the parsed object;
 * tag-value keeps the ordered tag/value pairs of the block.
 */
export type RawFields =
  | { kind: 'json'; value: Record<string, unknown> }
  | { kind: 'tv'; pairs: ReadonlyArray<readonly [string, string]> };

export interface ExternalRef {
  category?: string;
  type: string;
  locator: string;
}

export interface SbomElement {
  id: ElementId;
  documentId: DocumentId;
  spdxId: string;
  kind: 'package' | 'file';
  name: string;
  /** versionInfo, or derived from the purl when absent (common in trivy output). */
  version?: string;
  purl?: string;
  supplier?: string;
  originator?: string;
  downloadLocation?: string;
  /** License fields stay raw strings — viewing, not compliance. */
  licenseConcluded?: string;
  licenseDeclared?: string;
  copyright?: string;
  /** primaryPackagePurpose, open string. */
  purpose?: string;
  description?: string;
  comment?: string;
  checksums?: Checksum[];
  externalRefs?: ExternalRef[];
  /** SPDX packageFileName / SPDX 3 software_packageFileName: the artifact as delivered. */
  fileName?: string;
  /**
   * Support status as the producer states it. SPDX 3.0.1 `supportLevel`
   * vocabulary (support, limitedSupport, endOfSupport, noSupport,
   * development, deployed, noAssertion) kept verbatim; other formats carry
   * it only through conventions the parsers name explicitly.
   */
  supportLevel?: string;
  /**
   * SPDX 2.3 ValidUntilDate (end of the support period, §7.27) or SPDX 3.0.1
   * validUntilTime (when the data should be reassessed). The two are not the
   * same statement; profiles that care say which one they read.
   */
  validUntil?: string;
  /** CycloneDX `properties[]` (name/value), verbatim; SPDX has no equivalent. */
  properties?: { name: string; value: string }[];
  /** OCM artifact extras (type, relation, access, digest, labels). */
  ocm?: OcmElementExt;
  raw: RawFields;
}

/**
 * The license string a viewer should show: concluded wins over declared;
 * NOASSERTION/NONE count as absent.
 */
export function effectiveLicense(element: SbomElement): string | undefined {
  for (const value of [element.licenseConcluded, element.licenseDeclared]) {
    if (value && value !== 'NOASSERTION' && value !== 'NONE') return value;
  }
  return undefined;
}

export interface SbomDocument {
  id: DocumentId;
  spec: SpecInfo;
  spdxId: string;
  name: string;
  namespace: string | null;
  created?: string;
  creators: string[];
  comment?: string;
  dataLicense?: string;
  /** SPDXIDs of root elements (documentDescribes ∪ DESCRIBES relationships). */
  describes: string[];
  externalDocumentRefs: ExternalDocumentRef[];
  /**
   * What kind of SBOM this is, as the producer declared it: SPDX 3.0.1
   * `software_sbomType` (design, source, build, analyzed, deployed, runtime)
   * or, for CycloneDX, the first `metadata.lifecycles[].phase`. SPDX 2.x has
   * no field for it.
   */
  sbomType?: string;
  /** CycloneDX `metadata.lifecycles[].phase` in order, when present. */
  lifecycles?: string[];
  /** Packages and files, flat. */
  elements: SbomElement[];
  relationships: Relationship[];
  diagnostics: Diagnostic[];
  /** OCM component-descriptor extras (provider, labels, contexts, signatures). */
  ocm?: OcmDocumentExt;
}
