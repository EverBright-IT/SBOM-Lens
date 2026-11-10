import type { DocumentId, ElementId } from './ids';
import type { Diagnostic } from './diagnostics';
import type { CryptoElementExt } from './crypto';
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
  /**
   * Set by a parser on an edge it derived for the tree, not one the document
   * states: the CycloneDX flat `components[]` list rendered as CONTAINS under
   * the BOM subject. Dependency checks skip derived edges.
   */
  derived?: true;
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
  /**
   * The artifact as delivered: SPDX 2 packageFileName; SPDX 3 the name of the
   * File reached through hasDistributionArtifact (3.0.1 has no
   * packageFileName). CycloneDX has no field; the profile engine reads the
   * BSI property bsi:component:filename from `properties` instead.
   */
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
  /** CycloneDX cryptoProperties (CBOM): present on cryptographic-asset components. */
  crypto?: CryptoElementExt;
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

/**
 * Relationship types that state a dependency or containment between
 * components: SPDX 2 and 3 DEPENDS_ON, CONTAINS and their variants, which
 * CycloneDX dependencies[] and nested components map onto. DESCRIBES,
 * licence, lineage and documentation relationships are not dependencies,
 * and neither is an edge a parser derived for the tree (Relationship.derived).
 * Shared by analysis/quality.ts and the profile engine, which the NTIA
 * parity test pins against each other.
 */
const DEPENDENCY_RELATIONSHIP =
  /^(DEPENDS_ON|DEPENDENCY_OF|(DEV|BUILD|RUNTIME|OPTIONAL|PROVIDED|TEST)_DEPENDENCY_OF|HAS_(OPTIONAL|PROVIDED)_DEPENDENCY|CONTAINS|CONTAINED_BY|HAS_PREREQUISITE|PREREQUISITE_FOR|STATIC_LINK|DYNAMIC_LINK|HAS_(STATIC|DYNAMIC)_LINK|HAS_OPTIONAL_COMPONENT|OPTIONAL_COMPONENT_OF|DEV_TOOL_OF|BUILD_TOOL_OF)$/;

export function isDependencyRelationship(rel: Relationship): boolean {
  return rel.derived !== true && DEPENDENCY_RELATIONSHIP.test(rel.type);
}

/**
 * Identifier references, as opposed to references that point somewhere:
 * purl, CPE, SWID, SWHID and gitoid (TR-03183-2 5.2.4 names CPE, purl and
 * SWID; NTIA and CISA 2026 add SWHID and gitoid), plus anything an SPDX
 * document files under PACKAGE-MANAGER or PERSISTENT-ID. A website, vcs,
 * advisory, bom or url reference identifies nothing. Shared for the same
 * parity reason as isDependencyRelationship.
 */
const IDENTIFIER_CATEGORIES = new Set(['PACKAGE-MANAGER', 'PERSISTENT-ID']);
const IDENTIFIER_TYPES = /^(cpe22Type|cpe23Type|cpe22|cpe23|cpe|purl|swid|swhid|gitoid|omniborId)$/i;

export function hasUniqueIdentifier(element: SbomElement): boolean {
  if (element.purl) return true;
  return (element.externalRefs ?? []).some(
    (ref) =>
      (ref.category !== undefined && IDENTIFIER_CATEGORIES.has(ref.category.toUpperCase().replace(/_/g, '-'))) ||
      IDENTIFIER_TYPES.test(ref.type),
  );
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
  /** CycloneDX `metadata.lifecycles[]` in order: the pre-defined `phase`, or a custom lifecycle's `name`. */
  lifecycles?: string[];
  /** Packages and files, flat. */
  elements: SbomElement[];
  relationships: Relationship[];
  diagnostics: Diagnostic[];
  /** OCM component-descriptor extras (provider, labels, contexts, signatures). */
  ocm?: OcmDocumentExt;
}
