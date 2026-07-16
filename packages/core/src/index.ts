/**
 * Public surface of the framework-free core. The app layer imports only from
 * here; deep imports are reserved for core-internal code and tests.
 *
 * SPDX only — OCM component descriptors and delivery archives live behind
 * `@sbomlens/core/ocm` so a product that doesn't want them doesn't ship them.
 */
export type { DocumentId, ElementId } from './model/ids';
export { makeDocumentId, makeElementId, splitElementId } from './model/ids';
export type { Diagnostic, DiagnosticSeverity } from './model/diagnostics';
export type {
  Checksum,
  ElementRef,
  ExternalDocumentRef,
  ExternalRef,
  RawFields,
  Relationship,
  SbomDocument,
  SbomElement,
  Serialization,
  SpecInfo,
} from './model/document';

export type { ParseResult, SourceInput } from './parse/parser';
export { parseDocument } from './parse/parser';
export { sniffContainer } from './util/binary';
export type { ContainerKind } from './util/binary';
export type { Detection } from './parse/detect';
export { detect, registerYamlParser } from './parse/detect';
export { parseElementRef, refToString } from './parse/spdx2/common';

export { sha1Hex } from './util/sha1';

export type { DocumentIndexes, EdgeRec } from './graph/indexes';
export { buildIndexes } from './graph/indexes';
export type { SearchFacets, SearchHit, SearchResult } from './graph/search';
export { emptyFacets, searchWorkspace } from './graph/search';

export type { RefResolution, ResolutionMethod } from './workspace/resolve';
export { refKey, splitRefKey } from './workspace/resolve';
export type {
  AddResult,
  BatchAddResult,
  DocumentSource,
  LoadedDocument,
  WorkspaceState,
} from './workspace/workspace';
export {
  addDocument,
  addDocuments,
  bindRef,
  emptyWorkspace,
  removeDocument,
  removeDocuments,
  workspaceRoots,
} from './workspace/workspace';
export type { FetchCandidate } from './workspace/fetchPlan';
export { collectFetchCandidates } from './workspace/fetchPlan';
export type { RemovalPlan } from './workspace/removalPlan';
export { removalPlan } from './workspace/removalPlan';

export type { NodeTarget, TreeNode } from './tree/derive';
export {
  CHILD_EDGE_RULES,
  PATH_SEP,
  collectElementSubtree,
  collectSubtreePaths,
  docRootSpdxIds,
  flattenVisible,
  getChildren,
  informationalRefs,
  isChildDocument,
  nodeKey,
  pruneExpandedPaths,
  rootNodes,
  targetDocId,
} from './tree/derive';
export type { RevealTarget } from './tree/reveal';
export { revealPath } from './tree/reveal';
export type { TreeFilterResult } from './tree/filter';
export { filterTree } from './tree/filter';

export { effectiveLicense } from './model/document';
export type { InventoryRow, InventorySortKey } from './analysis/inventory';
export {
  inventoryRows,
  inventoryToCsv,
  inventoryToJson,
  sortInventory,
} from './analysis/inventory';
export type { ConflictGroup, VersionGroup, VersionOccurrence } from './analysis/conflicts';
export { NO_VERSION, findVersionConflicts, packageKey } from './analysis/conflicts';
export type { CascadeDiff, DiffChange, DiffEntry, DiffReason, DiffSide } from './analysis/diff';
export { diffCascades, diffToMarkdown, reachableDocs } from './analysis/diff';
export type { QualityReport } from './analysis/quality';
export { documentIssues, documentQuality } from './analysis/quality';

export type {
  ComplianceProfile,
  DocumentField,
  PackageField,
  ProfileCheck,
} from './profile/model';
export { MAX_PROFILE_BYTES, PROFILE_SCHEMA_V1, PROFILE_SCHEMA_V2 } from './profile/model';
export type { ProfileValidation } from './profile/validate';
export { sniffProfile, validateProfile } from './profile/validate';
export type { CoverageStat, ProfileCheckResult, ProfileReport } from './profile/evaluate';
export { evaluateProfile } from './profile/evaluate';
export { NTIA_PROFILE } from './profile/ntia';
export { BSI_TR_03183_PROFILE } from './profile/bsi';
export { profileReportToMarkdown } from './profile/markdown';

export type { SpecFieldDoc } from './spec/spdx23-field-docs';
export { SPDX23_DOCS } from './spec/spdx23-field-docs';

export type {
  DocGraphEdge,
  DocGraphNode,
  DocGraphStub,
  DocumentGraph,
} from './graph/documentGraph';
export { documentGraph } from './graph/documentGraph';
