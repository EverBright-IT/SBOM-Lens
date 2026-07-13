import { effectiveLicense } from '../model/document';
import { refKey } from '../workspace/resolve';
import type { LoadedDocument, WorkspaceState } from '../workspace/workspace';

/**
 * Factual per-document quality report, oriented on the NTIA minimum elements.
 * Deliberately no invented single score — the numbers speak for themselves.
 */

export interface QualityReport {
  document: {
    hasNamespace: boolean;
    hasCreated: boolean;
    hasCreators: boolean;
    hasRelationships: boolean;
  };
  packages: {
    total: number;
    withVersion: number;
    withSupplier: number;
    /** purl (or other cross-referenceable id from externalRefs). */
    withUniqueId: number;
    withChecksum: number;
    withLicense: number;
  };
  issues: {
    /** Relationship ends naming a local SPDXID that does not exist. */
    danglingLocalRefs: number;
    unresolvedStructuralRefs: number;
    duplicateSpdxIds: number;
  };
}

export function documentQuality(ws: WorkspaceState, loaded: LoadedDocument): QualityReport {
  const doc = loaded.document;

  const packages = {
    total: 0,
    withVersion: 0,
    withSupplier: 0,
    withUniqueId: 0,
    withChecksum: 0,
    withLicense: 0,
  };
  for (const element of doc.elements) {
    if (element.kind !== 'package') continue;
    packages.total++;
    if (element.version) packages.withVersion++;
    if (element.supplier && element.supplier !== 'NOASSERTION') packages.withSupplier++;
    if (element.purl || (element.externalRefs?.length ?? 0) > 0) packages.withUniqueId++;
    if ((element.checksums?.length ?? 0) > 0) packages.withChecksum++;
    if (effectiveLicense(element)) packages.withLicense++;
  }

  return {
    document: {
      hasNamespace: doc.namespace !== null,
      hasCreated: Boolean(doc.created),
      hasCreators: doc.creators.length > 0,
      hasRelationships: doc.relationships.length > 0,
    },
    packages,
    issues: documentIssues(ws, loaded),
  };
}

/**
 * Data-quality facts independent of any compliance profile — the UI shows
 * them alongside whichever profile is active.
 */
export function documentIssues(ws: WorkspaceState, loaded: LoadedDocument): QualityReport['issues'] {
  const doc = loaded.document;

  let danglingLocalRefs = 0;
  for (const rel of doc.relationships) {
    for (const end of [rel.from, rel.to]) {
      if (
        end.kind === 'local' &&
        end.spdxId !== doc.spdxId &&
        !loaded.indexes.elementBySpdxId.has(end.spdxId)
      ) {
        danglingLocalRefs++;
      }
    }
  }

  let unresolvedStructuralRefs = 0;
  for (const ref of doc.externalDocumentRefs) {
    const resolution = ws.resolutions.get(refKey(doc.id, ref.docRef));
    if (resolution?.status === 'unresolved' && resolution.structural) unresolvedStructuralRefs++;
  }

  const dupDiagnostic = doc.diagnostics.find((d) => d.code === 'DUP_SPDXID');
  const duplicateSpdxIds = dupDiagnostic ? Number.parseInt(dupDiagnostic.message, 10) || 0 : 0;

  return { danglingLocalRefs, unresolvedStructuralRefs, duplicateSpdxIds };
}
