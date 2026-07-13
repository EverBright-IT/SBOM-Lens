import type { ElementRef, SbomDocument } from '../model/document';
import { effectiveLicense } from '../model/document';

export interface EdgeRec {
  relIndex: number;
  type: string;
  from: ElementRef;
  to: ElementRef;
}

/**
 * Per-document adjacency and lookup structures, built once at load time.
 * Everything downstream (tree expansion, search, detail views) is a cheap
 * lookup instead of a per-render scan over relationships.
 */
export interface DocumentIndexes {
  /** spdxId → index into document.elements */
  elementBySpdxId: ReadonlyMap<string, number>;
  /** local from-spdxId → edges */
  outgoing: ReadonlyMap<string, readonly EdgeRec[]>;
  /** local to-spdxId → edges */
  incoming: ReadonlyMap<string, readonly EdgeRec[]>;
  /** edges with at least one external (DocumentRef-…) end */
  externalEdges: readonly EdgeRec[];
  /** docRefs that appear in relationships — these refs are "structural" */
  structuralDocRefs: ReadonlySet<string>;
  /** lowercase "name\0version\0purl\0spdxId" per element, aligned with document.elements */
  searchBlobs: readonly string[];
  purposeCounts: ReadonlyMap<string, number>;
  /** effective license → package count (files excluded) */
  licenseCounts: ReadonlyMap<string, number>;
  packageCount: number;
  fileCount: number;
}

export function buildIndexes(doc: SbomDocument): DocumentIndexes {
  const elementBySpdxId = new Map<string, number>();
  const searchBlobs: string[] = [];
  const purposeCounts = new Map<string, number>();
  const licenseCounts = new Map<string, number>();
  let packageCount = 0;
  let fileCount = 0;

  doc.elements.forEach((el, i) => {
    elementBySpdxId.set(el.spdxId, i);
    searchBlobs.push(
      `${el.name} ${el.version ?? ''} ${el.purl ?? ''} ${el.spdxId}`.toLowerCase(),
    );
    if (el.kind === 'package') {
      packageCount++;
      const license = effectiveLicense(el);
      if (license) licenseCounts.set(license, (licenseCounts.get(license) ?? 0) + 1);
    } else {
      fileCount++;
    }
    if (el.purpose) purposeCounts.set(el.purpose, (purposeCounts.get(el.purpose) ?? 0) + 1);
  });

  const outgoing = new Map<string, EdgeRec[]>();
  const incoming = new Map<string, EdgeRec[]>();
  const externalEdges: EdgeRec[] = [];
  const structuralDocRefs = new Set<string>();

  doc.relationships.forEach((rel, relIndex) => {
    const edge: EdgeRec = { relIndex, type: rel.type, from: rel.from, to: rel.to };
    if (rel.from.kind === 'local') {
      push(outgoing, rel.from.spdxId, edge);
    }
    if (rel.to.kind === 'local') {
      push(incoming, rel.to.spdxId, edge);
    }
    if (rel.from.kind === 'external' || rel.to.kind === 'external') {
      externalEdges.push(edge);
      if (rel.from.kind === 'external') structuralDocRefs.add(rel.from.docRef);
      if (rel.to.kind === 'external') structuralDocRefs.add(rel.to.docRef);
    }
  });

  return {
    elementBySpdxId,
    outgoing,
    incoming,
    externalEdges,
    structuralDocRefs,
    searchBlobs,
    purposeCounts,
    licenseCounts,
    packageCount,
    fileCount,
  };
}

function push(map: Map<string, EdgeRec[]>, key: string, edge: EdgeRec): void {
  const list = map.get(key);
  if (list) list.push(edge);
  else map.set(key, [edge]);
}
