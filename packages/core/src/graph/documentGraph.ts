import type { DocumentId } from '../model/ids';
import type { ResolutionMethod } from '../workspace/resolve';
import { refKey, splitRefKey } from '../workspace/resolve';
import type { WorkspaceState } from '../workspace/workspace';
import { workspaceRoots } from '../workspace/workspace';

/**
 * Document-level topology for the map views: documents as nodes, resolved
 * external references as edges, unresolved structural references as stubs.
 * Levels come from a BFS over resolution edges starting at the roots, so the
 * map reads top-down like the cascade itself. Within each level, one
 * barycenter pass orders items under their parents to reduce edge crossings.
 */

export interface DocGraphNode {
  docId: DocumentId;
  name: string;
  isRoot: boolean;
  level: number;
  /** Position within the level after barycenter ordering. */
  lane: number;
  packageCount: number;
}

export interface DocGraphEdge {
  from: DocumentId;
  to: DocumentId;
  method: ResolutionMethod;
}

export interface DocGraphStub {
  owningDocId: DocumentId;
  docRef: string;
  level: number;
  lane: number;
}

export interface DocumentGraph {
  nodes: DocGraphNode[];
  edges: DocGraphEdge[];
  /** Unresolved structural references, shown as dashed stub nodes. */
  stubs: DocGraphStub[];
  levelCount: number;
  maxLaneCount: number;
  /** Items (nodes + stubs) per level — lets views center each level. */
  laneCounts: readonly number[];
}

type Item =
  | { kind: 'doc'; key: string; docId: DocumentId; parentKeys: string[] }
  | { kind: 'stub'; key: string; owningDocId: DocumentId; docRef: string; parentKeys: string[] };

export function documentGraph(ws: WorkspaceState): DocumentGraph {
  const roots = workspaceRoots(ws);
  const level = new Map<DocumentId, number>();
  const queue: DocumentId[] = [];
  for (const root of roots) {
    level.set(root, 0);
    queue.push(root);
  }

  const edges: DocGraphEdge[] = [];
  const seenEdges = new Set<string>();
  while (queue.length > 0) {
    const docId = queue.shift()!;
    const currentLevel = level.get(docId)!;
    for (const [key, resolution] of ws.resolutions) {
      if (resolution.status !== 'resolved') continue;
      const { docId: owner } = splitRefKey(key);
      if (owner !== docId || resolution.targetDocId === docId) continue;
      const edgeKey = `${docId}->${resolution.targetDocId}`;
      if (!seenEdges.has(edgeKey)) {
        seenEdges.add(edgeKey);
        edges.push({ from: docId, to: resolution.targetDocId, method: resolution.method });
      }
      if (!level.has(resolution.targetDocId)) {
        level.set(resolution.targetDocId, currentLevel + 1);
        queue.push(resolution.targetDocId);
      }
    }
  }

  // Documents unreachable from any root (shouldn't happen, but stay honest).
  for (const docId of ws.order) {
    if (!level.has(docId)) level.set(docId, 0);
  }

  // -- Collect items per level: docs in ws.order, then stubs in owner order.
  const itemsPerLevel: Item[][] = [];
  const atLevel = (lvl: number): Item[] => (itemsPerLevel[lvl] ??= []);

  const parentsByChild = new Map<DocumentId, DocumentId[]>();
  for (const edge of edges) {
    if (level.get(edge.from) === level.get(edge.to)! - 1) {
      const list = parentsByChild.get(edge.to);
      if (list) list.push(edge.from);
      else parentsByChild.set(edge.to, [edge.from]);
    }
  }

  for (const docId of ws.order) {
    atLevel(level.get(docId)!).push({
      kind: 'doc',
      key: `d:${docId}`,
      docId,
      parentKeys: (parentsByChild.get(docId) ?? []).map((p) => `d:${p}`),
    });
  }
  const stubEntries: { owningDocId: DocumentId; docRef: string; level: number }[] = [];
  for (const docId of ws.order) {
    const loaded = ws.documents.get(docId)!;
    for (const ref of loaded.document.externalDocumentRefs) {
      const resolution = ws.resolutions.get(refKey(docId, ref.docRef));
      if (resolution?.status !== 'unresolved' || !resolution.structural) continue;
      const stubLevel = (level.get(docId) ?? 0) + 1;
      stubEntries.push({ owningDocId: docId, docRef: ref.docRef, level: stubLevel });
      atLevel(stubLevel).push({
        kind: 'stub',
        key: `s:${docId}:${ref.docRef}`,
        owningDocId: docId,
        docRef: ref.docRef,
        parentKeys: [`d:${docId}`],
      });
    }
  }

  // -- One barycenter pass, top-down: sort each level by mean parent lane.
  const laneOf = new Map<string, number>();
  itemsPerLevel.forEach((items, lvl) => {
    if (lvl > 0) {
      const keyed = items.map((item, index) => {
        const parentLanes = item.parentKeys
          .map((k) => laneOf.get(k))
          .filter((l): l is number => l !== undefined);
        const barycenter =
          parentLanes.length > 0
            ? parentLanes.reduce((a, b) => a + b, 0) / parentLanes.length
            : index;
        return { item, barycenter, index };
      });
      keyed.sort((a, b) => a.barycenter - b.barycenter || a.index - b.index);
      items = keyed.map((k) => k.item);
      itemsPerLevel[lvl] = items;
    }
    items.forEach((item, lane) => laneOf.set(item.key, lane));
  });

  const laneCounts = itemsPerLevel.map((items) => items.length);
  const rootSet = new Set(roots);

  const nodes: DocGraphNode[] = ws.order.map((docId) => {
    const loaded = ws.documents.get(docId)!;
    return {
      docId,
      name: loaded.document.name,
      isRoot: rootSet.has(docId),
      level: level.get(docId)!,
      lane: laneOf.get(`d:${docId}`)!,
      packageCount: loaded.indexes.packageCount,
    };
  });

  const stubs: DocGraphStub[] = stubEntries.map((stub) => ({
    owningDocId: stub.owningDocId,
    docRef: stub.docRef,
    level: stub.level,
    lane: laneOf.get(`s:${stub.owningDocId}:${stub.docRef}`)!,
  }));

  return {
    nodes,
    edges,
    stubs,
    levelCount: laneCounts.length,
    maxLaneCount: Math.max(0, ...laneCounts),
    laneCounts,
  };
}
