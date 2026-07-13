import type { DocGraphEdge, DocumentGraph } from '@sbomlens/core';
import type { DocumentId } from '@sbomlens/core';

/**
 * Left-to-right tidy-tree layout over the visible spanning tree of the
 * document graph. Levels become columns; children stack vertically, so a
 * component with 50 sub-SBOMs is a scrollable column instead of an endless
 * row. Collapsed nodes hide their subtree and carry a +N badge.
 *
 * Pure math, no React — unit-tested.
 */

export interface MapMetrics {
  nodeW: number;
  nodeH: number;
  /** Horizontal gap between columns. */
  gapX: number;
  /** Vertical distance between stacked rows (≥ nodeH). */
  rowH: number;
  pad: number;
}

export interface PlacedDoc {
  kind: 'doc';
  docId: DocumentId;
  level: number;
  x: number;
  y: number;
  /** Direct children (docs + stubs) hidden because this node is collapsed. */
  hiddenChildren: number;
  hasChildren: boolean;
  expanded: boolean;
}

export interface PlacedStub {
  kind: 'stub';
  owningDocId: DocumentId;
  docRef: string;
  x: number;
  y: number;
}

export interface MapLayout {
  docs: PlacedDoc[];
  stubs: PlacedStub[];
  /** Primary (spanning-tree) edges between visible docs. */
  treeEdges: DocGraphEdge[];
  /** Remaining DAG edges between visible docs — render de-emphasized. */
  extraEdges: DocGraphEdge[];
  contentW: number;
  contentH: number;
  /** Docs currently visible (for metrics/mode decisions). */
  visibleCount: number;
}

export function buildMapLayout(
  graph: DocumentGraph,
  expanded: ReadonlySet<DocumentId>,
  metrics: MapMetrics,
  /** Docs whose ancestor chain must be expanded (e.g. search matches). */
  forceVisible: ReadonlySet<DocumentId> = new Set(),
): MapLayout {
  const level = new Map<DocumentId, number>(graph.nodes.map((n) => [n.docId, n.level]));
  const nodeOrder = new Map<DocumentId, number>(graph.nodes.map((n, i) => [n.docId, i]));

  // Spanning tree: the primary parent of a doc is the first incoming edge
  // from the previous level (edges are emitted in BFS order).
  const primaryParent = new Map<DocumentId, DocumentId>();
  const treeEdgeSet = new Set<DocGraphEdge>();
  const extraEdges: DocGraphEdge[] = [];
  for (const edge of graph.edges) {
    if (
      !primaryParent.has(edge.to) &&
      level.get(edge.from) === (level.get(edge.to) ?? 0) - 1
    ) {
      primaryParent.set(edge.to, edge.from);
      treeEdgeSet.add(edge);
    } else {
      extraEdges.push(edge);
    }
  }

  const childDocs = new Map<DocumentId, DocumentId[]>();
  for (const [child, parent] of primaryParent) {
    const list = childDocs.get(parent);
    if (list) list.push(child);
    else childDocs.set(parent, [child]);
  }
  for (const list of childDocs.values()) {
    list.sort((a, b) => (nodeOrder.get(a) ?? 0) - (nodeOrder.get(b) ?? 0));
  }

  const stubsByOwner = new Map<DocumentId, { docRef: string }[]>();
  for (const stub of graph.stubs) {
    const list = stubsByOwner.get(stub.owningDocId);
    if (list) list.push({ docRef: stub.docRef });
    else stubsByOwner.set(stub.owningDocId, [{ docRef: stub.docRef }]);
  }

  // Effective expansion: user choices plus the ancestor chains of forced docs.
  const effectiveExpanded = new Set(expanded);
  for (const target of forceVisible) {
    let cursor = primaryParent.get(target);
    let guard = 0;
    while (cursor !== undefined && guard++ < 64) {
      effectiveExpanded.add(cursor);
      cursor = primaryParent.get(cursor);
    }
  }

  const directChildCount = (docId: DocumentId): number =>
    (childDocs.get(docId)?.length ?? 0) + (stubsByOwner.get(docId)?.length ?? 0);

  // Post-order placement: leaves take one row; parents center on their block.
  const docs: PlacedDoc[] = [];
  const stubs: PlacedStub[] = [];
  const visibleDocs = new Set<DocumentId>();
  let cursor = 0;
  let maxLevel = 0;

  const x = (lvl: number) => metrics.pad + lvl * (metrics.nodeW + metrics.gapX);

  const placeDoc = (docId: DocumentId, lvl: number): number => {
    visibleDocs.add(docId);
    maxLevel = Math.max(maxLevel, lvl);
    const isExpanded = effectiveExpanded.has(docId);
    const children = isExpanded ? (childDocs.get(docId) ?? []) : [];
    const ownStubs = isExpanded ? (stubsByOwner.get(docId) ?? []) : [];

    let y: number;
    if (children.length === 0 && ownStubs.length === 0) {
      y = metrics.pad + cursor * metrics.rowH;
      cursor += 1;
    } else {
      const childYs: number[] = [];
      for (const child of children) childYs.push(placeDoc(child, lvl + 1));
      for (const stub of ownStubs) {
        const sy = metrics.pad + cursor * metrics.rowH;
        cursor += 1;
        maxLevel = Math.max(maxLevel, lvl + 1);
        stubs.push({ kind: 'stub', owningDocId: docId, docRef: stub.docRef, x: x(lvl + 1), y: sy });
        childYs.push(sy);
      }
      y = (childYs[0]! + childYs[childYs.length - 1]!) / 2;
    }

    docs.push({
      kind: 'doc',
      docId,
      level: lvl,
      x: x(lvl),
      y,
      hiddenChildren: isExpanded ? 0 : directChildCount(docId),
      hasChildren: directChildCount(docId) > 0,
      expanded: isExpanded,
    });
    return y;
  };

  for (const node of graph.nodes) {
    if (node.isRoot) placeDoc(node.docId, 0);
  }
  // Honesty fallback: docs unreachable from any root still render.
  for (const node of graph.nodes) {
    if (!visibleDocs.has(node.docId) && !primaryParent.has(node.docId)) {
      placeDoc(node.docId, node.level);
    }
  }

  const treeEdges = [...treeEdgeSet].filter(
    (e) => visibleDocs.has(e.from) && visibleDocs.has(e.to),
  );
  const visibleExtraEdges = extraEdges.filter(
    (e) => visibleDocs.has(e.from) && visibleDocs.has(e.to),
  );

  return {
    docs,
    stubs,
    treeEdges,
    extraEdges: visibleExtraEdges,
    contentW: metrics.pad * 2 + (maxLevel + 1) * (metrics.nodeW + metrics.gapX) - metrics.gapX,
    contentH: metrics.pad * 2 + Math.max(cursor, 1) * metrics.rowH - (metrics.rowH - metrics.nodeH),
    visibleCount: docs.length + stubs.length,
  };
}

/** Default expansion policy: everything for small graphs, roots otherwise. */
export function defaultExpansion(graph: DocumentGraph, threshold = 24): Set<DocumentId> {
  if (graph.nodes.length + graph.stubs.length <= threshold) {
    return new Set(graph.nodes.map((n) => n.docId));
  }
  return new Set(graph.nodes.filter((n) => n.isRoot).map((n) => n.docId));
}
