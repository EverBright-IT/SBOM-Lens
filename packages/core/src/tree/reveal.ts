import type { DocumentId, ElementId } from '../model/ids';
import { makeElementId, splitElementId } from '../model/ids';
import { splitRefKey } from '../workspace/resolve';
import type { WorkspaceState } from '../workspace/workspace';
import {
  CHILD_EDGE_RULES,
  PATH_SEP,
  docRootSpdxIds,
  informationalRefs,
  nodeKey,
} from './derive';

export interface RevealTarget {
  /** Full tree path of the element. */
  path: string;
  /** Ancestor paths that must be expanded for the element to be visible. */
  expand: string[];
}

/**
 * Climbs from an element up to a workspace root, producing one concrete tree
 * path (elements can appear at several places; any one suffices for reveal).
 * Returns null when the element is unreachable from the roots — the caller
 * falls back to showing details without tree navigation.
 */
export function revealPath(ws: WorkspaceState, elementId: ElementId): RevealTarget | null {
  const keys = climbElement(ws, elementId, new Set());
  if (!keys) return null;
  const expand: string[] = [];
  for (let i = 1; i < keys.length; i++) {
    expand.push(keys.slice(0, i).join(PATH_SEP));
  }
  return { path: keys.join(PATH_SEP), expand };
}

function climbElement(
  ws: WorkspaceState,
  elementId: ElementId,
  visited: Set<string>,
): string[] | null {
  const key = nodeKey({ kind: 'element', elementId });
  if (visited.has(key) || visited.size > 128) return null;
  visited.add(key);

  const { documentId, spdxId } = splitElementId(elementId);
  const loaded = ws.documents.get(documentId);
  if (!loaded) return null;

  // Parent inside the same document via a child-edge rule.
  for (const rule of CHILD_EDGE_RULES) {
    const edges =
      rule.direction === 'forward'
        ? loaded.indexes.incoming.get(spdxId)
        : loaded.indexes.outgoing.get(spdxId);
    if (!edges) continue;
    for (const edge of edges) {
      if (edge.type !== rule.type || edge.type === 'DESCRIBES') continue;
      const parentEnd = rule.direction === 'forward' ? edge.from : edge.to;
      if (parentEnd.kind !== 'local' || parentEnd.spdxId === spdxId) continue;
      if (!loaded.indexes.elementBySpdxId.has(parentEnd.spdxId)) continue;
      const up = climbElement(ws, makeElementId(documentId, parentEnd.spdxId), visited);
      if (up) return [...up, key];
    }
  }

  // Root element of its document → continue at the document boundary.
  if (docRootSpdxIds(loaded).includes(spdxId)) {
    const container = climbDocument(ws, documentId, spdxId, visited);
    if (container) return [...container, key];
  }
  return null;
}

/**
 * Path of the container under which a given document's root elements appear:
 * the document node itself for workspace roots and informational-ref targets,
 * or the referencing element for structural (collapsed/element-hop) refs.
 */
function climbDocument(
  ws: WorkspaceState,
  docId: DocumentId,
  rootSpdxId: string,
  visited: Set<string>,
): string[] | null {
  for (const [key, resolution] of ws.resolutions) {
    if (resolution.status !== 'resolved' || resolution.targetDocId !== docId) continue;
    const { docId: ownerId, docRef } = splitRefKey(key);
    if (ownerId === docId) continue;
    const owner = ws.documents.get(ownerId);
    if (!owner) continue;

    // Structural ref: find the local element whose relationship crosses into us.
    for (const rule of CHILD_EDGE_RULES) {
      for (const edge of owner.indexes.externalEdges) {
        if (edge.type !== rule.type) continue;
        const end = rule.direction === 'forward' ? edge.to : edge.from;
        const localEnd = rule.direction === 'forward' ? edge.from : edge.to;
        if (end.kind !== 'external' || end.docRef !== docRef) continue;
        if (localEnd.kind !== 'local') continue;
        // Direct element hops only reveal the referenced element's subtree.
        const isCollapse =
          end.spdxId === null ||
          end.spdxId === ws.documents.get(docId)?.document.spdxId ||
          !ws.documents.get(docId)?.indexes.elementBySpdxId.has(end.spdxId);
        if (!isCollapse && end.spdxId !== rootSpdxId) continue;
        const parentPath = climbElement(ws, makeElementId(ownerId, localEnd.spdxId), visited);
        if (parentPath) return parentPath;
      }
    }

    // Informational ref: document node under the owner's "external documents" group.
    if (informationalRefs(owner).some((r) => r.docRef === docRef)) {
      const ownerRoot = docRootSpdxIds(owner)[0];
      const groupKey = nodeKey({ kind: 'extraRefs', docId: ownerId });
      const docKey = nodeKey({ kind: 'document', docId });
      const ownerIsRoot = climbDocumentNodePath(ws, ownerId, visited);
      if (ownerIsRoot) return [...ownerIsRoot, groupKey, docKey];
      if (ownerRoot) {
        const viaRoot = climbElement(ws, makeElementId(ownerId, ownerRoot), visited);
        if (viaRoot) return [...viaRoot, groupKey, docKey];
      }
    }
  }

  return climbDocumentNodePath(ws, docId, visited);
}

/** Path of a document rendered as its own node (workspace root), else null. */
function climbDocumentNodePath(
  ws: WorkspaceState,
  docId: DocumentId,
  visited: Set<string>,
): string[] | null {
  void visited;
  for (const [key, resolution] of ws.resolutions) {
    if (
      resolution.status === 'resolved' &&
      resolution.targetDocId === docId &&
      splitRefKey(key).docId !== docId
    ) {
      return null; // child document — has no root-level node
    }
  }
  return ws.documents.has(docId) ? [nodeKey({ kind: 'document', docId })] : null;
}
