import type { ElementRef } from '../model/document';
import type { DocumentId, ElementId } from '../model/ids';
import { makeElementId, splitElementId } from '../model/ids';
import { refKey, splitRefKey } from '../workspace/resolve';
import type { LoadedDocument, WorkspaceState } from '../workspace/workspace';
import { workspaceRoots } from '../workspace/workspace';

/**
 * Lazy tree derivation over the cross-document graph. Nothing is materialized:
 * children are computed per expanded node from the adjacency indexes, so a
 * late-arriving document simply changes what the next derivation returns.
 */

export const PATH_SEP = '\u0001';

export type NodeTarget =
  | { kind: 'document'; docId: DocumentId }
  | { kind: 'element'; elementId: ElementId }
  | { kind: 'placeholder'; owningDocId: DocumentId; docRef: string; spdxId: string | null }
  | { kind: 'extraRefs'; docId: DocumentId }
  | { kind: 'cycle'; elementId: ElementId };

export interface TreeNode {
  /** PATH_SEP-joined node keys from root — identity for expansion/selection. */
  path: string;
  depth: number;
  target: NodeTarget;
  /** Relationship type that produced this node (undefined for roots). */
  edgeType?: string;
  hasChildren: boolean;
}

/** Which relationship types define tree parenthood, and in which direction. */
export const CHILD_EDGE_RULES: ReadonlyArray<{
  type: string;
  direction: 'forward' | 'reverse';
  /** DESCRIBED_BY only cascades outward (pkg → child document), never locally. */
  externalOnly?: boolean;
}> = [
  { type: 'DESCRIBES', direction: 'forward' },
  { type: 'CONTAINS', direction: 'forward' },
  { type: 'CONTAINED_BY', direction: 'reverse' },
  { type: 'DEPENDS_ON', direction: 'forward' },
  { type: 'DEPENDENCY_OF', direction: 'reverse' },
  { type: 'DESCRIBED_BY', direction: 'forward', externalOnly: true },
];

const MAX_DEPTH = 64;

export function nodeKey(target: NodeTarget): string {
  switch (target.kind) {
    case 'document':
      return `d:${target.docId}`;
    case 'element':
      return `e:${target.elementId}`;
    case 'placeholder':
      return `p:${refKey(target.owningDocId, target.docRef)}`;
    case 'extraRefs':
      return `x:${target.docId}`;
    case 'cycle':
      return `c:${target.elementId}`;
  }
}

export function rootNodes(ws: WorkspaceState): TreeNode[] {
  return workspaceRoots(ws).map((docId) => {
    const target: NodeTarget = { kind: 'document', docId };
    return {
      path: nodeKey(target),
      depth: 0,
      target,
      hasChildren: documentHasChildren(ws, docId),
    };
  });
}

export function getChildren(ws: WorkspaceState, parent: TreeNode): TreeNode[] {
  if (parent.depth >= MAX_DEPTH) return [];
  const ancestors = new Set(parent.path.split(PATH_SEP));
  switch (parent.target.kind) {
    case 'document':
      return documentChildren(ws, parent, parent.target.docId, ancestors);
    case 'element':
      return elementChildren(ws, parent, parent.target.elementId, ancestors);
    case 'extraRefs':
      return extraRefsChildren(ws, parent, parent.target.docId, ancestors);
    case 'placeholder':
    case 'cycle':
      return [];
  }
}

/** Flattens the visible tree (roots + expanded descendants) for virtualization. */
export function flattenVisible(ws: WorkspaceState, expanded: ReadonlySet<string>): TreeNode[] {
  const rows: TreeNode[] = [];
  const stack = rootNodes(ws).reverse();
  while (stack.length > 0) {
    const node = stack.pop()!;
    rows.push(node);
    if (node.hasChildren && expanded.has(node.path)) {
      const children = getChildren(ws, node);
      for (let i = children.length - 1; i >= 0; i--) stack.push(children[i]!);
    }
  }
  return rows;
}

// -- children per node kind ---------------------------------------------------

function documentChildren(
  ws: WorkspaceState,
  parent: TreeNode,
  docId: DocumentId,
  ancestors: Set<string>,
): TreeNode[] {
  const loaded = ws.documents.get(docId);
  if (!loaded) return [];
  const children: TreeNode[] = [];
  for (const spdxId of docRootSpdxIds(loaded)) {
    appendElementNode(ws, children, ancestors, parent, docId, spdxId, 'DESCRIBES');
  }
  appendExtraRefsGroup(ws, children, parent, docId);
  return dedupe(children);
}

function elementChildren(
  ws: WorkspaceState,
  parent: TreeNode,
  elementId: ElementId,
  ancestors: Set<string>,
): TreeNode[] {
  const { documentId, spdxId } = splitElementId(elementId);
  const loaded = ws.documents.get(documentId);
  if (!loaded) return [];

  const children: TreeNode[] = [];
  for (const rule of CHILD_EDGE_RULES) {
    const edges =
      rule.direction === 'forward'
        ? loaded.indexes.outgoing.get(spdxId)
        : loaded.indexes.incoming.get(spdxId);
    if (!edges) continue;
    for (const edge of edges) {
      if (edge.type !== rule.type) continue;
      const end: ElementRef = rule.direction === 'forward' ? edge.to : edge.from;
      if (end.kind === 'special') continue;
      if (rule.externalOnly && end.kind !== 'external') continue;

      if (end.kind === 'local') {
        if (loaded.indexes.elementBySpdxId.has(end.spdxId) && end.spdxId !== spdxId) {
          appendElementNode(ws, children, ancestors, parent, documentId, end.spdxId, edge.type);
        }
        continue;
      }

      // Cross-document hop.
      const resolution = ws.resolutions.get(refKey(documentId, end.docRef));
      if (!resolution || resolution.status === 'unresolved') {
        children.push(
          makeNode(parent, {
            kind: 'placeholder',
            owningDocId: documentId,
            docRef: end.docRef,
            spdxId: end.spdxId,
          }, edge.type, false),
        );
        continue;
      }
      const target = ws.documents.get(resolution.targetDocId);
      if (!target) continue;
      const targetDocId = target.document.id;
      if (
        end.spdxId !== null &&
        end.spdxId !== target.document.spdxId &&
        target.indexes.elementBySpdxId.has(end.spdxId)
      ) {
        // Direct element reference into the other document.
        appendElementNode(ws, children, ancestors, parent, targetDocId, end.spdxId, edge.type);
      } else {
        // DocumentRef-X:SPDXRef-DOCUMENT (or dangling element): collapse the
        // document boundary — splice its roots so the cascade reads
        // release → component → leaf without artificial document rows.
        for (const rootId of docRootSpdxIds(target)) {
          appendElementNode(ws, children, ancestors, parent, targetDocId, rootId, edge.type);
        }
      }
    }
  }

  // A describes-root of a child document represents that document in the
  // tree; its document-level informational refs surface here.
  if (isChildDocument(ws, documentId) && docRootSpdxIds(loaded)[0] === spdxId) {
    appendExtraRefsGroup(ws, children, parent, documentId);
  }

  return dedupe(children);
}

function extraRefsChildren(
  ws: WorkspaceState,
  parent: TreeNode,
  docId: DocumentId,
  ancestors: Set<string>,
): TreeNode[] {
  const loaded = ws.documents.get(docId);
  if (!loaded) return [];
  const children: TreeNode[] = [];
  for (const ref of informationalRefs(loaded)) {
    const resolution = ws.resolutions.get(refKey(docId, ref.docRef));
    if (resolution?.status === 'resolved' && ws.documents.has(resolution.targetDocId)) {
      const target: NodeTarget = { kind: 'document', docId: resolution.targetDocId };
      if (ancestors.has(nodeKey(target))) continue;
      children.push(
        makeNode(parent, target, 'EXTERNAL_DOCUMENT', documentHasChildren(ws, resolution.targetDocId)),
      );
    } else {
      children.push(
        makeNode(parent, {
          kind: 'placeholder',
          owningDocId: docId,
          docRef: ref.docRef,
          spdxId: null,
        }, 'EXTERNAL_DOCUMENT', false),
      );
    }
  }
  return dedupe(children);
}

// -- shared helpers -------------------------------------------------------------

function makeNode(
  parent: TreeNode,
  target: NodeTarget,
  edgeType: string | undefined,
  hasChildren: boolean,
): TreeNode {
  return {
    path: `${parent.path}${PATH_SEP}${nodeKey(target)}`,
    depth: parent.depth + 1,
    target,
    edgeType,
    hasChildren,
  };
}

function appendElementNode(
  ws: WorkspaceState,
  out: TreeNode[],
  ancestors: Set<string>,
  parent: TreeNode,
  docId: DocumentId,
  spdxId: string,
  edgeType: string,
): void {
  const elementId = makeElementId(docId, spdxId);
  const target: NodeTarget = { kind: 'element', elementId };
  if (ancestors.has(nodeKey(target))) {
    out.push(makeNode(parent, { kind: 'cycle', elementId }, edgeType, false));
    return;
  }
  out.push(makeNode(parent, target, edgeType, elementHasChildren(ws, docId, spdxId)));
}

function appendExtraRefsGroup(
  ws: WorkspaceState,
  out: TreeNode[],
  parent: TreeNode,
  docId: DocumentId,
): void {
  const loaded = ws.documents.get(docId);
  if (loaded && informationalRefs(loaded).length > 0) {
    out.push(makeNode(parent, { kind: 'extraRefs', docId }, undefined, true));
  }
}

function dedupe(nodes: TreeNode[]): TreeNode[] {
  const seen = new Set<string>();
  return nodes.filter((n) => {
    if (seen.has(n.path)) return false;
    seen.add(n.path);
    return true;
  });
}

/**
 * Root elements of one document: DESCRIBES targets, falling back to packages
 * nothing points at, falling back to the first package.
 */
export function docRootSpdxIds(loaded: LoadedDocument): string[] {
  if (loaded.document.describes.length > 0) return loaded.document.describes;

  const candidates = loaded.document.elements.filter((el) => {
    if (el.kind !== 'package') return false;
    const incoming = loaded.indexes.incoming.get(el.spdxId) ?? [];
    if (incoming.some((e) => e.type === 'CONTAINS' || e.type === 'DEPENDS_ON')) return false;
    const outgoing = loaded.indexes.outgoing.get(el.spdxId) ?? [];
    if (outgoing.some((e) => e.type === 'DEPENDENCY_OF' || e.type === 'CONTAINED_BY')) return false;
    return true;
  });
  if (candidates.length > 0) return candidates.map((el) => el.spdxId);

  const firstPackage = loaded.document.elements.find((el) => el.kind === 'package');
  return firstPackage ? [firstPackage.spdxId] : [];
}

/** Refs no relationship consumes — scan reports, license attestations, etc. */
export function informationalRefs(loaded: LoadedDocument) {
  return loaded.document.externalDocumentRefs.filter(
    (ref) => !loaded.indexes.structuralDocRefs.has(ref.docRef),
  );
}

/**
 * Recursively collects the expansion paths of a node's entire subtree —
 * "show me everything under CMP", across document boundaries. Capped so a
 * 50k-package cascade cannot freeze the UI.
 */
export function collectSubtreePaths(
  ws: WorkspaceState,
  root: TreeNode,
  cap = 2000,
): { paths: string[]; capped: boolean } {
  const paths: string[] = [];
  const stack: TreeNode[] = [root];
  let capped = false;
  while (stack.length > 0) {
    const node = stack.pop()!;
    if (!node.hasChildren) continue;
    if (paths.length >= cap) {
      capped = true;
      break;
    }
    paths.push(node.path);
    for (const child of getChildren(ws, node)) stack.push(child);
  }
  return { paths, capped };
}

/**
 * Collects the element ids of an element's entire subtree — everything a
 * component transitively contains/depends on, across resolved document
 * boundaries (sub-SBOM roots are spliced in exactly like the tree renders
 * them). Unresolved references contribute nothing. The start element is
 * included. Capped so a pathological graph cannot freeze the UI.
 */
export function collectElementSubtree(
  ws: WorkspaceState,
  start: ElementId,
  cap = 50000,
): { ids: Set<ElementId>; capped: boolean } {
  const ids = new Set<ElementId>();
  const stack: ElementId[] = [start];
  let capped = false;
  while (stack.length > 0) {
    const id = stack.pop()!;
    if (ids.has(id)) continue;
    if (ids.size >= cap) {
      capped = true;
      break;
    }
    ids.add(id);
    const { documentId, spdxId } = splitElementId(id);
    const loaded = ws.documents.get(documentId);
    if (!loaded) continue;
    for (const rule of CHILD_EDGE_RULES) {
      const edges =
        rule.direction === 'forward'
          ? loaded.indexes.outgoing.get(spdxId)
          : loaded.indexes.incoming.get(spdxId);
      if (!edges) continue;
      for (const edge of edges) {
        if (edge.type !== rule.type) continue;
        const end: ElementRef = rule.direction === 'forward' ? edge.to : edge.from;
        if (end.kind === 'special') continue;
        if (rule.externalOnly && end.kind !== 'external') continue;

        if (end.kind === 'local') {
          if (loaded.indexes.elementBySpdxId.has(end.spdxId) && end.spdxId !== spdxId) {
            stack.push(makeElementId(documentId, end.spdxId));
          }
          continue;
        }

        const resolution = ws.resolutions.get(refKey(documentId, end.docRef));
        if (!resolution || resolution.status === 'unresolved') continue;
        const target = ws.documents.get(resolution.targetDocId);
        if (!target) continue;
        if (
          end.spdxId !== null &&
          end.spdxId !== target.document.spdxId &&
          target.indexes.elementBySpdxId.has(end.spdxId)
        ) {
          stack.push(makeElementId(target.document.id, end.spdxId));
        } else {
          for (const rootId of docRootSpdxIds(target)) {
            stack.push(makeElementId(target.document.id, rootId));
          }
        }
      }
    }
  }
  return { ids, capped };
}

/** The document a node target belongs to. */
export function targetDocId(target: NodeTarget): DocumentId {
  switch (target.kind) {
    case 'document':
    case 'extraRefs':
      return target.docId;
    case 'element':
    case 'cycle':
      return splitElementId(target.elementId).documentId;
    case 'placeholder':
      return target.owningDocId;
  }
}

/**
 * Drops expansion paths that touch a removed document. Stale entries would
 * silently re-expand if the same (namespace-keyed) document is re-added.
 * Returns the same Set instance when nothing changed.
 */
export function pruneExpandedPaths(
  expanded: ReadonlySet<string>,
  removedDocs: ReadonlySet<DocumentId>,
): ReadonlySet<string> {
  if (removedDocs.size === 0 || expanded.size === 0) return expanded;
  const keep = new Set<string>();
  let changed = false;
  for (const path of expanded) {
    const touchesRemoved = path.split(PATH_SEP).some((segment) => {
      const kind = segment.slice(0, 2);
      const rest = segment.slice(2);
      switch (kind) {
        case 'd:':
        case 'x:':
          return removedDocs.has(rest as DocumentId);
        case 'e:':
        case 'c:':
          return removedDocs.has(splitElementId(rest as ElementId).documentId);
        case 'p:':
          return removedDocs.has(splitRefKey(rest).docId);
        default:
          return false;
      }
    });
    if (touchesRemoved) changed = true;
    else keep.add(path);
  }
  return changed ? keep : expanded;
}

export function isChildDocument(ws: WorkspaceState, docId: DocumentId): boolean {
  for (const [key, resolution] of ws.resolutions) {
    if (
      resolution.status === 'resolved' &&
      resolution.targetDocId === docId &&
      splitRefKey(key).docId !== docId
    ) {
      return true;
    }
  }
  return false;
}

function documentHasChildren(ws: WorkspaceState, docId: DocumentId): boolean {
  const loaded = ws.documents.get(docId);
  if (!loaded) return false;
  return docRootSpdxIds(loaded).length > 0 || informationalRefs(loaded).length > 0;
}

function elementHasChildren(ws: WorkspaceState, docId: DocumentId, spdxId: string): boolean {
  const loaded = ws.documents.get(docId);
  if (!loaded) return false;
  for (const rule of CHILD_EDGE_RULES) {
    const edges =
      rule.direction === 'forward'
        ? loaded.indexes.outgoing.get(spdxId)
        : loaded.indexes.incoming.get(spdxId);
    if (!edges) continue;
    for (const edge of edges) {
      if (edge.type !== rule.type) continue;
      const end = rule.direction === 'forward' ? edge.to : edge.from;
      if (end.kind === 'special') continue;
      if (rule.externalOnly && end.kind !== 'external') continue;
      if (end.kind === 'local') {
        if (end.spdxId !== spdxId && loaded.indexes.elementBySpdxId.has(end.spdxId)) return true;
      } else {
        return true; // placeholder or collapse — either way, expandable
      }
    }
  }
  if (isChildDocument(ws, docId) && docRootSpdxIds(loaded)[0] === spdxId) {
    return informationalRefs(loaded).length > 0;
  }
  return false;
}
