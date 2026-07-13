import type { DocumentId, ElementId, NodeTarget } from '@sbomlens/core';
import { docRootSpdxIds, makeElementId, nodeKey, revealPath, workspaceRoots } from '@sbomlens/core';
import { useAppStore } from '../app/store';

/**
 * Selects an element, expanding the tree along one concrete path when the
 * element is reachable from a root; otherwise falls back to detail-only
 * selection (the tree keeps its state).
 */
export function revealElement(elementId: ElementId): void {
  const { ws, actions } = { ws: useAppStore.getState().ws, actions: useAppStore.getState().actions };
  const target: NodeTarget = { kind: 'element', elementId };
  const reveal = revealPath(ws, elementId);
  if (reveal) {
    actions.expandPaths(reveal.expand);
    actions.select({ path: reveal.path, target });
  } else {
    actions.select({ path: null, target });
  }
}

export function selectTarget(target: NodeTarget, path: string | null = null): void {
  useAppStore.getState().actions.select({ path, target });
}

/**
 * Jumps to a document in the Explore tree: roots have their own node; child
 * documents are collapsed into the tree, so their first describes-root
 * element stands in for them.
 */
export function revealDocument(docId: DocumentId): void {
  const state = useAppStore.getState();
  state.actions.setView('explore');
  const roots = new Set(workspaceRoots(state.ws));
  if (roots.has(docId)) {
    const target: NodeTarget = { kind: 'document', docId };
    state.actions.select({ path: nodeKey(target), target });
    return;
  }
  const loaded = state.ws.documents.get(docId);
  const rootSpdxId = loaded ? docRootSpdxIds(loaded)[0] : undefined;
  if (loaded && rootSpdxId) {
    revealElement(makeElementId(loaded.document.id, rootSpdxId));
  } else {
    selectTarget({ kind: 'document', docId });
  }
}
