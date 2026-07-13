import { reachableDocs } from '../analysis/diff';
import type { DocumentId } from '../model/ids';
import type { WorkspaceState } from './workspace';
import { workspaceRoots } from './workspace';

/**
 * Planning for cascade-aware removal: removing a document silently turns its
 * exclusive children into new workspace roots. This computes who those
 * children are, so the UI can ask instead of surprising.
 */

export interface RemovalPlan {
  /** The requested docs that are actually loaded, in ws.order. */
  requested: DocumentId[];
  /** Docs reachable only through the requested set — new roots if kept. */
  orphaned: DocumentId[];
}

export function removalPlan(ws: WorkspaceState, docIds: ReadonlySet<DocumentId>): RemovalPlan {
  const requested = ws.order.filter((id) => docIds.has(id));
  const requestedSet = new Set(requested);
  if (requested.length === 0) return { requested, orphaned: [] };

  // Everything still anchored after removal: BFS from every surviving root,
  // never entering a requested doc. Removal never creates resolution edges
  // among survivors, so the post-removal graph is the current one minus the
  // requested docs.
  const kept = new Set<DocumentId>();
  for (const root of workspaceRoots(ws)) {
    if (requestedSet.has(root)) continue;
    for (const id of reachableDocs(ws, root, requestedSet)) kept.add(id);
  }

  // Everything the requested set drags along.
  const dragged = new Set<DocumentId>();
  for (const id of requested) {
    for (const d of reachableDocs(ws, id)) dragged.add(d);
  }

  const orphaned = ws.order.filter(
    (id) => dragged.has(id) && !requestedSet.has(id) && !kept.has(id),
  );
  return { requested, orphaned };
}
