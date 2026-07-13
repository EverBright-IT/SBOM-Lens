import type { SearchFacets } from '../graph/search';
import { searchWorkspace } from '../graph/search';
import type { WorkspaceState } from '../workspace/workspace';
import type { TreeNode } from './derive';
import { flattenVisible } from './derive';
import { revealPath } from './reveal';

export interface TreeFilterResult {
  /** Matching nodes plus their ancestors, in tree order. */
  rows: TreeNode[];
  /** Paths of the actual matches (rows minus these are context ancestors). */
  matchPaths: ReadonlySet<string>;
  /** Ancestor paths force-expanded to make the matches visible. */
  expandedPaths: readonly string[];
  /** Matches reachable in the tree (elements can be orphaned from all roots). */
  shown: number;
  /** Total search matches across the workspace, before limit and reachability. */
  total: number;
}

/**
 * Filters the Explore tree in place: search hits become the visible leaves,
 * every ancestor on their reveal path stays as context, everything else is
 * dropped. Each element keeps ONE tree position (its reveal path) even when
 * relationships would render it in several places — filtering is about
 * finding, not enumerating occurrences.
 */
export function filterTree(
  ws: WorkspaceState,
  query: string,
  facets: SearchFacets,
  limit = 500,
): TreeFilterResult {
  const result = searchWorkspace(ws, query, facets, limit);
  const expand = new Set<string>();
  const keep = new Set<string>();
  const matchPaths = new Set<string>();

  for (const hit of result.hits) {
    const reveal = revealPath(ws, hit.element.id);
    if (!reveal) continue;
    matchPaths.add(reveal.path);
    keep.add(reveal.path);
    for (const ancestor of reveal.expand) {
      expand.add(ancestor);
      keep.add(ancestor);
    }
  }

  const rows = flattenVisible(ws, expand).filter((row) => keep.has(row.path));
  return {
    rows,
    matchPaths,
    expandedPaths: [...expand],
    shown: matchPaths.size,
    total: result.total,
  };
}
