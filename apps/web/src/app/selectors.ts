import type {
  ConflictGroup,
  SearchFacets,
  SearchResult,
  TreeFilterResult,
  TreeNode,
  WorkspaceState,
} from '@sbomlens/core';
import { filterTree, findVersionConflicts, flattenVisible, searchWorkspace } from '@sbomlens/core';
import { memoLast } from './memo';
import { useAppStore } from './store';

/**
 * Derived data, memoized on (wsVersion, inputs). wsVersion stands in for the
 * immutable workspace snapshot so memo keys stay primitive.
 */

const flattenMemo = memoLast(
  (ws: WorkspaceState, _version: number, expanded: ReadonlySet<string>): TreeNode[] =>
    flattenVisible(ws, expanded),
);

export function useVisibleRows(): TreeNode[] {
  const ws = useAppStore((s) => s.ws);
  const version = useAppStore((s) => s.wsVersion);
  const expanded = useAppStore((s) => s.expanded);
  return flattenMemo(ws, version, expanded);
}

const searchMemo = memoLast(
  (
    ws: WorkspaceState,
    _version: number,
    query: string,
    facets: SearchFacets,
  ): SearchResult => searchWorkspace(ws, query, facets),
);

const facetsMemo = memoLast(
  (
    docs: SearchFacets['docs'],
    kinds: SearchFacets['kinds'],
    purposes: SearchFacets['purposes'],
    licenses: SearchFacets['licenses'],
  ): SearchFacets => ({ docs, kinds, purposes, licenses }),
);

export function useSearchFacets(): SearchFacets {
  const docs = useAppStore((s) => s.facetDocs);
  const kinds = useAppStore((s) => s.facetKinds);
  const purposes = useAppStore((s) => s.facetPurposes);
  const licenses = useAppStore((s) => s.facetLicenses);
  return facetsMemo(docs, kinds, purposes, licenses);
}

export function useSearchResults(activeQuery: string): SearchResult {
  const ws = useAppStore((s) => s.ws);
  const version = useAppStore((s) => s.wsVersion);
  const facets = useSearchFacets();
  return searchMemo(ws, version, activeQuery, facets);
}

export function hasSearchCriteria(query: string, facets: SearchFacets): boolean {
  return (
    query.trim() !== '' || !!(facets.docs || facets.kinds || facets.purposes || facets.licenses)
  );
}

const filterMemo = memoLast(
  (ws: WorkspaceState, _version: number, query: string, facets: SearchFacets): TreeFilterResult =>
    filterTree(ws, query, facets),
);

const EMPTY_FILTER: TreeFilterResult = {
  rows: [],
  matchPaths: new Set(),
  expandedPaths: [],
  shown: 0,
  total: 0,
};

/**
 * In-place tree filter (Explore). Inactive (flag off or nothing to filter by)
 * returns a constant empty result without running the search.
 */
export function useFilteredTree(): { active: boolean; result: TreeFilterResult } {
  const ws = useAppStore((s) => s.ws);
  const version = useAppStore((s) => s.wsVersion);
  const treeFilter = useAppStore((s) => s.treeFilter);
  const query = useAppStore((s) => s.query);
  const facets = useSearchFacets();
  const active = treeFilter && hasSearchCriteria(query, facets);
  return {
    active,
    result: active ? filterMemo(ws, version, query.trim(), facets) : EMPTY_FILTER,
  };
}

export interface WorkspaceStats {
  documents: number;
  packages: number;
  files: number;
  unresolvedStructural: number;
  diagnostics: { errors: number; warnings: number; infos: number };
}

const statsMemo = memoLast((ws: WorkspaceState, _version: number, failureDiagnostics: number): WorkspaceStats => {
  let packages = 0;
  let files = 0;
  const diagnostics = { errors: failureDiagnostics, warnings: 0, infos: 0 };
  for (const loaded of ws.documents.values()) {
    packages += loaded.indexes.packageCount;
    files += loaded.indexes.fileCount;
    for (const d of loaded.document.diagnostics) {
      if (d.severity === 'error') diagnostics.errors++;
      else if (d.severity === 'warning') diagnostics.warnings++;
      else diagnostics.infos++;
    }
  }
  let unresolvedStructural = 0;
  for (const r of ws.resolutions.values()) {
    if (r.status === 'unresolved' && r.structural) unresolvedStructural++;
  }
  return { documents: ws.documents.size, packages, files, unresolvedStructural, diagnostics };
});

export function useWorkspaceStats(): WorkspaceStats {
  const ws = useAppStore((s) => s.ws);
  const version = useAppStore((s) => s.wsVersion);
  const failures = useAppStore((s) => s.failures);
  return statsMemo(ws, version, failures.length);
}

const conflictsMemo = memoLast((ws: WorkspaceState, version: number): ConflictGroup[] => {
  void version; // memo key only
  return findVersionConflicts(ws);
});

export function useVersionConflicts(): ConflictGroup[] {
  const ws = useAppStore((s) => s.ws);
  const version = useAppStore((s) => s.wsVersion);
  return conflictsMemo(ws, version);
}
