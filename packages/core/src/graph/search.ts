import type { SbomElement } from '../model/document';
import { effectiveLicense } from '../model/document';
import type { DocumentId } from '../model/ids';
import type { WorkspaceState } from '../workspace/workspace';

export interface SearchFacets {
  docs: ReadonlySet<DocumentId> | null;
  kinds: ReadonlySet<'package' | 'file'> | null;
  purposes: ReadonlySet<string> | null;
  licenses: ReadonlySet<string> | null;
}

export const emptyFacets: SearchFacets = {
  docs: null,
  kinds: null,
  purposes: null,
  licenses: null,
};

export interface SearchHit {
  element: SbomElement;
  docId: DocumentId;
  score: number;
}

export interface SearchResult {
  hits: SearchHit[];
  /** Total matches before the limit cap. */
  total: number;
}

/**
 * One linear pass over precomputed lowercase blobs. At ~50k elements this is
 * single-digit milliseconds — the old implementation's jank came from
 * re-rendering, not from scanning. Kept behind a small interface so an
 * inverted index could replace it if profiling ever demands one.
 */
export function searchWorkspace(
  ws: WorkspaceState,
  query: string,
  facets: SearchFacets = emptyFacets,
  limit = 500,
): SearchResult {
  const q = query.trim().toLowerCase();
  const hits: SearchHit[] = [];

  for (const docId of ws.order) {
    if (facets.docs && !facets.docs.has(docId)) continue;
    const loaded = ws.documents.get(docId);
    if (!loaded) continue;
    const { elements } = loaded.document;
    const blobs = loaded.indexes.searchBlobs;

    for (let i = 0; i < elements.length; i++) {
      const element = elements[i]!;
      if (facets.kinds && !facets.kinds.has(element.kind)) continue;
      if (facets.purposes && (!element.purpose || !facets.purposes.has(element.purpose))) continue;
      if (facets.licenses) {
        const license = effectiveLicense(element);
        if (!license || !facets.licenses.has(license)) continue;
      }

      if (q === '') {
        hits.push({ element, docId, score: 0 });
        continue;
      }
      const score = scoreMatch(q, element.name.toLowerCase(), blobs[i]!);
      if (score > 0) hits.push({ element, docId, score });
    }
  }

  const total = hits.length;
  if (q !== '') hits.sort((a, b) => b.score - a.score);
  return { hits: hits.slice(0, limit), total };
}

function scoreMatch(q: string, name: string, blob: string): number {
  let base = 0;
  if (name === q) base = 1000;
  else if (name.startsWith(q)) base = 800;
  else if (name.includes(q)) base = 600;
  else if (blob.includes(q)) base = 400;
  else if (q.length >= 3 && isSubsequence(q, name)) base = 100;
  if (base === 0) return 0;
  // Tie-break toward shorter names.
  return base - Math.min(name.length, 200) / 1000;
}

function isSubsequence(q: string, s: string): boolean {
  let i = 0;
  for (let j = 0; j < s.length && i < q.length; j++) {
    if (s[j] === q[i]) i++;
  }
  return i === q.length;
}
