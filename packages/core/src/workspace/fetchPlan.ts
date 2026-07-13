import type { DocumentId } from '../model/ids';
import { refKey } from './resolve';
import type { WorkspaceState } from './workspace';

/**
 * Planning for "fetch the whole cascade": which unresolved references are
 * worth downloading right now. Called repeatedly — every fetched document may
 * expose new references, so the caller loops to a fixpoint.
 */

export interface FetchCandidate {
  url: string;
  docRef: string;
  owningDocId: DocumentId;
  structural: boolean;
}

/** Heuristic for informational refs: only URLs that plausibly are SPDX docs. */
const SBOM_LIKE_URL = /\.(spdx|json|ya?ml)([?#]|$)/i;

/** Fetching only makes sense for web URLs — `ocm://` component references
 * and other synthetic schemes resolve by loading the delivery, not by HTTP. */
function isFetchableUrl(url: string): boolean {
  const scheme = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(url)?.[1];
  return scheme === undefined || scheme === 'http' || scheme === 'https';
}

/**
 * Structural references are always candidates — they are part of the tree.
 * Informational references (scan reports, attestations) are only fetched when
 * their URL looks like an SPDX document; tarballs and PDFs would just fail.
 * URLs in `exclude` (already attempted) and duplicates are skipped.
 */
export function collectFetchCandidates(
  ws: WorkspaceState,
  exclude: ReadonlySet<string> = new Set(),
): FetchCandidate[] {
  const seen = new Set<string>();
  const candidates: FetchCandidate[] = [];
  for (const docId of ws.order) {
    const loaded = ws.documents.get(docId);
    if (!loaded) continue;
    for (const ref of loaded.document.externalDocumentRefs) {
      const resolution = ws.resolutions.get(refKey(docId, ref.docRef));
      if (resolution?.status !== 'unresolved') continue;
      const url = ref.uri.trim();
      if (!url || !isFetchableUrl(url) || exclude.has(url) || seen.has(url)) continue;
      if (!resolution.structural && !SBOM_LIKE_URL.test(url)) continue;
      seen.add(url);
      candidates.push({ url, docRef: ref.docRef, owningDocId: docId, structural: resolution.structural });
    }
  }
  return candidates;
}
