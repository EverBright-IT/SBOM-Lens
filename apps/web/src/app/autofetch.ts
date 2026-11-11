import type { DocumentId } from '@sbomlens/core';
import { collectFetchCandidates } from '@sbomlens/core';
import { ingestUrl } from './ingest';
import { useAppStore } from './store';

/**
 * "Fetch all references": downloads every fetchable unresolved reference,
 * then repeats — newly loaded documents expose new references — until the
 * cascade reaches a fixpoint. One click instead of one click per placeholder.
 *
 * A fetched document is untrusted input: whoever answers for one URL must not
 * get to decide which other hosts this browser contacts, or where a stored
 * token travels. So a document that came over the network only pulls in
 * references on its own origin. The one exception is the first round after a
 * click on "Fetch all": those placeholders are on screen, and the user asked
 * for them. What the rule holds back stays a placeholder, and fetching it is
 * the user's next click.
 */

const MAX_ROUNDS = 16;
const MAX_FETCHES = 500;
const CONCURRENCY = 4;

export interface RefFetchSummary {
  fetched: number;
  failed: { url: string; docRef: string; message: string }[];
  /** References left alone because they point away from their document's origin. */
  held: number;
}

/** The running cascade's documents and the URL each was fetched from; null when idle. */
let running: Map<DocumentId, string> | null = null;

/**
 * `roots` are documents the caller fetched without anyone asking for their
 * references, each with the URL it came from (a catalog source with
 * `resolveRefs`). The cascade then starts from these alone, and no round is
 * exempt from the origin rule.
 */
export async function fetchAllReferences(
  roots?: ReadonlyMap<DocumentId, string>,
): Promise<RefFetchSummary | null> {
  if (running) {
    // A catalog source that finished loading meanwhile joins the running cascade.
    for (const [docId, url] of roots ?? []) running.set(docId, url);
    return null;
  }
  const fetchedFrom = new Map<DocumentId, string>(roots);
  running = fetchedFrom;
  const staysOnOrigin = (url: string, docId: DocumentId) => sameOrigin(url, fetchedFrom.get(docId));
  const { actions } = useAppStore.getState();
  const attempted = new Set<string>();
  const failed: RefFetchSummary['failed'] = [];
  let fetched = 0;
  let done = 0;

  try {
    for (let round = 0; round < MAX_ROUNDS && attempted.size < MAX_FETCHES; round++) {
      const candidates = collectFetchCandidates(
        useAppStore.getState().ws,
        attempted,
        // Without roots, the first round is the click itself.
        round === 0 && !roots ? undefined : staysOnOrigin,
      ).slice(0, MAX_FETCHES - attempted.size);
      if (candidates.length === 0) break;
      for (const candidate of candidates) attempted.add(candidate.url);
      actions.setRefFetch({ done, total: attempted.size });

      await runPool(candidates, CONCURRENCY, async (candidate) => {
        const result = await ingestUrl(candidate.url);
        if (result.ok) fetched++;
        else failed.push({ url: candidate.url, docRef: candidate.docRef, message: result.message ?? 'failed' });
        if (result.documentId) fetchedFrom.set(result.documentId, candidate.url);
        done++;
        actions.setRefFetch({ done, total: attempted.size });
      });
    }
  } finally {
    running = null;
    useAppStore.getState().actions.setRefFetch(null);
  }

  const held = collectFetchCandidates(
    useAppStore.getState().ws,
    attempted,
    (url, docId) => fetchedFrom.has(docId) && !staysOnOrigin(url, docId),
  ).length;
  const heldNote = held > 0 ? ` · ${held} on another host not followed` : '';
  const summary = { fetched, failed, held };
  if (fetched === 0 && failed.length === 0 && held === 0) {
    actions.toast('No fetchable references: everything is either resolved or has no URL.', 'info');
  } else if (failed.length === 0) {
    actions.toast(
      `Fetched ${fetched} referenced document${fetched === 1 ? '' : 's'}${heldNote}`,
      held > 0 ? 'info' : 'success',
    );
  } else {
    actions.toast(
      `Fetched ${fetched} · ${failed.length} failed${heldNote}. Open a placeholder for details`,
      fetched > 0 ? 'info' : 'error',
    );
  }
  return summary;
}

/**
 * Whether `url` is on the origin `from` was fetched from: same scheme, host
 * and port. Both are resolved the way `fetch` resolves them, so a relative or
 * scheme-relative reference is judged by where the request would really go.
 */
function sameOrigin(url: string, from: string | undefined): boolean {
  if (from === undefined) return false;
  try {
    const base = globalThis.location?.href;
    const target = new URL(url, base);
    const source = new URL(from, base);
    return target.protocol === source.protocol && target.host === source.host;
  } catch {
    return false;
  }
}

async function runPool<T>(
  items: readonly T[],
  concurrency: number,
  worker: (item: T) => Promise<void>,
): Promise<void> {
  let next = 0;
  const lanes = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (next < items.length) {
      const item = items[next++]!;
      await worker(item);
    }
  });
  await Promise.all(lanes);
}
