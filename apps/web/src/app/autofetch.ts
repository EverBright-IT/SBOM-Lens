import { collectFetchCandidates } from '@sbomlens/core';
import { ingestUrl } from './ingest';
import { useAppStore } from './store';

/**
 * "Fetch all references": downloads every fetchable unresolved reference,
 * then repeats — newly loaded documents expose new references — until the
 * cascade reaches a fixpoint. One click instead of one click per placeholder.
 */

const MAX_ROUNDS = 16;
const MAX_FETCHES = 500;
const CONCURRENCY = 4;

export interface RefFetchSummary {
  fetched: number;
  failed: { url: string; docRef: string; message: string }[];
}

let running = false;

export async function fetchAllReferences(): Promise<RefFetchSummary | null> {
  if (running) return null;
  running = true;
  const { actions } = useAppStore.getState();
  const attempted = new Set<string>();
  const failed: RefFetchSummary['failed'] = [];
  let fetched = 0;
  let done = 0;

  try {
    for (let round = 0; round < MAX_ROUNDS && attempted.size < MAX_FETCHES; round++) {
      const candidates = collectFetchCandidates(useAppStore.getState().ws, attempted).slice(
        0,
        MAX_FETCHES - attempted.size,
      );
      if (candidates.length === 0) break;
      for (const candidate of candidates) attempted.add(candidate.url);
      actions.setRefFetch({ done, total: attempted.size });

      await runPool(candidates, CONCURRENCY, async (candidate) => {
        const result = await ingestUrl(candidate.url);
        if (result.ok) fetched++;
        else failed.push({ url: candidate.url, docRef: candidate.docRef, message: result.message ?? 'failed' });
        done++;
        actions.setRefFetch({ done, total: attempted.size });
      });
    }
  } finally {
    running = false;
    useAppStore.getState().actions.setRefFetch(null);
  }

  const summary = { fetched, failed };
  if (fetched === 0 && failed.length === 0) {
    actions.toast('No fetchable references: everything is either resolved or has no URL.', 'info');
  } else if (failed.length === 0) {
    actions.toast(`Fetched ${fetched} referenced document${fetched === 1 ? '' : 's'}`, 'success');
  } else {
    actions.toast(
      `Fetched ${fetched} · ${failed.length} failed. Open a placeholder for details`,
      fetched > 0 ? 'info' : 'error',
    );
  }
  return summary;
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
