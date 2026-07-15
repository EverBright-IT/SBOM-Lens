import clsx from 'clsx';
import { useMemo } from 'react';
import { useAppStore } from '../app/store';

/**
 * Shared facet filter chips (documents, kinds, purposes, licenses) used by
 * the search panel and the inventory toolbar. All state lives in the store,
 * so both surfaces stay in sync.
 */
export function FacetChips() {
  const ws = useAppStore((s) => s.ws);
  const facetDocs = useAppStore((s) => s.facetDocs);
  const facetKinds = useAppStore((s) => s.facetKinds);
  const facetPurposes = useAppStore((s) => s.facetPurposes);
  const facetLicenses = useAppStore((s) => s.facetLicenses);
  const actions = useAppStore((s) => s.actions);

  const { purposes, licenses } = useMemo(() => {
    const purposeCounts = new Map<string, number>();
    const licenseCounts = new Map<string, number>();
    for (const loaded of ws.documents.values()) {
      for (const [purpose, count] of loaded.indexes.purposeCounts) {
        purposeCounts.set(purpose, (purposeCounts.get(purpose) ?? 0) + count);
      }
      for (const [license, count] of loaded.indexes.licenseCounts) {
        licenseCounts.set(license, (licenseCounts.get(license) ?? 0) + count);
      }
    }
    const top = (counts: Map<string, number>, n: number) =>
      [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
    return { purposes: top(purposeCounts, 6), licenses: top(licenseCounts, 6) };
  }, [ws]);

  const anyFacet =
    facetDocs !== null || facetKinds !== null || facetPurposes !== null || facetLicenses !== null;
  if (ws.documents.size < 2 && purposes.length === 0 && licenses.length === 0) return null;

  const chipClass = (active: boolean) =>
    clsx(
      'rounded-full border px-2 py-0.5 text-[11px] whitespace-nowrap',
      active
        ? 'border-accent-400 bg-accent-50 text-accent-800 dark:border-accent-600 dark:bg-accent-950 dark:text-accent-200'
        : 'border-slate-200 text-slate-500 hover:border-slate-300 dark:border-slate-700 dark:text-slate-400',
    );

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {ws.documents.size > 1 &&
        [...ws.documents.values()].map((loaded) => (
          <button
            key={loaded.document.id}
            type="button"
            className={chipClass(facetDocs?.has(loaded.document.id) ?? false)}
            onClick={() => actions.toggleFacetDoc(loaded.document.id)}
          >
            {loaded.document.name}
          </button>
        ))}
      {(['package', 'file'] as const).map((kind) => (
        <button
          key={kind}
          type="button"
          className={chipClass(facetKinds?.has(kind) ?? false)}
          onClick={() => actions.toggleFacetKind(kind)}
        >
          {kind}s
        </button>
      ))}
      {purposes.map(([purpose]) => (
        <button
          key={purpose}
          type="button"
          className={chipClass(facetPurposes?.has(purpose) ?? false)}
          onClick={() => actions.toggleFacetPurpose(purpose)}
        >
          {purpose.toLowerCase()}
        </button>
      ))}
      {licenses.map(([license]) => (
        <button
          key={license}
          type="button"
          className={clsx(chipClass(facetLicenses?.has(license) ?? false), 'font-mono')}
          title={`license: ${license}`}
          onClick={() => actions.toggleFacetLicense(license)}
        >
          {license}
        </button>
      ))}
      {anyFacet && (
        <button
          type="button"
          className="text-[11px] text-slate-400 underline hover:text-slate-600"
          onClick={() => actions.clearFacets()}
        >
          clear
        </button>
      )}
    </div>
  );
}
