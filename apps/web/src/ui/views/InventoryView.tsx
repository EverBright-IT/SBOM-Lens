import { useVirtualizer } from '@tanstack/react-virtual';
import clsx from 'clsx';
import { useMemo, useRef, useState } from 'react';
import type { InventoryRow, InventorySortKey, SearchFacets, VexStatus } from '@sbomlens/core';
import {
  VEX_STATUS_ORDER,
  effectiveLicense,
  inventoryRows,
  inventoryToCsv,
  inventoryToJson,
  sortInventory,
  worstVexStatus,
} from '@sbomlens/core';
import { useSearchFacets } from '../../app/selectors';
import { docAccent } from '../docColors';
import { useAppStore } from '../../app/store';
import { host } from '../../host/adapter';
import { FacetChips } from '../FacetChips';
import { revealElement } from '../navigate';
import { formatCount } from '../nodeInfo';
import { VEX_STATUS_LABEL, VexStatusChip } from '../detail/VexSection';

const ROW_HEIGHT = 28;
const GRID =
  'grid grid-cols-[minmax(10rem,1.7fr)_minmax(5rem,0.7fr)_minmax(7rem,1fr)_minmax(8rem,1fr)_minmax(5.5rem,0.7fr)_minmax(10rem,1.7fr)_minmax(7rem,1fr)] gap-x-3';
const GRID_VEX =
  'grid grid-cols-[minmax(10rem,1.7fr)_minmax(5rem,0.7fr)_minmax(7rem,1fr)_minmax(8rem,1fr)_minmax(5.5rem,0.7fr)_minmax(9rem,1.5fr)_minmax(6.5rem,0.8fr)_minmax(7rem,1fr)] gap-x-3';

type SortKey = InventorySortKey | 'vex';

const COLUMNS: { key: InventorySortKey; label: string }[] = [
  { key: 'name', label: 'Name' },
  { key: 'version', label: 'Version' },
  { key: 'license', label: 'License' },
  { key: 'supplier', label: 'Supplier' },
  { key: 'purpose', label: 'Purpose' },
  { key: 'purl', label: 'Package URL' },
  { key: 'document', label: 'Document' },
];

const PACKAGES_ONLY = new Set(['package'] as const);

/** Facet value for rows without any VEX statement. */
const NO_STATEMENT = 'none';

/** Aggregated bill of materials across the whole workspace, exportable. */
export function InventoryView() {
  const ws = useAppStore((s) => s.ws);
  const query = useAppStore((s) => s.query);
  const actions = useAppStore((s) => s.actions);
  const vex = useAppStore((s) => s.vex);
  const facets = useSearchFacets();
  const [sortKey, setSortKey] = useState<SortKey>('name');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');
  /** Local VEX-status facet; null = no filter. Lives with the overlay, not in core search. */
  const [vexFilter, setVexFilter] = useState<ReadonlySet<string> | null>(null);

  // The VEX column appears once VEX documents are loaded — an empty column
  // with a "0 matched" summary is honest signal, not noise.
  const vexActive = vex.documents.length > 0;

  // Files drown packages by sheer count; without an explicit kind facet the
  // inventory shows packages only.
  const filesHidden = facets.kinds === null;
  const effectiveFacets: SearchFacets = useMemo(
    () => (filesHidden ? { ...facets, kinds: PACKAGES_ONLY } : facets),
    [facets, filesHidden],
  );

  const scope = useAppStore((s) => s.inventoryScope);
  const rows = useMemo(
    () => inventoryRows(ws, query.trim(), effectiveFacets),
    [ws, query, effectiveFacets],
  );
  const scoped = useMemo(
    () => (scope ? rows.filter((row) => scope.ids.has(row.element.id)) : rows),
    [rows, scope],
  );
  const statusOf = (row: InventoryRow): string =>
    worstVexStatus(vex.findings.get(row.element.id)) ?? NO_STATEMENT;
  const vexFiltered = useMemo(
    () => (vexActive && vexFilter ? scoped.filter((row) => vexFilter.has(statusOf(row))) : scoped),
    // statusOf is derived from vex.findings, which is in the deps.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [scoped, vexActive, vexFilter, vex.findings],
  );
  const sorted = useMemo(() => {
    if (sortKey !== 'vex') return sortInventory(vexFiltered, sortKey, sortDir);
    const rank = (row: InventoryRow) => {
      const status = worstVexStatus(vex.findings.get(row.element.id));
      return status ? VEX_STATUS_ORDER.indexOf(status) : VEX_STATUS_ORDER.length;
    };
    const sign = sortDir === 'asc' ? 1 : -1;
    return [...vexFiltered].sort(
      (a, b) => sign * (rank(a) - rank(b)) || a.element.name.localeCompare(b.element.name),
    );
  }, [vexFiltered, sortKey, sortDir, vex.findings]);

  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: sorted.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
  });

  const onSort = (key: SortKey) => {
    if (key === sortKey) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else {
      setSortKey(key);
      setSortDir('asc');
    }
  };

  const toggleVexFilter = (value: string) => {
    setVexFilter((current) => {
      const next = new Set(current ?? []);
      if (next.has(value)) next.delete(value);
      else next.add(value);
      return next.size === 0 ? null : next;
    });
  };

  const grid = vexActive ? GRID_VEX : GRID;
  const columns: { key: SortKey; label: string }[] = vexActive
    ? [...COLUMNS.slice(0, 6), { key: 'vex', label: 'VEX' }, COLUMNS[6]!]
    : COLUMNS;

  const stamp = new Date().toISOString().slice(0, 10);

  return (
    <div className="flex h-full min-w-0 flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-100 px-4 py-2 dark:border-slate-800">
        {scope && (
          <button
            type="button"
            onClick={() => actions.setInventoryScope(null)}
            title={
              `Showing only the sub-components of ${scope.rootLabel}` +
              (scope.capped ? ' (traversal capped: very large subtree)' : '') +
              '. Click to show everything again'
            }
            className="flex items-center gap-1 rounded-full border border-accent-300 bg-accent-50 px-2 py-0.5 text-[11px] font-medium text-accent-800 hover:border-accent-400 dark:border-accent-700 dark:bg-accent-950 dark:text-accent-200"
          >
            ⊂ {scope.rootLabel}
            {scope.capped && <span className="text-amber-600 dark:text-amber-400">· capped</span>}
            <span aria-hidden>×</span>
          </button>
        )}
        <FacetChips />
        {vexActive && (
          <span className="flex items-center gap-1">
            {[...VEX_STATUS_ORDER, NO_STATEMENT].map((value) => (
              <button
                key={value}
                type="button"
                onClick={() => toggleVexFilter(value)}
                title={`Show only packages with VEX status "${value === NO_STATEMENT ? 'no statement' : VEX_STATUS_LABEL[value as VexStatus]}"`}
                className={clsx(
                  'rounded-full border px-1.5 py-0.5 text-[10px] whitespace-nowrap',
                  vexFilter?.has(value)
                    ? 'border-accent-400 bg-accent-50 font-medium text-accent-800 dark:border-accent-600 dark:bg-accent-950 dark:text-accent-200'
                    : 'border-slate-200 text-slate-400 hover:border-slate-300 hover:text-slate-600 dark:border-slate-700 dark:hover:text-slate-300',
                )}
              >
                {value === NO_STATEMENT ? 'no statement' : VEX_STATUS_LABEL[value as VexStatus]}
              </button>
            ))}
          </span>
        )}
        <span className="flex-1" />
        <span className="text-[11px] text-slate-400 tabular-nums">
          {formatCount(sorted.length)} {filesHidden ? 'packages' : 'elements'}
        </span>
        <button
          type="button"
          className="rounded border border-slate-200 px-2 py-1 text-[11px] font-medium text-slate-600 hover:border-accent-300 hover:text-accent-700 dark:border-slate-700 dark:text-slate-300 dark:hover:border-accent-700 dark:hover:text-accent-400"
          onClick={() =>
            host().exportFile(`sbom-inventory-${stamp}.csv`, 'text/csv', inventoryToCsv(sorted, vex.findings))
          }
        >
          Export CSV
        </button>
        <button
          type="button"
          className="rounded border border-slate-200 px-2 py-1 text-[11px] font-medium text-slate-600 hover:border-accent-300 hover:text-accent-700 dark:border-slate-700 dark:text-slate-300 dark:hover:border-accent-700 dark:hover:text-accent-400"
          onClick={() =>
            host().exportFile(
              `sbom-inventory-${stamp}.json`,
              'application/json',
              inventoryToJson(sorted, vex.findings),
            )
          }
        >
          Export JSON
        </button>
      </div>

      <div
        className={clsx(
          grid,
          'border-b border-slate-200 px-4 py-1.5 text-[11px] font-medium tracking-wide text-slate-400 uppercase select-none dark:border-slate-800',
        )}
      >
        {columns.map((col) => (
          <button
            key={col.key}
            type="button"
            onClick={() => onSort(col.key)}
            className="flex items-center gap-1 truncate text-left uppercase hover:text-slate-600 dark:hover:text-slate-300"
          >
            {col.label}
            {sortKey === col.key && <span className="text-accent-500">{sortDir === 'asc' ? '▲' : '▼'}</span>}
          </button>
        ))}
      </div>

      <div ref={scrollRef} className="min-h-0 flex-1 overflow-auto">
        <div className="relative" style={{ height: virtualizer.getTotalSize() }}>
          {virtualizer.getVirtualItems().map((item) => {
            const row = sorted[item.index]!;
            const license = effectiveLicense(row.element);
            const findings = vexActive ? vex.findings.get(row.element.id) : undefined;
            const worst = worstVexStatus(findings);
            return (
              <button
                key={row.element.id}
                type="button"
                onClick={() => {
                  actions.setView('explore');
                  revealElement(row.element.id);
                }}
                className={clsx(
                  grid,
                  'absolute inset-x-0 items-center px-4 text-left text-[13px] hover:bg-slate-50 dark:hover:bg-slate-900',
                )}
                style={{ top: item.start, height: ROW_HEIGHT }}
              >
                <span className="truncate" title={row.element.name}>
                  {row.element.name}
                </span>
                <span className="truncate font-mono text-xs text-slate-500 dark:text-slate-400">
                  {row.element.version}
                </span>
                <span className="truncate text-xs text-slate-500 dark:text-slate-400" title={license}>
                  {license}
                </span>
                <span className="truncate text-xs text-slate-500 dark:text-slate-400" title={row.element.supplier}>
                  {row.element.supplier?.replace(/^Organization: /, '')}
                </span>
                <span className="truncate text-[11px] text-slate-400">{row.element.purpose?.toLowerCase()}</span>
                <span className="truncate font-mono text-[11px] text-slate-400" title={row.element.purl}>
                  {row.element.purl}
                </span>
                {vexActive && (
                  <span className="min-w-0 truncate">
                    {worst && (
                      <>
                        <VexStatusChip status={worst} small />
                        {findings!.length > 1 && (
                          <span className="ml-1 align-middle text-[10px] text-slate-400 tabular-nums">
                            ×{findings!.length}
                          </span>
                        )}
                      </>
                    )}
                  </span>
                )}
                <span className="min-w-0" title={row.docName}>
                  <span
                    className={clsx(
                      'inline-block max-w-full truncate rounded-sm border px-1 align-middle text-[10px]',
                      docAccent(row.docName).chip,
                    )}
                  >
                    {row.docName}
                  </span>
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {filesHidden && (
        <div className="border-t border-slate-100 px-4 py-1.5 text-[11px] text-slate-400 dark:border-slate-800">
          Files are hidden — select the “files” chip to include them.
        </div>
      )}
    </div>
  );
}
