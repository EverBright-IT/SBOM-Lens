import clsx from 'clsx';
import { useMemo, useState } from 'react';
import type { LicenseIdKind, LicenseIdRow } from '@sbomlens/core';
import {
  SPDX_LICENSE_LIST_SOURCE,
  licenseInventory,
  licenseInventoryToCsv,
  licenseInventoryToMarkdown,
} from '@sbomlens/core';
import { useAppStore } from '../../app/store';
import { host } from '../../host/adapter';
import { formatCount } from '../nodeInfo';

/**
 * The licence inventory: every SPDX identifier the loaded documents name,
 * how many packages and documents carry it, and whether it is on the SPDX
 * License List, deprecated there, a LicenseRef, or unknown. Counts and
 * identifier facts only. Nothing here says what a licence obliges or
 * whether two are compatible; that is deliberately not this viewer's call.
 */

const GRID = 'grid grid-cols-[minmax(14rem,2fr)_minmax(6rem,0.8fr)_minmax(5rem,0.6fr)_minmax(5rem,0.6fr)_minmax(5rem,0.6fr)_minmax(6rem,0.6fr)] gap-x-3';

type SortKey = 'id' | 'kind' | 'declared' | 'concluded' | 'packages' | 'documents';

const COLUMNS: { key: SortKey; label: string; numeric?: boolean }[] = [
  { key: 'id', label: 'Identifier' },
  { key: 'kind', label: 'Status' },
  { key: 'declared', label: 'Declared', numeric: true },
  { key: 'concluded', label: 'Concluded', numeric: true },
  { key: 'packages', label: 'Packages', numeric: true },
  { key: 'documents', label: 'Documents', numeric: true },
];

const KIND_LABEL: Record<LicenseIdKind, string> = {
  listed: 'SPDX list',
  deprecated: 'deprecated',
  ref: 'LicenseRef',
  unknown: 'not on list',
};

const KIND_CLASS: Record<LicenseIdKind, string> = {
  listed: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-200',
  deprecated: 'bg-amber-100 text-amber-800 dark:bg-amber-900/60 dark:text-amber-200',
  ref: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300',
  unknown: 'bg-rose-100 text-rose-800 dark:bg-rose-900/50 dark:text-rose-200',
};

export function LicensesView() {
  const ws = useAppStore((s) => s.ws);
  const wsVersion = useAppStore((s) => s.wsVersion);
  const query = useAppStore((s) => s.query);
  const actions = useAppStore((s) => s.actions);
  const [sortKey, setSortKey] = useState<SortKey>('packages');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  // eslint-disable-next-line react-hooks/exhaustive-deps -- wsVersion is the memo key for everything derived from ws
  const inventory = useMemo(() => licenseInventory(ws), [wsVersion]);

  // The search box filters identifiers; the status column sorts by its label.
  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const sign = sortDir === 'asc' ? 1 : -1;
    const sortValue = (row: LicenseIdRow) => (sortKey === 'kind' ? KIND_LABEL[row.kind] : row[sortKey]);
    return inventory.rows
      .filter((row) => q === '' || row.id.toLowerCase().includes(q))
      .sort((a, b) => {
        const av = sortValue(a);
        const bv = sortValue(b);
        const cmp = typeof av === 'number' && typeof bv === 'number' ? av - bv : String(av).localeCompare(String(bv));
        return sign * cmp || a.id.localeCompare(b.id);
      });
  }, [inventory, query, sortKey, sortDir]);

  const onSort = (key: SortKey) => {
    if (key === sortKey) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else {
      setSortKey(key);
      setSortDir(COLUMNS.find((c) => c.key === key)?.numeric ? 'desc' : 'asc');
    }
  };

  // Drill-down: the identifier facet matches either licence field, so the
  // inventory shows exactly the packages this row counted. Other facets and
  // a subtree scope would silently shrink that set, so they are cleared.
  const showPackages = (row: LicenseIdRow) => {
    actions.setQuery(''); // the box filtered identifiers here; in the inventory it would filter names
    actions.clearFacets();
    actions.setInventoryScope(null);
    actions.setFacetLicenseIds(new Set([row.id]));
    actions.setView('inventory');
  };

  const stamp = () => new Date().toISOString().slice(0, 10);
  const exportButton =
    'rounded border border-slate-200 px-2 py-1 text-[11px] font-medium text-slate-600 hover:border-accent-300 hover:text-accent-700 dark:border-slate-700 dark:text-slate-300 dark:hover:border-accent-700 dark:hover:text-accent-400';

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-200 px-4 py-2 text-xs dark:border-slate-800">
        <span className="text-slate-500 dark:text-slate-400">
          {formatCount(inventory.rows.length)} identifiers across {formatCount(inventory.packagesTotal)} packages
        </span>
        <span className="text-slate-400">·</span>
        <span className="text-slate-500 dark:text-slate-400" title="Declared licence missing, NONE or NOASSERTION">
          {formatCount(inventory.withoutDeclared)} without declared
        </span>
        <span className="text-slate-400">·</span>
        <span className="text-slate-500 dark:text-slate-400" title="Concluded licence missing, NONE or NOASSERTION">
          {formatCount(inventory.withoutConcluded)} without concluded
        </span>
        {inventory.unparseable > 0 && (
          <>
            <span className="text-slate-400">·</span>
            <span className="text-amber-700 dark:text-amber-400" title="A licence text or a typo where an SPDX expression should be">
              {formatCount(inventory.unparseable)} not an SPDX expression
            </span>
          </>
        )}
        <span className="flex-1" />
        <button
          type="button"
          className={exportButton}
          onClick={() => host().exportFile(`sbom-licenses-${stamp()}.csv`, 'text/csv', licenseInventoryToCsv(inventory))}
        >
          Export CSV
        </button>
        <button
          type="button"
          className={exportButton}
          onClick={() =>
            host().exportFile(
              `sbom-licenses-${stamp()}.md`,
              'text/markdown',
              licenseInventoryToMarkdown(inventory, { generatedAt: new Date().toISOString() }),
            )
          }
        >
          Export Markdown
        </button>
      </div>

      <div
        className={clsx(
          GRID,
          'border-b border-slate-200 px-4 py-1.5 text-[11px] font-medium tracking-wide text-slate-400 uppercase select-none dark:border-slate-800',
        )}
      >
        {COLUMNS.map((col) => (
          <button
            key={col.key}
            type="button"
            onClick={() => onSort(col.key)}
            className={clsx(
              'flex items-center gap-1 truncate uppercase hover:text-slate-600 dark:hover:text-slate-300',
              col.numeric ? 'justify-end text-right' : 'text-left',
            )}
          >
            {col.label}
            {sortKey === col.key && <span className="text-accent-500">{sortDir === 'asc' ? '▲' : '▼'}</span>}
          </button>
        ))}
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        {rows.length === 0 ? (
          <p className="px-4 py-6 text-sm text-slate-500 dark:text-slate-400">
            {inventory.rows.length === 0 ? 'No licence identifiers in the loaded documents.' : 'No identifier matches the search box.'}
          </p>
        ) : (
          rows.map((row) => (
            <div
              key={row.id}
              className={clsx(GRID, 'items-center border-b border-slate-100 px-4 py-1 text-xs dark:border-slate-800/60')}
            >
              <button
                type="button"
                title="Show the packages naming this identifier in the inventory"
                onClick={() => showPackages(row)}
                className="min-w-0 truncate text-left font-mono text-[11px] text-accent-700 hover:underline dark:text-accent-400"
              >
                {row.id}
              </button>
              <span>
                <span className={clsx('rounded px-1.5 py-0.5 text-[10px] font-medium', KIND_CLASS[row.kind])}>
                  {KIND_LABEL[row.kind]}
                </span>
              </span>
              <span className="text-right tabular-nums">{formatCount(row.declared)}</span>
              <span className="text-right tabular-nums">{formatCount(row.concluded)}</span>
              <span className="text-right tabular-nums">{formatCount(row.packages)}</span>
              <span className="text-right tabular-nums">{formatCount(row.documents)}</span>
            </div>
          ))
        )}
      </div>

      <p className="border-t border-slate-200 px-4 py-1.5 text-[11px] text-slate-400 dark:border-slate-800">
        Identifiers are checked against the SPDX License List as packaged in {SPDX_LICENSE_LIST_SOURCE} (ids and
        deprecation flags only). This view states nothing about what a licence obliges or whether licences are
        compatible.
      </p>
    </div>
  );
}
