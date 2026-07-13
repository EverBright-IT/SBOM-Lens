import { useVirtualizer } from '@tanstack/react-virtual';
import clsx from 'clsx';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { CascadeDiff, DocumentId, ElementId } from '@sbomlens/core';
import { diffCascades, diffToMarkdown, workspaceRoots } from '@sbomlens/core';
import { useAppStore } from '../../app/store';
import { revealElement } from '../navigate';
import { formatCount } from '../nodeInfo';

const ROW_HEIGHT = 28;
// Below this the three columns truncate too hard (VS Code split panels) — stack instead.
const COLUMNS_MIN_WIDTH = 1024;

type DiffRow =
  | { kind: 'header'; label: string; count: number }
  | { kind: 'added' | 'removed'; name: string; versions: string; elementId: ElementId }
  | { kind: 'changed'; name: string; from: string; to: string; elementId: ElementId };

interface DiffCell {
  name: string;
  versions?: string;
  from?: string;
  to?: string;
  elementId: ElementId;
}

interface DiffColumn {
  key: 'changed' | 'added' | 'removed';
  label: string;
  marker: string;
  markerClass: string;
  cells: DiffCell[];
}

function useWideLayout(): boolean {
  const [wide, setWide] = useState(
    () => window.matchMedia(`(min-width: ${COLUMNS_MIN_WIDTH}px)`).matches,
  );
  useEffect(() => {
    const mq = window.matchMedia(`(min-width: ${COLUMNS_MIN_WIDTH}px)`);
    const onChange = () => setWide(mq.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);
  return wide;
}

/** Compares two cascades package by package — releases, snapshots, variants. */
export function DiffView() {
  const ws = useAppStore((s) => s.ws);
  const diffA = useAppStore((s) => s.diffA);
  const diffB = useAppStore((s) => s.diffB);
  const actions = useAppStore((s) => s.actions);
  const wide = useWideLayout();

  const docs = useMemo(() => ws.order.map((id) => ws.documents.get(id)!).filter(Boolean), [ws]);
  const roots = useMemo(() => new Set(workspaceRoots(ws)), [ws]);

  const a = diffA && ws.documents.has(diffA) ? diffA : null;
  const b = diffB && ws.documents.has(diffB) ? diffB : null;

  // Sensible default: the first two roots (two releases dropped side by side).
  useEffect(() => {
    if (a === null || b === null) {
      const rootIds = [...roots];
      const defaultA = a ?? rootIds[0] ?? docs[0]?.document.id ?? null;
      const defaultB = b ?? rootIds.find((id) => id !== defaultA) ?? defaultA;
      if (defaultA !== a || defaultB !== b) actions.setDiffSides(defaultA, defaultB ?? null);
    }
  }, [a, b, roots, docs, actions]);

  const diff: CascadeDiff | null = useMemo(
    () => (a && b ? diffCascades(ws, a, b) : null),
    [ws, a, b],
  );

  // Narrow layout: one flat list with section headers (scrolls past long sections).
  const rows: DiffRow[] = useMemo(() => {
    if (!diff) return [];
    const result: DiffRow[] = [];
    if (diff.changed.length > 0) {
      result.push({ kind: 'header', label: 'Version changes', count: diff.changed.length });
      for (const change of diff.changed) {
        result.push({
          kind: 'changed',
          name: change.name,
          from: change.a.versions.join(' / '),
          to: change.b.versions.join(' / '),
          elementId: change.b.occurrences[0]!.element.id,
        });
      }
    }
    if (diff.added.length > 0) {
      result.push({ kind: 'header', label: 'Added', count: diff.added.length });
      for (const entry of diff.added) {
        result.push({
          kind: 'added',
          name: entry.name,
          versions: entry.side.versions.join(' / '),
          elementId: entry.side.occurrences[0]!.element.id,
        });
      }
    }
    if (diff.removed.length > 0) {
      result.push({ kind: 'header', label: 'Removed', count: diff.removed.length });
      for (const entry of diff.removed) {
        result.push({
          kind: 'removed',
          name: entry.name,
          versions: entry.side.versions.join(' / '),
          elementId: entry.side.occurrences[0]!.element.id,
        });
      }
    }
    return result;
  }, [diff]);

  // Wide layout: three side-by-side columns, virtualized together row-by-row.
  const columns: DiffColumn[] = useMemo(() => {
    if (!diff) return [];
    return [
      {
        key: 'changed',
        label: 'Version changes',
        marker: '~',
        markerClass: 'text-amber-600 dark:text-amber-400',
        cells: diff.changed.map((change) => ({
          name: change.name,
          from: change.a.versions.join(' / '),
          to: change.b.versions.join(' / '),
          elementId: change.b.occurrences[0]!.element.id,
        })),
      },
      {
        key: 'added',
        label: 'Added',
        marker: '+',
        markerClass: 'text-emerald-600 dark:text-emerald-400',
        cells: diff.added.map((entry) => ({
          name: entry.name,
          versions: entry.side.versions.join(' / '),
          elementId: entry.side.occurrences[0]!.element.id,
        })),
      },
      {
        key: 'removed',
        label: 'Removed',
        marker: '−',
        markerClass: 'text-red-600 dark:text-red-400',
        cells: diff.removed.map((entry) => ({
          name: entry.name,
          versions: entry.side.versions.join(' / '),
          elementId: entry.side.occurrences[0]!.element.id,
        })),
      },
    ];
  }, [diff]);

  const columnRowCount = useMemo(
    () => columns.reduce((max, col) => Math.max(max, col.cells.length), 0),
    [columns],
  );

  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: wide ? columnRowCount : rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
  });

  if (docs.length < 2) {
    return (
      <div className="grid h-full place-items-center p-6 text-center text-sm text-slate-400">
        Load at least two documents (e.g. two releases) to compare their cascades.
      </div>
    );
  }

  const docName = (id: DocumentId | null) =>
    id ? (ws.documents.get(id)?.document.name ?? '') : '';

  const select = (side: 'a' | 'b') => (e: React.ChangeEvent<HTMLSelectElement>) => {
    const value = e.target.value as DocumentId;
    actions.setDiffSides(side === 'a' ? value : a, side === 'b' ? value : b);
  };

  const reveal = (elementId: ElementId) => {
    actions.setView('explore');
    revealElement(elementId);
  };

  const selectClass =
    'max-w-64 rounded border border-slate-300 bg-transparent px-1.5 py-1 text-xs outline-none focus:border-sky-400 dark:border-slate-600 dark:bg-slate-900';

  const hasDiff = diff !== null && (wide ? columnRowCount > 0 : rows.length > 0);

  return (
    <div className="flex h-full min-w-0 flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-100 px-4 py-2 dark:border-slate-800">
        <select value={a ?? ''} onChange={select('a')} className={selectClass} aria-label="Diff side A">
          {docs.map((d) => (
            <option key={d.document.id} value={d.document.id}>
              {d.document.name}
              {roots.has(d.document.id) ? ' (root)' : ''}
            </option>
          ))}
        </select>
        <span className="text-slate-400">→</span>
        <select value={b ?? ''} onChange={select('b')} className={selectClass} aria-label="Diff side B">
          {docs.map((d) => (
            <option key={d.document.id} value={d.document.id}>
              {d.document.name}
              {roots.has(d.document.id) ? ' (root)' : ''}
            </option>
          ))}
        </select>

        {diff && (
          <>
            <span className="ml-2 text-[11px] text-slate-400 tabular-nums">
              <span className="text-amber-600 dark:text-amber-400">~{formatCount(diff.changed.length)}</span>
              {' · '}
              <span className="text-emerald-600 dark:text-emerald-400">+{formatCount(diff.added.length)}</span>
              {' · '}
              <span className="text-red-600 dark:text-red-400">−{formatCount(diff.removed.length)}</span>
              {' · '}
              {formatCount(diff.unchanged)} unchanged · cascades of {diff.aDocCount} vs {diff.bDocCount} docs
            </span>
            <span className="flex-1" />
            <button
              type="button"
              className="rounded border border-slate-200 px-2 py-1 text-[11px] font-medium text-slate-600 hover:border-sky-300 hover:text-sky-700 dark:border-slate-700 dark:text-slate-300 dark:hover:border-sky-700 dark:hover:text-sky-400"
              onClick={() => {
                void navigator.clipboard
                  .writeText(diffToMarkdown(diff, docName(a), docName(b)))
                  .then(() => actions.toast('Diff copied as Markdown', 'success'));
              }}
            >
              Copy as Markdown
            </button>
          </>
        )}
      </div>

      {wide && hasDiff && (
        <div className="grid grid-cols-3 border-b border-slate-100 dark:border-slate-800">
          {columns.map((col, colIndex) => (
            <div
              key={col.key}
              className={clsx(
                'flex items-baseline gap-2 px-4 py-1.5 text-[11px] font-medium tracking-wide text-slate-400 uppercase',
                colIndex > 0 && 'border-l border-slate-100 dark:border-slate-800',
              )}
            >
              <span className={clsx('font-mono normal-case', col.markerClass)}>{col.marker}</span>
              {col.label} ({formatCount(col.cells.length)})
            </div>
          ))}
        </div>
      )}

      <div ref={scrollRef} className="min-h-0 flex-1 overflow-auto">
        {diff && !hasDiff && (
          <p className="p-6 text-center text-sm text-slate-400">
            No differences — both cascades contain the same packages and versions.
          </p>
        )}
        <div className="relative" style={{ height: virtualizer.getTotalSize() }}>
          {wide
            ? virtualizer.getVirtualItems().map((item) => (
                <div
                  key={item.index}
                  className="absolute inset-x-0 grid grid-cols-3"
                  style={{ top: item.start, height: ROW_HEIGHT }}
                >
                  {columns.map((col, colIndex) => {
                    const cell = col.cells[item.index];
                    const borderClass = colIndex > 0 && 'border-l border-slate-100 dark:border-slate-800';
                    if (!cell) {
                      return (
                        <div key={col.key} className={clsx('flex items-baseline px-4', borderClass)}>
                          {item.index === 0 && col.cells.length === 0 && (
                            <span className="text-xs text-slate-300 dark:text-slate-600">none</span>
                          )}
                        </div>
                      );
                    }
                    return (
                      <button
                        key={col.key}
                        type="button"
                        onClick={() => reveal(cell.elementId)}
                        className={clsx(
                          'flex min-w-0 items-baseline gap-2 px-4 text-left text-[13px] hover:bg-slate-50 dark:hover:bg-slate-900',
                          borderClass,
                        )}
                      >
                        <span className={clsx('w-3 shrink-0 text-center font-mono', col.markerClass)}>
                          {col.marker}
                        </span>
                        <span className="truncate">{cell.name}</span>
                        {col.key === 'changed' ? (
                          <span className="shrink-0 font-mono text-xs text-slate-500 dark:text-slate-400">
                            {cell.from} <span className="text-slate-300 dark:text-slate-600">→</span> {cell.to}
                          </span>
                        ) : (
                          <span className="shrink-0 font-mono text-xs text-slate-400">{cell.versions}</span>
                        )}
                      </button>
                    );
                  })}
                </div>
              ))
            : virtualizer.getVirtualItems().map((item) => {
                const row = rows[item.index]!;
                if (row.kind === 'header') {
                  return (
                    <div
                      key={`h-${row.label}`}
                      className="absolute inset-x-0 flex items-center px-4 text-[11px] font-medium tracking-wide text-slate-400 uppercase"
                      style={{ top: item.start, height: ROW_HEIGHT }}
                    >
                      {row.label} ({formatCount(row.count)})
                    </div>
                  );
                }
                return (
                  <button
                    key={`${row.kind}-${row.name}-${item.index}`}
                    type="button"
                    onClick={() => reveal(row.elementId)}
                    className="absolute inset-x-0 flex items-baseline gap-3 px-4 text-left text-[13px] hover:bg-slate-50 dark:hover:bg-slate-900"
                    style={{ top: item.start, height: ROW_HEIGHT }}
                  >
                    <span
                      className={clsx(
                        'w-4 shrink-0 text-center font-mono',
                        row.kind === 'added' && 'text-emerald-600 dark:text-emerald-400',
                        row.kind === 'removed' && 'text-red-600 dark:text-red-400',
                        row.kind === 'changed' && 'text-amber-600 dark:text-amber-400',
                      )}
                    >
                      {row.kind === 'added' ? '+' : row.kind === 'removed' ? '−' : '~'}
                    </span>
                    <span className="truncate">{row.name}</span>
                    {row.kind === 'changed' ? (
                      <span className="shrink-0 font-mono text-xs text-slate-500 dark:text-slate-400">
                        {row.from} <span className="text-slate-300 dark:text-slate-600">→</span> {row.to}
                      </span>
                    ) : (
                      <span className="shrink-0 font-mono text-xs text-slate-400">{row.versions}</span>
                    )}
                  </button>
                );
              })}
        </div>
      </div>
    </div>
  );
}
