import { useVirtualizer } from '@tanstack/react-virtual';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { DocumentId } from '@sbomlens/core';
import { removalPlan, workspaceRoots } from '@sbomlens/core';
import { useAppStore } from '../app/store';
import { dialogClass, useDialog } from './dialogs';
import { Chip } from './detail/FieldRow';
import { formatCount } from './nodeInfo';

const ROW_HEIGHT = 32;

/**
 * Bulk document management: the boring, honest checkbox list. Opened from the
 * status-bar document count; removal itself goes through the same
 * cascade-aware confirm flow as single removal.
 */
export function ManageDocumentsDialog() {
  const open = useAppStore((s) => s.manageOpen);
  const ws = useAppStore((s) => s.ws);
  const wsVersion = useAppStore((s) => s.wsVersion);
  const actions = useAppStore((s) => s.actions);
  const ref = useDialog(open, () => actions.setManageOpen(false));

  const [selected, setSelected] = useState<ReadonlySet<DocumentId>>(new Set());

  // Drop selections that no longer exist (e.g. after a removal round).
  useEffect(() => {
    setSelected((current) => {
      const next = new Set([...current].filter((id) => ws.documents.has(id)));
      return next.size === current.size ? current : next;
    });
  }, [wsVersion, ws]);

  const roots = useMemo(() => new Set(workspaceRoots(ws)), [ws]);
  const rows = useMemo(() => ws.order.map((id) => ws.documents.get(id)!), [ws]);

  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 15,
  });

  const plan = useMemo(
    () => (selected.size > 0 ? removalPlan(ws, selected) : null),
    [ws, selected],
  );

  const allSelected = rows.length > 0 && selected.size === rows.length;
  const selectAllRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (selectAllRef.current) {
      selectAllRef.current.indeterminate = selected.size > 0 && !allSelected;
    }
  }, [selected, allSelected]);

  const toggle = (id: DocumentId) => {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <dialog ref={ref} className={`${dialogClass} w-[42rem]`}>
      <div className="flex max-h-[80vh] flex-col p-5">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold">Documents ({formatCount(rows.length)})</h2>
          <label className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
            <input
              ref={selectAllRef}
              type="checkbox"
              checked={allSelected}
              onChange={() =>
                setSelected(allSelected ? new Set() : new Set(rows.map((r) => r.document.id)))
              }
              className="accent-accent-600"
            />
            Select all
          </label>
        </div>

        <div ref={scrollRef} className="mt-3 min-h-0 flex-1 overflow-auto rounded border border-slate-100 dark:border-slate-800">
          <div className="relative" style={{ height: virtualizer.getTotalSize() }}>
            {virtualizer.getVirtualItems().map((item) => {
              const loaded = rows[item.index]!;
              const id = loaded.document.id;
              return (
                <label
                  key={id}
                  className="absolute inset-x-0 flex cursor-pointer items-center gap-2.5 px-3 text-[13px] hover:bg-slate-50 dark:hover:bg-slate-900"
                  style={{ top: item.start, height: ROW_HEIGHT }}
                >
                  <input
                    type="checkbox"
                    checked={selected.has(id)}
                    onChange={() => toggle(id)}
                    className="shrink-0 accent-accent-600"
                  />
                  <span className="min-w-0 flex-1 truncate" title={loaded.document.name}>
                    {loaded.document.name}
                  </span>
                  {roots.has(id) && <Chip tone="accent">root</Chip>}
                  <span
                    className="max-w-48 shrink-0 truncate font-mono text-[11px] text-slate-400"
                    title={loaded.source.fileName}
                  >
                    {loaded.source.fileName}
                  </span>
                  <span className="w-20 shrink-0 text-right text-[11px] text-slate-400 tabular-nums">
                    {formatCount(loaded.indexes.packageCount)} pkgs
                  </span>
                </label>
              );
            })}
          </div>
          {rows.length === 0 && (
            <p className="p-6 text-center text-xs text-slate-400">No documents loaded.</p>
          )}
        </div>

        <div className="mt-3 flex items-center gap-3">
          <span className="min-w-0 flex-1 truncate text-xs text-slate-500 dark:text-slate-400">
            {selected.size > 0 ? (
              <>
                {formatCount(selected.size)} selected
                {plan && plan.orphaned.length > 0 && (
                  <>
                    {' · '}
                    <span className="text-amber-600 dark:text-amber-400">
                      {formatCount(plan.orphaned.length)} more only referenced by the selection
                    </span>
                  </>
                )}
              </>
            ) : (
              'Select documents to remove them from the workspace.'
            )}
          </span>
          <button
            type="button"
            onClick={() => actions.setManageOpen(false)}
            className="rounded border border-slate-200 px-3 py-1.5 text-xs dark:border-slate-700"
          >
            Close
          </button>
          <button
            type="button"
            disabled={selected.size === 0}
            onClick={() => actions.requestRemoval([...selected])}
            className="rounded bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-700 disabled:opacity-40"
          >
            Remove {selected.size > 0 ? formatCount(selected.size) : ''}…
          </button>
        </div>
      </div>
    </dialog>
  );
}
