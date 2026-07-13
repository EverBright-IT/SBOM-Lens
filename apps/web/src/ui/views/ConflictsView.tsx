import { useState } from 'react';
import { useVersionConflicts } from '../../app/selectors';
import { useAppStore } from '../../app/store';
import { CheckIcon, ChevronIcon } from '../icons';
import { revealElement } from '../navigate';
import { formatCount } from '../nodeInfo';

const DISPLAY_CAP = 500;

/** Same package identity, more than one version anywhere in the cascade. */
export function ConflictsView() {
  const conflicts = useVersionConflicts();
  const actions = useAppStore((s) => s.actions);
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());

  if (conflicts.length === 0) {
    return (
      <div className="grid h-full place-items-center p-6">
        <div className="text-center">
          <CheckIcon width={28} height={28} className="mx-auto text-emerald-500" />
          <p className="mt-3 text-sm text-slate-500 dark:text-slate-400">
            No version conflicts — every package identity resolves to a single version across all
            loaded documents.
          </p>
        </div>
      </div>
    );
  }

  const toggle = (key: string) => {
    const next = new Set(expanded);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    setExpanded(next);
  };

  return (
    <div className="h-full overflow-auto">
      <div className="mx-auto max-w-4xl px-4 py-4">
        <p className="mb-3 text-xs text-slate-400">
          {formatCount(conflicts.length)} package identit{conflicts.length === 1 ? 'y' : 'ies'} with
          multiple versions (grouped by purl, falling back to name).
        </p>
        <div className="space-y-2">
          {conflicts.slice(0, DISPLAY_CAP).map((group) => {
            const isOpen = expanded.has(group.key);
            return (
              <div
                key={group.key}
                className="rounded-md border border-slate-200 dark:border-slate-800"
              >
                <button
                  type="button"
                  onClick={() => toggle(group.key)}
                  className="flex w-full items-center gap-2 px-3 py-2 text-left"
                >
                  <ChevronIcon
                    className={`shrink-0 text-slate-400 transition-transform duration-75 ${isOpen ? 'rotate-90' : ''}`}
                  />
                  <span className="truncate text-[13px] font-medium">{group.name}</span>
                  <span className="flex min-w-0 flex-wrap gap-1">
                    {group.versions.map((v) => (
                      <span
                        key={v.version}
                        className="rounded border border-amber-300 bg-amber-50 px-1.5 text-[11px] font-mono text-amber-800 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-300"
                      >
                        {v.version}
                        {v.occurrences.length > 1 && ` ×${v.occurrences.length}`}
                      </span>
                    ))}
                  </span>
                  <span className="ml-auto shrink-0 text-[11px] text-slate-400">
                    {group.versions.length} versions · {group.total} occurrence{group.total === 1 ? '' : 's'}
                  </span>
                </button>
                {isOpen && (
                  <div className="border-t border-slate-100 px-3 py-1.5 dark:border-slate-800">
                    {group.versions.flatMap((v) =>
                      v.occurrences.map((occ) => (
                        <button
                          key={occ.element.id}
                          type="button"
                          onClick={() => {
                            actions.setView('explore');
                            revealElement(occ.element.id);
                          }}
                          className="flex w-full items-baseline gap-2 rounded px-1.5 py-1 text-left text-xs hover:bg-slate-50 dark:hover:bg-slate-900"
                        >
                          <span className="w-24 shrink-0 font-mono text-slate-600 dark:text-slate-300">
                            {v.version}
                          </span>
                          <span className="truncate text-slate-400">{occ.docName}</span>
                          <span className="ml-auto shrink-0 font-mono text-[10px] text-slate-300 dark:text-slate-600">
                            {occ.element.spdxId}
                          </span>
                        </button>
                      )),
                    )}
                  </div>
                )}
              </div>
            );
          })}
          {conflicts.length > DISPLAY_CAP && (
            <p className="text-xs text-slate-400">
              … and {conflicts.length - DISPLAY_CAP} more groups.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
