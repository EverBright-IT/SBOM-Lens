import { useMemo } from 'react';
import { removalPlan } from '@sbomlens/core';
import { useAppStore } from '../app/store';
import { dialogClass, useDialog } from './dialogs';
import { formatCount } from './nodeInfo';

const ORPHAN_LIST_CAP = 8;

/**
 * Cascade-aware removal confirmation. Recomputes the plan from the live
 * workspace so the numbers can never go stale while the dialog is open.
 */
export function RemoveDialog() {
  const prompt = useAppStore((s) => s.removalPrompt);
  const ws = useAppStore((s) => s.ws);
  const actions = useAppStore((s) => s.actions);
  const ref = useDialog(prompt !== null, actions.cancelRemoval);

  const plan = useMemo(
    () => (prompt ? removalPlan(ws, new Set(prompt.docIds)) : null),
    [ws, prompt],
  );

  const docName = (id: string) =>
    ws.documents.get(id as never)?.document.name ?? '(unknown document)';

  const requested = plan?.requested ?? [];
  const orphaned = plan?.orphaned ?? [];
  const total = requested.length + orphaned.length;

  const buttonBase = 'rounded px-3 py-1.5 text-xs font-medium';

  return (
    <dialog ref={ref} className={dialogClass}>
      {plan && requested.length > 0 && (
        <div className="p-5">
          <h2 className="text-sm font-semibold">
            {requested.length === 1
              ? `Remove “${docName(requested[0]!)}”?`
              : `Remove ${formatCount(requested.length)} documents?`}
          </h2>

          {orphaned.length > 0 ? (
            <>
              <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                {formatCount(orphaned.length)} document{orphaned.length === 1 ? ' is' : 's are'}{' '}
                referenced only through the selection and would be left behind as new roots:
              </p>
              <ul className="mt-2 space-y-0.5 text-xs">
                {orphaned.slice(0, ORPHAN_LIST_CAP).map((id) => (
                  <li key={id} className="flex items-baseline gap-2">
                    <span className="truncate font-medium">{docName(id)}</span>
                    <span className="shrink-0 text-slate-400">
                      {formatCount(ws.documents.get(id)?.indexes.packageCount ?? 0)} packages
                    </span>
                  </li>
                ))}
                {orphaned.length > ORPHAN_LIST_CAP && (
                  <li className="text-slate-400">+ {orphaned.length - ORPHAN_LIST_CAP} more</li>
                )}
              </ul>
            </>
          ) : (
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">This cannot be undone.</p>
          )}

          <div className="mt-5 flex justify-end gap-2">
            <button
              type="button"
              onClick={actions.cancelRemoval}
              className={`${buttonBase} border border-slate-200 dark:border-slate-700`}
            >
              Cancel
            </button>
            {orphaned.length > 0 && (
              <button
                type="button"
                onClick={() => actions.confirmRemoval(false)}
                className={`${buttonBase} border border-slate-200 text-slate-600 hover:border-slate-400 dark:border-slate-700 dark:text-slate-300`}
                title="Remove only the selection; referenced documents stay loaded as new roots"
              >
                Keep them as roots
              </button>
            )}
            <button
              type="button"
              onClick={() => actions.confirmRemoval(true)}
              className={`${buttonBase} bg-red-600 text-white hover:bg-red-700`}
            >
              Remove {orphaned.length > 0 ? `all ${formatCount(total)}` : formatCount(requested.length)}
            </button>
          </div>
        </div>
      )}
    </dialog>
  );
}
