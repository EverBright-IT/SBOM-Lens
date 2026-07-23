import clsx from 'clsx';
import type { Diagnostic } from '@sbomlens/core';
import { isSpecFinding } from '@sbomlens/core';
import { useAppStore } from '../app/store';
import { CloseIcon } from './icons';

export function DiagnosticsDrawer() {
  const open = useAppStore((s) => s.diagnosticsOpen);
  const ws = useAppStore((s) => s.ws);
  const failures = useAppStore((s) => s.failures);
  const specOnly = useAppStore((s) => s.diagnosticsSpecOnly);
  const actions = useAppStore((s) => s.actions);

  // Spec findings ('your document violates the spec') and parser notes ('we
  // had trouble reading it') answer different questions; the filter keeps a
  // long list from burying whichever one the reader came for.
  const visible = (diagnostics: Diagnostic[]) =>
    specOnly ? diagnostics.filter((d) => isSpecFinding(d.code)) : diagnostics;

  if (!open) return null;

  return (
    <div className="absolute inset-x-0 bottom-7 z-20 max-h-72 overflow-auto border-t border-slate-200 bg-white shadow-[0_-8px_24px_-12px_rgb(0_0_0/0.15)] dark:border-slate-700 dark:bg-slate-900">
      <div className="sticky top-0 flex items-center justify-between border-b border-slate-100 bg-white px-4 py-2 dark:border-slate-800 dark:bg-slate-900">
        <div className="flex items-center gap-3">
          <h2 className="text-xs font-medium tracking-wide text-slate-500 uppercase">Diagnostics</h2>
          <label className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
            <input
              type="checkbox"
              checked={specOnly}
              onChange={(e) => actions.setDiagnosticsSpecOnly(e.target.checked)}
              className="h-3 w-3 accent-amber-600"
            />
            Spec findings only
          </label>
        </div>
        <button
          type="button"
          onClick={() => actions.setDiagnosticsOpen(false)}
          className="rounded p-1 text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800"
        >
          <CloseIcon />
        </button>
      </div>

      <div className="space-y-3 px-4 py-3">
        {failures
          .filter((failure) => visible(failure.diagnostics).length > 0)
          .map((failure, i) => (
          <Group key={`failure-${i}`} title={`${failure.fileName} (not loaded)`}>
            {visible(failure.diagnostics).map((d, j) => (
              <Row key={j} diagnostic={d} />
            ))}
          </Group>
        ))}

        {[...ws.documents.values()]
          .filter((loaded) => visible(loaded.document.diagnostics).length > 0)
          .map((loaded) => (
            <Group
              key={loaded.document.id}
              title={`${loaded.document.name} (${loaded.source.fileName})`}
            >
              {visible(loaded.document.diagnostics).map((d, i) => (
                <Row
                  key={i}
                  diagnostic={d}
                  onJump={
                    d.line !== undefined
                      ? () => actions.jumpToSource({ kind: 'document', docId: loaded.document.id }, d.line!)
                      : undefined
                  }
                />
              ))}
            </Group>
          ))}

        {failures.every((f) => visible(f.diagnostics).length === 0) &&
          [...ws.documents.values()].every((l) => visible(l.document.diagnostics).length === 0) && (
            <p className="py-4 text-center text-xs text-slate-400">
              {specOnly ? 'No spec findings.' : 'No diagnostics.'}
            </p>
          )}
      </div>
    </div>
  );
}

function Group({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="mb-1 truncate text-xs font-medium text-slate-600 dark:text-slate-300">{title}</h3>
      <div className="space-y-0.5">{children}</div>
    </div>
  );
}

function Row({ diagnostic, onJump }: { diagnostic: Diagnostic; onJump?: () => void }) {
  return (
    <div className="flex items-baseline gap-2 text-xs">
      <span
        className={clsx(
          'w-14 shrink-0 font-medium',
          diagnostic.severity === 'error' && 'text-red-600 dark:text-red-400',
          diagnostic.severity === 'warning' && 'text-amber-600 dark:text-amber-400',
          diagnostic.severity === 'info' && 'text-slate-400',
        )}
      >
        {diagnostic.severity}
      </span>
      {isSpecFinding(diagnostic.code) && (
        <span className="shrink-0 rounded bg-amber-100 px-1 text-[10px] text-amber-800 dark:bg-amber-900/40 dark:text-amber-300">
          spec
        </span>
      )}
      <span className="shrink-0 font-mono text-[10px] text-slate-400">{diagnostic.code}</span>
      <span className="min-w-0 text-slate-600 dark:text-slate-300">{diagnostic.message}</span>
      {onJump && (
        <button
          type="button"
          onClick={onJump}
          className="shrink-0 font-mono text-[11px] text-accent-700 hover:underline dark:text-accent-400"
        >
          line {diagnostic.line}
        </button>
      )}
    </div>
  );
}
