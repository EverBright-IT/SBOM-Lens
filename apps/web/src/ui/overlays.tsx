import clsx from 'clsx';
import { useEffect, useRef, useState } from 'react';
import { BRAND } from '../app/brand';
import { ingestDataTransfer } from '../app/ingest';
import { useAppStore } from '../app/store';
import { CloseIcon, UploadIcon } from './icons';

/** Full-window drop target: drag documents or folders anywhere. */
export function DropOverlay() {
  const [active, setActive] = useState(false);
  const depth = useRef(0);

  useEffect(() => {
    const hasFiles = (e: DragEvent) => e.dataTransfer?.types.includes('Files');
    const enter = (e: DragEvent) => {
      if (!hasFiles(e)) return;
      depth.current++;
      setActive(true);
    };
    const leave = (e: DragEvent) => {
      if (!hasFiles(e)) return;
      depth.current = Math.max(0, depth.current - 1);
      if (depth.current === 0) setActive(false);
    };
    const over = (e: DragEvent) => {
      if (hasFiles(e)) e.preventDefault();
    };
    const drop = (e: DragEvent) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      depth.current = 0;
      setActive(false);
      if (e.dataTransfer) void ingestDataTransfer(e.dataTransfer);
    };
    window.addEventListener('dragenter', enter);
    window.addEventListener('dragleave', leave);
    window.addEventListener('dragover', over);
    window.addEventListener('drop', drop);
    return () => {
      window.removeEventListener('dragenter', enter);
      window.removeEventListener('dragleave', leave);
      window.removeEventListener('dragover', over);
      window.removeEventListener('drop', drop);
    };
  }, []);

  if (!active) return null;
  return (
    <div className="pointer-events-none fixed inset-0 z-50 grid place-items-center bg-accent-500/10 p-6">
      <div className="grid h-full w-full place-items-center rounded-xl border-2 border-dashed border-accent-400 bg-white/70 dark:bg-slate-950/70">
      <div className="flex items-center gap-2 text-lg font-medium text-accent-700 dark:text-accent-300">
        <UploadIcon width={22} height={22} /> {BRAND.dropHint}
      </div>
      </div>
    </div>
  );
}

export function Toasts() {
  const toasts = useAppStore((s) => s.toasts);
  const actions = useAppStore((s) => s.actions);
  if (toasts.length === 0) return null;

  return (
    <div className="fixed right-4 bottom-10 z-40 flex w-80 flex-col gap-2">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={clsx(
            'flex items-start gap-2 rounded-md border px-3 py-2 text-xs shadow-lg',
            toast.kind === 'error' &&
              'border-red-200 bg-red-50 text-red-800 dark:border-red-900 dark:bg-red-950 dark:text-red-200',
            toast.kind === 'success' &&
              'border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950 dark:text-emerald-200',
            toast.kind === 'info' &&
              'border-slate-200 bg-white text-slate-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200',
          )}
        >
          <span className="min-w-0 flex-1 break-words">{toast.message}</span>
          <button
            type="button"
            onClick={() => actions.dismissToast(toast.id)}
            className="shrink-0 opacity-50 hover:opacity-100"
          >
            <CloseIcon width={12} height={12} />
          </button>
        </div>
      ))}
    </div>
  );
}
