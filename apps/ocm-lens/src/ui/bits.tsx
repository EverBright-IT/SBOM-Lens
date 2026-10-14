import clsx from 'clsx';
import type { ReactNode } from 'react';

/** Small shared UI vocabulary — chips, sections, key/value rows. */

export type ChipTone = 'neutral' | 'ok' | 'danger' | 'warn' | 'accent';

const CHIP_TONES: Record<ChipTone, string> = {
  neutral: 'border-slate-200 text-slate-500 dark:border-slate-700 dark:text-slate-400',
  ok: 'border-emerald-300 bg-emerald-50 text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400',
  danger: 'border-red-300 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400',
  warn: 'border-amber-300 bg-amber-50 text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400',
  accent: 'border-accent-200 bg-accent-50 text-accent-700 dark:border-accent-800 dark:bg-accent-950 dark:text-accent-400',
};

export function Chip({
  tone = 'neutral',
  title,
  children,
}: {
  tone?: ChipTone;
  title?: string;
  children: ReactNode;
}) {
  return (
    <span
      title={title}
      className={clsx('inline-block rounded border px-1 py-px text-[10px] whitespace-nowrap', CHIP_TONES[tone])}
    >
      {children}
    </span>
  );
}

export function Section({
  title,
  action,
  children,
}: {
  title: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="mb-5">
      <div className="mb-1.5 flex items-center gap-2">
        <h2 className="text-[11px] font-medium tracking-wide text-slate-400 uppercase dark:text-slate-500">
          {title}
        </h2>
        {action && <span className="ml-auto">{action}</span>}
      </div>
      {children}
    </section>
  );
}

export function KV({ label, mono, children }: { label: string; mono?: boolean; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[10rem_1fr] items-baseline gap-x-3 py-0.5 text-sm">
      <div className="text-xs text-slate-400 dark:text-slate-500">{label}</div>
      <div className={clsx('min-w-0 break-words', mono && 'font-mono text-xs')}>{children}</div>
    </div>
  );
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = n;
  let unit = -1;
  do {
    value /= 1024;
    unit++;
  } while (value >= 1024 && unit < units.length - 1);
  return `${value >= 100 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

export const BUTTON_SECONDARY =
  'rounded border border-slate-200 px-2 py-1 text-xs text-slate-600 hover:border-accent-300 hover:text-accent-700 disabled:opacity-40 dark:border-slate-700 dark:text-slate-300 dark:hover:border-accent-700 dark:hover:text-accent-400';
export const BUTTON_PRIMARY =
  'rounded bg-accent-600 px-2 py-1 text-xs text-white hover:bg-accent-700 disabled:opacity-40';
