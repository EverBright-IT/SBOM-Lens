import clsx from 'clsx';
import { useState, type ReactNode } from 'react';
import type { SpecFieldDoc } from '@sbomlens/core';
import { CheckIcon, CopyIcon, InfoIcon } from '../icons';

const MUTED_VALUES = new Set(['NOASSERTION', 'NONE']);

export function FieldRow({
  label,
  value,
  mono = false,
  copyable = false,
  info,
}: {
  label: string;
  value: string | undefined;
  mono?: boolean;
  copyable?: boolean;
  /** Field documentation from the SPDX spec, shown as a hover tooltip (ⓘ links into the spec). */
  info?: SpecFieldDoc;
}) {
  if (!value) return null;
  const muted = MUTED_VALUES.has(value);
  return (
    <div className="grid grid-cols-[9rem_1fr] items-baseline gap-x-3 py-1">
      <div className="flex items-center gap-1 text-xs text-slate-400 dark:text-slate-500">
        {label}
        {info && <SpecInfo doc={info} />}
      </div>
      <div
        className={clsx(
          'flex min-w-0 items-baseline gap-1 text-[13px]',
          mono && !muted && 'font-mono text-xs',
          muted && 'text-slate-400 dark:text-slate-600',
        )}
      >
        <span className="break-words whitespace-pre-wrap [overflow-wrap:anywhere]" title={muted ? value : undefined}>
          {muted ? '—' : value}
        </span>
        {copyable && !muted && <CopyButton text={value} />}
      </div>
    </div>
  );
}

export function CopyButton({ text, className }: { text: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      title="Copy"
      className={clsx(
        'shrink-0 self-center rounded p-0.5 text-slate-300 hover:bg-slate-100 hover:text-slate-500 dark:text-slate-600 dark:hover:bg-slate-800 dark:hover:text-slate-400',
        className,
      )}
      onClick={() => {
        void navigator.clipboard.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        });
      }}
    >
      {copied ? <CheckIcon className="text-emerald-500" /> : <CopyIcon />}
    </button>
  );
}

export function Section({
  title,
  info,
  actions,
  children,
}: {
  title: string;
  info?: SpecFieldDoc;
  /** Right-aligned controls in the heading row (profile picker, export…). */
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="border-t border-slate-100 pt-3 pb-4 first:border-t-0 first:pt-0 dark:border-slate-800/80">
      <h3 className="mb-1.5 flex items-center gap-1 text-[11px] font-medium tracking-wide text-slate-400 uppercase dark:text-slate-500">
        {title}
        {info && <SpecInfo doc={info} />}
        {actions && <span className="ml-auto flex items-center gap-1.5 normal-case">{actions}</span>}
      </h3>
      {children}
    </section>
  );
}

/**
 * ⓘ hover tooltip carrying the SPDX spec's own field documentation.
 * With a specUrl it becomes a link straight into the rendered spec chapter.
 */
export function SpecInfo({ doc }: { doc: SpecFieldDoc }) {
  const className =
    'inline-flex shrink-0 text-slate-300 hover:text-accent-500 dark:text-slate-600 dark:hover:text-accent-400';
  if (doc.specUrl) {
    return (
      <a
        href={doc.specUrl}
        target="_blank"
        rel="noreferrer"
        title={`${doc.description}\n\nOpen this field in the SPDX 2.3 specification ↗`}
        aria-label={`${doc.description} (opens SPDX specification)`}
        onClick={(e) => e.stopPropagation()}
        className={className}
      >
        <InfoIcon />
      </a>
    );
  }
  return (
    <span title={doc.description} aria-label={doc.description} className={clsx(className, 'cursor-help')}>
      <InfoIcon />
    </span>
  );
}

export function Chip({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'accent' | 'warn' }) {
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1 rounded border px-1.5 py-px text-[11px]',
        tone === 'neutral' && 'border-slate-200 text-slate-500 dark:border-slate-700 dark:text-slate-400',
        tone === 'accent' && 'border-accent-200 text-accent-700 dark:border-accent-800 dark:text-accent-300',
        tone === 'warn' && 'border-amber-300 text-amber-700 dark:border-amber-700 dark:text-amber-400',
      )}
    >
      {children}
    </span>
  );
}
