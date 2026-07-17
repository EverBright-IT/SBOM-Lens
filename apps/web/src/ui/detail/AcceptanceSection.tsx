import clsx from 'clsx';
import type { AcceptanceVerdict, ElementId } from '@sbomlens/core';
import { useAppStore } from '../../app/store';
import { CopyButton, Section } from './FieldRow';

/**
 * Delivery-acceptance overlay in the detail pane: whether the delivered bytes
 * match the SBOM's file checksums. Per file element, and a workspace-level
 * report of mismatches, missing files, and extras. A verifier, not a guess —
 * a file with no shared checksum reads *unverifiable*, never *match*.
 */

const VERDICT_LABEL: Record<AcceptanceVerdict, string> = {
  match: 'match',
  mismatch: 'mismatch',
  missing: 'missing',
  unverifiable: 'unverifiable',
};

const CHIP: Record<AcceptanceVerdict, string> = {
  match:
    'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/60 dark:text-emerald-300',
  mismatch:
    'border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950/60 dark:text-red-300',
  missing:
    'border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/60 dark:text-amber-300',
  unverifiable:
    'border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300',
};

export function AcceptanceChip({ verdict, small }: { verdict: AcceptanceVerdict; small?: boolean }) {
  return (
    <span
      className={clsx(
        'inline-block rounded-full border font-medium whitespace-nowrap',
        small ? 'px-1.5 text-[10px]' : 'px-2 py-0.5 text-[11px]',
        CHIP[verdict],
      )}
    >
      {VERDICT_LABEL[verdict]}
    </span>
  );
}

/** The acceptance verdict for one file element, when a delivery was checked. */
export function AcceptanceElementSection({ elementId }: { elementId: ElementId }) {
  const report = useAppStore((s) => s.acceptance.report);
  const file = report?.files.find((f) => f.elementId === elementId);
  if (!file) return null;
  return (
    <Section title="Delivery acceptance">
      <div className="space-y-1 text-xs">
        <div className="flex items-center gap-2">
          <AcceptanceChip verdict={file.verdict} />
          {file.algorithm && <span className="text-slate-400">{file.algorithm}</span>}
        </div>
        {file.verdict === 'mismatch' && (
          <div className="space-y-0.5 font-mono text-[11px] break-all">
            <div className="text-slate-500 dark:text-slate-400">declared {file.declared}</div>
            <div className="text-red-600 dark:text-red-400">actual&nbsp;&nbsp; {file.actual}</div>
          </div>
        )}
        {file.verdict === 'missing' && (
          <p className="text-slate-500 dark:text-slate-400">
            Described in the SBOM but not present in the delivery.
          </p>
        )}
        {file.verdict === 'unverifiable' && file.reason && (
          <p className="text-slate-500 dark:text-slate-400">{file.reason}.</p>
        )}
      </div>
    </Section>
  );
}

/** Workspace-level acceptance report: the counts, then what went wrong. */
export function AcceptanceReportSection() {
  const report = useAppStore((s) => s.acceptance.report);
  const actions = useAppStore((s) => s.actions);
  if (!report) return null;
  const { summary, files, extra } = report;
  const mismatches = files.filter((f) => f.verdict === 'mismatch');
  const missing = files.filter((f) => f.verdict === 'missing');
  const clean = summary.mismatch === 0 && summary.missing === 0 && summary.extra === 0;

  return (
    <Section
      title="Delivery acceptance"
      actions={
        <button
          type="button"
          onClick={() => actions.setAcceptanceReport(null)}
          title="Clear the delivery-acceptance report"
          className="rounded border border-slate-200 px-1 text-[10px] text-slate-400 hover:border-red-300 hover:text-red-600 dark:border-slate-700 dark:hover:border-red-800 dark:hover:text-red-400"
        >
          Clear
        </button>
      }
    >
      <div className="mb-2 flex flex-wrap gap-x-3 gap-y-1 text-[11px] tabular-nums">
        <span className="text-emerald-600 dark:text-emerald-400">{summary.match} match</span>
        <span className={summary.mismatch > 0 ? 'text-red-600 dark:text-red-400' : 'text-slate-400'}>
          {summary.mismatch} mismatch
        </span>
        <span className={summary.missing > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-slate-400'}>
          {summary.missing} missing
        </span>
        {summary.unverifiable > 0 && <span className="text-slate-400">{summary.unverifiable} unverifiable</span>}
        <span className={summary.extra > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-slate-400'}>
          {summary.extra} extra
        </span>
      </div>

      {clean ? (
        <p className="text-[11px] text-emerald-600 dark:text-emerald-400">
          Every delivered file matches the SBOM.
        </p>
      ) : (
        <div className="space-y-2 text-[11px]">
          {mismatches.length > 0 && (
            <AcceptanceList title="Tampered or corrupt" tone="red" items={mismatches.map((f) => f.path)} />
          )}
          {missing.length > 0 && (
            <AcceptanceList title="Missing from the delivery" tone="amber" items={missing.map((f) => f.path)} />
          )}
          {extra.length > 0 && (
            <AcceptanceList title="Not in the SBOM" tone="amber" items={extra.map((f) => f.path)} />
          )}
        </div>
      )}
      <p className="mt-2 text-[10px] text-slate-400 dark:text-slate-500">
        Delivered files hashed locally and compared to the SBOM's file checksums.
      </p>
    </Section>
  );
}

function AcceptanceList({ title, tone, items }: { title: string; tone: 'red' | 'amber'; items: string[] }) {
  const CAP = 50;
  const shown = items.slice(0, CAP);
  return (
    <div>
      <div
        className={clsx(
          'mb-0.5 font-medium',
          tone === 'red' ? 'text-red-600 dark:text-red-400' : 'text-amber-600 dark:text-amber-400',
        )}
      >
        {title} ({items.length})
      </div>
      <ul className="space-y-0.5">
        {shown.map((path) => (
          <li key={path} className="flex items-center gap-1 font-mono break-all text-slate-600 dark:text-slate-300">
            {path}
            <CopyButton text={path} />
          </li>
        ))}
      </ul>
      {items.length > CAP && (
        <div className="text-slate-400">…and {items.length - CAP} more</div>
      )}
    </div>
  );
}
