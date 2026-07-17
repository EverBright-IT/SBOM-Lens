import clsx from 'clsx';
import type { ElementId, VexStatus } from '@sbomlens/core';
import { useAppStore } from '../../app/store';
import { Section } from './FieldRow';

/**
 * The OpenVEX overlay in the detail pane: what the supplier communicates
 * about known vulnerabilities. Rendered only when VEX documents are loaded
 * and something matched — this is a communication channel, not a scanner,
 * and the UI never pretends otherwise.
 */

export const VEX_STATUS_LABEL: Record<VexStatus, string> = {
  affected: 'affected',
  under_investigation: 'under investigation',
  fixed: 'fixed',
  not_affected: 'not affected',
};

const CHIP: Record<VexStatus, string> = {
  affected:
    'border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950/60 dark:text-red-300',
  under_investigation:
    'border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/60 dark:text-amber-300',
  fixed:
    'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/60 dark:text-emerald-300',
  not_affected:
    'border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300',
};

export function VexStatusChip({ status, small }: { status: VexStatus; small?: boolean }) {
  return (
    <span
      className={clsx(
        'inline-block rounded-full border font-medium whitespace-nowrap',
        small ? 'px-1.5 text-[10px]' : 'px-2 py-0.5 text-[11px]',
        CHIP[status],
      )}
    >
      {VEX_STATUS_LABEL[status]}
    </span>
  );
}

/** Per-element findings, one row per vulnerability (time rule already applied). */
export function VexElementSection({ elementId }: { elementId: ElementId }) {
  const findings = useAppStore((s) => s.vex.findings.get(elementId));
  if (!findings || findings.length === 0) return null;
  return (
    <Section title={`Vulnerability communication (${findings.length})`}>
      <div className="space-y-2">
        {findings.map((f) => (
          <div key={f.vulnerability} className="text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono font-medium text-slate-700 dark:text-slate-200">
                {f.vulnerability}
              </span>
              <VexStatusChip status={f.status} />
              {f.viaSubcomponent && (
                <span className="text-[10px] text-slate-400" title="The statement names this package as a subcomponent of the affected product">
                  via subcomponent
                </span>
              )}
            </div>
            {f.justification && (
              <div className="mt-0.5 text-slate-500 dark:text-slate-400">
                Justification: <span className="font-mono">{f.justification}</span>
              </div>
            )}
            {f.impactStatement && (
              <div className="mt-0.5 text-slate-500 dark:text-slate-400">{f.impactStatement}</div>
            )}
            {f.actionStatement && (
              <div className="mt-0.5 text-slate-600 dark:text-slate-300">
                Action: {f.actionStatement}
              </div>
            )}
            <div className="mt-0.5 text-[10px] text-slate-400 dark:text-slate-500">
              {f.source}
              {f.timestamp ? ` · ${f.timestamp.slice(0, 10)}` : ''}
            </div>
          </div>
        ))}
      </div>
      <p className="mt-2 text-[10px] text-slate-400 dark:text-slate-500">
        Supplier statements from loaded VEX documents, matched by package URL. This is not a
        vulnerability scan.
      </p>
    </Section>
  );
}

/** Workspace-level overview of loaded VEX documents, with removal. */
export function VexDocumentsSection() {
  const vex = useAppStore((s) => s.vex);
  const actions = useAppStore((s) => s.actions);
  if (vex.documents.length === 0) return null;
  return (
    <Section title={`VEX documents (${vex.documents.length})`}>
      <div className="space-y-1.5">
        {vex.documents.map((doc) => (
          <div key={doc.id} className="flex items-baseline gap-2 text-xs">
            {doc.format && (
              <span className="shrink-0 rounded bg-slate-100 px-1 text-[9px] font-medium tracking-wide text-slate-500 uppercase dark:bg-slate-800 dark:text-slate-400">
                {doc.format === 'csaf' ? 'CSAF' : 'OpenVEX'}
              </span>
            )}
            <span className="min-w-0 flex-1 truncate font-mono text-slate-600 dark:text-slate-300" title={doc.id}>
              {doc.id}
            </span>
            <span className="shrink-0 text-[10px] text-slate-400 tabular-nums">
              {doc.statements.length} stmt{doc.statements.length === 1 ? '' : 's'}
              {doc.timestamp ? ` · ${doc.timestamp.slice(0, 10)}` : ''}
            </span>
            <button
              type="button"
              onClick={() => actions.removeVexDocument(doc.id)}
              title="Remove this VEX document (the overlay recomputes)"
              className="shrink-0 rounded border border-slate-200 px-1 text-[10px] text-slate-400 hover:border-red-300 hover:text-red-600 dark:border-slate-700 dark:hover:border-red-800 dark:hover:text-red-400"
            >
              ×
            </button>
          </div>
        ))}
      </div>
      <p className="mt-1.5 text-[10px] text-slate-400 dark:text-slate-500">
        {vex.findings.size} package{vex.findings.size === 1 ? '' : 's'} in the workspace matched.
        Conflicting statements resolve by timestamp (newest wins).
      </p>
    </Section>
  );
}
