import clsx from 'clsx';
import type { ElementId, VexDocument, VexStatus } from '@sbomlens/core';
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

/** Advisory content is untrusted input: only http(s) URLs become anchors. */
function isHttpUrl(value: string): boolean {
  return /^https?:\/\//i.test(value);
}

/** Lists render at most this many rows; an advisory mirror can hold thousands. */
const LIST_CAP = 50;

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
  const hidden = Math.max(0, findings.length - LIST_CAP);
  return (
    <Section title={`Vulnerability communication (${findings.length})`}>
      <div className="space-y-2">
        {findings.slice(0, LIST_CAP).map((f) => (
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
            {f.remediations && f.remediations.length > 0 ? (
              <ul className="mt-0.5 space-y-0.5 text-slate-600 dark:text-slate-300">
                {f.remediations.map((r, i) => (
                  <li key={i}>
                    <span className="rounded bg-slate-100 px-1 text-[10px] font-medium text-slate-500 dark:bg-slate-800 dark:text-slate-400">
                      {r.category.replace(/_/g, ' ')}
                    </span>{' '}
                    {r.details}
                    {r.url && (
                      <>
                        {' '}
                        {isHttpUrl(r.url) ? (
                          <a href={r.url} target="_blank" rel="noreferrer" className="text-accent-700 hover:underline dark:text-accent-400">
                            link
                          </a>
                        ) : (
                          <span className="font-mono text-[10px] text-slate-400" title="Not an http(s) URL; not linked">
                            {r.url}
                          </span>
                        )}
                      </>
                    )}
                    {r.date ? <span className="text-slate-400"> · {r.date.slice(0, 10)}</span> : null}
                    {r.restartRequired ? <span className="text-slate-400"> · restart: {r.restartRequired}</span> : null}
                  </li>
                ))}
              </ul>
            ) : (
              f.actionStatement && (
                <div className="mt-0.5 text-slate-600 dark:text-slate-300">
                  Action: {f.actionStatement}
                </div>
              )
            )}
            <div className="mt-0.5 text-[10px] text-slate-400 dark:text-slate-500">
              {f.source}
              {f.timestamp ? ` · ${f.timestamp.slice(0, 10)}` : ''}
              {f.matchedBy === 'hash' ? ' · matched by file hash' : f.matchedBy === 'cpe' ? ' · matched by CPE' : ''}
            </div>
          </div>
        ))}
      </div>
      {hidden > 0 && (
        <p className="mt-1 text-[10px] text-slate-400 dark:text-slate-500">
          {hidden} more statement{hidden === 1 ? '' : 's'} not listed; the exports carry all of them.
        </p>
      )}
      <p className="mt-2 text-[10px] text-slate-400 dark:text-slate-500">
        Supplier statements from loaded VEX and CSAF documents, matched by package URL, CPE or file hash.
        This is not a vulnerability scan.
      </p>
    </Section>
  );
}

/** Workspace-level overview of loaded VEX documents, with removal. */
export function VexDocumentsSection() {
  const vex = useAppStore((s) => s.vex);
  const actions = useAppStore((s) => s.actions);
  if (vex.documents.length === 0) return null;
  const hidden = Math.max(0, vex.documents.length - LIST_CAP);
  return (
    <Section title={`VEX and advisory documents (${vex.documents.length})`}>
      <div className="space-y-1.5">
        {vex.documents.slice(0, LIST_CAP).map((doc) => (
          <VexDocumentRow key={doc.id} doc={doc} onRemove={() => actions.removeVexDocument(doc.id)} />
        ))}
      </div>
      {hidden > 0 && (
        <p className="mt-1 text-[10px] text-slate-400 dark:text-slate-500">
          {hidden} more document{hidden === 1 ? '' : 's'} loaded and matched, not listed here.
        </p>
      )}
      <p className="mt-1.5 text-[10px] text-slate-400 dark:text-slate-500">
        {vex.findings.size} package{vex.findings.size === 1 ? '' : 's'} in the workspace matched.
        Conflicting statements resolve by timestamp (newest wins).
      </p>
    </Section>
  );
}

/**
 * CSAF 2.0 labels are AMBER, GREEN, RED, WHITE (2.1 adds AMBER+STRICT and
 * CLEAR); a document that writes "TLP:RED" is normalised for the chip.
 */
const TLP_CLASS: Record<string, string> = {
  RED: 'bg-red-600 text-white',
  AMBER: 'bg-amber-500 text-black',
  'AMBER+STRICT': 'bg-amber-500 text-black',
  GREEN: 'bg-emerald-600 text-white',
  CLEAR: 'bg-slate-200 text-slate-800 dark:bg-slate-700 dark:text-slate-100',
  WHITE: 'bg-slate-200 text-slate-800 dark:bg-slate-700 dark:text-slate-100',
};

/** One loaded document: format, profile, TLP, statement count, and for CSAF the TR-03191 measurement. */
export function VexDocumentRow({ doc, onRemove }: { doc: VexDocument; onRemove?: () => void }) {
  // Clauses with nothing to apply to and counted facts are shown, never tallied.
  const measured = doc.tr03191?.filter((f) => f.applicable !== false && !f.informational) ?? [];
  const passed = measured.filter((f) => f.pass).length;
  const total = measured.length;
  const notApplicable = doc.tr03191?.filter((f) => f.applicable === false).length ?? 0;
  const tlp = doc.tlp ? doc.tlp.toUpperCase().replace(/^TLP:/, '') : undefined;
  const tlpKnown = tlp !== undefined && Object.hasOwn(TLP_CLASS, tlp);
  return (
    <div className="text-xs">
      <div className="flex items-baseline gap-2">
        {doc.format && (
          <span className="shrink-0 rounded bg-slate-100 px-1 text-[9px] font-medium tracking-wide text-slate-500 uppercase dark:bg-slate-800 dark:text-slate-400">
            {doc.format === 'csaf' ? 'CSAF' : 'OpenVEX'}
          </span>
        )}
        {tlp && tlpKnown && (
          <span className={clsx('shrink-0 rounded px-1 text-[9px] font-semibold tracking-wide', TLP_CLASS[tlp])}>
            TLP:{tlp}
          </span>
        )}
        {tlp && !tlpKnown && (
          <span
            className="shrink-0 rounded bg-slate-200 px-1 text-[9px] font-medium text-slate-600 dark:bg-slate-700 dark:text-slate-300"
            title="distribution.tlp.label is not a label the standard defines (AMBER, GREEN, RED, WHITE; AMBER+STRICT and CLEAR in 2.1)"
          >
            {doc.tlp}
          </span>
        )}
        <span className="min-w-0 flex-1 truncate font-mono text-slate-600 dark:text-slate-300" title={doc.title ? `${doc.id}: ${doc.title}` : doc.id}>
          {doc.id}
        </span>
        <span className="shrink-0 text-[10px] text-slate-400 tabular-nums">
          {doc.category ? `${doc.category.replace(/^csaf_/, '').replace(/_/g, ' ')} · ` : ''}
          {doc.statements.length} stmt{doc.statements.length === 1 ? '' : 's'}
          {doc.timestamp ? ` · ${doc.timestamp.slice(0, 10)}` : ''}
        </span>
        {onRemove && (
          <button
            type="button"
            onClick={onRemove}
            title="Remove this document (the overlay recomputes)"
            className="shrink-0 rounded border border-slate-200 px-1 text-[10px] text-slate-400 hover:border-red-300 hover:text-red-600 dark:border-slate-700 dark:hover:border-red-800 dark:hover:text-red-400"
          >
            ×
          </button>
        )}
      </div>
      {doc.tr03191 && doc.tr03191.length > 0 && (
        <details className="mt-0.5 pl-1">
          <summary className="cursor-pointer text-[10px] text-slate-500 select-none hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200">
            BSI TR-03191: {passed} of {total} measured requirements present
            {notApplicable > 0 ? `, ${notApplicable} not applicable` : ''}
          </summary>
          <ul className="mt-1 space-y-0.5 text-[11px]">
            {doc.tr03191.map((f) => {
              const neutral = f.applicable === false || f.informational;
              return (
                <li key={f.id} className="flex items-baseline gap-1.5">
                  <span
                    className={clsx(
                      'shrink-0 font-semibold',
                      neutral ? 'text-slate-400' : f.pass ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400',
                    )}
                    title={f.applicable === false ? 'Nothing in this document the clause applies to' : f.informational ? 'A counted fact, not pass or fail' : undefined}
                  >
                    {f.applicable === false ? 'n/a' : f.informational ? 'i' : f.pass ? '✓' : '✗'}
                  </span>
                  <span className="shrink-0 font-mono text-[10px] text-slate-400">{f.clause}</span>
                  <span className="min-w-0 text-slate-600 dark:text-slate-300">
                    {f.label}
                    {f.actual ? <span className="text-slate-400"> · {f.actual}</span> : null}
                  </span>
                </li>
              );
            })}
          </ul>
          <p className="mt-1 text-[10px] text-slate-400 dark:text-slate-500">
            Facts about the document against the clauses of TR-03191. Distribution, signature validity and the
            48-hour reaction window cannot be read off a file and are not measured.
          </p>
        </details>
      )}
    </div>
  );
}
