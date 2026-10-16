import type { ReactNode } from 'react';
import { useState } from 'react';
import clsx from 'clsx';
import type { OcmBundle, SbomOccurrence, SbomSummary } from '@sbomlens/core/ocm';
import { ntiaLabel, ntiaSummary } from '@sbomlens/core/ocm';
import { useSbomEvidence } from '../app/evidence';
import { runSbomAnalysis } from '../app/ingest';
import type { LoadedDelivery } from '../app/store';
import { useAppStore } from '../app/store';
import { BUTTON_SECONDARY, Chip, KV, Section, formatBytes } from './bits';
import { TransportChip } from './ComponentsView';
import {
  BindingChip,
  CoverageChip,
  artifactAt,
  bindingExplanation,
  bsiLabel,
  downloadSbom,
  generatorLabel,
} from './sbomBits';

/** NTIA minimum elements at package level: a gap there is shown as one. */
const NTIA_FIELDS = new Set(['pkg-version', 'pkg-supplier', 'pkg-unique-id']);

/**
 * "Is the right SBOM with every artifact?" The SBOMs embedded in the
 * delivery, tied to the artifacts they describe and graded by what matched
 * (digest, reference, component), plus each SBOM's fact sheet. Evidence,
 * not verdict: the transport verdict on the dashboard stays independent.
 */

export function SbomsView() {
  const delivery = useAppStore((s) => s.delivery);
  const selectedSbom = useAppStore((s) => s.selectedSbom);
  const selectSbom = useAppStore((s) => s.actions.selectSbom);
  const selectArtifact = useAppStore((s) => s.actions.selectArtifact);
  const evidence = useSbomEvidence();
  const sbomRun = useAppStore((s) => s.sbomRun);
  const sbomError = useAppStore((s) => s.sbomError);
  const [showOptional, setShowOptional] = useState(false);

  if (!delivery || !evidence) return null;
  const { bundle } = delivery;
  const c = evidence.counts;
  const rows = evidence.coverage.filter((r) => showOptional || r.expected || r.status === 'bound');
  const optional =
    evidence.coverage.length -
    evidence.coverage.filter((r) => r.expected || r.status === 'bound').length;
  const selected =
    selectedSbom &&
    evidence.sboms.find(
      (s) => s.at.cvId === selectedSbom.cvId && s.at.index === selectedSbom.index,
    );

  return (
    <div className="flex h-full min-h-0">
      <div className="min-w-0 flex-1 overflow-auto p-4">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <h1 className="text-lg font-semibold">SBOM evidence</h1>
          {c.expected > 0 && (
            <Chip tone={c.covered === c.expected ? 'ok' : c.missing > 0 ? 'danger' : 'warn'}>
              {c.covered} of {c.expected} artifact{c.expected === 1 ? '' : 's'} covered
            </Chip>
          )}
          {c.byDigest > 0 && <Chip tone="ok">{c.byDigest} by digest</Chip>}
          {c.byReference > 0 && <Chip tone="accent">{c.byReference} by reference</Chip>}
          {c.byComponent > 0 && <Chip>{c.byComponent} by component</Chip>}
          {c.missing > 0 && <Chip tone="danger">{c.missing} missing</Chip>}
          {c.unverified + c.declared > 0 && (
            <Chip tone="warn">{c.unverified + c.declared} unconfirmed</Chip>
          )}
        </div>
        <p className="mb-4 max-w-3xl text-xs text-slate-500 dark:text-slate-400">
          An SBOM is tied to an artifact <b>by digest</b> when it names a digest of the delivered
          bytes, <b>by reference</b> when only repository and tag match, and <b>by component</b>{' '}
          when it names the component version. SBOM evidence does not change the transport verdict.
        </p>

        {sbomRun ? (
          <div className="mb-4 rounded border border-slate-200 px-2.5 py-1.5 text-sm text-slate-600 dark:border-slate-700 dark:text-slate-300">
            Analysing SBOMs... {sbomRun.done} of {sbomRun.total}
          </div>
        ) : (
          c.deferred > 0 && (
            <div className="mb-4 flex items-center gap-2 rounded border border-amber-300 bg-amber-50 px-2.5 py-1.5 text-sm dark:border-amber-800 dark:bg-amber-950">
              <span>
                {c.deferred} SBOM{c.deferred === 1 ? ' is' : 's are'} not analysed yet (beyond the
                load-time size budget, or a stopped run).
              </span>
              <button
                type="button"
                onClick={() => void runSbomAnalysis()}
                className={clsx(BUTTON_SECONDARY, 'ml-auto')}
              >
                Analyse now
              </button>
            </div>
          )
        )}
        {sbomError && !sbomRun && (
          <p className="mb-4 text-xs text-red-600 dark:text-red-400">
            The SBOM analysis stopped: {sbomError}. The SBOMs it did not reach stay marked; try
            again with "Analyse now".
          </p>
        )}

        <Section
          title="Artifacts"
          action={
            optional > 0 ? (
              <label className="flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400">
                <input
                  type="checkbox"
                  checked={showOptional}
                  onChange={(e) => setShowOptional(e.target.checked)}
                />
                {optional} without SBOM requirement
              </label>
            ) : undefined
          }
        >
          {rows.length === 0 ? (
            <p className="text-sm text-slate-500 dark:text-slate-400">
              No artifact in this delivery calls for an SBOM (images, executables, extensions do).
            </p>
          ) : (
            <Table
              head={['Artifact', 'Component version', 'Type', 'Transport', 'SBOM', 'Evidence']}
            >
              {rows.map((row) => {
                const artifact = artifactAt(bundle, row.artifact);
                return (
                  <tr
                    key={`${row.artifact.cvId}:${row.artifact.index}`}
                    className="border-t border-slate-100 dark:border-slate-800/60"
                  >
                    <td className="px-3 py-1.5">
                      <button
                        type="button"
                        onClick={() =>
                          selectArtifact({
                            cvId: row.artifact.cvId,
                            role: 'resource',
                            index: row.artifact.index,
                          })
                        }
                        className="font-medium hover:text-accent-700 dark:hover:text-accent-400"
                      >
                        {artifact?.name}
                      </button>
                    </td>
                    <td className="px-3 py-1.5 font-mono text-xs text-slate-500 dark:text-slate-400">
                      {row.artifact.cvId}
                    </td>
                    <td className="px-3 py-1.5 text-slate-500 dark:text-slate-400">
                      {artifact?.type ?? '-'}
                    </td>
                    <td className="px-3 py-1.5">
                      {artifact && <TransportChip transport={artifact.transport} />}
                    </td>
                    <td className="px-3 py-1.5">
                      {row.sboms.length === 0
                        ? '-'
                        : row.sboms.map((ref) => (
                            <button
                              key={`${ref.cvId}:${ref.index}`}
                              type="button"
                              onClick={() =>
                                selectSbom({ cvId: ref.cvId, role: 'resource', index: ref.index })
                              }
                              className="mr-2 text-accent-700 hover:underline dark:text-accent-400"
                            >
                              {artifactAt(bundle, ref)?.name}
                            </button>
                          ))}
                    </td>
                    <td className="px-3 py-1.5">
                      <CoverageChip row={row} />
                    </td>
                  </tr>
                );
              })}
            </Table>
          )}
        </Section>

        <Section title={`SBOMs (${evidence.sboms.length})`}>
          {evidence.sboms.length === 0 ? (
            <p className="text-sm text-slate-500 dark:text-slate-400">
              This delivery carries no SBOM resources.
            </p>
          ) : (
            <Table
              head={[
                'SBOM',
                'Component version',
                'Format',
                'Packages',
                'Describes',
                'Binding',
                'NTIA',
              ]}
            >
              {evidence.sboms.map((occurrence) => {
                const summary = summaryOf(delivery, occurrence);
                const isSelected = selected === occurrence;
                return (
                  <tr
                    key={`${occurrence.at.cvId}:${occurrence.at.index}`}
                    onClick={() =>
                      selectSbom({
                        cvId: occurrence.at.cvId,
                        role: 'resource',
                        index: occurrence.at.index,
                      })
                    }
                    className={clsx(
                      'cursor-pointer border-t border-slate-100 dark:border-slate-800/60',
                      isSelected
                        ? 'bg-accent-50 dark:bg-accent-950'
                        : 'hover:bg-slate-50 dark:hover:bg-slate-900',
                    )}
                  >
                    <td className="px-3 py-1.5 font-medium">{occurrence.name}</td>
                    <td className="px-3 py-1.5 font-mono text-xs text-slate-500 dark:text-slate-400">
                      {occurrence.at.cvId}
                    </td>
                    <td className="px-3 py-1.5 text-slate-500 dark:text-slate-400">
                      {summary ? summary.spec : <PresenceChip occurrence={occurrence} />}
                    </td>
                    <td className="px-3 py-1.5 text-slate-500 dark:text-slate-400">
                      {summary ? summary.packages : '-'}
                    </td>
                    <td
                      className="max-w-56 truncate px-3 py-1.5 text-xs text-slate-500 dark:text-slate-400"
                      title={subjectLabel(summary)}
                    >
                      {subjectLabel(summary)}
                    </td>
                    <td className="px-3 py-1.5">
                      {summary ? <BindingChip binding={occurrence.binding} /> : '-'}
                    </td>
                    <td className="px-3 py-1.5 text-xs text-slate-500 dark:text-slate-400">
                      {summary ? <NtiaCell summary={summary} /> : '-'}
                    </td>
                  </tr>
                );
              })}
            </Table>
          )}
        </Section>

        {evidence.findings.length > 0 && (
          <Section title={`Findings (${evidence.findings.length})`}>
            <ul className="space-y-1 text-sm">
              {evidence.findings.map((f) => (
                <li key={f.code} className="flex gap-2">
                  <span
                    className={
                      f.severity === 'warning'
                        ? 'text-amber-600 dark:text-amber-400'
                        : 'text-slate-400'
                    }
                  >
                    {f.severity}
                  </span>
                  <span>{f.message}</span>
                </li>
              ))}
            </ul>
          </Section>
        )}
      </div>

      {selected && (
        <aside className="w-96 shrink-0 overflow-auto border-l border-slate-200 p-3 dark:border-slate-800">
          <SbomDetail
            occurrence={selected}
            bundle={bundle}
            delivery={delivery}
            onClose={() => selectSbom(null)}
          />
        </aside>
      )}
    </div>
  );
}

function Table({ head, children }: { head: string[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto rounded-md border border-slate-200 dark:border-slate-800">
      <table className="w-full text-sm">
        <thead className="bg-slate-50 text-left text-xs text-slate-500 dark:bg-slate-900 dark:text-slate-400">
          <tr>
            {head.map((h) => (
              <th key={h} className="px-3 py-1.5 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

function summaryOf(delivery: LoadedDelivery, occurrence: SbomOccurrence): SbomSummary | undefined {
  const analysis = occurrence.sha1 ? delivery.sbomAnalyses[occurrence.sha1] : undefined;
  return analysis?.state === 'analyzed' ? analysis.summary : undefined;
}

function subjectLabel(summary: SbomSummary | undefined): string {
  if (!summary) return '-';
  const version = summary.subject.version?.replace(
    /^(sha256:)?([0-9a-f]{12})[0-9a-f]{52}$/i,
    'sha256:$2...',
  );
  return [summary.subject.name, version].filter(Boolean).join(' ') || '-';
}

function PresenceChip({ occurrence }: { occurrence: SbomOccurrence }) {
  if (occurrence.presence === 'external')
    return <Chip title="Declared with an external access; not in this delivery">external</Chip>;
  if (occurrence.presence === 'deferred') return <Chip tone="warn">not analysed yet</Chip>;
  return <Chip tone="danger">unreadable</Chip>;
}

function SbomDetail({
  occurrence,
  bundle,
  delivery,
  onClose,
}: {
  occurrence: SbomOccurrence;
  bundle: OcmBundle;
  delivery: LoadedDelivery;
  onClose: () => void;
}) {
  const selectCv = useAppStore((s) => s.actions.selectCv);
  const showPackages = useAppStore((s) => s.actions.showPackages);
  const artifact = artifactAt(bundle, occurrence.at);
  const analysis = occurrence.sha1 ? delivery.sbomAnalyses[occurrence.sha1] : undefined;
  const summary = analysis?.state === 'analyzed' ? analysis.summary : undefined;
  if (!artifact) return null;

  return (
    <div>
      <div className="mb-2 flex items-start justify-between gap-2">
        <div>
          <div className="font-medium">{occurrence.name}</div>
          <button
            type="button"
            onClick={() => selectCv(occurrence.at.cvId)}
            className="font-mono text-xs text-slate-400 hover:text-accent-700 dark:hover:text-accent-400"
          >
            {occurrence.at.cvId}
          </button>
        </div>
        <button type="button" onClick={onClose} className="text-slate-400" aria-label="Close">
          ✕
        </button>
      </div>

      {occurrence.binding && (
        <Section title="Describes">
          <div className="mb-1.5">
            <BindingChip binding={occurrence.binding} />
          </div>
          {bindingExplanation(occurrence.binding, bundle).map((line) => (
            <p key={line} className="mb-1 text-sm text-slate-600 dark:text-slate-300">
              {line}
            </p>
          ))}
        </Section>
      )}

      {!summary && (
        <Section title="Analysis">
          <p className="text-sm text-slate-600 dark:text-slate-300">
            {occurrence.presence === 'external'
              ? 'This SBOM is declared with an external access and is not part of the delivery, so it cannot be analysed offline.'
              : occurrence.presence === 'deferred'
                ? 'Not analysed at load time (size budget). Use "Analyse now" above.'
                : analysis?.state === 'unreadable'
                  ? `The parsers could not read it: ${analysis.reason}`
                  : 'Its bytes could not be read from the delivery.'}
          </p>
        </Section>
      )}

      {summary && (
        <>
          <Section title="Fact sheet">
            <KV label="Format">{summary.spec}</KV>
            <KV label="Name">{summary.documentName || '-'}</KV>
            <KV label="Generator">{generatorLabel(summary.creators)}</KV>
            {summary.created && <KV label="Created">{summary.created}</KV>}
            <KV label="Packages">
              {summary.packages}
              {occurrence.sha1 && (
                <button
                  type="button"
                  onClick={() => showPackages({ sbom: occurrence.sha1! })}
                  className="ml-2 text-xs text-accent-700 hover:underline dark:text-accent-400"
                >
                  Show in Packages
                </button>
              )}
            </KV>
            <KV label="Relationships">{summary.relationships}</KV>
            {artifact.sbom && <KV label="Size">{formatBytes(artifact.sbom.size)}</KV>}
            <KV label="Subject">
              {subjectLabel(summary)}
              {summary.subject.source === 'inferred' && (
                <span className="ml-1 text-xs text-slate-400">(inferred)</span>
              )}
            </KV>
          </Section>

          <Section title="Package fields">
            {(
              [
                ['Version', summary.fields.version],
                ['Supplier', summary.fields.supplier],
                ['purl or other ID', summary.fields.uniqueId],
                ['Checksum', summary.fields.checksum],
                ['License', summary.fields.license],
              ] as const
            ).map(([label, count]) => (
              <Meter key={label} label={label} count={count} total={summary.packages} />
            ))}
          </Section>

          <Section
            title={`NTIA minimum elements · ${ntiaLabel(ntiaSummary(summary.profiles.ntia))}`}
          >
            <Checks results={summary.profiles.ntia.results} required={NTIA_FIELDS} />
            <p className="mt-1 text-xs text-slate-400">
              Version, supplier and unique ID are minimum elements for every component: below 100 %
              they show as a gap. Checksums and licenses are measured, not required.
            </p>
          </Section>
          <Section title={`BSI TR-03183-2 (approximation) · ${bsiLabel(summary.profiles.bsi)}`}>
            <Checks results={summary.profiles.bsi.results} />
            <p className="mt-1 text-xs text-slate-400">
              The TR accepts only SPDX 3.0.1+ or CycloneDX 1.6+; the field checks still show what is
              present.
            </p>
          </Section>

          {summary.parse.errors + summary.parse.warnings > 0 && (
            <Section
              title={`Parser findings · ${summary.parse.errors} error(s), ${summary.parse.warnings} warning(s)`}
            >
              <ul className="space-y-1 text-xs text-slate-500 dark:text-slate-400">
                {summary.parse.first.map((d, i) => (
                  <li key={i}>{d.message}</li>
                ))}
              </ul>
            </Section>
          )}
        </>
      )}

      {artifact.sbom && (
        <button
          type="button"
          onClick={() => downloadSbom(delivery, artifact)}
          className={BUTTON_SECONDARY}
        >
          Download SBOM ({artifact.sbom.format})
        </button>
      )}
    </div>
  );
}

function Meter({ label, count, total }: { label: string; count: number; total: number }) {
  const percent = total === 0 ? 0 : Math.round((count / total) * 100);
  return (
    <div className="grid grid-cols-[8rem_1fr_3.5rem] items-center gap-2 py-0.5 text-xs">
      <span className="text-slate-500 dark:text-slate-400">{label}</span>
      <span className="h-1.5 overflow-hidden rounded bg-slate-100 dark:bg-slate-800">
        <span className="block h-full bg-accent-500" style={{ width: `${percent}%` }} />
      </span>
      <span className="text-right text-slate-500 dark:text-slate-400">{percent} %</span>
    </div>
  );
}

/** The NTIA reading in a table cell: complete, or the weakest element. */
function NtiaCell({ summary }: { summary: SbomSummary }) {
  const ntia = ntiaSummary(summary.profiles.ntia);
  return (
    <span
      className={ntia.complete ? 'text-emerald-600 dark:text-emerald-400' : undefined}
      title="NTIA minimum elements: document checks, then the package field with the lowest coverage"
    >
      {ntiaLabel(ntia)}
    </span>
  );
}

function Checks({
  results,
  required,
}: {
  results: SbomSummary['profiles']['ntia']['results'];
  /** Meters that are minimum elements: below 100 % they are a gap, not info. */
  required?: ReadonlySet<string>;
}) {
  return (
    <ul className="space-y-0.5 text-xs">
      {results.map((r) => {
        // Coverage meters without a threshold inform; they never gate,
        // unless the caller names them required (NTIA package elements).
        const meter =
          r.informational === true ||
          (r.kind === 'coverage' && r.coverage?.threshold === undefined);
        const complete = r.coverage ? r.coverage.satisfied === r.coverage.total : r.pass;
        const status = required?.has(r.id)
          ? complete
            ? 'pass'
            : 'gap'
          : meter
            ? 'info'
            : r.pass
              ? 'pass'
              : 'fail';
        return (
          <li key={r.id} className="flex items-baseline gap-2">
            <span
              className={clsx(
                'w-8 shrink-0',
                status === 'info'
                  ? 'text-slate-400'
                  : status === 'pass'
                    ? 'text-emerald-600 dark:text-emerald-400'
                    : status === 'gap'
                      ? 'text-amber-600 dark:text-amber-400'
                      : 'text-red-600 dark:text-red-400',
              )}
            >
              {status}
            </span>
            <span className="text-slate-600 dark:text-slate-300">
              {r.label}
              {r.coverage && <span className="ml-1 text-slate-400">({r.coverage.percent} %)</span>}
            </span>
          </li>
        );
      })}
    </ul>
  );
}
