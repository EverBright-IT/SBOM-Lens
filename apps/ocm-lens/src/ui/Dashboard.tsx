import type { OcmBundle } from '@sbomlens/core/ocm';
import type { MainView } from '../app/store';
import { useSbomEvidence } from '../app/evidence';
import { useAppStore } from '../app/store';
import { formatBytes } from './bits';

/**
 * The delivery at a glance — the view OCM Lens 1.x never had. Every number
 * is a door: the cards jump into the view that explains them.
 */

const LAYOUT_LABEL: Record<OcmBundle['layout'], string> = {
  ctf: 'CTF',
  'component-archive': 'Component archive',
  descriptor: 'Component descriptor',
};

function Kpi({ label, value, hint, goto }: { label: string; value: string; hint?: string; goto?: MainView }) {
  const setView = useAppStore((s) => s.actions.setView);
  return (
    <button
      type="button"
      disabled={!goto}
      onClick={() => goto && setView(goto)}
      className="rounded-md border border-slate-200 px-3 py-2 text-left enabled:cursor-pointer enabled:hover:border-accent-300 dark:border-slate-800 dark:enabled:hover:border-accent-700"
    >
      <div className="text-[11px] tracking-wide text-slate-400 uppercase dark:text-slate-500">{label}</div>
      <div className="mt-0.5 text-lg font-semibold">{value}</div>
      {hint && <div className="text-xs text-slate-500 dark:text-slate-400">{hint}</div>}
    </button>
  );
}

export function Dashboard() {
  const delivery = useAppStore((s) => s.delivery);
  const evidence = useSbomEvidence();
  const sbomRun = useAppStore((s) => s.sbomRun);
  if (!delivery) return null;
  const { bundle, diagnostics } = delivery;
  const c = bundle.completeness;

  const signedCvs = bundle.componentVersions.filter((cv) => (cv.signatures?.length ?? 0) > 0).length;
  const issues = [...bundle.issues, ...diagnostics, ...(evidence?.findings ?? [])];
  const e = evidence?.counts;

  return (
    <div className="mx-auto max-w-5xl space-y-5 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="text-lg font-semibold">{bundle.fileName}</h1>
        <span className="rounded border border-slate-200 px-1.5 py-0.5 text-[11px] text-slate-500 dark:border-slate-700 dark:text-slate-400">
          {LAYOUT_LABEL[bundle.layout]}
          {bundle.compressed ? ' (gzip)' : ''}
        </span>
        {c.broken > 0 ? (
          <span className="rounded border border-red-300 bg-red-50 px-1.5 py-0.5 text-[11px] text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            incomplete · {c.broken} broken
          </span>
        ) : c.airGapReady ? (
          <span className="rounded border border-emerald-300 bg-emerald-50 px-1.5 py-0.5 text-[11px] text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400">
            self-contained — air-gap ready
          </span>
        ) : (
          <span className="rounded border border-amber-300 bg-amber-50 px-1.5 py-0.5 text-[11px] text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400">
            needs network to deploy
          </span>
        )}
        {bundle.digestsDeferred && (
          <button
            type="button"
            onClick={() => useAppStore.getState().actions.setView('verify')}
            className="rounded border border-amber-300 bg-amber-50 px-1.5 py-0.5 text-[11px] text-amber-700 hover:border-amber-400 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400"
            title="Digest checks were deferred at load; run them in the Verify view"
          >
            {bundle.digestsDeferred.blobs} digest{bundle.digestsDeferred.blobs === 1 ? '' : 's'} unchecked (
            {formatBytes(bundle.digestsDeferred.bytes)})
          </button>
        )}
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
        <Kpi
          label="Component versions"
          value={String(bundle.componentVersions.length)}
          hint={`${bundle.roots.length} root${bundle.roots.length === 1 ? '' : 's'}${bundle.shared.length > 0 ? ` · ${bundle.shared.length} shared` : ''}`}
          goto="components"
        />
        <Kpi
          label="Archive"
          value={formatBytes(bundle.archiveSize)}
          hint={`${bundle.blobs.length} blobs${bundle.dedupSavedBytes > 0 ? ` · ${formatBytes(bundle.dedupSavedBytes)} deduped` : ''}`}
          goto="resources"
        />
        <Kpi
          label="Transported"
          value={String(c.transported)}
          hint={`${c.external} external · ${c.broken} broken${c.unknown > 0 ? ` · ${c.unknown} unknown` : ''}`}
          goto="resources"
        />
        <Kpi
          label="References"
          value={c.unresolvedRefs === 0 ? 'closed' : `${c.unresolvedRefs} open`}
          hint={c.unresolvedRefs === 0 ? 'closure complete in-bundle' : 'point outside this bundle'}
          goto="components"
        />
        <Kpi
          label="Signatures"
          value={signedCvs === 0 ? 'none' : `${signedCvs} signed`}
          hint={signedCvs === 0 ? 'no component version signed' : 'verify in the Verify view'}
          goto="verify"
        />
        <Kpi
          label="SBOMs"
          value={
            sbomRun
              ? 'analysing'
              : e && e.expected > 0
                ? `${e.covered} of ${e.expected}`
                : String(e?.sboms ?? 0)
          }
          hint={
            sbomRun
              ? `${sbomRun.done} of ${sbomRun.total} SBOMs read`
              : !e
                ? 'not analysed'
                : e.expected > 0
                  ? `artifacts covered${e.missing > 0 ? ` · ${e.missing} missing` : ''}${e.deferred > 0 ? ` · ${e.deferred} deferred` : ''}`
                  : `embedded · none expected`
          }
          goto="sboms"
        />
      </div>

      <section>
        <h2 className="mb-1.5 text-[11px] font-medium tracking-wide text-slate-400 uppercase dark:text-slate-500">
          Component versions
        </h2>
        <div className="overflow-hidden rounded-md border border-slate-200 dark:border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-xs text-slate-500 dark:bg-slate-900 dark:text-slate-400">
              <tr>
                <th className="px-3 py-1.5 font-medium">Component</th>
                <th className="px-3 py-1.5 font-medium">Provider</th>
                <th className="px-3 py-1.5 font-medium">Resources</th>
                <th className="px-3 py-1.5 font-medium">References</th>
                <th className="px-3 py-1.5 font-medium">Evidence</th>
              </tr>
            </thead>
            <tbody>
              {bundle.componentVersions.map((cv) => {
                const unresolved = cv.references.filter((r) => !r.target).length;
                return (
                  <tr key={cv.id} className="border-t border-slate-100 dark:border-slate-800/60">
                    <td className="px-3 py-1.5">
                      <span className="font-medium">{cv.name}</span>{' '}
                      <span className="text-slate-400">{cv.version}</span>
                      {bundle.roots.includes(cv.id) && (
                        <span className="ml-1.5 rounded bg-accent-50 px-1 py-px text-[10px] text-accent-700 dark:bg-accent-950 dark:text-accent-400">
                          root
                        </span>
                      )}
                      {bundle.shared.includes(cv.id) && (
                        <span className="ml-1.5 rounded bg-slate-100 px-1 py-px text-[10px] text-slate-500 dark:bg-slate-800 dark:text-slate-400">
                          shared
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-1.5 text-slate-500 dark:text-slate-400">{cv.provider?.name ?? '-'}</td>
                    <td className="px-3 py-1.5 text-slate-500 dark:text-slate-400">
                      {cv.resources.length}
                      {cv.sources.length > 0 ? ` (+${cv.sources.length} sources)` : ''}
                    </td>
                    <td className="px-3 py-1.5 text-slate-500 dark:text-slate-400">
                      {cv.references.length === 0 ? '-' : `${cv.references.length}${unresolved > 0 ? ` (${unresolved} open)` : ''}`}
                    </td>
                    <td className="px-3 py-1.5">
                      {(cv.signatures?.length ?? 0) > 0 && (
                        <span className="mr-1 rounded border border-slate-200 px-1 py-px text-[10px] text-slate-500 dark:border-slate-700 dark:text-slate-400">
                          signed
                        </span>
                      )}
                      {cv.resources.some((r) => r.sbom) && (
                        <span className="rounded border border-slate-200 px-1 py-px text-[10px] text-slate-500 dark:border-slate-700 dark:text-slate-400">
                          SBOM
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {issues.length > 0 && (
        <section>
          <h2 className="mb-1.5 text-[11px] font-medium tracking-wide text-slate-400 uppercase dark:text-slate-500">
            Findings ({issues.length})
          </h2>
          <ul className="space-y-1 text-xs">
            {issues.map((d, i) => (
              <li key={i} className="flex gap-2">
                <span
                  className={
                    d.severity === 'error'
                      ? 'text-red-600 dark:text-red-400'
                      : d.severity === 'warning'
                        ? 'text-amber-600 dark:text-amber-400'
                        : 'text-slate-400'
                  }
                >
                  {d.severity}
                </span>
                <span className="text-slate-600 dark:text-slate-300">{d.message}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
