import type { AcceptanceReport } from '@sbomlens/core/ocm';
import { acceptanceReport } from '@sbomlens/core/ocm';
import { APP_VERSION } from '../version';
import { loadSbomPackages, loadVexSources } from './ingest';
import { useAppStore } from './store';

export type ReportOutcome =
  { ok: true; report: AcceptanceReport; fileBase: string } | { ok: false; reason: string };

/**
 * The acceptance report of the open delivery, complete or not at all.
 * While SBOMs are still being analysed it declines: the report would grade
 * a half-read delivery. The package figures need the SBOMs' package lists,
 * so missing ones are read first; when that fails, it declines with the
 * reason instead of exporting a report that calls them "not loaded".
 */
export async function prepareAcceptanceReport(now = new Date()): Promise<ReportOutcome> {
  const started = useAppStore.getState();
  if (!started.delivery) return { ok: false, reason: 'No delivery is open.' };
  if (started.sbomRun) return { ok: false, reason: analysing(started.sbomRun) };

  const loaded = await loadSbomPackages();
  // The delivery's own VEX documents belong in the report; one that cannot
  // be read is reported as unreadable, not left out.
  await loadVexSources();
  const { delivery, sbomRun, packageError, verification } = useAppStore.getState();
  if (!delivery || delivery.extracted !== started.delivery.extracted) {
    return { ok: false, reason: 'Another delivery was opened meanwhile.' };
  }
  if (sbomRun) return { ok: false, reason: analysing(sbomRun) };
  if (!loaded) {
    return {
      ok: false,
      reason: `The report needs the package lists of the SBOMs, and reading them stopped${packageError ? `: ${packageError}` : ''}. Export again to retry.`,
    };
  }
  const report = acceptanceReport({
    bundle: delivery.bundle,
    signatures: verification?.entries,
    toolVersion: APP_VERSION,
    generatedAt: now.toISOString(),
    sbomAnalyses: delivery.sbomAnalyses,
    sbomPackages: delivery.sbomPackages,
    vexSources: delivery.vexSources,
  });
  const fileBase = delivery.bundle.fileName.replace(/(\.(ctf|tar|tgz|gz|yaml|yml|json))+$/i, '');
  return { ok: true, report, fileBase };
}

function analysing(run: { done: number; total: number }): string {
  return `The SBOMs are still being analysed (${run.done} of ${run.total}); export the report when the analysis is done.`;
}
