import type { QualityReport } from '../analysis/quality';
import type { ProfileReport } from './evaluate';

/**
 * Audit-friendly Markdown rendering of a profile report (host-free; the UI
 * hands it to host().exportFile).
 */
export function profileReportToMarkdown(
  report: ProfileReport,
  opts: {
    docName: string;
    sourceFileName?: string;
    issues?: QualityReport['issues'];
    generatedAt?: string;
  },
): string {
  const lines: string[] = [];
  lines.push(`# Quality report: ${opts.docName}`);
  lines.push('');
  lines.push(`- Profile: **${report.profileName}**`);
  if (opts.sourceFileName) lines.push(`- Source file: \`${opts.sourceFileName}\``);
  if (opts.generatedAt) lines.push(`- Generated: ${opts.generatedAt}`);
  const gates = report.gatedPassed + report.gatedFailed;
  lines.push(`- Result: **${report.gatedPassed}/${gates} gated checks passed**`);
  lines.push('');

  const booleans = report.results.filter((r) => r.kind === 'boolean');
  if (booleans.length > 0) {
    lines.push('## Document checks');
    lines.push('');
    for (const result of booleans) {
      lines.push(`- [${result.pass ? 'x' : ' '}] ${result.label}: ${result.actual ?? ''}`.trimEnd());
    }
    lines.push('');
  }

  const coverages = report.results.filter((r) => r.coverage);
  if (coverages.length > 0) {
    lines.push(`## Package coverage (${report.packagesTotal} packages)`);
    lines.push('');
    lines.push('| Check | Coverage | Percent | Threshold | Result |');
    lines.push('| --- | --- | --- | --- | --- |');
    for (const result of coverages) {
      const c = result.coverage!;
      const threshold = c.threshold === undefined ? '-' : `≥ ${c.threshold}%`;
      const verdict = c.threshold === undefined ? 'info' : result.pass ? 'pass' : '**fail**';
      lines.push(`| ${result.label} | ${c.satisfied}/${c.total} | ${c.percent}% | ${threshold} | ${verdict} |`);
    }
    lines.push('');
  }

  if (opts.issues) {
    const parts = [
      opts.issues.unresolvedStructuralRefs > 0 &&
        `${opts.issues.unresolvedStructuralRefs} unresolved external reference(s)`,
      opts.issues.danglingLocalRefs > 0 &&
        `${opts.issues.danglingLocalRefs} dangling relationship target(s)`,
      opts.issues.duplicateSpdxIds > 0 && `${opts.issues.duplicateSpdxIds} duplicate SPDXID(s)`,
    ].filter(Boolean);
    if (parts.length > 0) {
      lines.push(`Issues: ${parts.join(' · ')}`);
      lines.push('');
    }
  }

  return lines.join('\n');
}
