import type { QualityReport } from '../analysis/quality';
import type { ProfileCheckResult, ProfileReport } from './evaluate';

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
  if (report.profileSpecUrl) lines.push(`- Requirement source: <${report.profileSpecUrl}>`);
  if (opts.sourceFileName) lines.push(`- Source file: \`${opts.sourceFileName}\``);
  if (opts.generatedAt) lines.push(`- Generated: ${opts.generatedAt}`);
  const gates = report.gatedPassed + report.gatedFailed;
  lines.push(`- Result: **${report.gatedPassed}/${gates} gated checks passed**`);
  if (report.noneInScope > 0) {
    lines.push(`- Meters with nothing in scope: ${report.noneInScope} (0/0, pass by construction)`);
  }
  lines.push('');

  // The description carries what the profile approximates and what it
  // cannot check. An exported report that drops it would read as a
  // conformance statement, which is exactly what it is not.
  if (report.profileDescription) {
    lines.push('> ' + report.profileDescription);
    lines.push('');
  }

  const booleans = report.results.filter((r) => r.kind === 'boolean');
  if (booleans.length > 0) {
    lines.push('## Document checks');
    lines.push('');
    for (const result of booleans) {
      const note = result.informational ? ' (informational)' : '';
      lines.push(`- [${result.pass ? 'x' : ' '}] ${result.label}${note}: ${result.actual ?? ''}`.trimEnd());
    }
    lines.push('');
  }

  const coverageTable = (title: string, rows: ProfileCheckResult[]) => {
    if (rows.length === 0) return;
    lines.push(title);
    lines.push('');
    lines.push('| Check | Coverage | Percent | Threshold | Result |');
    lines.push('| --- | --- | --- | --- | --- |');
    for (const result of rows) {
      const c = result.coverage!;
      const threshold = c.threshold === undefined ? '-' : `≥ ${c.threshold}%`;
      const verdict = c.threshold === undefined ? 'info' : result.pass ? 'pass' : '**fail**';
      const percent = c.total === 0 ? 'none in scope' : `${c.percent}%`;
      lines.push(`| ${result.label} | ${c.satisfied}/${c.total} | ${percent} | ${threshold} | ${verdict} |`);
    }
    lines.push('');
  };
  // Package meters and crypto-asset meters count different things; one table
  // headed "packages" would misstate what a CBOM row's total is.
  const coverages = report.results.filter((r) => r.coverage);
  // Cryptographic assets are packages too (CycloneDX components), so the two
  // totals overlap rather than add up.
  const packagesLabel =
    report.cryptoAssetsTotal > 0
      ? `${report.packagesTotal} packages, ${report.cryptoAssetsTotal} of them cryptographic assets`
      : `${report.packagesTotal} packages`;
  coverageTable(`## Package coverage (${packagesLabel})`, coverages.filter((r) => r.subject !== 'crypto'));
  coverageTable(
    `## Cryptographic asset coverage (${report.cryptoAssetsTotal} assets)`,
    coverages.filter((r) => r.subject === 'crypto'),
  );

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
