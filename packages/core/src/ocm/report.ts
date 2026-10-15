import type { OcmArtifact, OcmBundle, OcmCv } from '../model/ocm-bundle';
import type { ResourceRef, SbomAnalysis, SbomBinding, SbomCoverageRow, SbomEvidence } from './sbom-evidence';
import { ntiaLabel, ntiaSummary, sbomEvidence } from './sbom-evidence';
import type { SignatureVerdict } from './verify';

/**
 * The delivery acceptance report: everything a consultant hands a customer
 * after checking a delivery, as Markdown (to read) and JSON (to archive or
 * diff). Pure function of its input — the caller injects timestamp and tool
 * version, so reports and their golden tests are deterministic.
 */

export interface AcceptanceSignatureEntry {
  cvId: string;
  name: string;
  verdict: SignatureVerdict;
  reason?: string;
  /** Which key vouched: a pinned key's label, or "pasted key". */
  keyLabel?: string;
}

export interface AcceptanceReportInput {
  bundle: OcmBundle;
  /** Signature verification results; omit when no verification ran. */
  signatures?: AcceptanceSignatureEntry[];
  toolVersion: string;
  /** ISO timestamp, injected for determinism. */
  generatedAt: string;
  /**
   * What the worker learned about the extracted SBOMs (by SHA-1). With it
   * the report grades SBOM evidence; without it, it lists the embedded
   * SBOMs as before.
   */
  sbomAnalyses?: Readonly<Record<string, SbomAnalysis>>;
}

export interface AcceptanceReport {
  markdown: string;
  json: Record<string, unknown>;
}

export interface DigestSummary {
  checked: number;
  match: number;
  mismatch: { cvId: string; artifact: string }[];
  /** Declared but not checkable (unsupported algorithm, compressed form). */
  unchecked: number;
  /** Deferred at load time (eager-hash budget); checkable on demand. */
  pending: number;
  pendingBytes: number;
}

export function digestSummary(bundle: OcmBundle): DigestSummary {
  const summary: DigestSummary = {
    checked: 0,
    match: 0,
    mismatch: [],
    unchecked: 0,
    pending: 0,
    pendingBytes: 0,
  };
  for (const cv of bundle.componentVersions) {
    for (const artifact of [...cv.resources, ...cv.sources]) {
      const check = artifact.blob?.digestCheck;
      if (!check) continue;
      if (check === 'pending') {
        summary.pending++;
        summary.pendingBytes += artifact.blob?.size ?? 0;
      } else if (check === 'match') {
        summary.checked++;
        summary.match++;
      } else if (check === 'mismatch') {
        summary.checked++;
        summary.mismatch.push({ cvId: cv.id, artifact: artifact.name });
      } else {
        summary.unchecked++;
      }
    }
  }
  return summary;
}

function transportGaps(bundle: OcmBundle): { cv: OcmCv; artifact: OcmArtifact }[] {
  const gaps: { cv: OcmCv; artifact: OcmArtifact }[] = [];
  for (const cv of bundle.componentVersions) {
    for (const artifact of cv.resources) {
      if (artifact.transport === 'external' || artifact.transport === 'broken' || artifact.transport === 'unknown') {
        gaps.push({ cv, artifact });
      }
    }
  }
  return gaps;
}

const LAYOUT_LABEL: Record<OcmBundle['layout'], string> = {
  ctf: 'CTF',
  'component-archive': 'Component archive',
  descriptor: 'Component descriptor',
};

function formatBytes(n: number): string {
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

export function acceptanceReport(input: AcceptanceReportInput): AcceptanceReport {
  const { bundle, signatures, toolVersion, generatedAt } = input;
  const c = bundle.completeness;
  const digests = digestSummary(bundle);
  const gaps = transportGaps(bundle);
  const signedCvs = bundle.componentVersions.filter((cv) => (cv.signatures?.length ?? 0) > 0);
  const validCvs = new Set(
    (signatures ?? []).filter((s) => s.verdict === 'valid').map((s) => s.cvId),
  );
  const sbomCarriers = bundle.componentVersions
    .map((cv) => ({ cv, sboms: cv.resources.filter((r) => r.sbom) }))
    .filter((e) => e.sboms.length > 0);
  const evidence = input.sbomAnalyses ? sbomEvidence(bundle, input.sbomAnalyses) : undefined;

  const reasons: string[] = [];
  if (c.broken > 0) reasons.push(`${c.broken} localBlob resource(s) are missing from the archive or incomplete`);
  if (c.external > 0) reasons.push(`${c.external} resource(s) live outside the bundle (external access)`);
  if (c.unknown > 0) reasons.push(`${c.unknown} resource(s) use an access type this tool cannot classify`);
  if (c.unresolvedRefs > 0) reasons.push(`${c.unresolvedRefs} component reference(s) point outside the bundle`);

  const findings = [
    ...bundle.issues,
    ...bundle.componentVersions.flatMap((cv) =>
      cv.diagnostics.map((d) => ({ ...d, message: `${cv.id}: ${d.message}` })),
    ),
    ...(evidence?.findings ?? []),
  ];

  const lines: string[] = [];
  const push = (s = '') => lines.push(s);

  push('# Delivery acceptance report');
  push();
  push('| | |');
  push('| --- | --- |');
  push(`| Delivery | \`${bundle.fileName}\` |`);
  push(`| Layout | ${LAYOUT_LABEL[bundle.layout]}${bundle.compressed ? ' (gzip)' : ''} |`);
  push(`| Size | ${formatBytes(bundle.archiveSize)} |`);
  push(`| Generated | ${generatedAt} by OCM Lens ${toolVersion} (client-side, nothing uploaded) |`);
  push();
  push('## Verdict');
  push();
  // Broken outranks external: no network brings back a localBlob the
  // delivery lost or cut short.
  push(
    c.broken > 0
      ? `**INCOMPLETE DELIVERY.** ${reasons.join('; ')}.`
      : c.airGapReady
        ? '**SELF-CONTAINED.** Every resource is transported in the bundle and the reference closure is complete: deploying from this delivery needs no network.'
        : `**NEEDS NETWORK TO DEPLOY.** ${reasons.join('; ')}.`,
  );
  push();
  push(`- ${bundle.componentVersions.length} component version(s), ${bundle.roots.length} root(s)${bundle.shared.length > 0 ? `, ${bundle.shared.length} shared via multiple references` : ''}`);
  push(`- Resources: ${c.transported} transported, ${c.external} external, ${c.broken} broken, ${c.unknown} unknown`);
  push(`- Reference closure: ${c.unresolvedRefs === 0 ? 'complete in-bundle' : `${c.unresolvedRefs} reference(s) open`}`);
  push(`- Blob digests: ${digests.checked} checked, ${digests.match} match, ${digests.mismatch.length} mismatch${digests.unchecked > 0 ? `, ${digests.unchecked} declared but not checkable` : ''}${digests.pending > 0 ? `, ${digests.pending} deferred (not checked in this run)` : ''}`);
  push(
    signedCvs.length === 0
      ? '- Signatures: none in this delivery'
      : signatures
        ? `- Signatures: ${validCvs.size} of ${signedCvs.length} signed component version(s) verified valid`
        : `- Signatures: ${signedCvs.length} component version(s) carry signatures (not verified in this run)`,
  );
  push(
    evidence
      ? `- ${evidenceLine(evidence)}`
      : `- SBOMs: ${sbomCarriers.length} of ${bundle.componentVersions.length} component version(s) carry embedded SBOMs`,
  );
  push();
  push('## Component versions');
  push();
  push('| Component | Version | Provider | Resources | References | Signed | SBOM |');
  push('| --- | --- | --- | --- | --- | --- | --- |');
  for (const cv of bundle.componentVersions) {
    const open = cv.references.filter((r) => !r.target).length;
    push(
      `| ${cv.name} | ${cv.version} | ${cv.provider?.name ?? '-'} | ${cv.resources.length} | ${cv.references.length}${open > 0 ? ` (${open} open)` : ''} | ${(cv.signatures?.length ?? 0) > 0 ? 'yes' : '-'} | ${cv.resources.some((r) => r.sbom) ? 'yes' : '-'} |`,
    );
  }

  if (gaps.length > 0 || c.unresolvedRefs > 0) {
    push();
    push('## Transport gaps');
    push();
    for (const { cv, artifact } of gaps) {
      push(
        `- ${cv.id}: resource \`${artifact.name}\` (${artifact.type ?? 'untyped'}) is ${artifact.transport}${artifact.access?.type ? ` via \`${artifact.access.type}\`` : ''}${artifact.location ? ` — ${artifact.location}` : ''}`,
      );
    }
    for (const cv of bundle.componentVersions) {
      for (const ref of cv.references) {
        if (!ref.target) push(`- ${cv.id}: reference \`${ref.name}\` → ${ref.componentName}@${ref.version} is not in this bundle`);
      }
    }
  }

  push();
  push('## Integrity (blob digests)');
  push();
  if (digests.pending > 0) {
    push(`${digests.pending} declared digest(s) (${formatBytes(digests.pendingBytes)}) were deferred at load and NOT checked in this run.`);
    push();
  }
  if (digests.checked === 0 && digests.unchecked === 0 && digests.pending === 0) {
    push('No resources with bytes in the bundle.');
  } else if (digests.mismatch.length === 0) {
    push(`All ${digests.match} declared digest(s) match the delivered bytes.${digests.unchecked > 0 ? ` ${digests.unchecked} digest(s) are declared but not checkable (unsupported algorithm or compressed form).` : ''}`);
  } else {
    push(`**${digests.mismatch.length} MISMATCH(ES)** — the delivered bytes do not match the descriptor:`);
    push();
    for (const m of digests.mismatch) push(`- ${m.cvId}: \`${m.artifact}\``);
  }

  push();
  push('## Signatures');
  push();
  if (signedCvs.length === 0) {
    push('This delivery carries no signatures.');
  } else if (!signatures) {
    push('Signatures present but not verified in this run.');
  } else {
    push('| Component | Signature | Verdict | Key | Detail |');
    push('| --- | --- | --- | --- | --- |');
    for (const entry of signatures) {
      push(`| ${entry.cvId} | ${entry.name} | ${entry.verdict} | ${entry.keyLabel ?? '-'} | ${entry.reason ?? '-'} |`);
    }
  }

  push();
  if (evidence) {
    for (const line of evidenceSection(bundle, evidence, input.sbomAnalyses!)) push(line);
  } else {
    push('## Embedded SBOMs');
    push();
    if (sbomCarriers.length === 0) {
      push('No embedded SBOMs.');
    } else {
      for (const { cv, sboms } of sbomCarriers) {
        for (const r of sboms) {
          push(`- ${cv.id}: \`${r.name}\` (${r.sbom!.format}, ${formatBytes(r.sbom!.size)})`);
        }
      }
    }
  }

  if (findings.length > 0) {
    push();
    push(`## Findings (${findings.length})`);
    push();
    for (const d of findings.slice(0, 50)) push(`- ${d.severity}: ${d.message}`);
    if (findings.length > 50) push(`- ... and ${findings.length - 50} more`);
  }
  push();

  const json: Record<string, unknown> = {
    schema: 'ocm-lens-acceptance-report/v1',
    generatedAt,
    tool: { name: 'OCM Lens', version: toolVersion },
    delivery: {
      file: bundle.fileName,
      layout: bundle.layout,
      compressed: bundle.compressed,
      size: bundle.archiveSize,
    },
    verdict: { airGapReady: c.airGapReady, reasons },
    completeness: { ...c },
    componentVersions: bundle.componentVersions.map((cv) => ({
      id: cv.id,
      provider: cv.provider?.name,
      resources: cv.resources.length,
      references: cv.references.map((r) => ({
        name: r.name,
        target: `${r.componentName}@${r.version}`,
        resolved: r.target !== undefined,
      })),
      signed: (cv.signatures?.length ?? 0) > 0,
      sboms: cv.resources.filter((r) => r.sbom).map((r) => r.name),
    })),
    digests: {
      checked: digests.checked,
      match: digests.match,
      mismatch: digests.mismatch,
      unchecked: digests.unchecked,
      pending: digests.pending,
    },
    signatures: signatures ?? null,
    ...(evidence ? { sbomEvidence: evidenceJson(bundle, evidence, input.sbomAnalyses!) } : {}),
    findings: findings.map((d) => ({ severity: d.severity, code: d.code, message: d.message })),
  };

  return { markdown: lines.join('\n'), json };
}

function evidenceLine(evidence: SbomEvidence): string {
  const c = evidence.counts;
  if (c.expected === 0) return `SBOM evidence: no artifact in this delivery calls for an SBOM (${c.sboms} SBOM(s) embedded)`;
  const how = [
    c.byDigest > 0 ? `${c.byDigest} by digest` : '',
    c.byReference > 0 ? `${c.byReference} by reference` : '',
    c.byComponent > 0 ? `${c.byComponent} by component` : '',
  ].filter(Boolean);
  const rest = [
    c.unverified > 0 ? `${c.unverified} unverified` : '',
    c.declared > 0 ? `${c.declared} with an SBOM declared but not analysed` : '',
    c.missing > 0 ? `${c.missing} without an SBOM` : '',
  ].filter(Boolean);
  return `SBOM evidence: ${c.covered} of ${c.expected} artifact(s) that ship software have a bound SBOM${how.length > 0 ? ` (${how.join(', ')})` : ''}${rest.length > 0 ? `; ${rest.join(', ')}` : ''}`;
}

const NOTE_LABEL: Record<SbomBinding['notes'][number], string> = {
  'digest-differs': 'digest differs',
  'other-component': 'in another component version',
  ambiguous: 'ambiguous',
  'inferred-subject': 'subject inferred',
};

function bindingLabel(binding: SbomBinding | undefined): string {
  if (!binding) return '-';
  const notes = binding.notes.map((n) => NOTE_LABEL[n]);
  return notes.length > 0 ? `${binding.strength} (${notes.join(', ')})` : binding.strength;
}

function coverageLabel(row: SbomCoverageRow): string {
  if (row.status === 'bound') return row.strength!;
  if (row.status === 'declared') return `declared, ${row.reason}`;
  return row.status === 'missing' ? 'none' : row.status;
}

function resourceAt(bundle: OcmBundle, ref: ResourceRef): OcmArtifact | undefined {
  return bundle.componentVersions.find((cv) => cv.id === ref.cvId)?.resources[ref.index];
}

/** "4 of 4" over the profile's gated checks. */
function gated(report: { gatedPassed: number; gatedFailed: number }): string {
  return `${report.gatedPassed} of ${report.gatedPassed + report.gatedFailed}`;
}

function formatGateFailed(results: { id: string; pass: boolean }[]): boolean {
  return results.some((r) => r.id === 'format-baseline' && !r.pass);
}

/** A digest-shaped version, shortened for a table cell. */
function shortDigest(version: string): string {
  const match = /^(sha256:)?([0-9a-f]{64})$/i.exec(version);
  return match ? `sha256:${match[2]!.slice(0, 12)}` : version;
}

function generators(creators: string[]): string {
  const tools = creators.filter((c) => /^tool:/i.test(c)).map((c) => c.replace(/^tool:\s*/i, ''));
  return (tools.length > 0 ? tools : creators).join(', ') || '-';
}

function evidenceSection(
  bundle: OcmBundle,
  evidence: SbomEvidence,
  analyses: Readonly<Record<string, SbomAnalysis>>,
): string[] {
  const out: string[] = ['## SBOM evidence', ''];
  out.push(
    'How an SBOM is tied to an artifact: **digest** (the SBOM names a digest of the delivered artifact), **reference** (same repository and tag, no shared digest), **component** (the SBOM names the component version). SBOM evidence does not change the transport verdict.',
  );
  const rows = evidence.coverage.filter((r) => r.expected || r.status === 'bound');
  if (rows.length > 0) {
    out.push('', '| Component version | Artifact | Type | SBOM | Binding |', '| --- | --- | --- | --- | --- |');
    for (const row of rows) {
      const artifact = resourceAt(bundle, row.artifact);
      const sboms = row.sboms.map((ref) => resourceAt(bundle, ref)?.name ?? '?').join(', ') || '-';
      out.push(
        `| ${row.artifact.cvId} | ${artifact?.name ?? '?'} | ${artifact?.type ?? '-'}${row.expected ? '' : ' (optional)'} | ${sboms} | ${coverageLabel(row)} |`,
      );
    }
  }
  if (evidence.sboms.length === 0) {
    out.push('', 'No SBOMs in this delivery.');
    return out;
  }
  out.push(
    '',
    '| Component version | SBOM | Format | Generator | Packages | Describes | Binding | NTIA | BSI TR-03183 |',
    '| --- | --- | --- | --- | --- | --- | --- | --- | --- |',
  );
  for (const occurrence of evidence.sboms) {
    const analysis = occurrence.sha1 ? analyses[occurrence.sha1] : undefined;
    if (analysis?.state !== 'analyzed') {
      const why = occurrence.presence === 'external' ? 'external, not analysed' : occurrence.presence === 'deferred' ? 'deferred (size budget)' : 'unreadable';
      out.push(`| ${occurrence.at.cvId} | ${occurrence.name} | ${why} | - | - | - | - | - | - |`);
      continue;
    }
    const s = analysis.summary;
    const subject = [s.subject.name, s.subject.version && shortDigest(s.subject.version)].filter(Boolean).join(' ') || '-';
    const bsi = formatGateFailed(s.profiles.bsi.results) ? 'format not accepted' : gated(s.profiles.bsi);
    out.push(
      `| ${occurrence.at.cvId} | ${occurrence.name} | ${s.spec} | ${generators(s.creators)} | ${s.packages} | ${subject} | ${bindingLabel(occurrence.binding)} | ${ntiaLabel(ntiaSummary(s.profiles.ntia))} | ${bsi} |`,
    );
  }
  out.push(
    '',
    'NTIA: the document-level minimum elements, then the package-level element (version, supplier, unique ID) with the lowest coverage. Profiles are approximations of the published requirements; the BSI TR-03183-2 accepts only SPDX 3.0.1+ or CycloneDX 1.6+.',
  );
  return out;
}

function evidenceJson(
  bundle: OcmBundle,
  evidence: SbomEvidence,
  analyses: Readonly<Record<string, SbomAnalysis>>,
): Record<string, unknown> {
  const named = (ref: ResourceRef) => ({ cvId: ref.cvId, artifact: resourceAt(bundle, ref)?.name ?? null });
  return {
    counts: evidence.counts,
    artifacts: evidence.coverage.map((row) => ({
      ...named(row.artifact),
      type: resourceAt(bundle, row.artifact)?.type ?? null,
      expected: row.expected,
      status: row.status,
      ...(row.strength ? { strength: row.strength } : {}),
      ...(row.reason ? { reason: row.reason } : {}),
      sboms: row.sboms.map((ref) => resourceAt(bundle, ref)?.name ?? null),
    })),
    sboms: evidence.sboms.map((occurrence) => {
      const analysis = occurrence.sha1 ? analyses[occurrence.sha1] : undefined;
      const summary = analysis?.state === 'analyzed' ? analysis.summary : undefined;
      return {
        ...named(occurrence.at),
        presence: occurrence.presence,
        sha1: occurrence.sha1 ?? null,
        ...(summary
          ? {
              spec: summary.spec,
              creators: summary.creators,
              packages: summary.packages,
              subject: { source: summary.subject.source, name: summary.subject.name ?? null, version: summary.subject.version ?? null },
              profiles: {
                ntia: ntiaSummary(summary.profiles.ntia),
                bsiTr03183: {
                  passed: summary.profiles.bsi.gatedPassed,
                  failed: summary.profiles.bsi.gatedFailed,
                  formatAccepted: !formatGateFailed(summary.profiles.bsi.results),
                },
              },
            }
          : {}),
        ...(occurrence.binding
          ? {
              binding: {
                strength: occurrence.binding.strength,
                ...(occurrence.binding.target ? { target: named(occurrence.binding.target) } : {}),
                ...(occurrence.binding.targetCv ? { targetCv: occurrence.binding.targetCv } : {}),
                notes: occurrence.binding.notes,
              },
            }
          : {}),
      };
    }),
  };
}
