import type { OcmArtifact, OcmBundle, OcmCv } from '../model/ocm-bundle';
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

  const reasons: string[] = [];
  if (c.external > 0) reasons.push(`${c.external} resource(s) live outside the bundle (external access)`);
  if (c.broken > 0) reasons.push(`${c.broken} localBlob resource(s) are missing from the archive`);
  if (c.unknown > 0) reasons.push(`${c.unknown} resource(s) use an access type this tool cannot classify`);
  if (c.unresolvedRefs > 0) reasons.push(`${c.unresolvedRefs} component reference(s) point outside the bundle`);

  const findings = [
    ...bundle.issues,
    ...bundle.componentVersions.flatMap((cv) =>
      cv.diagnostics.map((d) => ({ ...d, message: `${cv.id}: ${d.message}` })),
    ),
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
  push(
    c.airGapReady
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
  push(`- SBOMs: ${sbomCarriers.length} of ${bundle.componentVersions.length} component version(s) carry embedded SBOMs`);
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
    findings: findings.map((d) => ({ severity: d.severity, code: d.code, message: d.message })),
  };

  return { markdown: lines.join('\n'), json };
}
