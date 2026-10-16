import type { OcmArtifact, OcmBundle, OcmCv } from '../model/ocm-bundle';
import type { ResourceRef, SbomAnalysis, SbomBinding, SbomCoverageRow, SbomEvidence } from './sbom-evidence';
import { ntiaLabel, ntiaSummary, sbomEvidence } from './sbom-evidence';
import type { DeliveryConflict, DeliveryLicenses, DeliveryPackages, SbomPackageList } from './sbom-packages';
import { deliveryConflicts, deliveryLicenses, deliveryPackages, NOT_LISTED_LABEL, placeLabel } from './sbom-packages';
import type { DeliveryVex, VexOrigin, VexSource } from './sbom-vex';
import { deliveryVex, tr03191Summary, VEX_STATUS_LABEL } from './sbom-vex';
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
  /**
   * The analysed SBOMs' package lists (by SHA-1; null where none could be
   * read). With them and the analyses, the report adds the delivery's
   * package figures; the full list belongs in the package export.
   */
  sbomPackages?: Readonly<Record<string, SbomPackageList | null>>;
  /**
   * VEX and CSAF documents of the delivery or added to it, read or not.
   * With any, the report adds what the supplier states about the packages.
   */
  vexSources?: readonly VexSource[];
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

/**
 * Text from the delivery or a supplier document, made safe for a table cell
 * or a list item: a line break or a pipe in a name or a supplier's note must
 * not end the cell or open a section the report never wrote.
 */
function inline(text: string): string {
  return text.replace(/\s+/g, ' ').trim().replace(/\|/g, '\\|');
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
  const packages = evidence && input.sbomPackages ? packageFigures(deliveryPackages(evidence, input.sbomPackages)) : undefined;
  // Without package lists every statement names something the list lacks.
  const vex =
    input.vexSources && input.vexSources.length > 0
      ? deliveryVex(packages?.model ?? deliveryPackages(evidence ?? sbomEvidence(bundle, {}), {}), input.vexSources)
      : undefined;

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
  push(`| Delivery | \`${inline(bundle.fileName)}\` |`);
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
  if (packages) push(`- ${packagesLine(packages)}`);
  if (vex) push(`- ${vexLine(vex, input.vexSources!)}`);
  push();
  push('## Component versions');
  push();
  push('| Component | Version | Provider | Resources | References | Signed | SBOM |');
  push('| --- | --- | --- | --- | --- | --- | --- |');
  for (const cv of bundle.componentVersions) {
    const open = cv.references.filter((r) => !r.target).length;
    push(
      `| ${inline(cv.name)} | ${inline(cv.version)} | ${inline(cv.provider?.name ?? '-')} | ${cv.resources.length} | ${cv.references.length}${open > 0 ? ` (${open} open)` : ''} | ${(cv.signatures?.length ?? 0) > 0 ? 'yes' : '-'} | ${cv.resources.some((r) => r.sbom) ? 'yes' : '-'} |`,
    );
  }

  if (gaps.length > 0 || c.unresolvedRefs > 0) {
    push();
    push('## Transport gaps');
    push();
    for (const { cv, artifact } of gaps) {
      push(
        `- ${inline(cv.id)}: resource \`${inline(artifact.name)}\` (${inline(artifact.type ?? 'untyped')}) is ${artifact.transport}${artifact.access?.type ? ` via \`${inline(artifact.access.type)}\`` : ''}${artifact.location ? ` — ${inline(artifact.location)}` : ''}`,
      );
    }
    for (const cv of bundle.componentVersions) {
      for (const ref of cv.references) {
        if (!ref.target) push(`- ${inline(cv.id)}: reference \`${inline(ref.name)}\` → ${inline(`${ref.componentName}@${ref.version}`)} is not in this bundle`);
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
    for (const m of digests.mismatch) push(`- ${inline(m.cvId)}: \`${inline(m.artifact)}\``);
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
      push(`| ${inline(entry.cvId)} | ${inline(entry.name)} | ${entry.verdict} | ${inline(entry.keyLabel ?? '-')} | ${inline(entry.reason ?? '-')} |`);
    }
  }

  push();
  if (evidence) {
    for (const line of evidenceSection(bundle, evidence, input.sbomAnalyses!)) push(line);
    if (packages) {
      push();
      for (const line of packagesSection(bundle, packages)) push(line);
    }
  } else {
    push('## Embedded SBOMs');
    push();
    if (sbomCarriers.length === 0) {
      push('No embedded SBOMs.');
    } else {
      for (const { cv, sboms } of sbomCarriers) {
        for (const r of sboms) {
          push(`- ${inline(cv.id)}: \`${inline(r.name)}\` (${r.sbom!.format}, ${formatBytes(r.sbom!.size)})`);
        }
      }
    }
  }

  if (vex) {
    push();
    for (const line of vexSection(bundle, vex, input.vexSources!)) push(line);
  }

  if (findings.length > 0) {
    push();
    push(`## Findings (${findings.length})`);
    push();
    for (const d of findings.slice(0, 50)) push(`- ${d.severity}: ${inline(d.message)}`);
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
    ...(packages ? { packages: packagesJson(bundle, packages) } : {}),
    ...(vex ? { vex: vexJson(bundle, vex, input.vexSources!) } : {}),
    findings: findings.map((d) => ({ severity: d.severity, code: d.code, message: d.message })),
  };

  return { markdown: lines.join('\n'), json };
}

interface PackageFigures {
  model: DeliveryPackages;
  licenses: DeliveryLicenses;
  conflicts: DeliveryConflict[];
}

function packageFigures(model: DeliveryPackages): PackageFigures {
  return { model, licenses: deliveryLicenses(model), conflicts: deliveryConflicts(model) };
}

function packagesLine({ model, conflicts }: PackageFigures): string {
  const across = conflicts.filter((c) => c.acrossPlaces).length;
  return `Packages: ${model.packages.length} listed by ${model.sources.length} analysed SBOM(s); ${
    across === 0 ? 'no package differs in version between artifacts' : `${across} package(s) differ in version between artifacts`
  }`;
}

const KIND_LABEL = { listed: 'on the SPDX License List', deprecated: 'deprecated there', ref: 'LicenseRef', unknown: 'not on the list' } as const;

/** Key figures only: the full list with every artifact belongs in the package export. */
function packagesSection(bundle: OcmBundle, { model, licenses, conflicts }: PackageFigures): string[] {
  const out: string[] = ['## Packages', ''];
  out.push(
    `${model.packages.length} package(s) listed by ${model.sources.length} analysed SBOM(s), each identity and version counted once${model.subjects > 0 ? `, ${model.subjects} of them an SBOM's subject (the image or product it describes)` : ''}.${model.omitted.files > 0 ? ` Not counted: ${model.omitted.files} file entries.` : ''} The package export (CSV or JSON) lists every package with the artifact it ships in.`,
  );
  out.push('');
  if (model.ecosystems.length > 0) {
    out.push(`- Ecosystems (purl type): ${model.ecosystems.map((e) => `${inline(e.ecosystem ?? 'without purl')} ${e.packages}`).join(', ')}`);
  }
  const kinds = (Object.keys(KIND_LABEL) as (keyof typeof KIND_LABEL)[])
    .filter((k) => licenses.kinds[k] > 0)
    .map((k) => `${licenses.kinds[k]} ${KIND_LABEL[k]}`);
  out.push(
    `- License identifiers: ${licenses.rows.length} distinct${kinds.length > 0 ? ` (${kinds.join(', ')})` : ''}; ${licenses.withoutLicense} package(s) without a license${licenses.subjectsWithoutLicense > 0 ? ` (${licenses.subjectsWithoutLicense} of them SBOM subjects)` : ''}; ${licenses.unparsed.reduce((n, u) => n + u.packages, 0)} with a value that is not an SPDX expression`,
  );
  if (licenses.rows.length > 0) {
    const top = licenses.rows.slice(0, 10).map((r) => `${inline(r.id)} (${r.packages})`);
    out.push(`- Most named: ${top.join(', ')}${licenses.rows.length > 10 ? `, and ${licenses.rows.length - 10} more` : ''}`);
  }
  const where = (ref: ResourceRef) => inline(`${ref.cvId} ${resourceAt(bundle, ref)?.name ?? '?'}`);
  if (model.scope.notListed.length > 0) {
    out.push(
      `- Not covered by this list: ${model.scope.notListed.map(({ row, reason }) => `${where(row.artifact)} (${NOT_LISTED_LABEL[reason]})`).join('; ')}`,
    );
  }
  if (model.scope.unverified.length > 0) {
    out.push(
      `- Covered only by an SBOM that does not identify them: ${model.scope.unverified.map((row) => where(row.artifact)).join('; ')}`,
    );
  }
  if (model.scope.digestDiffers.length > 0) {
    out.push(
      `- Covered by an SBOM that states a different digest (it may describe a local build, not the delivered bytes): ${model.scope.digestDiffers.map((row) => where(row.artifact)).join('; ')}`,
    );
  }
  out.push('');
  out.push('License identifiers are counted, not judged: what a license obliges is not part of this report.');

  const across = conflicts.filter((c) => c.acrossPlaces);
  if (across.length > 0) {
    out.push('', '### Versions that differ between artifacts', '', '| Package | Versions |', '| --- | --- |');
    for (const conflict of across.slice(0, 15)) {
      const versions = conflict.versions.map(
        (v) => `${v.version} in ${v.package.places.map((p) => placeLabel(bundle, p)).join(', ')}`,
      );
      const identity = conflict.key.startsWith('purl:') ? ` (${conflict.key.slice('purl:'.length)})` : '';
      out.push(`| ${inline(conflict.name + identity)} | ${inline(versions.join('; '))} |`);
    }
    if (across.length > 15) out.push('', `... and ${across.length - 15} more in the package views and the JSON report.`);
  }
  const within = conflicts.length - across.length;
  if (within > 0) {
    out.push('', `${within} more package(s) occur in several versions inside one artifact.`);
  }
  return out;
}

function packagesJson(bundle: OcmBundle, { model, licenses, conflicts }: PackageFigures): Record<string, unknown> {
  const named = (ref: ResourceRef) => ({ cvId: ref.cvId, artifact: resourceAt(bundle, ref)?.name ?? null });
  return {
    total: model.packages.length,
    sboms: model.sources.length,
    subjects: model.subjects,
    omitted: model.omitted,
    ecosystems: model.ecosystems.map((e) => ({ ecosystem: e.ecosystem ?? null, packages: e.packages })),
    licenses: {
      identifiers: licenses.rows.map((r) => ({ id: r.id, kind: r.kind, packages: r.packages })),
      withoutLicense: licenses.withoutLicense,
      subjectsWithoutLicense: licenses.subjectsWithoutLicense,
      notSpdxExpressions: licenses.unparsed.reduce((n, u) => n + u.packages, 0),
    },
    conflicts: conflicts.map((c) => ({
      name: c.name,
      identity: c.key,
      acrossArtifacts: c.acrossPlaces,
      versions: c.versions.map((v) => ({
        version: v.version,
        foundIn: v.package.places.map((p) => ({
          cvId: p.cvId,
          artifact: p.kind === 'artifact' && p.ref ? (resourceAt(bundle, p.ref)?.name ?? null) : null,
          binding: p.strength,
        })),
      })),
    })),
    notListed: model.scope.notListed.map(({ row, reason }) => ({ ...named(row.artifact), reason })),
    unverified: model.scope.unverified.map((row) => named(row.artifact)),
    digestDiffers: model.scope.digestDiffers.map((row) => named(row.artifact)),
  };
}

function vexLine(vex: DeliveryVex, sources: readonly VexSource[]): string {
  const unread = sources.length - vex.documents.length;
  const read = `${vex.documents.length} VEX/CSAF document(s) read${unread > 0 ? `, ${unread} not read` : ''}`;
  // Both counts are about delivered packages; a statement that names none
  // is counted on its own, not as an open question about the delivery.
  const reaching = vex.vulnerabilities.filter((v) => v.packages.length > 0);
  const affected = reaching.filter((v) => v.status === 'affected').length;
  const open = reaching.filter((v) => v.status === 'under_investigation').length;
  const unmatched = vex.unmatched.length > 0 ? `; ${vex.unmatched.length} statement(s) name no listed package` : '';
  return `Vulnerability communication: ${read}; per the supplier, ${affected} vulnerability(ies) affect a delivered package, ${open} under investigation${unmatched}`;
}

function originLabel(bundle: OcmBundle, origin: VexOrigin): string {
  return origin.kind === 'resource'
    ? inline(`${origin.ref.cvId} ${resourceAt(bundle, origin.ref)?.name ?? '?'}`)
    : `added file ${inline(origin.fileName)}`;
}

const VEX_STATE_LABEL = {
  pending: 'not read',
  external: 'outside the delivery, not fetched',
  unreadable: 'unreadable',
} as const;

/** What the supplier states, as facts: OCM Lens matches statements, it scans nothing. */
function vexSection(bundle: OcmBundle, vex: DeliveryVex, sources: readonly VexSource[]): string[] {
  const out: string[] = ['## Vulnerability communication (VEX)', ''];
  out.push(
    `What the supplier states about known vulnerabilities in the delivered packages, read offline from ${vex.documents.length} document(s) with ${vex.statements} statement(s). OCM Lens matches these statements to the package list by purl, CPE and file hash; it does not scan. A package without a statement is not cleared.`,
  );
  out.push('', '| Document | Format | From | Statements | State |', '| --- | --- | --- | --- | --- |');
  for (const source of sources) {
    if (source.state === 'loaded') {
      const d = source.document;
      const tr = d.format === 'csaf' ? tr03191Summary(d) : undefined;
      const format = d.format === 'csaf' ? `CSAF${tr ? ` (BSI TR-03191: ${tr.passed} of ${tr.total})` : ''}` : 'OpenVEX';
      out.push(
        `| ${inline(d.title ?? d.id)} | ${format} | ${originLabel(bundle, source.origin)} | ${d.statements.length} | read |`,
      );
    } else {
      out.push(
        `| ${inline(source.name)} | - | ${originLabel(bundle, source.origin)} | - | ${VEX_STATE_LABEL[source.state]}${source.reason ? `: ${inline(source.reason)}` : ''} |`,
      );
    }
  }
  const c = vex.counts;
  out.push(
    '',
    `- Packages: ${c.affected} affected, ${c.under_investigation} under investigation, ${c.fixed} fixed, ${c.not_affected} not affected; ${c.without} with a purl or CPE but no statement; ${c.unmatchable} without either`,
  );
  if (vex.unmatched.length > 0) {
    const ids = [...new Set(vex.unmatched.map((u) => inline(u.vulnerability)))];
    out.push(
      `- Statements that name no package in the list: ${vex.unmatched.length} (${ids.slice(0, 10).join(', ')}${ids.length > 10 ? ', ...' : ''}). Their products may still ship in an artifact the package list does not cover${c.unmatchable > 0 ? `, or as one of the ${c.unmatchable} package(s) without a purl or CPE, which no statement can name` : ''}.`,
    );
  }
  const actionable = vex.vulnerabilities.filter((v) => v.status === 'affected' || v.status === 'under_investigation');
  if (actionable.length > 0) {
    out.push('', '| Vulnerability | Status | Packages | Supplier\'s note |', '| --- | --- | --- | --- |');
    for (const v of actionable.slice(0, 25)) {
      const packages =
        v.packages.length === 0
          ? 'none in the package list'
          : v.packages
              .map(({ pkg, finding }) => {
                const where = pkg.places.map((p) => placeLabel(bundle, p)).join(', ');
                return inline(`${pkg.name} ${pkg.version ?? ''}`) + `${where ? ` in ${inline(where)}` : ''} (${VEX_STATUS_LABEL[finding.status]})`;
              })
              .join('; ');
      // The note of a package in the vulnerability's own status: a sibling's
      // "not affected" justification says nothing about the affected one.
      const note =
        v.packages
          .filter(({ finding }) => finding.status === v.status)
          .map(({ finding }) => finding.actionStatement ?? finding.impactStatement ?? finding.justification)
          .find(Boolean) ?? '-';
      out.push(`| ${inline(v.id)} | ${VEX_STATUS_LABEL[v.status]} | ${packages} | ${inline(note)} |`);
    }
    if (actionable.length > 25) out.push('', `... and ${actionable.length - 25} more in the JSON report.`);
  }
  const settled = vex.vulnerabilities.length - actionable.length;
  if (settled > 0) {
    out.push('', `${settled} more vulnerability(ies) are stated fixed or not affected (listed in the JSON report).`);
  }
  return out;
}

function vexJson(bundle: OcmBundle, vex: DeliveryVex, sources: readonly VexSource[]): Record<string, unknown> {
  const origin = (o: VexOrigin) =>
    o.kind === 'resource' ? { cvId: o.ref.cvId, artifact: resourceAt(bundle, o.ref)?.name ?? null } : { file: o.fileName };
  return {
    documents: sources.map((source) =>
      source.state === 'loaded'
        ? {
            name: source.name,
            id: source.document.id,
            title: source.document.title ?? null,
            format: source.document.format ?? 'openvex',
            origin: origin(source.origin),
            state: 'read',
            statements: source.document.statements.length,
          }
        : { name: source.name, origin: origin(source.origin), state: source.state, reason: source.reason ?? null },
    ),
    statements: vex.statements,
    counts: vex.counts,
    vulnerabilities: vex.vulnerabilities.map((v) => ({
      id: v.id,
      aliases: v.aliases,
      status: v.status,
      packages: v.packages.map(({ pkg, finding }) => ({
        name: pkg.name,
        version: pkg.version ?? null,
        purl: pkg.purl ?? null,
        status: finding.status,
        ...(finding.justification ? { justification: finding.justification } : {}),
        ...(finding.impactStatement ? { impactStatement: finding.impactStatement } : {}),
        ...(finding.actionStatement ? { actionStatement: finding.actionStatement } : {}),
        document: finding.sourceFile,
        foundIn: pkg.places.map((p) => ({
          cvId: p.cvId,
          artifact: p.kind === 'artifact' && p.ref ? (resourceAt(bundle, p.ref)?.name ?? null) : null,
          binding: p.strength,
        })),
      })),
      unmatchedStatements: v.unmatched.length,
    })),
    unmatched: vex.unmatched.map((u) => ({
      vulnerability: u.vulnerability,
      status: u.status,
      products: u.products,
      document: u.document,
      origin: origin(u.origin),
    })),
  };
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
      const sboms = inline(row.sboms.map((ref) => resourceAt(bundle, ref)?.name ?? '?').join(', ') || '-');
      out.push(
        `| ${inline(row.artifact.cvId)} | ${inline(artifact?.name ?? '?')} | ${inline(artifact?.type ?? '-')}${row.expected ? '' : ' (optional)'} | ${sboms} | ${inline(coverageLabel(row))} |`,
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
      out.push(`| ${inline(occurrence.at.cvId)} | ${inline(occurrence.name)} | ${why} | - | - | - | - | - | - |`);
      continue;
    }
    const s = analysis.summary;
    const subject = [s.subject.name, s.subject.version && shortDigest(s.subject.version)].filter(Boolean).join(' ') || '-';
    const bsi = formatGateFailed(s.profiles.bsi.results) ? 'format not accepted' : gated(s.profiles.bsi);
    out.push(
      `| ${inline(occurrence.at.cvId)} | ${inline(occurrence.name)} | ${inline(s.spec)} | ${inline(generators(s.creators))} | ${s.packages} | ${inline(subject)} | ${bindingLabel(occurrence.binding)} | ${ntiaLabel(ntiaSummary(s.profiles.ntia))} | ${bsi} |`,
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
