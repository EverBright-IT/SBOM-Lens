import type {
  OcmArtifact,
  OcmBundle,
  ResourceRef,
  SbomBinding,
  SbomCoverageRow,
  SbomSummary,
} from '@sbomlens/core/ocm';
import { saveBytes } from '../app/download';
import type { LoadedDelivery } from '../app/store';
import type { ChipTone } from './bits';
import { Chip } from './bits';

/**
 * Shared SBOM vocabulary for the SBOMs view and the resource drawer: the
 * binding and coverage chips, the sentences that explain them, and the
 * download that keeps the SBOM's real file type.
 */

const STRENGTH_TONE: Record<SbomBinding['strength'], ChipTone> = {
  digest: 'ok',
  reference: 'accent',
  component: 'neutral',
  none: 'warn',
};

const STRENGTH_TITLE: Record<SbomBinding['strength'], string> = {
  digest: 'The SBOM names a digest of the delivered artifact',
  reference: 'Same repository and tag, no shared digest',
  component: 'The SBOM names the component version, not a specific artifact',
  none: 'The SBOM describes nothing found in this delivery',
};

export function BindingChip({ binding }: { binding: SbomBinding | undefined }) {
  if (!binding) return <Chip>not analysed</Chip>;
  const label = binding.strength === 'none' ? 'unbound' : `by ${binding.strength}`;
  return (
    <span className="inline-flex flex-wrap gap-1">
      <Chip tone={STRENGTH_TONE[binding.strength]} title={STRENGTH_TITLE[binding.strength]}>
        {label}
      </Chip>
      {binding.notes.includes('digest-differs') && (
        <Chip tone="warn" title="The SBOM states a different digest than the delivered artifact">
          digest differs
        </Chip>
      )}
      {binding.notes.includes('ambiguous') && <Chip tone="warn">ambiguous</Chip>}
    </span>
  );
}

export function CoverageChip({ row }: { row: SbomCoverageRow }) {
  if (row.status === 'bound') {
    return (
      <Chip tone={STRENGTH_TONE[row.strength!]} title={STRENGTH_TITLE[row.strength!]}>
        SBOM by {row.strength}
      </Chip>
    );
  }
  if (row.status === 'unverified') {
    return (
      <Chip
        tone="warn"
        title="An SBOM sits in this component version, but nothing in it identifies this artifact"
      >
        unverified
      </Chip>
    );
  }
  if (row.status === 'declared') {
    const why =
      row.reason === 'external'
        ? 'external'
        : row.reason === 'deferred'
          ? 'not analysed yet'
          : 'unreadable';
    return (
      <Chip tone="warn" title="An SBOM is declared next to this artifact but could not be used">
        SBOM {why}
      </Chip>
    );
  }
  return row.expected ? <Chip tone="danger">no SBOM</Chip> : <Chip>no SBOM (optional)</Chip>;
}

export function artifactAt(bundle: OcmBundle, ref: ResourceRef): OcmArtifact | undefined {
  return bundle.componentVersions.find((cv) => cv.id === ref.cvId)?.resources[ref.index];
}

/** One plain sentence per binding: what matched, and what that means. */
export function bindingExplanation(binding: SbomBinding, bundle: OcmBundle): string[] {
  const subject =
    [binding.subject.name, binding.subject.version].filter(Boolean).join(' ') ||
    'an unnamed subject';
  const target = binding.target ? artifactAt(bundle, binding.target)?.name : undefined;
  const lines: string[] = [];
  switch (binding.strength) {
    case 'digest':
      lines.push(
        `The SBOM names a digest of "${target}": it describes exactly the delivered bytes.`,
      );
      break;
    case 'reference':
      lines.push(`The SBOM names the same repository and tag as "${target}".`);
      if (binding.notes.includes('digest-differs')) {
        lines.push(
          'Its digest differs from the delivered one: the SBOM was most likely generated from a local build before the push, so it may not describe the delivered bytes exactly.',
        );
      }
      break;
    case 'component':
      lines.push(
        `The SBOM names the component version (${subject}): it speaks for its software, not for one artifact.`,
      );
      break;
    case 'none':
      lines.push(`The SBOM describes ${subject}, which matches nothing in this delivery.`);
      break;
  }
  if (binding.notes.includes('other-component'))
    lines.push('The match sits in another component version.');
  if (binding.notes.includes('ambiguous')) {
    lines.push(
      'More than one artifact matches equally well; the first one in the same component version is shown.',
    );
  }
  if (binding.notes.includes('inferred-subject')) {
    lines.push('The SBOM does not name its subject; its top-level packages stand in.');
  }
  return lines;
}

/**
 * "4 of 4" over a profile's gated checks. Only meaningful where the package
 * checks gate too (BSI); NTIA meters its package fields, see ntiaSummary.
 */
function gatedLabel(report: SbomSummary['profiles']['bsi']): string {
  return `${report.gatedPassed} of ${report.gatedPassed + report.gatedFailed}`;
}

export function bsiLabel(report: SbomSummary['profiles']['bsi']): string {
  return report.results.some((r) => r.id === 'format-baseline' && !r.pass)
    ? 'format not accepted'
    : gatedLabel(report);
}

/** The tools that generated an SBOM, else whoever created it. */
export function generatorLabel(creators: string[]): string {
  const tools = creators.filter((c) => /^tool:/i.test(c)).map((c) => c.replace(/^tool:\s*/i, ''));
  return (tools.length > 0 ? tools : creators).join(', ') || '-';
}

/** Save an extracted SBOM under its own name and media type. */
export function downloadSbom(delivery: LoadedDelivery, artifact: OcmArtifact): void {
  if (!artifact.sbom) return;
  const entry = delivery.extracted[artifact.sbom.extractedIndex];
  if (!entry) return;
  const base = entry.fileName.split('!').pop() ?? entry.fileName;
  saveBytes(base, artifact.sbom.contentType, entry.bytes);
}
