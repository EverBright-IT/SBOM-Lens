import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
// @ts-expect-error - plain-JS fixture builder without type declarations
import { buildSbomDemoCtf } from '../../scripts/generate-ocm-fixtures.mjs';
import type { OcmBundle } from '../model/ocm-bundle';
import { readOcmBundle } from '../parse/ocm/bundle';
import { digestSummary } from './report';
import { analyzeDeliverySboms } from './sbom-analyze';
import { sbomEvidence } from './sbom-evidence';

/**
 * The SBOM evidence demo is a showcase and a regression net: every binding
 * level the product grades, in one delivery. If the demo stops telling its
 * story, CI says so.
 */

function fixture(): Uint8Array {
  return new Uint8Array(
    readFileSync(new URL('../../fixtures/ocm/ecme-sbom-delivery.ctf.tar', import.meta.url)),
  );
}

async function open() {
  const { bundle, extracted } = await readOcmBundle('ecme-sbom-delivery.ctf.tar', fixture());
  const entries = bundle!.componentVersions.flatMap((cv) =>
    cv.resources.flatMap((r) =>
      r.sbom
        ? [
            {
              fileName: r.sbom.fileName,
              bytes: extracted[r.sbom.extractedIndex]!.bytes,
              sha1: r.sbom.sha1,
            },
          ]
        : [],
    ),
  );
  const analyses = await analyzeDeliverySboms(entries, { now: Date.parse('2026-10-15T00:00:00Z') });
  return { bundle: bundle!, analyses, evidence: sbomEvidence(bundle!, analyses) };
}

const at = (bundle: OcmBundle, ref: { cvId: string; index: number } | undefined) =>
  ref
    ? `${ref.cvId}#${bundle.componentVersions.find((c) => c.id === ref.cvId)!.resources[ref.index]!.name}`
    : undefined;

describe('SBOM evidence demo delivery', () => {
  it('matches a fresh generator run byte-for-byte', () => {
    expect(fixture()).toEqual(new Uint8Array(buildSbomDemoCtf()));
  });

  it('exhibits every binding level, an external SBOM and a gap', async () => {
    const { bundle, evidence } = await open();
    const bindings = Object.fromEntries(
      evidence.sboms.map((s) => [
        at(bundle, s.at),
        s.binding ? `${s.binding.strength} ${s.binding.notes.join(',')}`.trim() : s.presence,
      ]),
    );
    expect(bindings).toEqual({
      'ecme.org/shop/api@3.2.0#sbom': 'digest',
      'ecme.org/shop/web@3.2.0#sbom': 'reference digest-differs',
      'ecme.org/shop/worker@3.2.0#sbom': 'digest',
      'ecme.org/shop/shop-cli@3.2.0#release-sbom': 'component',
      'ecme.org/shop/payments@3.2.0#sbom': 'external',
    });
    expect(evidence.counts).toMatchObject({
      expected: 6,
      covered: 4,
      byDigest: 2,
      byReference: 1,
      byComponent: 1,
      declared: 1,
      missing: 1,
    });
    const gateway = evidence.coverage.find(
      (r) => r.artifact.cvId === 'ecme.org/shop/gateway@3.2.0' && r.expected,
    )!;
    expect(at(bundle, gateway.artifact)).toBe('ecme.org/shop/gateway@3.2.0#image');
    expect(gateway.status).toBe('missing');
    expect(evidence.findings.map((f) => [f.code, f.severity])).toEqual([
      ['OCM_SBOM_MISSING', 'warning'],
      ['OCM_SBOM_EXTERNAL', 'info'],
    ]);
  });

  it('reads the worker SBOM as CycloneDX although it is declared as plain JSON', async () => {
    const { bundle, analyses } = await open();
    const sbom = bundle.componentVersions.find((cv) => cv.name === 'ecme.org/shop/worker')!
      .resources[1]!.sbom!;
    expect(sbom).toMatchObject({
      format: 'cyclonedx',
      contentType: 'application/vnd.cyclonedx+json',
    });
    const analysis = analyses[sbom.sha1];
    expect(analysis?.state === 'analyzed' && analysis.summary.spec).toBe('CycloneDX 1.6');
  });

  it('keeps every declared digest intact (the demo is about SBOMs, not tampering)', async () => {
    const { bundle } = await open();
    expect(digestSummary(bundle).mismatch).toEqual([]);
    expect(bundle.completeness.broken).toBe(0);
  });
});
