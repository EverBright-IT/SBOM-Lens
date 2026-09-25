import { describe, expect, it } from 'vitest';
import { loadFixture, loadedFromText } from '../test-fixtures';
import { emptyWorkspace } from '../workspace/workspace';
import { AUTOMOTIVE_SBOM_PROFILE } from './automotive';
import { evaluateProfile } from './evaluate';
import { validateProfile } from './validate';

/**
 * The Automotive preset is data on the v4 engine. Pinned: it validates, its
 * two document facts that a leaf SBOM legitimately lacks never gate, and the
 * fields the specification adds over NTIA (file name, concluded licence,
 * copyright) are read where the formats carry them.
 */

const byId = (doc: ReturnType<typeof loadedFromText>, id: string) =>
  evaluateProfile(emptyWorkspace, doc, AUTOMOTIVE_SBOM_PROFILE).results.find((r) => r.id === id)!;

function spdx(pkg: string[], docLines: string[] = []) {
  return loadedFromText(
    't.spdx',
    [
      'SPDXVersion: SPDX-2.3',
      'DataLicense: CC0-1.0',
      'SPDXID: SPDXRef-DOCUMENT',
      'DocumentName: vehicle',
      'DocumentNamespace: https://example.org/spdxdocs/vehicle',
      'Creator: Organization: ACME Automotive',
      'Created: 2026-06-01T10:00:00Z',
      ...docLines,
      '',
      'PackageName: ecu-firmware',
      'SPDXID: SPDXRef-Package-ecu',
      'PackageDownloadLocation: NOASSERTION',
      ...pkg,
      '',
    ].join('\n'),
  );
}

describe('AUTOMOTIVE_SBOM_PROFILE', () => {
  it('is valid v4 profile data and says what it does not check', () => {
    expect(validateProfile(AUTOMOTIVE_SBOM_PROFILE).ok).toBe(true);
    expect(AUTOMOTIVE_SBOM_PROFILE.description).toContain('contractual');
    expect(AUTOMOTIVE_SBOM_PROFILE.description).toContain('Component name is satisfied by construction');
  });

  it('never gates on package fields: a contractual requirement is a meter', () => {
    for (const check of AUTOMOTIVE_SBOM_PROFILE.checks) {
      if (check.type === 'package-coverage') expect(check.threshold).toBeUndefined();
    }
  });

  it('reports SBOM type and external references without gating them', () => {
    // SPDX 2.x cannot express an SBOM type, and a leaf SBOM references nothing.
    const leaf = spdx([]);
    const report = evaluateProfile(emptyWorkspace, leaf, AUTOMOTIVE_SBOM_PROFILE);
    const sbomType = report.results.find((r) => r.id === 'sbom-type')!;
    const refs = report.results.find((r) => r.id === 'external-document-refs')!;
    expect(sbomType).toMatchObject({ pass: false, informational: true });
    expect(refs).toMatchObject({ pass: false, informational: true });
    const gatedIds = report.results.filter((r) => r.kind === 'boolean' && !r.informational).map((r) => r.id);
    expect(gatedIds).not.toContain('sbom-type');
    expect(gatedIds).not.toContain('external-document-refs');
  });

  it('reads file name, concluded licence and copyright from SPDX 2.3', () => {
    const doc = spdx([
      'PackageVersion: 4.2.0',
      'PackageSupplier: Organization: Tier One GmbH',
      'PackageFileName: ecu-firmware-4.2.0.bin',
      'PackageLicenseConcluded: GPL-2.0-only WITH Linux-syscall-note',
      'PackageCopyrightText: Copyright 2026 Tier One GmbH',
    ]);
    expect(byId(doc, 'component-file-name').coverage?.satisfied).toBe(1);
    expect(byId(doc, 'component-concluded-license').coverage?.satisfied).toBe(1);
    expect(byId(doc, 'component-copyright').coverage?.satisfied).toBe(1);
    expect(byId(doc, 'component-hash').coverage?.satisfied).toBe(0);
  });

  it('sees a supplier SBOM link as the external document reference it is', () => {
    const doc = spdx([], [
      'ExternalDocumentRef: DocumentRef-tier2 https://example.org/spdxdocs/tier2 SHA1: ' + 'b'.repeat(40),
    ]);
    expect(byId(doc, 'external-document-refs').pass).toBe(true);
  });

  it('takes the SBOM type from a CycloneDX lifecycle phase', () => {
    const cdx = loadedFromText(
      'v.cdx.json',
      JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        version: 1,
        metadata: {
          lifecycles: [{ phase: 'build' }],
          authors: [{ name: 'ACME Automotive' }],
          component: { type: 'device', 'bom-ref': 'root', name: 'vehicle' },
        },
        components: [],
      }),
    );
    expect(byId(cdx, 'sbom-type')).toMatchObject({ pass: true, actual: 'build' });
  });

  it('evaluates every parsed model without throwing', () => {
    for (const name of ['minimal.spdx.json', 'spdx3/webstack.spdx3.json', 'cdx/parity.cdx.xml']) {
      const loaded = loadedFromText(name.split('/').pop()!, loadFixture(name));
      const report = evaluateProfile(emptyWorkspace, loaded, AUTOMOTIVE_SBOM_PROFILE);
      expect(report.results).toHaveLength(AUTOMOTIVE_SBOM_PROFILE.checks.length);
    }
  });
});
