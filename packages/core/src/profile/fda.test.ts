import { describe, expect, it } from 'vitest';
import { loadFixture, loadedFromText } from '../test-fixtures';
import { emptyWorkspace } from '../workspace/workspace';
import { evaluateProfile } from './evaluate';
import { FDA_524B_PROFILE } from './fda';
import { NTIA_PROFILE } from './ntia';
import { validateProfile } from './validate';

/**
 * The FDA preset = NTIA baseline + level of support + end of support. Pinned
 * here: the three field conventions it documents are the ones the engine
 * reads (one per format), nothing gates, and the baseline ids match the NTIA
 * preset so a reader can compare the two reports line by line.
 */

const byId = (doc: ReturnType<typeof loadedFromText>, id: string) =>
  evaluateProfile(emptyWorkspace, doc, FDA_524B_PROFILE).results.find((r) => r.id === id)!;

describe('FDA_524B_PROFILE', () => {
  it('is valid v4 profile data, nonbinding by design, and names its conventions', () => {
    expect(validateProfile(FDA_524B_PROFILE).ok).toBe(true);
    for (const check of FDA_524B_PROFILE.checks) {
      if (check.type === 'package-coverage') expect(check.threshold).toBeUndefined();
    }
    expect(FDA_524B_PROFILE.description).toContain('ValidUntilDate');
    expect(FDA_524B_PROFILE.description).toContain('fda:lifecycle:');
    expect(FDA_524B_PROFILE.description).toContain('not a statement of acceptability');
  });

  it('shares its baseline ids with the NTIA preset', () => {
    const ntiaIds = new Set(NTIA_PROFILE.checks.map((c) => c.id));
    for (const id of ['creators', 'created', 'relationships', 'pkg-version', 'pkg-supplier', 'pkg-unique-id']) {
      expect(ntiaIds.has(id), id).toBe(true);
      expect(FDA_524B_PROFILE.checks.some((c) => c.id === id), id).toBe(true);
    }
  });

  it('reads the end-of-support date from SPDX 2.3 ValidUntilDate', () => {
    const doc = loadedFromText(
      'd.spdx',
      [
        'SPDXVersion: SPDX-2.3',
        'DataLicense: CC0-1.0',
        'SPDXID: SPDXRef-DOCUMENT',
        'DocumentName: device',
        'DocumentNamespace: https://example.org/spdxdocs/device',
        'Creator: Organization: ACME Medical',
        'Created: 2026-06-01T10:00:00Z',
        '',
        'PackageName: rtos',
        'SPDXID: SPDXRef-Package-rtos',
        'PackageDownloadLocation: NOASSERTION',
        'ValidUntilDate: 2029-06-30T00:00:00Z',
        '',
        'PackageName: legacy-lib',
        'SPDXID: SPDXRef-Package-legacy',
        'PackageDownloadLocation: NOASSERTION',
        '',
      ].join('\n'),
    );
    expect(byId(doc, 'pkg-end-of-support').coverage).toMatchObject({ satisfied: 1, total: 2 });
    // SPDX 2.3 has no support-level field at all: honestly zero, not guessed.
    expect(byId(doc, 'pkg-support-level').coverage).toMatchObject({ satisfied: 0, total: 2 });
  });

  it('reads supportLevel and validUntilTime from SPDX 3.0.1', () => {
    const doc = loadedFromText(
      'd.spdx3.json',
      JSON.stringify({
        '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
        '@graph': [
          {
            type: 'SpdxDocument',
            spdxId: 'https://acme.example/doc',
            name: 'device',
            creationInfo: '_:ci',
            rootElement: ['https://acme.example/pkg/rtos'],
          },
          { type: 'CreationInfo', '@id': '_:ci', specVersion: '3.0.1', created: '2026-06-01T10:00:00Z', createdBy: ['https://acme.example/agent'] },
          { type: 'Organization', spdxId: 'https://acme.example/agent', name: 'ACME Medical', creationInfo: '_:ci' },
          {
            type: 'software_Package',
            spdxId: 'https://acme.example/pkg/rtos',
            name: 'rtos',
            creationInfo: '_:ci',
            supportLevel: ['support'],
            validUntilTime: '2029-06-30T00:00:00Z',
          },
        ],
      }),
    );
    expect(byId(doc, 'pkg-support-level').coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(byId(doc, 'pkg-end-of-support').coverage).toMatchObject({ satisfied: 1, total: 1 });
  });

  it('reads the documented CycloneDX property names, and nothing else', () => {
    const cdx = (properties: { name: string; value: string }[]) =>
      loadedFromText(
        'd.cdx.json',
        JSON.stringify({
          bomFormat: 'CycloneDX',
          specVersion: '1.6',
          version: 1,
          metadata: { authors: [{ name: 'ACME Medical' }] },
          components: [{ type: 'library', 'bom-ref': 'c1', name: 'rtos', version: '2.0', properties }],
        }),
      );
    const documented = cdx([
      { name: 'fda:lifecycle:support-level', value: 'actively maintained' },
      { name: 'end-of-support', value: '2029-06-30' },
    ]);
    expect(byId(documented, 'pkg-support-level').coverage?.satisfied).toBe(1);
    expect(byId(documented, 'pkg-end-of-support').coverage?.satisfied).toBe(1);

    const other = cdx([{ name: 'vendor:maintenance', value: 'yes' }]);
    expect(byId(other, 'pkg-support-level').coverage?.satisfied).toBe(0);
    expect(byId(other, 'pkg-end-of-support').coverage?.satisfied).toBe(0);
  });

  it('evaluates every parsed model without throwing', () => {
    for (const name of ['minimal.spdx.json', 'spdx3/webstack.spdx3.json', 'cdx/parity.cdx.json']) {
      const loaded = loadedFromText(name.split('/').pop()!, loadFixture(name));
      expect(evaluateProfile(emptyWorkspace, loaded, FDA_524B_PROFILE).results).toHaveLength(FDA_524B_PROFILE.checks.length);
    }
  });
});
