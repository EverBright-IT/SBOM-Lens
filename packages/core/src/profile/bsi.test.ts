import { describe, expect, it } from 'vitest';
import { emptyWorkspace } from '../workspace/workspace';
import { loadFixture, loadedFromText } from '../test-fixtures';
import { BSI_TR_03183_PROFILE } from './bsi';
import { evaluateProfile } from './evaluate';
import { validateProfile } from './validate';

/**
 * The BSI preset is plain profile data — the fail-closed validator is the
 * schema authority, so it must accept every builtin without exceptions.
 * Pinned: the format baseline by version, the gates the TR states without
 * condition, the meters it conditions (3.2.1, 3.2.2), and the appendix 8.2
 * mappings on both formats the TR accepts.
 */

const byId = (report: ReturnType<typeof evaluateProfile>, id: string) => report.results.find((r) => r.id === id)!;

const spdx3Graph = (specVersion: string) =>
  JSON.stringify({
    '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
    '@graph': [
      { type: 'CreationInfo', '@id': '_:ci', specVersion, created: '2026-06-01T10:00:00Z' },
      { type: 'SpdxDocument', spdxId: 'https://acme.example/doc/v', creationInfo: '_:ci', name: 'v' },
      { type: 'software_Package', spdxId: 'https://acme.example/pkg/a', creationInfo: '_:ci', name: 'a' },
    ],
  });

describe('BSI_TR_03183_PROFILE', () => {
  it('is valid profile data and says what it cannot check', () => {
    const result = validateProfile(BSI_TR_03183_PROFILE);
    expect(result.ok).toBe(true);
    expect(BSI_TR_03183_PROFILE.description).toContain('SPDX 3.0.1+');
    expect(BSI_TR_03183_PROFILE.description).toContain('Not checkable');
    // Every check names the clause it reads.
    for (const check of BSI_TR_03183_PROFILE.checks) expect(check.label).toMatch(/\(5\.2\.[1-5]/);
  });

  it('gates exactly what the TR states without condition', () => {
    const gated = BSI_TR_03183_PROFILE.checks
      .filter((c) => (c.type === 'package-coverage' ? c.threshold !== undefined : !('informational' in c && c.informational)))
      .map((c) => c.id);
    expect(gated).toEqual(['creators', 'created', 'relationships', 'pkg-version', 'pkg-creator', 'pkg-license']);
  });

  it('passes the format baseline on CycloneDX 1.6 and fails it on 1.5', () => {
    const cdx = (specVersion: string) =>
      JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion,
        version: 1,
        metadata: { component: { type: 'application', 'bom-ref': 'r', name: 'app' } },
      });
    const sixteen = loadedFromText('app16.cdx.json', cdx('1.6'));
    const baseline16 = byId(evaluateProfile(emptyWorkspace, sixteen, BSI_TR_03183_PROFILE), 'format-baseline');
    expect(baseline16.pass).toBe(true);
    expect(baseline16.label).toContain('CycloneDX 1.6');

    const fifteen = loadedFromText('app15.cdx.json', cdx('1.5'));
    expect(byId(evaluateProfile(emptyWorkspace, fifteen, BSI_TR_03183_PROFILE), 'format-baseline').pass).toBe(false);
  });

  it('fails the format baseline on SPDX 2.x, passes it on SPDX 3.0.1 and later, not on 3.0.0', () => {
    const two = loadedFromText('two.spdx.json', loadFixture('minimal.spdx.json'));
    const twoReport = evaluateProfile(emptyWorkspace, two, BSI_TR_03183_PROFILE);
    const twoBaseline = byId(twoReport, 'format-baseline');
    expect(twoBaseline.pass).toBe(false);
    expect(twoBaseline.actual).toBe('SPDX-2.3');
    expect(twoReport.results[0]!.id).toBe('format-baseline'); // leads the report

    const three = loadedFromText('webstack.spdx3.json', loadFixture('spdx3/webstack.spdx3.json'));
    expect(byId(evaluateProfile(emptyWorkspace, three, BSI_TR_03183_PROFILE), 'format-baseline').pass).toBe(true);

    // The label says 3.0.1 or later; the check compares the version it says.
    const old = loadedFromText('old.spdx3.json', spdx3Graph('3.0.0'));
    const oldBaseline = byId(evaluateProfile(emptyWorkspace, old, BSI_TR_03183_PROFILE), 'format-baseline');
    expect(oldBaseline.pass).toBe(false);
    expect(oldBaseline.actual).toBe('SPDX-3.0.0');
    const next = loadedFromText('next.spdx3.json', spdx3Graph('3.1.0'));
    expect(byId(evaluateProfile(emptyWorkspace, next, BSI_TR_03183_PROFILE), 'format-baseline').pass).toBe(true);
  });

  it('passes a document that carries every required field', () => {
    const loaded = loadedFromText(
      'full.spdx',
      [
        'SPDXVersion: SPDX-2.3',
        'DataLicense: CC0-1.0',
        'SPDXID: SPDXRef-DOCUMENT',
        'DocumentName: acme-product-1.0.0',
        'DocumentNamespace: https://example.org/spdxdocs/acme-product-1.0.0',
        'Creator: Organization: ACME Corp (security@acme.example)',
        'Created: 2026-06-01T10:00:00Z',
        '',
        'PackageName: acme-product',
        'SPDXID: SPDXRef-Package-product',
        'PackageVersion: 1.0.0',
        'PackageSupplier: Organization: ACME Distribution',
        'PackageOriginator: Organization: ACME Corp (security@acme.example)',
        'PackageFileName: acme-product-1.0.0.tar.gz',
        'PackageDownloadLocation: https://example.org/acme-product-1.0.0.tar.gz',
        'PackageChecksum: SHA512: ' + 'ab'.repeat(64),
        'PackageLicenseConcluded: Apache-2.0',
        'PackageLicenseDeclared: Apache-2.0',
        'ExternalRef: PACKAGE-MANAGER purl pkg:generic/acme-product@1.0.0',
        '',
        'PackageName: libwidget',
        'SPDXID: SPDXRef-Package-lib',
        'PackageVersion: 2.4.0',
        'PackageOriginator: Person: Widget Author (https://widgets.example)',
        'PackageDownloadLocation: NOASSERTION',
        'PackageLicenseConcluded: MIT',
        '',
        'Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-product',
        'Relationship: SPDXRef-Package-product CONTAINS SPDXRef-Package-lib',
      ].join('\n') + '\n',
    );
    const report = evaluateProfile(emptyWorkspace, loaded, BSI_TR_03183_PROFILE);
    // Every FIELD check passes; the only gated failure is the format
    // baseline, because complete 2.x data is still not the TR's format.
    expect(report.gatedFailed).toBe(1);
    expect(byId(report, 'format-baseline').pass).toBe(false);
    expect(byId(report, 'creators').pass).toBe(true);
    expect(byId(report, 'relationships').pass).toBe(true);
    expect(byId(report, 'pkg-creator').coverage).toMatchObject({ satisfied: 2, total: 2 });
    expect(byId(report, 'pkg-license').coverage).toMatchObject({ satisfied: 2, total: 2 });
    // The library is a logical component without a file or a hash: the
    // meters say so without failing the document (3.2.2).
    expect(byId(report, 'pkg-filename').coverage).toMatchObject({ satisfied: 1, total: 2, threshold: undefined });
    expect(byId(report, 'pkg-checksum').coverage).toMatchObject({ satisfied: 1, total: 2, threshold: undefined });
    expect(byId(report, 'sbom-uri')).toMatchObject({ pass: true, informational: true });
  });

  it('a tool version "@" never satisfies the contact check', () => {
    const loaded = loadedFromText(
      'toolonly.spdx',
      [
        'SPDXVersion: SPDX-2.3',
        'DataLicense: CC0-1.0',
        'SPDXID: SPDXRef-DOCUMENT',
        'DocumentName: toolonly',
        'DocumentNamespace: https://example.org/spdxdocs/toolonly',
        'Creator: Tool: npm@10.1.0',
        'Created: 2026-06-01T10:00:00Z',
        '',
        'PackageName: thing',
        'SPDXID: SPDXRef-Package-thing',
        'PackageDownloadLocation: NOASSERTION',
        '',
        'Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-thing',
      ].join('\n') + '\n',
    );
    const report = evaluateProfile(emptyWorkspace, loaded, BSI_TR_03183_PROFILE);
    expect(byId(report, 'creators').pass).toBe(false);
  });

  it('measures the SHA-512 hash without gating on it: a SHA-256-only package reads 0 of 1', () => {
    const loaded = loadedFromText(
      'sha256only.spdx',
      [
        'SPDXVersion: SPDX-2.3',
        'DataLicense: CC0-1.0',
        'SPDXID: SPDXRef-DOCUMENT',
        'DocumentName: sha256only',
        'DocumentNamespace: https://example.org/spdxdocs/sha256only',
        'Creator: Organization: ACME Corp (security@acme.example)',
        'Created: 2026-06-01T10:00:00Z',
        '',
        'PackageName: thing',
        'SPDXID: SPDXRef-Package-thing',
        'PackageDownloadLocation: NOASSERTION',
        'PackageChecksum: SHA256: ' + 'ab'.repeat(32),
        '',
        'Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-thing',
      ].join('\n') + '\n',
    );
    const report = evaluateProfile(emptyWorkspace, loaded, BSI_TR_03183_PROFILE);
    const checksum = byId(report, 'pkg-checksum');
    expect(checksum.coverage).toMatchObject({ satisfied: 0, total: 1, threshold: undefined });
    expect(checksum.pass).toBe(true); // a meter never gates
    expect(byId(report, 'creators').pass).toBe(true);
  });

  it('gates on a creator without contact, on a lone DESCRIBES, and on missing component creator and licence', () => {
    const loaded = loadedFromText(
      'bare.spdx',
      [
        'SPDXVersion: SPDX-2.3',
        'DataLicense: CC0-1.0',
        'SPDXID: SPDXRef-DOCUMENT',
        'DocumentName: bare',
        'DocumentNamespace: https://example.org/spdxdocs/bare',
        'Creator: Organization: ACME Corp',
        'Created: 2026-06-01T10:00:00Z',
        '',
        'PackageName: thing',
        'SPDXID: SPDXRef-Package-thing',
        'PackageVersion: 1.0.0',
        'PackageSupplier: Organization: ACME Corp (security@acme.example)',
        'PackageDownloadLocation: NOASSERTION',
        '',
        'Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-thing',
      ].join('\n') + '\n',
    );
    const report = evaluateProfile(emptyWorkspace, loaded, BSI_TR_03183_PROFILE);
    expect(byId(report, 'creators').pass).toBe(false); // no email/URL
    expect(byId(report, 'relationships').pass).toBe(false); // DESCRIBES enumerates no dependency
    // The supplier is not the creator the TR asks for (3.2.9, appendix 8.2).
    expect(byId(report, 'pkg-creator').pass).toBe(false);
    expect(byId(report, 'pkg-license').pass).toBe(false);
    expect(byId(report, 'pkg-version').pass).toBe(true);
    // Meters never gate.
    for (const id of ['pkg-filename', 'pkg-checksum', 'pkg-executable', 'pkg-archive', 'pkg-structured', 'pkg-unique-id']) {
      expect(byId(report, id).coverage?.threshold).toBeUndefined();
    }
    expect(report.gatedFailed).toBe(5); // format baseline + creators + relationships + pkg-creator + pkg-license
  });

  it('reads the CycloneDX forms of appendix 8.2: manufacturer contacts, the filename property, identifiers', () => {
    const loaded = loadedFromText(
      'widgets.cdx.json',
      JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        serialNumber: 'urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79',
        version: 1,
        metadata: {
          timestamp: '2026-06-01T10:00:00Z',
          manufacturer: { name: 'ACME Corp', contact: [{ name: 'ACME Security', email: 'security@acme.example' }] },
          component: {
            type: 'application',
            'bom-ref': 'root',
            name: 'acme-app',
            version: '1.0.0',
            manufacturer: { name: 'ACME Corp', url: ['https://acme.example'] },
            licenses: [{ license: { id: 'Apache-2.0' }, acknowledgement: 'concluded' }],
          },
        },
        components: [
          {
            type: 'library',
            'bom-ref': 'widget',
            name: 'widget',
            version: '2.0.0',
            manufacturer: { name: 'Widget Works', url: ['https://widgets.example'] },
            cpe: 'cpe:2.3:a:widgets:widget:2.0.0:*:*:*:*:*:*:*',
            licenses: [{ license: { id: 'MIT' }, acknowledgement: 'concluded' }],
            properties: [
              { name: 'bsi:component:filename', value: 'widget-2.0.0.jar' },
              { name: 'bsi:component:executable', value: 'non-executable' },
              { name: 'bsi:component:archive', value: 'archive' },
            ],
          },
          {
            type: 'library',
            'bom-ref': 'docs',
            name: 'widget-docs',
            version: '2.0.0',
            authors: [{ name: 'Doc Writer', email: 'docs@widgets.example' }],
            licenses: [{ license: { id: 'CC-BY-4.0' }, acknowledgement: 'concluded' }],
            externalReferences: [{ type: 'website', url: 'https://widgets.example/docs' }],
          },
        ],
        dependencies: [{ ref: 'root', dependsOn: ['widget', 'docs'] }],
      }),
    );
    const report = evaluateProfile(emptyWorkspace, loaded, BSI_TR_03183_PROFILE);
    expect(byId(report, 'format-baseline').pass).toBe(true);
    expect(byId(report, 'creators')).toMatchObject({ pass: true, actual: 'Organization: ACME Corp (security@acme.example)' });
    expect(byId(report, 'relationships').pass).toBe(true);
    expect(byId(report, 'pkg-creator').coverage).toMatchObject({ satisfied: 3, total: 3 });
    expect(byId(report, 'pkg-license').coverage).toMatchObject({ satisfied: 3, total: 3 });
    expect(byId(report, 'pkg-filename').coverage).toMatchObject({ satisfied: 1, total: 3 });
    expect(byId(report, 'pkg-executable').coverage).toMatchObject({ satisfied: 1, total: 3 });
    expect(byId(report, 'pkg-archive').coverage).toMatchObject({ satisfied: 1, total: 3 });
    expect(byId(report, 'pkg-structured').coverage).toMatchObject({ satisfied: 0, total: 3 });
    // A website link is not an identifier; the CPE is.
    expect(byId(report, 'pkg-unique-id').coverage).toMatchObject({ satisfied: 1, total: 3 });
    expect(byId(report, 'sbom-uri')).toMatchObject({ pass: true, informational: true });
    expect(report.gatedFailed).toBe(0);
  });

  it('reads the SPDX 3 forms of appendix 8.2: agent contacts and the distribution artifact', () => {
    const ci = '_:ci';
    const graph = JSON.stringify({
      '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
      '@graph': [
        { type: 'CreationInfo', '@id': ci, specVersion: '3.0.1', created: '2026-06-01T10:00:00Z', createdBy: ['https://acme.example/agent/acme'] },
        {
          type: 'Organization',
          spdxId: 'https://acme.example/agent/acme',
          creationInfo: ci,
          name: 'ACME Corp',
          externalIdentifier: [{ type: 'ExternalIdentifier', externalIdentifierType: 'email', identifier: 'security@acme.example' }],
        },
        { type: 'SpdxDocument', spdxId: 'https://acme.example/doc/widget', creationInfo: ci, name: 'widget', rootElement: ['https://acme.example/pkg/widget'] },
        {
          type: 'software_Package',
          spdxId: 'https://acme.example/pkg/widget',
          creationInfo: ci,
          name: 'widget',
          software_packageVersion: '2.0.0',
          originatedBy: ['https://acme.example/agent/acme'],
        },
        { type: 'software_File', spdxId: 'https://acme.example/file/widget-jar', creationInfo: ci, name: 'widget-2.0.0.jar' },
        { type: 'simplelicensing_LicenseExpression', spdxId: 'https://acme.example/lic/mit', creationInfo: ci, simplelicensing_licenseExpression: 'MIT' },
        { type: 'Relationship', spdxId: 'https://acme.example/rel/lic', creationInfo: ci, from: 'https://acme.example/pkg/widget', relationshipType: 'hasConcludedLicense', to: ['https://acme.example/lic/mit'] },
        { type: 'Relationship', spdxId: 'https://acme.example/rel/dist', creationInfo: ci, from: 'https://acme.example/pkg/widget', relationshipType: 'hasDistributionArtifact', to: ['https://acme.example/file/widget-jar'] },
        { type: 'Relationship', spdxId: 'https://acme.example/rel/contains', creationInfo: ci, from: 'https://acme.example/pkg/widget', relationshipType: 'contains', to: ['https://acme.example/file/widget-jar'] },
      ],
    });
    const loaded = loadedFromText('widget.spdx3.json', graph);
    const report = evaluateProfile(emptyWorkspace, loaded, BSI_TR_03183_PROFILE);
    expect(byId(report, 'format-baseline').pass).toBe(true);
    expect(byId(report, 'creators')).toMatchObject({ pass: true, actual: 'Organization: ACME Corp (security@acme.example)' });
    expect(byId(report, 'relationships').pass).toBe(true);
    expect(byId(report, 'pkg-creator').coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(byId(report, 'pkg-license').coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(byId(report, 'pkg-filename').coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(report.gatedFailed).toBe(0);
  });
});
