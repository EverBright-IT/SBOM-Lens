import { describe, expect, it } from 'vitest';
import { emptyWorkspace } from '../workspace/workspace';
import { loadFixture, loadedFromText } from '../test-fixtures';
import { BSI_TR_03183_PROFILE } from './bsi';
import { evaluateProfile } from './evaluate';
import { validateProfile } from './validate';

/**
 * The BSI preset is plain profile data — the fail-closed validator is the
 * schema authority, so it must accept every builtin without exceptions.
 */

describe('BSI_TR_03183_PROFILE', () => {
  it('is valid profile data and says what it cannot check', () => {
    const result = validateProfile(BSI_TR_03183_PROFILE);
    expect(result.ok).toBe(true);
    expect(BSI_TR_03183_PROFILE.description).toContain('SPDX 3.0.1+');
    expect(BSI_TR_03183_PROFILE.description).toContain('Not checkable');
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
    const baseline16 = evaluateProfile(emptyWorkspace, sixteen, BSI_TR_03183_PROFILE).results.find(
      (r) => r.id === 'format-baseline',
    )!;
    expect(baseline16.pass).toBe(true);
    expect(baseline16.label).toContain('CycloneDX 1.6');

    const fifteen = loadedFromText('app15.cdx.json', cdx('1.5'));
    expect(
      evaluateProfile(emptyWorkspace, fifteen, BSI_TR_03183_PROFILE).results.find(
        (r) => r.id === 'format-baseline',
      )?.pass,
    ).toBe(false);
  });

  it('fails the format baseline on SPDX 2.x, passes it on SPDX 3.x', () => {
    const two = loadedFromText('two.spdx.json', loadFixture('minimal.spdx.json'));
    const twoReport = evaluateProfile(emptyWorkspace, two, BSI_TR_03183_PROFILE);
    const twoBaseline = twoReport.results.find((r) => r.id === 'format-baseline')!;
    expect(twoBaseline.pass).toBe(false);
    expect(twoBaseline.actual).toBe('SPDX-2.3');
    expect(twoReport.results[0]!.id).toBe('format-baseline'); // leads the report

    const three = loadedFromText('webstack.spdx3.json', loadFixture('spdx3/webstack.spdx3.json'));
    const threeReport = evaluateProfile(emptyWorkspace, three, BSI_TR_03183_PROFILE);
    expect(threeReport.results.find((r) => r.id === 'format-baseline')?.pass).toBe(true);
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
        'PackageSupplier: Organization: ACME Corp',
        'PackageDownloadLocation: https://example.org/acme-product-1.0.0.tar.gz',
        'PackageChecksum: SHA512: ' + 'ab'.repeat(64),
        'PackageLicenseDeclared: Apache-2.0',
        'ExternalRef: PACKAGE-MANAGER purl pkg:generic/acme-product@1.0.0',
        '',
        'Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-product',
      ].join('\n') + '\n',
    );
    const report = evaluateProfile(emptyWorkspace, loaded, BSI_TR_03183_PROFILE);
    // Every FIELD check passes; the only gated failure is the format
    // baseline, because complete 2.x data is still not the TR's format.
    expect(report.gatedFailed).toBe(1);
    expect(report.results.find((r) => r.id === 'format-baseline')?.pass).toBe(false);
    expect(report.results.find((r) => r.id === 'creators')?.pass).toBe(true);
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
    expect(report.results.find((r) => r.id === 'creators')?.pass).toBe(false);
  });

  it('a SHA-256-only checksum does not satisfy the SHA-512 gate', () => {
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
    expect(report.results.find((r) => r.id === 'pkg-checksum')?.pass).toBe(false);
    expect(report.results.find((r) => r.id === 'creators')?.pass).toBe(true);
  });

  it('gates on a creator without contact and on missing hashes', () => {
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
        'PackageDownloadLocation: NOASSERTION',
        '',
        'Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-thing',
      ].join('\n') + '\n',
    );
    const report = evaluateProfile(emptyWorkspace, loaded, BSI_TR_03183_PROFILE);
    expect(report.results.find((r) => r.id === 'creators')?.pass).toBe(false); // no email/URL
    expect(report.results.find((r) => r.id === 'pkg-checksum')?.pass).toBe(false);
    expect(report.results.find((r) => r.id === 'pkg-supplier')?.pass).toBe(false);
    expect(report.results.find((r) => r.id === 'pkg-license')?.pass).toBe(false);
    expect(report.results.find((r) => r.id === 'pkg-version')?.pass).toBe(true);
    // uniqueId carries no threshold: informational, never gates.
    expect(report.results.find((r) => r.id === 'pkg-unique-id')?.coverage?.threshold).toBeUndefined();
    expect(report.gatedFailed).toBe(5); // 4 field checks + the format baseline
  });
});
