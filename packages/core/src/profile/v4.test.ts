import { describe, expect, it } from 'vitest';
import { licenseIdsInExpression } from '../parse/spec-lint';
import { isDeprecatedLicenseId, isKnownExceptionId, isKnownLicenseId } from '../spec/spdx-license-ids';
import { loadedFromText } from '../test-fixtures';
import { addDocument, emptyWorkspace } from '../workspace/workspace';
import { evaluateProfile } from './evaluate';
import type { ComplianceProfile, ProfileCheck } from './model';
import { PROFILE_SCHEMA_V3, PROFILE_SCHEMA_V4 } from './model';
import { validateProfile } from './validate';

/**
 * Schema v4: the lifecycle/licensing fields, the `informational` flag on
 * boolean checks, and identifier validity on licence coverage. Each is
 * fail-closed below v4 and pinned here from both sides: rejected where it
 * must be, evaluated as documented where it is allowed.
 */

const v4 = (...checks: ProfileCheck[]): ComplianceProfile => ({ schema: PROFILE_SCHEMA_V4, name: 'v4', checks });

function spdx(pkgLines: string[], docLines: string[] = []) {
  const text = [
    'SPDXVersion: SPDX-2.3',
    'DataLicense: CC0-1.0',
    'SPDXID: SPDXRef-DOCUMENT',
    'DocumentName: t',
    'DocumentNamespace: https://example.org/spdxdocs/t',
    'Creator: Organization: ACME',
    'Created: 2026-06-01T10:00:00Z',
    ...docLines,
    '',
    'PackageName: widget',
    'SPDXID: SPDXRef-Package-widget',
    'PackageDownloadLocation: NOASSERTION',
    ...pkgLines,
    '',
  ].join('\n');
  const loaded = loadedFromText('t.spdx', text);
  return { ws: addDocument(emptyWorkspace, loaded).workspace, loaded };
}

const only = (profile: ComplianceProfile, docText: ReturnType<typeof spdx>) =>
  evaluateProfile(docText.ws, docText.loaded, profile).results[0]!;

describe('schema v4 validation', () => {
  it('accepts the v4 schema id and the new fields', () => {
    const result = validateProfile({
      schema: PROFILE_SCHEMA_V4,
      name: 'ok',
      checks: [
        { type: 'package-coverage', field: 'fileName' },
        { type: 'package-coverage', field: 'supportLevel' },
        { type: 'package-coverage', field: 'validUntil' },
        { type: 'package-coverage', field: 'licenseDeclared', licenseIds: 'known-or-ref', allowDeprecated: false },
        { type: 'package-coverage', field: 'properties', pattern: '^fda:' },
        { type: 'document-field', field: 'sbomType', informational: true },
        { type: 'document-field', field: 'externalDocumentRefs', informational: true },
        { type: 'relationships', informational: true },
      ],
    });
    expect(result.ok).toBe(true);
  });

  it.each([
    ['a v4 package field', { type: 'package-coverage', field: 'supportLevel' }, 'requires schema'],
    ['a v4 document field', { type: 'document-field', field: 'sbomType' }, 'requires schema'],
    ['informational', { type: 'relationships', informational: true }, 'requires schema'],
    ['licenseIds', { type: 'package-coverage', field: 'license', licenseIds: 'known' }, 'require schema'],
  ])('rejects %s under v3, fail-closed', (_label, check, message) => {
    const result = validateProfile({ schema: PROFILE_SCHEMA_V3, name: 'old', checks: [check] });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.join('\n')).toContain(message);
  });

  it.each([
    ['informational on coverage', { type: 'package-coverage', field: 'version', informational: true }],
    ['licenseIds on a non-licence field', { type: 'package-coverage', field: 'version', licenseIds: 'known' }],
    ['allowDeprecated without licenseIds', { type: 'package-coverage', field: 'license', allowDeprecated: false }],
    ['an unknown licenseIds mode', { type: 'package-coverage', field: 'license', licenseIds: 'any' }],
  ])('rejects %s even under v4', (_label, check) => {
    expect(validateProfile({ schema: PROFILE_SCHEMA_V4, name: 'bad', checks: [check] }).ok).toBe(false);
  });
});

describe('informational boolean checks', () => {
  it('report pass or fail but never count as a gate', () => {
    const profile = v4(
      { id: 'type', type: 'document-field', field: 'sbomType', informational: true },
      { id: 'rels', type: 'relationships', informational: true },
    );
    // No sbomType on SPDX 2.x, no relationships in this document: both fail.
    const report = evaluateProfile(spdx([]).ws, spdx([]).loaded, profile);
    expect(report.results.map((r) => r.pass)).toEqual([false, false]);
    expect(report.results.every((r) => r.informational)).toBe(true);
    expect(report.gatedFailed).toBe(0);
    expect(report.gatedPassed).toBe(0);
    expect(report.informational).toBe(2);
  });
});

describe('licence identifier validity', () => {
  it('knows the list, its deprecated ids, and the exceptions', () => {
    expect(isKnownLicenseId('MIT')).toBe(true);
    expect(isKnownLicenseId('GPL-2.0')).toBe(true); // deprecated but on the list
    expect(isDeprecatedLicenseId('GPL-2.0')).toBe(true);
    expect(isDeprecatedLicenseId('GPL-2.0-only')).toBe(false);
    expect(isKnownLicenseId('Totally-Made-Up-1.0')).toBe(false);
    expect(isKnownExceptionId('Classpath-exception-2.0')).toBe(true);
  });

  it('extracts licence ids from an expression, not the exception, not the plus', () => {
    expect(licenseIdsInExpression('GPL-2.0-only WITH Classpath-exception-2.0 OR (MIT AND Apache-2.0+)')).toEqual([
      'GPL-2.0-only',
      'MIT',
      'Apache-2.0',
    ]);
    expect(licenseIdsInExpression('LicenseRef-acme-internal AND MIT')).toEqual(['LicenseRef-acme-internal', 'MIT']);
    expect(licenseIdsInExpression('NOASSERTION')).toEqual([]);
    expect(licenseIdsInExpression('MIT AND')).toEqual([]); // grammar failure: nothing to validate
  });

  it.each([
    ['a known id', 'PackageLicenseDeclared: MIT', 'known', undefined, 1],
    ['an unknown id', 'PackageLicenseDeclared: Made-Up-1.0', 'known', undefined, 0],
    ['a LicenseRef under known', 'PackageLicenseDeclared: LicenseRef-acme', 'known', undefined, 0],
    ['a LicenseRef under known-or-ref', 'PackageLicenseDeclared: LicenseRef-acme', 'known-or-ref', undefined, 1],
    ['a deprecated id by default', 'PackageLicenseDeclared: GPL-2.0', 'known', undefined, 1],
    ['a deprecated id when disallowed', 'PackageLicenseDeclared: GPL-2.0', 'known', false, 0],
    ['one bad id in a compound', 'PackageLicenseDeclared: MIT AND Made-Up-1.0', 'known', undefined, 0],
    ['NOASSERTION', 'PackageLicenseDeclared: NOASSERTION', 'known', undefined, 0],
  ] as const)('%s', (_label, line, licenseIds, allowDeprecated, satisfied) => {
    const check: ProfileCheck = {
      id: 'lic',
      type: 'package-coverage',
      field: 'licenseDeclared',
      licenseIds,
      ...(allowDeprecated !== undefined ? { allowDeprecated } : {}),
    };
    expect(only(v4(check), spdx([line])).coverage?.satisfied).toBe(satisfied);
  });
});

describe('v4 field extractors on SPDX 2.3', () => {
  it('reads the declared and concluded licences separately', () => {
    const doc = spdx(['PackageLicenseDeclared: MIT', 'PackageLicenseConcluded: NOASSERTION']);
    expect(only(v4({ type: 'package-coverage', field: 'licenseDeclared' }), doc).coverage?.satisfied).toBe(1);
    expect(only(v4({ type: 'package-coverage', field: 'licenseConcluded' }), doc).coverage?.satisfied).toBe(0);
  });

  it('reads the package file name and the valid-until date', () => {
    const doc = spdx(['PackageFileName: widget-1.0.tar.gz', 'ValidUntilDate: 2028-12-31T00:00:00Z']);
    expect(only(v4({ type: 'package-coverage', field: 'fileName' }), doc).coverage?.satisfied).toBe(1);
    expect(only(v4({ type: 'package-coverage', field: 'validUntil' }), doc).coverage?.satisfied).toBe(1);
    expect(only(v4({ type: 'package-coverage', field: 'supportLevel' }), doc).coverage?.satisfied).toBe(0);
  });

  it('exposes describes and external document refs as document facts', () => {
    const doc = spdx([], [
      'ExternalDocumentRef: DocumentRef-child https://example.org/spdxdocs/child SHA1: ' + 'a'.repeat(40),
      'Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-widget',
    ]);
    expect(only(v4({ type: 'document-field', field: 'describes' }), doc).pass).toBe(true);
    expect(only(v4({ type: 'document-field', field: 'externalDocumentRefs' }), doc).pass).toBe(true);
    expect(only(v4({ type: 'document-field', field: 'sbomType' }), doc).pass).toBe(false);
  });
});

describe('v4 field extractors on CycloneDX', () => {
  const cdx = (component: Record<string, unknown>, metadata: Record<string, unknown> = {}) =>
    loadedFromText(
      'c.cdx.json',
      JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        version: 1,
        metadata: { component: { type: 'application', 'bom-ref': 'root', name: 'app' }, ...metadata },
        components: [{ type: 'library', 'bom-ref': 'c1', name: 'widget', version: '1.0.0', ...component }],
      }),
    );

  it('reads properties as name=value lines a pattern can target', () => {
    const loaded = cdx({ properties: [{ name: 'fda:lifecycle:support-level', value: 'actively-maintained' }] });
    const report = evaluateProfile(
      emptyWorkspace,
      loaded,
      v4({ id: 'p', type: 'package-coverage', field: 'properties', pattern: '^fda:lifecycle:support-level=' }),
    );
    // metadata.component counts as a package too and carries no properties.
    expect(report.results[0]!.coverage).toMatchObject({ satisfied: 1, total: 2 });
  });

  it('takes the sbom type from the first lifecycle phase', () => {
    const loaded = cdx({}, { lifecycles: [{ phase: 'build' }, { phase: 'post-build' }] });
    expect(loaded.document.sbomType).toBe('build');
    expect(loaded.document.lifecycles).toEqual(['build', 'post-build']);
    const report = evaluateProfile(emptyWorkspace, loaded, v4({ id: 't', type: 'document-field', field: 'sbomType' }));
    expect(report.results[0]!).toMatchObject({ pass: true, actual: 'build' });
  });
});
