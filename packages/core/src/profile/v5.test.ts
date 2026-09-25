import { describe, expect, it } from 'vitest';
import { loadedFromText } from '../test-fixtures';
import { addDocument, emptyWorkspace } from '../workspace/workspace';
import { evaluateProfile } from './evaluate';
import type { ComplianceProfile, ProfileCheck } from './model';
import { PROFILE_SCHEMA_V4, PROFILE_SCHEMA_V5 } from './model';
import { validateProfile } from './validate';

/**
 * Schema v5: the `purposes` filter on package coverage and the `description`
 * package field. Both are fail-closed below v5, and the filter is pinned from
 * both sides: it scopes the total, matches case-insensitively, and an empty
 * scope reads 0/0 and passes instead of failing a meter nobody can satisfy.
 */

const v5 = (...checks: ProfileCheck[]): ComplianceProfile => ({ schema: PROFILE_SCHEMA_V5, name: 'v5', checks });

function spdx(packages: string[][]) {
  const text = [
    'SPDXVersion: SPDX-2.3',
    'DataLicense: CC0-1.0',
    'SPDXID: SPDXRef-DOCUMENT',
    'DocumentName: t',
    'DocumentNamespace: https://example.org/spdxdocs/t',
    'Creator: Organization: ACME',
    'Created: 2026-06-01T10:00:00Z',
    '',
    ...packages.flatMap((lines, i) => [`PackageName: p${i}`, `SPDXID: SPDXRef-P${i}`, 'PackageDownloadLocation: NOASSERTION', ...lines, '']),
  ].join('\n');
  const loaded = loadedFromText('t.spdx', text);
  return { ws: addDocument(emptyWorkspace, loaded).workspace, loaded };
}

const coverageOf = (profile: ComplianceProfile, doc: ReturnType<typeof spdx>) =>
  evaluateProfile(doc.ws, doc.loaded, profile).results[0]!;

describe('schema v5 validation', () => {
  it('accepts purposes and the description field under v5', () => {
    const result = validateProfile({
      schema: PROFILE_SCHEMA_V5,
      name: 'ok',
      checks: [
        { type: 'package-coverage', field: 'checksum', purposes: ['MODEL', 'data'] },
        { type: 'package-coverage', field: 'description', threshold: 50 },
      ],
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.profile.checks[0]).toMatchObject({ purposes: ['MODEL', 'data'] });
  });

  it.each([
    ['purposes', { type: 'package-coverage', field: 'checksum', purposes: ['MODEL'] }],
    ['the description field', { type: 'package-coverage', field: 'description' }],
  ])('rejects %s under v4, fail-closed', (_label, check) => {
    const result = validateProfile({ schema: PROFILE_SCHEMA_V4, name: 'old', checks: [check] });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors[0]).toContain('requires schema');
  });

  it.each([
    ['an empty list', []],
    ['a non-array', 'MODEL'],
    ['an empty entry', ['MODEL', ' ']],
    ['a non-string entry', ['MODEL', 7]],
    ['too many entries', Array.from({ length: 17 }, (_, i) => `P${i}`)],
  ])('rejects purposes given as %s', (_label, purposes) => {
    const result = validateProfile({
      schema: PROFILE_SCHEMA_V5,
      name: 'bad',
      checks: [{ type: 'package-coverage', field: 'version', purposes }],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors[0]).toContain('"purposes"');
  });

  it('still rejects a newer schema id', () => {
    const result = validateProfile({ schema: 'sbomlens-profile/v6', name: 'future', checks: [] });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors[0]).toContain('unsupported profile schema');
  });
});

describe('purpose-scoped coverage', () => {
  const doc = spdx([
    ['PrimaryPackagePurpose: LIBRARY', 'PackageVersion: 1.0.0', 'PackageDescription: <text>Parses widgets.</text>'],
    ['PrimaryPackagePurpose: APPLICATION'],
    ['PackageVersion: 2.0.0'], // no purpose: never in a scoped meter
  ]);

  it('scopes the total to the packages with a listed purpose', () => {
    const result = coverageOf(v5({ type: 'package-coverage', field: 'version', purposes: ['LIBRARY'] }), doc);
    expect(result.coverage).toMatchObject({ satisfied: 1, total: 1, percent: 100 });
    const app = coverageOf(v5({ type: 'package-coverage', field: 'version', purposes: ['APPLICATION'] }), doc);
    expect(app.coverage).toMatchObject({ satisfied: 0, total: 1, percent: 0 });
  });

  it('matches purposes case-insensitively and accepts several', () => {
    const result = coverageOf(v5({ type: 'package-coverage', field: 'version', purposes: ['library', 'Application'] }), doc);
    expect(result.coverage).toMatchObject({ satisfied: 1, total: 2, percent: 50 });
  });

  it('measures every package without a filter, unchanged from v4', () => {
    const result = coverageOf(v5({ type: 'package-coverage', field: 'version' }), doc);
    expect(result.coverage).toMatchObject({ satisfied: 2, total: 3 });
  });

  it('reads 0/0 and passes when nothing is in scope, even with a threshold', () => {
    const result = coverageOf(v5({ type: 'package-coverage', field: 'version', purposes: ['MODEL'], threshold: 100 }), doc);
    expect(result.coverage).toMatchObject({ satisfied: 0, total: 0, percent: 100, threshold: 100 });
    expect(result.pass).toBe(true);
  });

  it('reads the description field', () => {
    const result = coverageOf(v5({ type: 'package-coverage', field: 'description' }), doc);
    expect(result.coverage).toMatchObject({ satisfied: 1, total: 3 });
  });
});
