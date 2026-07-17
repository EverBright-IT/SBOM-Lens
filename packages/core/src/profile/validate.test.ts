import { describe, expect, it } from 'vitest';
import { PROFILE_SCHEMA_V1 } from './model';
import { sniffProfile, validateProfile } from './validate';

const minimal = {
  schema: PROFILE_SCHEMA_V1,
  name: 'Minimal',
  checks: [{ type: 'document-field', field: 'creators' }],
};

function errorsOf(raw: unknown): string[] {
  const result = validateProfile(raw);
  return result.ok ? [] : result.errors;
}

describe('validateProfile', () => {
  it('accepts a minimal profile', () => {
    const result = validateProfile(minimal);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.profile.checks).toHaveLength(1);
  });

  it('accepts a full-featured profile and ignores unknown keys', () => {
    const result = validateProfile({
      schema: PROFILE_SCHEMA_V1,
      name: 'Full',
      description: 'desc',
      vendorMetadata: { anything: true },
      checks: [
        { id: 'ns', type: 'document-field', field: 'namespace', pattern: '^https://' },
        { type: 'document-field', field: 'dataLicense', values: ['CC0-1.0'] },
        { type: 'relationships', minCount: 2 },
        { type: 'created-recency', maxAgeDays: 180 },
        { type: 'package-coverage', field: 'supplier', threshold: 95, pattern: '^Organization: ' },
        { type: 'package-coverage', field: 'version' },
        { type: 'package-coverage', field: 'purpose', threshold: 100, values: ['APPLICATION'] },
        { extraKey: 1, type: 'package-coverage', field: 'checksum', threshold: 100 },
      ],
    });
    expect(result.ok).toBe(true);
  });

  it('rejects wrong or newer schemas with a precise message', () => {
    expect(errorsOf({ ...minimal, schema: 'sbomlens-profile/v4' })[0]).toContain('unsupported profile schema');
    expect(errorsOf({ ...minimal, schema: undefined })[0]).toContain('missing or invalid "schema"');
    expect(errorsOf('nope')[0]).toContain('must be a JSON object');
    // v2 is understood since the algorithms modifier landed.
    expect(validateProfile({ ...minimal, schema: 'sbomlens-profile/v2' }).ok).toBe(true);
  });

  it('fails closed on unknown check types and fields', () => {
    expect(errorsOf({ ...minimal, checks: [{ type: 'shell-exec', cmd: 'rm' }] })[0]).toBe(
      'checks[0]: unknown check type "shell-exec"',
    );
    expect(errorsOf({ ...minimal, checks: [{ type: 'document-field', field: 'wat' }] })[0]).toContain(
      'unknown document field',
    );
    expect(
      errorsOf({ ...minimal, checks: [{ type: 'package-coverage', field: 'wat' }] })[0],
    ).toContain('unknown package field');
  });

  it('rejects structural problems and collects multiple errors at once', () => {
    const errors = errorsOf({
      schema: PROFILE_SCHEMA_V1,
      name: '',
      checks: [
        { type: 'package-coverage', field: 'version', threshold: 150 },
        { type: 'created-recency', maxAgeDays: 0 },
      ],
    });
    expect(errors).toHaveLength(3);
    expect(errors.join('\n')).toContain('missing "name"');
    expect(errors.join('\n')).toContain('threshold');
    expect(errors.join('\n')).toContain('maxAgeDays');
  });

  it('rejects invalid or oversized regex patterns', () => {
    expect(
      errorsOf({ ...minimal, checks: [{ type: 'document-field', field: 'name', pattern: '(' }] })[0],
    ).toContain('not a valid regular expression');
    expect(
      errorsOf({
        ...minimal,
        checks: [{ type: 'document-field', field: 'name', pattern: 'a'.repeat(501) }],
      })[0],
    ).toContain('exceeds 500');
  });

  it('rejects pattern/values on non-string package fields', () => {
    expect(
      errorsOf({
        ...minimal,
        checks: [{ type: 'package-coverage', field: 'checksum', pattern: 'x' }],
      })[0],
    ).toContain('non-string field "checksum"');
    expect(
      errorsOf({
        ...minimal,
        checks: [{ type: 'package-coverage', field: 'uniqueId', values: ['x'] }],
      })[0],
    ).toContain('non-string field "uniqueId"');
  });

  it('rejects duplicate ids and empty checks', () => {
    expect(
      errorsOf({
        ...minimal,
        checks: [
          { id: 'a', type: 'relationships' },
          { id: 'a', type: 'document-field', field: 'name' },
        ],
      })[0],
    ).toContain('duplicate id "a"');
    expect(errorsOf({ ...minimal, checks: [] })[0]).toContain('non-empty array');
  });
});

describe('validateProfile — v2 algorithms', () => {
  const v2check = (extra: Record<string, unknown>) => ({
    schema: 'sbomlens-profile/v2',
    name: 'algo test',
    checks: [{ type: 'package-coverage', field: 'checksum', threshold: 100, ...extra }],
  });

  it('accepts algorithms on a v2 checksum check', () => {
    const result = validateProfile(v2check({ algorithms: ['SHA512', 'SHA-384'] }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.profile.schema).toBe('sbomlens-profile/v2');
      expect(result.profile.checks[0]).toMatchObject({ algorithms: ['SHA512', 'SHA-384'] });
    }
  });

  it('rejects algorithms under schema v1 — old engines must not silently weaken the gate', () => {
    const result = validateProfile({ ...v2check({ algorithms: ['SHA512'] }), schema: 'sbomlens-profile/v1' });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.join(' ')).toContain('requires schema "sbomlens-profile/v2"');
  });

  it('rejects algorithms on non-checksum fields and malformed lists', () => {
    const onVersion = validateProfile({
      schema: 'sbomlens-profile/v2',
      name: 'x',
      checks: [{ type: 'package-coverage', field: 'version', algorithms: ['SHA512'] }],
    });
    expect(onVersion.ok).toBe(false);
    expect(validateProfile(v2check({ algorithms: [] })).ok).toBe(false);
    expect(validateProfile(v2check({ algorithms: [42] })).ok).toBe(false);
  });

  it('still accepts plain v1 profiles unchanged', () => {
    const result = validateProfile({
      schema: 'sbomlens-profile/v1',
      name: 'plain',
      checks: [{ type: 'package-coverage', field: 'checksum', threshold: 100 }],
    });
    expect(result.ok).toBe(true);
  });
});

describe('sniffProfile', () => {
  it('detects a real profile', () => {
    const result = sniffProfile(JSON.stringify(minimal));
    expect(result.isProfile).toBe(true);
  });

  it('ignores SPDX JSON, marker mentions inside strings, and non-JSON', () => {
    expect(sniffProfile('{"spdxVersion":"SPDX-2.3"}').isProfile).toBe(false);
    // Marker appears as a value, but top-level schema is not a profile schema.
    expect(
      sniffProfile('{"spdxVersion":"SPDX-2.3","comment":"see \\"sbomlens-profile/v1\\""}')
        .isProfile,
    ).toBe(false);
    expect(sniffProfile('SPDXVersion: SPDX-2.3').isProfile).toBe(false);
    expect(sniffProfile('not json but "sbomlens-profile/ marker {').isProfile).toBe(false);
  });
});

describe('schema v3: requires', () => {
  const base = { name: 'x', checks: [{ type: 'relationships' }] };

  it('accepts requires under v3 and carries it into the profile', () => {
    const result = validateProfile({ ...base, schema: 'sbomlens-profile/v3', requires: { spec: 'spdx-3' } });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.profile.requires).toEqual({ spec: 'spdx-3' });
  });

  it('rejects requires under v2 (an older engine would silently under-check)', () => {
    const result = validateProfile({ ...base, schema: 'sbomlens-profile/v2', requires: { spec: 'spdx-3' } });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.join()).toContain('sbomlens-profile/v3');
  });

  it('rejects unknown requires shapes fail-closed', () => {
    for (const bad of [{ spec: 'spdx-9' }, { spec: 'spdx-3', extra: true }, 'spdx-3', {}]) {
      const result = validateProfile({ ...base, schema: 'sbomlens-profile/v3', requires: bad });
      expect(result.ok, JSON.stringify(bad)).toBe(false);
    }
  });

  it('v3 still accepts the v2 algorithms modifier', () => {
    const result = validateProfile({
      schema: 'sbomlens-profile/v3',
      name: 'x',
      checks: [{ type: 'package-coverage', field: 'checksum', threshold: 100, algorithms: ['SHA512'] }],
    });
    expect(result.ok).toBe(true);
  });
});
