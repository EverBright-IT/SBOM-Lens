import { describe, expect, it } from 'vitest';
import { loadFixture } from '../../test-fixtures';
import { validateSpdx2Structure } from './validate';

/**
 * Spec lint (SPDX2_SCHEMA_*): one negative case per rule, plus the
 * counter-proof that real generator output produces ZERO spec findings. A lint
 * that cries wolf on a clean syft SBOM would be worse than none — every rule
 * here has to survive that fixture set.
 */

/** A minimal document that is spec-clean, so each test breaks exactly one thing. */
function clean(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: 'acme',
    documentNamespace: 'https://acme.example/spdx/acme-1.0',
    creationInfo: { created: '2026-07-23T10:00:00Z', creators: ['Tool: sbomlens-0.24.0'] },
    packages: [
      {
        SPDXID: 'SPDXRef-Package-acme',
        name: 'acme',
        downloadLocation: 'NOASSERTION',
      },
    ],
    ...overrides,
  };
}

function codes(root: Record<string, unknown>): string[] {
  return validateSpdx2Structure(root).map((d) => d.code);
}

function messageFor(root: Record<string, unknown>, code: string): string {
  return validateSpdx2Structure(root).find((d) => d.code === code)?.message ?? '';
}

describe('validateSpdx2Structure', () => {
  it('passes a clean document', () => {
    expect(codes(clean())).toEqual([]);
  });

  it('reports a version literal that is not SPDX-2.x', () => {
    expect(codes(clean({ spdxVersion: '2.3' }))).toContain('SPDX2_SCHEMA_BAD_VERSION');
  });

  it('reports a data license other than CC0-1.0', () => {
    expect(codes(clean({ dataLicense: 'MIT' }))).toContain('SPDX2_SCHEMA_BAD_DATA_LICENSE');
  });

  it('reports a namespace that is not an absolute URI', () => {
    expect(codes(clean({ documentNamespace: 'acme/spdx' }))).toContain('SPDX2_SCHEMA_BAD_NAMESPACE');
  });

  it('reports a namespace with a fragment', () => {
    const message = messageFor(clean({ documentNamespace: 'https://acme.example/spdx#doc' }), 'SPDX2_SCHEMA_BAD_NAMESPACE');
    expect(message).toContain('fragment');
  });

  it('reports a created timestamp that is not UTC', () => {
    const root = clean({ creationInfo: { created: '2026-07-23T10:00:00+02:00', creators: ['Tool: t'] } });
    expect(codes(root)).toContain('SPDX2_SCHEMA_BAD_CREATED');
  });

  it('accepts fractional seconds in the timestamp', () => {
    const root = clean({ creationInfo: { created: '2026-07-23T10:00:00.123Z', creators: ['Tool: t'] } });
    expect(codes(root)).toEqual([]);
  });

  it('reports a creator without a kind prefix', () => {
    const root = clean({ creationInfo: { created: '2026-07-23T10:00:00Z', creators: ['syft'] } });
    expect(codes(root)).toContain('SPDX2_SCHEMA_BAD_CREATOR');
  });

  it('reports an identifier that is not SPDXRef-shaped', () => {
    const root = clean({ packages: [{ SPDXID: 'Package-1', name: 'a', downloadLocation: 'NONE' }] });
    expect(codes(root)).toContain('SPDX2_SCHEMA_BAD_SPDXID');
  });

  it('reports a package without the mandatory downloadLocation', () => {
    const root = clean({ packages: [{ SPDXID: 'SPDXRef-a', name: 'a' }] });
    expect(codes(root)).toContain('SPDX2_SCHEMA_MISSING_DOWNLOAD_LOCATION');
  });

  it('reports a purpose outside the vocabulary', () => {
    const root = clean({
      packages: [{ SPDXID: 'SPDXRef-a', name: 'a', downloadLocation: 'NONE', primaryPackagePurpose: 'MICROSERVICE' }],
    });
    expect(codes(root)).toContain('SPDX2_SCHEMA_BAD_PACKAGE_PURPOSE');
  });

  it('reports a checksum whose length does not match its algorithm', () => {
    const root = clean({
      packages: [
        {
          SPDXID: 'SPDXRef-a',
          name: 'a',
          downloadLocation: 'NONE',
          checksums: [{ algorithm: 'SHA256', checksumValue: 'abc123' }],
        },
      ],
    });
    expect(messageFor(root, 'SPDX2_SCHEMA_BAD_CHECKSUM')).toContain('expected 64');
  });

  it('reports an unknown checksum algorithm', () => {
    const root = clean({
      packages: [
        {
          SPDXID: 'SPDXRef-a',
          name: 'a',
          downloadLocation: 'NONE',
          checksums: [{ algorithm: 'CRC32', checksumValue: 'deadbeef' }],
        },
      ],
    });
    expect(messageFor(root, 'SPDX2_SCHEMA_BAD_CHECKSUM')).toContain('unknown algorithm');
  });

  it('reports a verification code that is not 40 hex characters', () => {
    const root = clean({
      packages: [
        {
          SPDXID: 'SPDXRef-a',
          name: 'a',
          downloadLocation: 'NONE',
          packageVerificationCode: { packageVerificationCodeValue: 'nothex' },
        },
      ],
    });
    expect(codes(root)).toContain('SPDX2_SCHEMA_BAD_VERIFICATION_CODE');
  });

  it('reports a purl reference whose locator is not a purl', () => {
    const root = clean({
      packages: [
        {
          SPDXID: 'SPDXRef-a',
          name: 'a',
          downloadLocation: 'NONE',
          externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'npm/left-pad@1.0.0' }],
        },
      ],
    });
    expect(codes(root)).toContain('SPDX2_SCHEMA_BAD_PURL_REF');
  });

  it('reports a relationship type outside the vocabulary', () => {
    const root = clean({
      relationships: [
        { spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'SHIPS_WITH', relatedSpdxElement: 'SPDXRef-Package-acme' },
      ],
    });
    expect(codes(root)).toContain('SPDX2_SCHEMA_UNKNOWN_RELATIONSHIP');
  });

  it('accepts the hyphenated spelling of a known relationship type', () => {
    const root = clean({
      relationships: [
        { spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'depends-on', relatedSpdxElement: 'SPDXRef-Package-acme' },
      ],
    });
    expect(codes(root)).toEqual([]);
  });

  it('aggregates many findings of one kind into a single diagnostic', () => {
    const packages = Array.from({ length: 40 }, (_, i) => ({ SPDXID: `SPDXRef-p${i}`, name: `p${i}` }));
    const found = validateSpdx2Structure(clean({ packages }));
    const downloadFindings = found.filter((d) => d.code === 'SPDX2_SCHEMA_MISSING_DOWNLOAD_LOCATION');
    expect(downloadFindings).toHaveLength(1);
    const message = downloadFindings[0]?.message ?? '';
    expect(message).toContain('40 package(s)');
    expect(message).toContain('...');
  });

  it('keeps every finding a warning, never an error', () => {
    const found = validateSpdx2Structure(clean({ spdxVersion: 'nope', dataLicense: 'MIT' }));
    expect(found.length).toBeGreaterThan(0);
    expect(found.every((d) => d.severity === 'warning')).toBe(true);
  });

  describe('license expressions', () => {
    const withLicense = (expr: string) =>
      clean({ packages: [{ SPDXID: 'SPDXRef-a', name: 'a', downloadLocation: 'NONE', licenseDeclared: expr }] });

    it.each([
      'MIT',
      'NOASSERTION',
      'NONE',
      'Apache-2.0 AND MIT',
      '(MIT OR Apache-2.0) AND ISC',
      'GPL-2.0-only WITH Classpath-exception-2.0',
      'LicenseRef-acme-internal',
      'DocumentRef-other:LicenseRef-vendor',
      'GPL-3.0+',
    ])('accepts %s', (expr) => {
      expect(codes(withLicense(expr))).toEqual([]);
    });

    it.each([
      ['Apache 2.0', 'missing operator'],
      ['MIT AND', 'ends with an operator'],
      ['(MIT OR Apache-2.0', 'unbalanced'],
      ['MIT and Apache-2.0', 'uppercase'],
      ['AND MIT', 'without a left-hand license'],
      ['MIT AND NOASSERTION', 'cannot be combined'],
    ])('reports %s', (expr, reason) => {
      expect(messageFor(withLicense(expr), 'SPDX2_SCHEMA_BAD_LICENSE_EXPRESSION')).toContain(reason);
    });
  });

  describe('counter-proof: real-world fixtures stay silent', () => {
    it.each(['syft-style.spdx.json', 'trivy-style.spdx.json', 'minimal.spdx.json', 'cycle.spdx.json'])(
      '%s produces no spec findings',
      (fixture) => {
        const root = JSON.parse(loadFixture(fixture)) as Record<string, unknown>;
        expect(validateSpdx2Structure(root)).toEqual([]);
      },
    );
  });
});
