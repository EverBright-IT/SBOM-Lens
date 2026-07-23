import { describe, expect, it } from 'vitest';
import { loadFixture } from '../../test-fixtures';
import { validateCdxStructure } from './validate';

/**
 * Spec lint (CDX_SCHEMA_*): one negative case per rule, plus the counter-proof
 * that the shipped CycloneDX fixture produces ZERO spec findings.
 */

/** A spec-clean 1.6 BOM, so each test breaks exactly one thing. */
function clean(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: 'urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79',
    version: 1,
    components: [{ 'bom-ref': 'pkg:npm/left-pad@1.0.0', type: 'library', name: 'left-pad', purl: 'pkg:npm/left-pad@1.0.0' }],
    ...overrides,
  };
}

function codes(root: Record<string, unknown>): string[] {
  return validateCdxStructure(root).map((d) => d.code);
}

describe('validateCdxStructure', () => {
  it('passes a clean BOM', () => {
    expect(codes(clean())).toEqual([]);
  });

  it('reports an unknown specVersion', () => {
    expect(codes(clean({ specVersion: '2.0' }))).toContain('CDX_SCHEMA_UNKNOWN_SPEC_VERSION');
  });

  it('accepts every known 1.x version', () => {
    for (const specVersion of ['1.4', '1.5', '1.6', '1.7']) {
      expect(codes(clean({ specVersion }))).toEqual([]);
    }
  });

  it('reports a serialNumber that is not a urn:uuid', () => {
    expect(codes(clean({ serialNumber: '3e671687-395b-41f5-a30f-a58921a69b79' }))).toContain('CDX_SCHEMA_BAD_SERIAL_NUMBER');
  });

  it('reports a version that is not a positive integer', () => {
    expect(codes(clean({ version: 0 }))).toContain('CDX_SCHEMA_BAD_VERSION');
    expect(codes(clean({ version: '1' }))).toContain('CDX_SCHEMA_BAD_VERSION');
  });

  it('reports a component type outside the vocabulary', () => {
    const root = clean({ components: [{ type: 'microservice', name: 'a' }] });
    expect(codes(root)).toContain('CDX_SCHEMA_BAD_COMPONENT_TYPE');
  });

  it('reports a duplicate bom-ref', () => {
    const root = clean({
      components: [
        { 'bom-ref': 'ref-1', type: 'library', name: 'a' },
        { 'bom-ref': 'ref-1', type: 'library', name: 'b' },
      ],
    });
    expect(codes(root)).toContain('CDX_SCHEMA_DUPLICATE_BOM_REF');
  });

  it('finds problems in nested assemblies too', () => {
    const root = clean({
      components: [
        { type: 'application', name: 'app', components: [{ type: 'nonsense', name: 'nested' }] },
      ],
    });
    expect(codes(root)).toContain('CDX_SCHEMA_BAD_COMPONENT_TYPE');
  });

  it('reports a hash whose length does not match its algorithm', () => {
    const root = clean({
      components: [{ type: 'library', name: 'a', hashes: [{ alg: 'SHA-256', content: 'abcd' }] }],
    });
    expect(codes(root)).toContain('CDX_SCHEMA_BAD_HASH');
  });

  it('accepts the CycloneDX spelling of hash algorithms', () => {
    const root = clean({
      components: [{ type: 'library', name: 'a', hashes: [{ alg: 'BLAKE2b-256', content: 'a'.repeat(64) }] }],
    });
    expect(codes(root)).toEqual([]);
  });

  it('reports a purl that is not a purl', () => {
    const root = clean({ components: [{ type: 'library', name: 'a', purl: 'npm/a@1.0.0' }] });
    expect(codes(root)).toContain('CDX_SCHEMA_BAD_PURL');
  });

  it('reports a malformed license expression', () => {
    const root = clean({ components: [{ type: 'library', name: 'a', licenses: [{ expression: 'MIT AND' }] }] });
    expect(codes(root)).toContain('CDX_SCHEMA_BAD_LICENSE_EXPRESSION');
  });

  it('reports a license carrying both id and name', () => {
    const root = clean({
      components: [{ type: 'library', name: 'a', licenses: [{ license: { id: 'MIT', name: 'MIT License' } }] }],
    });
    expect(codes(root)).toContain('CDX_SCHEMA_BAD_LICENSE_EXPRESSION');
  });

  it('checks the metadata component as well', () => {
    const root = clean({ metadata: { component: { type: 'wrong', name: 'product' } } });
    expect(codes(root)).toContain('CDX_SCHEMA_BAD_COMPONENT_TYPE');
  });

  it('keeps every finding a warning', () => {
    const found = validateCdxStructure(clean({ specVersion: '9.9', version: -1 }));
    expect(found.length).toBeGreaterThan(0);
    expect(found.every((d) => d.severity === 'warning')).toBe(true);
  });

  it('counter-proof: the shipped fixture produces no spec findings', () => {
    const root = JSON.parse(loadFixture('cdx/minimal.cdx.json')) as Record<string, unknown>;
    expect(validateCdxStructure(root)).toEqual([]);
  });
});
