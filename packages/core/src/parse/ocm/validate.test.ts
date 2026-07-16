import { describe, expect, it } from 'vitest';
import { loadFixture } from '../../test-fixtures';
import { detect } from '../detect';
import { parseOcmComponentDescriptor } from './cd';
import type { SourceInput } from '../parser';

/**
 * Structural lint (OCM_SCHEMA_*): one negative case per rule, plus the
 * counter-proof that our well-formed fixtures produce ZERO schema warnings —
 * a lint that cries wolf on clean descriptors would be worse than none.
 */

const input: SourceInput = { fileName: 'test.yaml', text: '', sha1: 'f'.repeat(40), byteSize: 0 };

function parse(yaml: string) {
  const detection = detect(yaml);
  if (detection.format !== 'ocm-cd') throw new Error('fixture is not detected as a CD');
  return parseOcmComponentDescriptor(input, detection.parsed, 'yaml');
}

function codes(yaml: string): string[] {
  return parse(yaml).diagnostics.filter((d) => d.code.startsWith('OCM_SCHEMA_')).map((d) => d.code);
}

const base = (collections: string) => `meta:
  schemaVersion: v2
component:
  name: acme.org/webstack
  version: 2.1.0
  provider: ACME
${collections}`;

describe('validateCdStructure', () => {
  it('warns on a missing provider (meta is a detection prerequisite, not a lint)', () => {
    const yaml = `meta:
  schemaVersion: v2
component:
  name: acme.org/webstack
  version: 2.1.0
  resources: []
`;
    expect(codes(yaml)).toEqual(['OCM_SCHEMA_MISSING_FIELD']);
  });

  it('warns on a component name that ignores the spec pattern', () => {
    const yaml = `meta:
  schemaVersion: v2
component:
  name: MyComponent
  version: 2.1.0
  provider: ACME
  resources: []
`;
    expect(codes(yaml)).toContain('OCM_SCHEMA_BAD_NAME');
  });

  it('warns on non-semver component and artifact versions', () => {
    const yaml = `meta:
  schemaVersion: v2
component:
  name: acme.org/webstack
  version: latest
  provider: ACME
  resources:
    - name: cfg
      version: not.a@version
      type: plainText
      relation: local
`;
    const found = codes(yaml);
    expect(found.filter((c) => c === 'OCM_SCHEMA_BAD_VERSION').length).toBeGreaterThanOrEqual(2);
  });

  it('warns on bad relation, typeless access, and incomplete digest', () => {
    const yaml = base(`  resources:
    - name: cfg
      version: 1.0.0
      type: plainText
      relation: internal
      access:
        localReference: sha256.abc
      digest:
        hashAlgorithm: SHA-256
        value: "abc"
`);
    const found = codes(yaml);
    expect(found).toContain('OCM_SCHEMA_BAD_RELATION');
    expect(found).toContain('OCM_SCHEMA_ACCESS_MISSING_TYPE');
    expect(found).toContain('OCM_SCHEMA_DIGEST_INCOMPLETE');
  });

  it('warns on duplicate identities, but not on extraIdentity-disambiguated twins', () => {
    const dupes = base(`  resources:
    - name: cfg
      version: 1.0.0
      type: plainText
      relation: local
    - name: cfg
      version: 1.0.0
      type: plainText
      relation: local
`);
    expect(codes(dupes)).toContain('OCM_SCHEMA_DUPLICATE_IDENTITY');

    const twins = base(`  resources:
    - name: cfg
      version: 1.0.0
      type: plainText
      relation: local
      extraIdentity:
        os: linux
    - name: cfg
      version: 1.0.0
      type: plainText
      relation: local
      extraIdentity:
        os: darwin
`);
    expect(codes(twins)).not.toContain('OCM_SCHEMA_DUPLICATE_IDENTITY');
  });

  it('warns on labels without a name and on an unparseable creationTime', () => {
    const yaml = `meta:
  schemaVersion: v2
component:
  name: acme.org/webstack
  version: 2.1.0
  provider: ACME
  creationTime: not-a-date
  labels:
    - value: orphaned
  resources: []
`;
    const found = codes(yaml);
    expect(found).toContain('OCM_SCHEMA_LABEL_MALFORMED');
    expect(found).toContain('OCM_SCHEMA_BAD_TIMESTAMP');
  });

  it('counter-proof: the well-formed fixtures produce zero schema warnings', () => {
    expect(codes(loadFixture('ocm/cd-v2.yaml'))).toEqual([]);
    const signed = JSON.parse(loadFixture('ocm/signed-descriptor.json')) as Record<string, unknown>;
    const detection = detect(JSON.stringify(signed));
    if (detection.format !== 'ocm-cd') throw new Error('signed fixture not detected');
    const result = parseOcmComponentDescriptor(input, detection.parsed, 'json');
    expect(result.diagnostics.filter((d) => d.code.startsWith('OCM_SCHEMA_'))).toEqual([]);
  });
});
