import { describe, expect, it } from 'vitest';
import { fixtureInput } from '../test-fixtures';
import { parseDocument } from './parser';

function parse(name: string) {
  const { document, diagnostics } = parseDocument(fixtureInput(name));
  expect(document).not.toBeNull();
  return { doc: document!, diagnostics };
}

describe('json parser: minimal', () => {
  it('normalizes to the same model as the tag-value twin', () => {
    const { doc: json } = parse('minimal.spdx.json');
    const { doc: tv } = parse('minimal.spdx');

    expect(json.id).toBe(tv.id);
    expect(json.name).toBe(tv.name);
    expect(json.describes).toEqual(tv.describes);
    expect(json.elements.map((e) => [e.spdxId, e.name, e.version])).toEqual(
      tv.elements.map((e) => [e.spdxId, e.name, e.version]),
    );
    // documentDescribes becomes a synthetic DESCRIBES relationship,
    // matching the explicit one in the tag-value twin.
    expect(json.relationships).toEqual(expect.arrayContaining(tv.relationships));
    expect(json.relationships).toHaveLength(tv.relationships.length);
  });

  it('keeps the original JSON object as raw fields', () => {
    const { doc } = parse('minimal.spdx.json');
    const app = doc.elements[0]!;
    expect(app.raw.kind).toBe('json');
    if (app.raw.kind === 'json') expect(app.raw.value.SPDXID).toBe('SPDXRef-Package-app');
  });
});

describe('yaml serialization', () => {
  it('normalizes YAML to the same model as the JSON twin', () => {
    const { doc: yaml } = parse('minimal.spdx.yaml');
    const { doc: json } = parse('minimal.spdx.json');

    expect(yaml.spec.serialization).toBe('yaml');
    expect(yaml.id).toBe(json.id);
    expect(yaml.describes).toEqual(json.describes);
    expect(yaml.elements.map((e) => [e.spdxId, e.name, e.version, e.purl])).toEqual(
      json.elements.map((e) => [e.spdxId, e.name, e.version, e.purl]),
    );
    expect(yaml.relationships).toEqual(json.relationships);
  });
});

describe('json parser: trivy-style output', () => {
  const { doc, diagnostics } = parse('trivy-style.spdx.json');

  it('derives the version from the purl when versionInfo is absent', () => {
    const pkg = doc.elements.find((e) => e.spdxId === 'SPDXRef-Package-abc')!;
    expect(pkg.version).toBe('3.4.3-r2');
    expect(pkg.purl).toBe('pkg:apk/alpine/alpine-baselayout@3.4.3-r2?distro=3.19');
  });

  it('computes describes from DESCRIBES relationships when documentDescribes is absent', () => {
    expect(doc.describes).toEqual(['SPDXRef-Package-image']);
  });

  it('dedupes repeated file blocks with a diagnostic', () => {
    expect(doc.elements.filter((e) => e.spdxId === 'SPDXRef-File-1')).toHaveLength(1);
    expect(diagnostics.some((d) => d.code === 'DUP_SPDXID')).toBe(true);
  });

  it('keeps DEPENDENCY_OF and OTHER relationships', () => {
    const types = doc.relationships.map((r) => r.type);
    expect(types).toContain('DEPENDENCY_OF');
    expect(types).toContain('OTHER');
  });
});

describe('json parser: syft-style output', () => {
  it('synthesizes a DESCRIBES relationship from documentDescribes', () => {
    const { doc } = parse('syft-style.spdx.json');
    expect(doc.describes).toEqual(['SPDXRef-Package-root']);
    expect(doc.relationships).toContainEqual({
      from: { kind: 'local', spdxId: 'SPDXRef-DOCUMENT' },
      type: 'DESCRIBES',
      to: { kind: 'local', spdxId: 'SPDXRef-Package-root' },
    });
  });

  it('parses files into elements', () => {
    const { doc } = parse('syft-style.spdx.json');
    const file = doc.elements.find((e) => e.kind === 'file');
    expect(file?.name).toBe('package.json');
  });
});

describe('parseDocument: unsupported formats', () => {
  it.each([
    ['negative/trivy-native.json', 'TRIVY_NATIVE_NOT_SUPPORTED'],
    ['negative/garbage.txt', 'UNRECOGNIZED_FORMAT'],
  ])('%s → null document with %s', (fixture, code) => {
    const { document, diagnostics } = parseDocument(fixtureInput(fixture));
    expect(document).toBeNull();
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({ severity: 'error', code });
  });
});
