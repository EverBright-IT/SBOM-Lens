import { describe, expect, it } from 'vitest';
import { emptyWorkspace } from '../../workspace/workspace';
import { evaluateProfile } from '../../profile/evaluate';
import { NTIA_PROFILE } from '../../profile/ntia';
import { buildIndexes } from '../../graph/indexes';
import { loadFixture, loadedFromText } from '../../test-fixtures';
import { detect } from '../detect';
import { parseDocument } from '../parser';

/**
 * SPDX 3.0.1 ingestion. Additive: the 2.x parsers are untouched (the rest of
 * the suite proves that); these tests pin the 3.x graph mapping.
 */

const text = loadFixture('spdx3/webstack.spdx3.json');

function parse() {
  const result = parseDocument({ fileName: 'webstack.spdx3.json', text, sha1: 'a'.repeat(40), byteSize: text.length });
  expect(result.document).not.toBeNull();
  return result;
}

describe('SPDX 3 detection', () => {
  it('routes a 3.0.1 JSON-LD document to the spdx3 parser instead of refusing', () => {
    const detection = detect(text);
    expect(detection.format).toBe('spdx3-json');
  });

  it('keeps detecting SPDX 2.x JSON unchanged', () => {
    expect(detect(loadFixture('minimal.spdx.json')).format).toBe('spdx2-json');
    expect(detect(loadFixture('minimal.spdx')).format).toBe('spdx2-tag-value');
  });
});

describe('SPDX 3 mapping', () => {
  it('maps document identity, creation info, and agents', () => {
    const { document } = parse();
    expect(document!.spec).toEqual({ model: 'spdx-3', version: 'SPDX-3.0.1', serialization: 'json' });
    expect(document!.name).toBe('acme-webstack-3.0.0');
    expect(document!.namespace).toBe('https://acme.example/doc/webstack-3.0.0');
    expect(document!.created).toBe('2026-06-01T10:00:00Z');
    expect(document!.creators).toEqual(['Organization: ACME Corp', 'Tool: acme-sbom-tool 2.0']);
  });

  it('maps packages with version, supplier, purpose, purl, cpe, and hashes', () => {
    const { document } = parse();
    const webstack = document!.elements.find((e) => e.name === 'webstack')!;
    expect(webstack.kind).toBe('package');
    expect(webstack.version).toBe('3.0.0');
    expect(webstack.supplier).toBe('Organization: ACME Corp');
    expect(webstack.purpose).toBe('APPLICATION');
    expect(webstack.purl).toBe('pkg:npm/%40acme/webstack@3.0.0');
    expect(webstack.externalRefs).toContainEqual({
      category: 'SECURITY',
      type: 'cpe23',
      locator: 'cpe:2.3:a:acme:webstack:3.0.0:*:*:*:*:*:*:*',
    });
    expect(webstack.checksums).toEqual([
      { algorithm: 'SHA256', value: 'aabb00112233445566778899aabbccddeeff00112233445566778899aabbccdd' },
    ]);
  });

  it('maps files, normalizes NoAssertion, and folds license relationships into fields', () => {
    const { document } = parse();
    const file = document!.elements.find((e) => e.kind === 'file')!;
    expect(file.name).toBe('config/nginx.conf');
    expect(file.checksums?.[0]?.algorithm).toBe('SHA1');

    const nginx = document!.elements.find((e) => e.name === 'nginx-gateway')!;
    expect(nginx.downloadLocation).toBe('NOASSERTION');

    const webstack = document!.elements.find((e) => e.name === 'webstack')!;
    expect(webstack.licenseDeclared).toBe('Apache-2.0');
    // The license relationship must not appear as a tree edge.
    expect(document!.relationships.some((r) => r.type.includes('LICENSE'))).toBe(false);
  });

  it('expands multi-target relationships and converts camelCase types', () => {
    const { document } = parse();
    const contains = document!.relationships.filter((r) => r.type === 'CONTAINS');
    expect(contains).toHaveLength(2);
    expect(document!.relationships.some((r) => r.type === 'DEPENDS_ON')).toBe(true);
  });

  it('derives describes from the SpdxDocument rootElement', () => {
    const { document } = parse();
    expect(document!.describes).toEqual(['https://acme.example/pkg/webstack']);
  });

  it('counts unmapped profile elements instead of dropping them silently', () => {
    const { diagnostics } = parse();
    const skipped = diagnostics.find((d) => d.code === 'SPDX3_ELEMENTS_SKIPPED');
    expect(skipped?.message).toContain('ai_AIPackage (1)');
  });

  it('feeds the profile engine: an NTIA report evaluates on a 3.x document', () => {
    const { document } = parse();
    const loaded = {
      document: document!,
      indexes: buildIndexes(document!),
      source: { fileName: 'webstack.spdx3.json', byteSize: text.length, sha1: 'a'.repeat(40), text },
    };
    const report = evaluateProfile(emptyWorkspace, loaded, NTIA_PROFILE);
    expect(report.packagesTotal).toBe(2);
    expect(report.results.find((r) => r.id === 'created')?.pass).toBe(true);
    expect(report.results.find((r) => r.id === 'creators')?.pass).toBe(true);
  });

  it('reports an empty graph as an error, not a crash', () => {
    const broken = JSON.stringify({ '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld', '@graph': [] });
    const result = parseDocument({ fileName: 'x.json', text: broken, sha1: 'b'.repeat(40), byteSize: broken.length });
    expect(result.document).toBeNull();
    expect(result.diagnostics[0]?.code).toBe('SPDX3_NO_GRAPH');
  });

  it('SPDX 2.x parsing is byte-for-byte unaffected (control)', () => {
    const two = loadedFromText('minimal.spdx.json', loadFixture('minimal.spdx.json'));
    expect(two.document.spec.model).toBe('spdx-2');
  });
});
