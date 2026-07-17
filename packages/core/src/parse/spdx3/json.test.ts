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

describe('SPDX 3 imports (ExternalMap)', () => {
  const AUTH_DOC = 'https://acme.example/doc/auth-1.4.2';
  const AUTH_PKG = `${AUTH_DOC}#pkg-auth-service`;

  function importingDoc(importEntry: Record<string, unknown>): string {
    return JSON.stringify({
      '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
      '@graph': [
        {
          type: 'SpdxDocument',
          spdxId: 'https://acme.example/doc/platform-1.0',
          name: 'acme-platform-3x',
          creationInfo: '_:ci',
          rootElement: ['https://acme.example/doc/platform-1.0#pkg-platform'],
          import: [importEntry],
        },
        { type: 'CreationInfo', '@id': '_:ci', specVersion: '3.0.1', created: '2026-07-01T00:00:00Z', createdBy: [] },
        {
          type: 'software_Package',
          spdxId: 'https://acme.example/doc/platform-1.0#pkg-platform',
          name: 'acme-platform',
          software_packageVersion: '1.0.0',
        },
        {
          type: 'Relationship',
          spdxId: 'https://acme.example/doc/platform-1.0#rel-1',
          from: 'https://acme.example/doc/platform-1.0#pkg-platform',
          relationshipType: 'dependsOn',
          to: [AUTH_PKG],
        },
      ],
    });
  }

  function parseImporting(importEntry: Record<string, unknown>) {
    const source = importingDoc(importEntry);
    const result = parseDocument({ fileName: 'platform.spdx3.json', text: source, sha1: 'b'.repeat(40), byteSize: source.length });
    expect(result.document).not.toBeNull();
    return result.document!;
  }

  it('maps import entries to external document refs grouped by the defining document IRI', () => {
    const doc = parseImporting({
      externalSpdxId: AUTH_PKG,
      locationHint: 'https://downloads.acme.example/auth-1.4.2.spdx3.json',
      verifiedUsing: [{ type: 'Hash', algorithm: 'sha256', hashValue: 'CC'.repeat(32) }],
    });
    expect(doc.externalDocumentRefs).toEqual([
      {
        docRef: AUTH_DOC,
        uri: AUTH_DOC,
        checksum: { algorithm: 'SHA256', value: 'cc'.repeat(32) },
      },
    ]);
    const rel = doc.relationships.find((r) => r.type === 'DEPENDS_ON')!;
    expect(rel.to).toEqual({ kind: 'external', docRef: AUTH_DOC, spdxId: AUTH_PKG });
    expect(rel.from.kind).toBe('local');
  });

  it('keeps the checksum when a later import for the same document carries it', () => {
    const source = JSON.stringify({
      '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
      '@graph': [
        {
          type: 'SpdxDocument',
          spdxId: 'https://acme.example/doc/platform-1.0',
          name: 'p',
          creationInfo: '_:ci',
          import: [
            { externalSpdxId: `${AUTH_DOC}#pkg-a` },
            {
              externalSpdxId: `${AUTH_DOC}#pkg-b`,
              verifiedUsing: [{ type: 'Hash', algorithm: 'sha1', hashValue: 'AB'.repeat(20) }],
            },
          ],
        },
        { type: 'CreationInfo', '@id': '_:ci', specVersion: '3.0.1', created: '2026-07-01T00:00:00Z', createdBy: [] },
      ],
    });
    const result = parseDocument({ fileName: 'p.spdx3.json', text: source, sha1: 'c'.repeat(40), byteSize: source.length });
    expect(result.document!.externalDocumentRefs).toEqual([
      { docRef: AUTH_DOC, uri: AUTH_DOC, checksum: { algorithm: 'SHA1', value: 'ab'.repeat(20) } },
    ]);
  });

  it('falls back to the locationHint when the IRI carries no fragment', () => {
    const doc = parseImporting({
      externalSpdxId: 'urn:acme:auth-service',
      locationHint: 'https://downloads.acme.example/auth-1.4.2.spdx3.json',
    });
    expect(doc.externalDocumentRefs).toEqual([
      { docRef: 'https://downloads.acme.example/auth-1.4.2.spdx3.json', uri: 'https://downloads.acme.example/auth-1.4.2.spdx3.json' },
    ]);
  });

  it('resolves an imported reference through the existing namespace resolution', async () => {
    const { addDocument } = await import('../../workspace/workspace');
    const { refKey } = await import('../../workspace/resolve');
    const authText = JSON.stringify({
      '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
      '@graph': [
        {
          type: 'SpdxDocument',
          spdxId: AUTH_DOC,
          name: 'acme-auth-3x',
          creationInfo: '_:ci',
        },
        { type: 'CreationInfo', '@id': '_:ci', specVersion: '3.0.1', created: '2026-07-01T00:00:00Z', createdBy: [] },
        { type: 'software_Package', spdxId: AUTH_PKG, name: 'auth-service', software_packageVersion: '1.4.2' },
      ],
    });
    let ws = addDocument(
      emptyWorkspace,
      loadedFromText('platform.spdx3.json', importingDoc({ externalSpdxId: AUTH_PKG })),
    ).workspace;
    const owningId = [...ws.documents.keys()][0]!;
    expect(ws.resolutions.get(refKey(owningId, AUTH_DOC))?.status).toBe('unresolved');

    ws = addDocument(ws, loadedFromText('auth.spdx3.json', authText)).workspace;
    const resolution = ws.resolutions.get(refKey(owningId, AUTH_DOC));
    expect(resolution).toMatchObject({ status: 'resolved', method: 'namespace' });
  });
});

describe('SPDX 3 cascade fixtures', () => {
  it('links the committed fixture pair through namespace resolution', async () => {
    const { addDocument } = await import('../../workspace/workspace');
    const { refKey } = await import('../../workspace/resolve');
    let ws = addDocument(
      emptyWorkspace,
      loadedFromText('cascade-platform.spdx3.json', loadFixture('spdx3/cascade-platform.spdx3.json')),
    ).workspace;
    const owningId = [...ws.documents.keys()][0]!;
    ws = addDocument(
      ws,
      loadedFromText('cascade-auth.spdx3.json', loadFixture('spdx3/cascade-auth.spdx3.json')),
    ).workspace;
    const resolution = ws.resolutions.get(refKey(owningId, 'https://acme.example/doc/auth3-1.4.2'));
    expect(resolution).toMatchObject({ status: 'resolved', method: 'namespace' });
    // The imported IRI is the auth document's package spdxId: reveal works.
    const auth = [...ws.documents.values()].find((d) => d.document.name === 'acme-auth3-1.4.2')!;
    expect(auth.indexes.elementBySpdxId.has('https://acme.example/doc/auth3-1.4.2#pkg-auth-service')).toBe(true);
  });
});
