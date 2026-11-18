import { describe, expect, it } from 'vitest';
import { emptyWorkspace } from '../../workspace/workspace';
import { evaluateProfile } from '../../profile/evaluate';
import { NTIA_PROFILE } from '../../profile/ntia';
import { buildIndexes } from '../../graph/indexes';
import { loadFixture, loadedFromText } from '../../test-fixtures';
import { detect } from '../detect';
import { parseDocument } from '../parser';
import { hasUniqueIdentifier } from '../../model/document';

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

  it('maps licence targets to expressions: listed ids, LicenseRef for custom licences, NOASSERTION/NONE individuals', () => {
    // A licence TEXT must never land in a licence field: downstream it would
    // read as an unparseable expression. CustomLicense becomes the
    // LicenseRef- form SPDX 2 uses for the same thing.
    const ci = '_:ci';
    const graph = JSON.stringify({
      '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
      '@graph': [
        { type: 'CreationInfo', '@id': ci, specVersion: '3.0.1', created: '2026-06-01T10:00:00Z', createdBy: ['https://acme.example/agent/acme'] },
        { type: 'Organization', spdxId: 'https://acme.example/agent/acme', creationInfo: ci, name: 'ACME Corp' },
        { type: 'SpdxDocument', spdxId: 'https://acme.example/doc/licences', creationInfo: ci, name: 'licences', rootElement: ['https://acme.example/pkg/a'] },
        { type: 'software_Package', spdxId: 'https://acme.example/pkg/a', creationInfo: ci, name: 'a' },
        { type: 'software_Package', spdxId: 'https://acme.example/pkg/b', creationInfo: ci, name: 'b' },
        { type: 'software_Package', spdxId: 'https://acme.example/pkg/c', creationInfo: ci, name: 'c' },
        {
          type: 'expandedlicensing_CustomLicense',
          spdxId: 'https://acme.example/licenses/LicenseRef-acme-eula',
          creationInfo: ci,
          name: 'ACME EULA',
          simplelicensing_licenseText: 'Permission is granted to ACME customers only, and to nobody else.',
        },
        {
          type: 'expandedlicensing_CustomLicense',
          spdxId: 'https://acme.example/eula#v2026',
          creationInfo: ci,
          name: 'ACME EULA 2026',
          simplelicensing_licenseText: 'The 2026 edition of the same text.',
        },
        rel('a', 'hasDeclaredLicense', 'https://acme.example/licenses/LicenseRef-acme-eula'),
        rel('b', 'hasDeclaredLicense', 'https://spdx.org/rdf/3.0.1/terms/ExpandedLicensing/NoAssertionLicense'),
        rel('b', 'hasConcludedLicense', 'https://spdx.org/rdf/3.0.1/terms/ExpandedLicensing/NoneLicense'),
        rel('c', 'hasDeclaredLicense', 'https://spdx.org/licenses/MIT'),
        rel('c', 'hasConcludedLicense', 'https://acme.example/eula#v2026'),
      ],
    });
    function rel(from: string, relationshipType: string, to: string) {
      return {
        type: 'Relationship',
        spdxId: `https://acme.example/rel/${from}-${relationshipType}`,
        creationInfo: ci,
        from: `https://acme.example/pkg/${from}`,
        relationshipType,
        to: [to],
      };
    }
    const result = parseDocument({ fileName: 'licences.spdx3.json', text: graph, sha1: 'b'.repeat(40), byteSize: graph.length });
    const byName = Object.fromEntries(result.document!.elements.map((e) => [e.name, e]));
    expect(byName.a!.licenseDeclared).toBe('LicenseRef-acme-eula');
    expect(byName.b!.licenseDeclared).toBe('NOASSERTION');
    expect(byName.b!.licenseConcluded).toBe('NONE');
    expect(byName.c!.licenseDeclared).toBe('MIT');
    expect(byName.c!.licenseConcluded).toBe('LicenseRef-v2026');
    // Listed-licence IRIs and the vocabulary individuals are well known, not dangling.
    expect(result.diagnostics.map((d) => d.code)).not.toContain('SPDX3_SCHEMA_DANGLING_REF');
  });

  it('accepts the 3.0.1 expression dialect and maps its operators to the 2.x spelling', () => {
    const ci = '_:ci';
    const graph = JSON.stringify({
      '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
      '@graph': [
        { type: 'CreationInfo', '@id': ci, specVersion: '3.0.1', created: '2026-06-01T10:00:00Z' },
        { type: 'SpdxDocument', spdxId: 'https://acme.example/doc/dialect', creationInfo: ci, name: 'dialect' },
        { type: 'software_Package', spdxId: 'https://acme.example/pkg/a', creationInfo: ci, name: 'a' },
        {
          type: 'simplelicensing_LicenseExpression',
          spdxId: 'https://acme.example/lic/1',
          creationInfo: ci,
          simplelicensing_licenseExpression: 'MIT and (Apache-2.0 or GPL-2.0-only with AdditionRef-acme)',
        },
        { type: 'Relationship', spdxId: 'https://acme.example/rel/1', creationInfo: ci, from: 'https://acme.example/pkg/a', relationshipType: 'hasDeclaredLicense', to: ['https://acme.example/lic/1'] },
      ],
    });
    const result = parseDocument({ fileName: 'dialect.spdx3.json', text: graph, sha1: 'e'.repeat(40), byteSize: graph.length });
    expect(result.diagnostics.map((d) => d.code)).not.toContain('SPDX3_SCHEMA_BAD_LICENSE_EXPRESSION');
    expect(result.document!.elements.find((e) => e.name === 'a')!.licenseDeclared).toBe('MIT AND (Apache-2.0 OR GPL-2.0-only WITH AdditionRef-acme)');
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

  it('maps AI packages as packages with purpose MODEL, profile fields left raw', () => {
    const { document, diagnostics } = parse();
    const model = document!.elements.find((e) => e.name === 'recommendation-model')!;
    expect(model.kind).toBe('package');
    expect(model.purpose).toBe('MODEL');
    expect(diagnostics.find((d) => d.code === 'SPDX3_ELEMENTS_SKIPPED')).toBeUndefined();
  });

  it('counts unmapped profile elements instead of dropping them silently', () => {
    const graph = JSON.stringify({
      '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
      '@graph': [
        { type: 'CreationInfo', '@id': '_:ci', specVersion: '3.0.1', created: '2026-06-01T10:00:00Z' },
        { type: 'SpdxDocument', spdxId: 'https://acme.example/doc/build', creationInfo: '_:ci', name: 'build' },
        { type: 'build_Build', spdxId: 'https://acme.example/build/nightly', creationInfo: '_:ci', name: 'nightly' },
      ],
    });
    const { diagnostics } = parseDocument({ fileName: 'build.spdx3.json', text: graph, sha1: 'c'.repeat(40), byteSize: graph.length });
    const skipped = diagnostics.find((d) => d.code === 'SPDX3_ELEMENTS_SKIPPED');
    expect(skipped?.message).toContain('build_Build (1)');
  });

  it('feeds the profile engine: an NTIA report evaluates on a 3.x document', () => {
    const { document } = parse();
    const loaded = {
      document: document!,
      indexes: buildIndexes(document!),
      source: { fileName: 'webstack.spdx3.json', byteSize: text.length, sha1: 'a'.repeat(40), text },
    };
    const report = evaluateProfile(emptyWorkspace, loaded, NTIA_PROFILE);
    expect(report.packagesTotal).toBe(3); // two software packages and the AI package
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

describe('SPDX 3 contacts and distribution artifacts (TR-03183-2 appendix 8.2)', () => {
  const ci = '_:ci';
  const graph = JSON.stringify({
    '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
    '@graph': [
      { type: 'CreationInfo', '@id': ci, specVersion: '3.0.1', created: '2026-06-01T10:00:00Z', createdBy: ['https://acme.example/agent/acme'] },
      {
        type: 'Organization',
        spdxId: 'https://acme.example/agent/acme',
        creationInfo: ci,
        name: 'ACME Corp',
        externalIdentifier: [{ type: 'ExternalIdentifier', externalIdentifierType: 'email', identifier: 'security@acme.example' }],
      },
      {
        type: 'Organization',
        spdxId: 'https://acme.example/agent/widgets',
        creationInfo: ci,
        name: 'Widget Works',
        externalIdentifier: [{ type: 'ExternalIdentifier', externalIdentifierType: 'other', identifier: 'https://widgets.example' }],
      },
      { type: 'SpdxDocument', spdxId: 'https://acme.example/doc/contacts', creationInfo: ci, name: 'contacts', rootElement: ['https://acme.example/pkg/widget'] },
      {
        type: 'software_Package',
        spdxId: 'https://acme.example/pkg/widget',
        creationInfo: ci,
        name: 'widget',
        software_packageVersion: '1.0.0',
        suppliedBy: 'https://acme.example/agent/widgets',
        originatedBy: ['https://acme.example/agent/widgets'],
      },
      { type: 'software_File', spdxId: 'https://acme.example/file/widget-jar', creationInfo: ci, name: 'widget-1.0.0.jar' },
      {
        type: 'Relationship',
        spdxId: 'https://acme.example/rel/dist',
        creationInfo: ci,
        from: 'https://acme.example/pkg/widget',
        relationshipType: 'hasDistributionArtifact',
        to: ['https://acme.example/file/widget-jar'],
      },
    ],
  });

  it('carries the creator and originator contacts, keeps the supplier bare, and names the distribution artifact', () => {
    const { document } = parseDocument({ fileName: 'contacts.spdx3.json', text: graph, sha1: 'd'.repeat(40), byteSize: graph.length });
    expect(document!.creators).toEqual(['Organization: ACME Corp (security@acme.example)']);
    const widget = document!.elements.find((e) => e.name === 'widget')!;
    expect(widget.originator).toBe('Organization: Widget Works (https://widgets.example)');
    expect(widget.supplier).toBe('Organization: Widget Works');
    expect(widget.fileName).toBe('widget-1.0.0.jar');
    // The relationship stays an edge of the tree as well.
    expect(document!.relationships).toContainEqual(expect.objectContaining({ type: 'HAS_DISTRIBUTION_ARTIFACT' }));
  });
});

describe('SPDX 3 reading gaps', () => {
  const B = 'https://acme.example';
  const ci = '_:ci';
  const creation = { type: 'CreationInfo', '@id': ci, specVersion: '3.0.1', created: '2026-06-01T10:00:00Z' };
  const docNode = { type: 'SpdxDocument', spdxId: `${B}/doc/gaps`, creationInfo: ci, name: 'gaps', rootElement: [`${B}/pkg/app`] };
  const pkg = (name: string, extra: Record<string, unknown> = {}) => ({
    type: 'software_Package',
    spdxId: `${B}/pkg/${name}`,
    creationInfo: ci,
    name,
    ...extra,
  });
  const rel = (from: string, relationshipType: string, to: unknown, extra: Record<string, unknown> = {}) => ({
    type: 'Relationship',
    spdxId: `${B}/rel/${from}-${relationshipType}-${Math.random().toString(36).slice(2)}`,
    creationInfo: ci,
    from: `${B}/pkg/${from}`,
    relationshipType,
    to,
    ...extra,
  });
  function parse3(nodes: Record<string, unknown>[], options: { context?: unknown; creation?: Record<string, unknown> } = {}) {
    const text = JSON.stringify({
      '@context': options.context ?? 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
      '@graph': [options.creation ?? creation, docNode, ...nodes],
    });
    return parseDocument({ fileName: 'gaps.spdx3.json', text, sha1: 'e'.repeat(40), byteSize: text.length });
  }
  const codes = (result: { diagnostics: { code: string }[] }) => result.diagnostics.map((d) => d.code);

  it('reads LifecycleScopedRelationship as an edge and keeps its scope', () => {
    const result = parse3([
      pkg('app'),
      pkg('lib'),
      pkg('gcc'),
      { ...rel('app', 'dependsOn', [`${B}/pkg/lib`]), type: 'LifecycleScopedRelationship', scope: 'runtime' },
      {
        ...rel('app', 'dependsOn', [`${B}/pkg/gcc`]),
        type: 'LifecycleScopedRelationship',
        scope: 'https://spdx.org/rdf/3.0.1/terms/Core/LifecycleScopeType/build',
      },
    ]);
    const deps = result.document!.relationships.filter((r) => r.type === 'DEPENDS_ON');
    expect(deps).toEqual([
      expect.objectContaining({ from: { kind: 'local', spdxId: `${B}/pkg/app` }, to: { kind: 'local', spdxId: `${B}/pkg/lib` }, scope: 'runtime' }),
      expect.objectContaining({ to: { kind: 'local', spdxId: `${B}/pkg/gcc` }, scope: 'build' }),
    ]);
    expect(codes(result)).not.toContain('SPDX3_ELEMENTS_SKIPPED');
    const loaded = loadedFromText('gaps.spdx3.json', JSON.stringify({
      '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
      '@graph': [creation, docNode, pkg('app'), pkg('lib'), { ...rel('app', 'dependsOn', [`${B}/pkg/lib`]), type: 'LifecycleScopedRelationship', scope: 'runtime' }],
    }));
    const report = evaluateProfile(emptyWorkspace, loaded, NTIA_PROFILE);
    expect(report.results.find((r) => r.id === 'relationships')?.pass).toBe(true);
  });

  it('folds structured licence sets and operators into one expression', () => {
    const result = parse3([
      pkg('a'),
      pkg('b'),
      pkg('c'),
      pkg('d'),
      { type: 'expandedlicensing_ConjunctiveLicenseSet', spdxId: `${B}/lic/and`, creationInfo: ci, expandedlicensing_member: ['https://spdx.org/licenses/MIT', `${B}/lic/or`] },
      { type: 'expandedlicensing_DisjunctiveLicenseSet', spdxId: `${B}/lic/or`, creationInfo: ci, expandedlicensing_member: ['https://spdx.org/licenses/Apache-2.0', 'https://spdx.org/licenses/BSD-3-Clause'] },
      { type: 'expandedlicensing_OrLaterOperator', spdxId: `${B}/lic/gpl-or-later`, creationInfo: ci, expandedlicensing_subjectLicense: 'https://spdx.org/licenses/GPL-2.0-only' },
      {
        type: 'expandedlicensing_WithAdditionOperator',
        spdxId: `${B}/lic/gpl-cp`,
        creationInfo: ci,
        expandedlicensing_subjectExtendableLicense: `${B}/lic/gpl-or-later`,
        expandedlicensing_subjectAddition: 'https://spdx.org/licenses/Classpath-exception-2.0',
      },
      {
        type: 'expandedlicensing_ConjunctiveLicenseSet',
        spdxId: `${B}/lic/inline`,
        creationInfo: ci,
        expandedlicensing_member: [
          { type: 'expandedlicensing_CustomLicense', spdxId: `${B}/licenses/LicenseRef-acme`, creationInfo: ci, name: 'ACME' },
          'https://spdx.org/licenses/MIT',
        ],
      },
      { type: 'expandedlicensing_ConjunctiveLicenseSet', spdxId: `${B}/lic/unknown`, creationInfo: ci, expandedlicensing_member: ['https://spdx.org/licenses/MIT', `${B}/lic/mystery`] },
      { type: 'expandedlicensing_Mystery', spdxId: `${B}/lic/mystery`, creationInfo: ci },
      rel('a', 'hasConcludedLicense', [`${B}/lic/and`]),
      rel('b', 'hasDeclaredLicense', [`${B}/lic/gpl-cp`]),
      rel('c', 'hasDeclaredLicense', [`${B}/lic/inline`]),
      rel('d', 'hasDeclaredLicense', [`${B}/lic/unknown`]),
    ]);
    const byName = Object.fromEntries(result.document!.elements.map((e) => [e.name, e]));
    expect(byName.a!.licenseConcluded).toBe('MIT AND (Apache-2.0 OR BSD-3-Clause)');
    expect(byName.b!.licenseDeclared).toBe('GPL-2.0-only+ WITH Classpath-exception-2.0');
    expect(byName.c!.licenseDeclared).toBe('LicenseRef-acme AND MIT');
    // Never half an expression: an unreadable member leaves the field empty and says so.
    expect(byName.d!.licenseDeclared).toBeUndefined();
    expect(result.diagnostics.find((d) => d.code === 'SPDX3_LICENSE_NOT_MAPPED')?.message).toContain('1 licence statement');
  });

  it('maps NoneElement and NoAssertionElement targets to the special ends', () => {
    const result = parse3([
      pkg('app'),
      rel('app', 'dependsOn', ['https://spdx.org/rdf/3.0.1/terms/Core/NoneElement']),
      rel('app', 'contains', ['https://spdx.org/rdf/3.0.1/terms/Core/NoAssertionElement']),
    ]);
    const rels = result.document!.relationships;
    expect(rels.find((r) => r.type === 'DEPENDS_ON')?.to).toEqual({ kind: 'special', value: 'NONE' });
    expect(rels.find((r) => r.type === 'CONTAINS')?.to).toEqual({ kind: 'special', value: 'NOASSERTION' });
  });

  it('accepts a single-value to, as the spec lint already does', () => {
    const result = parse3([pkg('app'), pkg('lib'), rel('app', 'contains', `${B}/pkg/lib`)]);
    expect(result.document!.relationships).toContainEqual(
      expect.objectContaining({ type: 'CONTAINS', to: { kind: 'local', spdxId: `${B}/pkg/lib` } }),
    );
    expect(codes(result)).not.toContain('REL_MALFORMED');
  });

  it('reads general externalRef links next to the identifiers, without counting them as identifiers', () => {
    const result = parse3([
      pkg('app', {
        externalRef: [
          { type: 'ExternalRef', externalRefType: 'vcs', locator: ['https://git.acme.example/app.git'] },
          {
            type: 'ExternalRef',
            externalRefType: 'https://spdx.org/rdf/3.0.1/terms/Core/ExternalRefType/securityAdvisory',
            locator: ['https://acme.example/adv/1', 'https://acme.example/adv/2'],
          },
        ],
      }),
    ]);
    const app = result.document!.elements.find((e) => e.name === 'app')!;
    expect(app.externalRefs).toEqual([
      { category: 'OTHER', type: 'vcs', locator: 'https://git.acme.example/app.git' },
      { category: 'OTHER', type: 'securityAdvisory', locator: 'https://acme.example/adv/1' },
      { category: 'OTHER', type: 'securityAdvisory', locator: 'https://acme.example/adv/2' },
    ]);
    expect(hasUniqueIdentifier(app)).toBe(false);
  });

  it('does not count helper nodes as skipped elements', () => {
    const result = parse3([
      pkg('app'),
      { type: 'ExternalMap', '@id': '_:m', externalSpdxId: 'https://other.example/doc#x' },
      { type: 'NamespaceMap', '@id': '_:n', prefix: 'acme', namespace: `${B}/` },
      { type: 'DictionaryEntry', '@id': '_:d', key: 'k', value: 'v' },
      { type: 'PositiveIntegerRange', '@id': '_:r', beginIntegerRange: 1, endIntegerRange: 2 },
      { type: 'PackageVerificationCode', '@id': '_:p', algorithm: 'sha1', hashValue: 'a'.repeat(40) },
      { type: 'ExternalRef', '@id': '_:e', externalRefType: 'vcs', locator: ['https://git.acme.example/x.git'] },
    ]);
    expect(codes(result)).not.toContain('SPDX3_ELEMENTS_SKIPPED');
  });

  it('names a plain Agent creator as an organization; SoftwareAgent and Tool stay tools', () => {
    const result = parse3(
      [
        { type: 'Agent', spdxId: `${B}/agent/oe`, creationInfo: ci, name: 'OpenEmbedded' },
        { type: 'SoftwareAgent', spdxId: `${B}/agent/bot`, creationInfo: ci, name: 'release-bot' },
        { type: 'Tool', spdxId: `${B}/tool/gen`, creationInfo: ci, name: 'generator 1.0' },
        pkg('app'),
      ],
      { creation: { ...creation, createdBy: [`${B}/agent/oe`, `${B}/agent/bot`], createdUsing: [`${B}/tool/gen`] } },
    );
    expect(result.document!.creators).toEqual(['Organization: OpenEmbedded', 'Tool: release-bot', 'Tool: generator 1.0']);
  });

  it('ignores node types that exist only on the prototype chain', () => {
    const result = parse3([
      pkg('app'),
      { type: 'constructor', spdxId: `${B}/x/1`, creationInfo: ci, name: 'not-a-package' },
      { type: '__proto__', spdxId: `${B}/x/2`, creationInfo: ci, name: 'not-a-package-either' },
      { type: 'toString', spdxId: `${B}/x/3`, creationInfo: ci, name: 'nor-this' },
    ]);
    const names = result.document!.elements.map((e) => e.name);
    expect(names).toEqual(['app']);
    for (const element of result.document!.elements) expect(['string', 'undefined']).toContain(typeof element.purpose);
    expect(result.diagnostics.find((d) => d.code === 'SPDX3_ELEMENTS_SKIPPED')?.message).toContain('constructor (1)');
  });

  it('names a CustomLicense with a long hyphen run in linear time', () => {
    const iri = `${B}/licenses/a${'-'.repeat(60_000)}b`;
    const started = performance.now();
    const result = parse3([
      pkg('app'),
      { type: 'expandedlicensing_CustomLicense', spdxId: iri, creationInfo: ci, name: 'odd' },
      rel('app', 'hasDeclaredLicense', [iri]),
    ]);
    const elapsed = performance.now() - started;
    expect(result.document!.elements[0]!.licenseDeclared).toBe(`LicenseRef-a${'-'.repeat(60_000)}b`);
    expect(elapsed).toBeLessThan(250);
  });

  it('reads a licence set that contains itself as unreadable, without recursing forever', () => {
    const result = parse3([
      pkg('app'),
      { type: 'expandedlicensing_ConjunctiveLicenseSet', spdxId: `${B}/lic/loop`, creationInfo: ci, expandedlicensing_member: ['https://spdx.org/licenses/MIT', `${B}/lic/loop`] },
      rel('app', 'hasDeclaredLicense', [`${B}/lic/loop`]),
    ]);
    expect(result.document!.elements[0]!.licenseDeclared).toBeUndefined();
    expect(codes(result)).toContain('SPDX3_LICENSE_NOT_MAPPED');
  });

  it('folds a wide, shared licence structure in bounded time and size', () => {
    // Seven levels of sets, each naming the next level six times: without
    // memoisation and a length cap this fans out to 6^7 calls and megabytes.
    const levels = 7;
    const nodes: Record<string, unknown>[] = [pkg('app')];
    for (let level = 0; level < levels; level++) {
      const next = level + 1 < levels ? `${B}/lic/l${level + 1}` : 'https://spdx.org/licenses/MIT';
      nodes.push({ type: 'expandedlicensing_DisjunctiveLicenseSet', spdxId: `${B}/lic/l${level}`, creationInfo: ci, expandedlicensing_member: Array(6).fill(next) });
    }
    nodes.push(rel('app', 'hasDeclaredLicense', [`${B}/lic/l0`]));
    const started = performance.now();
    const result = parse3(nodes);
    expect(performance.now() - started).toBeLessThan(250);
    const declared = result.document!.elements[0]!.licenseDeclared;
    expect(declared === undefined || declared.length <= 8192).toBe(true);
  });

  it('reads a set member that points at nothing as unreadable, not as licence text', () => {
    const result = parse3([
      pkg('app'),
      { type: 'expandedlicensing_ConjunctiveLicenseSet', spdxId: `${B}/lic/dangling`, creationInfo: ci, expandedlicensing_member: ['https://spdx.org/licenses/MIT', `${B}/lic/nowhere`] },
      rel('app', 'hasDeclaredLicense', [`${B}/lic/dangling`]),
    ]);
    expect(result.document!.elements[0]!.licenseDeclared).toBeUndefined();
  });

  it('reads the short terms the official context defines for the individuals, and does not call them dangling', () => {
    // The 3.0.1 context maps NoneElement, NoAssertionElement and the two
    // licence individuals to short terms, and `to` is @vocab-typed there:
    // a compacting serializer writes these, not the IRIs.
    const result = parse3([
      pkg('app'),
      pkg('lib'),
      rel('app', 'dependsOn', ['NoneElement']),
      rel('app', 'contains', ['NoAssertionElement']),
      rel('app', 'hasDeclaredLicense', ['expandedlicensing_NoAssertionLicense']),
      rel('lib', 'hasConcludedLicense', ['expandedlicensing_NoneLicense']),
    ]);
    const rels = result.document!.relationships;
    expect(rels.find((r) => r.type === 'DEPENDS_ON')?.to).toEqual({ kind: 'special', value: 'NONE' });
    expect(rels.find((r) => r.type === 'CONTAINS')?.to).toEqual({ kind: 'special', value: 'NOASSERTION' });
    const byName = Object.fromEntries(result.document!.elements.map((e) => [e.name, e]));
    expect(byName.app!.licenseDeclared).toBe('NOASSERTION');
    expect(byName.lib!.licenseConcluded).toBe('NONE');
    expect(codes(result)).not.toContain('SPDX3_SCHEMA_DANGLING_REF');
    expect(codes(result)).not.toContain('SPDX3_LICENSE_NOT_MAPPED');
  });

  it("keeps a document's own element whose IRI merely ends in NoneElement", () => {
    const odd = `${B}/pkg/NoneElement`;
    const result = parse3([
      pkg('app'),
      { type: 'software_Package', spdxId: odd, creationInfo: ci, name: 'odd' },
      rel('app', 'dependsOn', [odd]),
    ]);
    expect(result.document!.relationships.find((r) => r.type === 'DEPENDS_ON')?.to).toEqual({ kind: 'local', spdxId: odd });
  });

  it('leaves the field empty when an operator is applied to an absence or to nothing', () => {
    const result = parse3([
      pkg('a'),
      pkg('b'),
      pkg('c'),
      { type: 'expandedlicensing_OrLaterOperator', spdxId: `${B}/lic/later-none`, creationInfo: ci, expandedlicensing_subjectLicense: 'expandedlicensing_NoAssertionLicense' },
      { type: 'expandedlicensing_OrLaterOperator', spdxId: `${B}/lic/later-dangling`, creationInfo: ci, expandedlicensing_subjectLicense: 'urn:acme:nowhere' },
      {
        type: 'expandedlicensing_WithAdditionOperator',
        spdxId: `${B}/lic/with-none`,
        creationInfo: ci,
        expandedlicensing_subjectExtendableLicense: 'https://spdx.org/rdf/3.0.1/terms/ExpandedLicensing/NoneLicense',
        expandedlicensing_subjectAddition: 'https://spdx.org/licenses/Classpath-exception-2.0',
      },
      rel('a', 'hasDeclaredLicense', [`${B}/lic/later-none`]),
      rel('b', 'hasDeclaredLicense', [`${B}/lic/later-dangling`]),
      rel('c', 'hasDeclaredLicense', [`${B}/lic/with-none`]),
    ]);
    for (const element of result.document!.elements) expect(element.licenseDeclared).toBeUndefined();
    expect(result.diagnostics.find((d) => d.code === 'SPDX3_LICENSE_NOT_MAPPED')?.message).toContain('3 licence statement');
  });

  it('reads the version from an object-valued @context', () => {
    const { creationInfo: _drop, ...docWithoutCi } = docNode;
    void _drop;
    const text = JSON.stringify({
      '@context': [{ '@import': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld' }],
      '@graph': [{ type: 'CreationInfo', '@id': ci, created: '2026-06-01T10:00:00Z' }, { ...docWithoutCi, creationInfo: ci }, pkg('app')],
    });
    const result = parseDocument({ fileName: 'ctx.spdx3.json', text, sha1: 'f'.repeat(40), byteSize: text.length });
    expect(result.document?.spec.version).toBe('SPDX-3.0.1');
  });
});
