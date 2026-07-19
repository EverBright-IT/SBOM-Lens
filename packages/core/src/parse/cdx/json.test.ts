import { describe, expect, it } from 'vitest';
import { parseDocument } from '../parser';
import { loadedFromText } from '../../test-fixtures';
import { addDocuments, emptyWorkspace } from '../../workspace/workspace';

/**
 * CycloneDX 1.x JSON → document model: component mapping (purl, CPE, files,
 * hashes, licenses), dependencies, and the BOM-Link cascade — a parent BOM
 * linking a child by urn:cdx resolves through the same namespace matcher
 * SPDX cascades use.
 */

const CHILD_SERIAL = 'urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';

function bom(extra: Record<string, unknown>): string {
  return JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, ...extra });
}

function input(fileName: string, text: string) {
  return { fileName, text, sha1: 'f'.repeat(39) + fileName.length.toString(16), byteSize: text.length };
}

describe('parseCdxJson', () => {
  it('maps components with purl, CPE, supplier, hashes, and licenses', () => {
    const text = bom({
      serialNumber: CHILD_SERIAL,
      metadata: {
        timestamp: '2026-05-01T00:00:00Z',
        authors: [{ name: 'ACME Security' }],
        tools: { components: [{ name: 'acme-gen', version: '2.0' }] },
        component: { type: 'application', 'bom-ref': 'root', name: 'acme-web', version: '1.0.0' },
      },
      components: [
        {
          type: 'library',
          'bom-ref': 'lib-a',
          name: 'left-pad',
          version: '1.3.0',
          purl: 'pkg:npm/left-pad@1.3.0',
          cpe: 'cpe:2.3:a:acme:left-pad:1.3.0:*:*:*:*:*:*:*',
          supplier: { name: 'ACME Corp' },
          hashes: [{ alg: 'SHA-256', content: 'AB'.repeat(32) }],
          licenses: [
            { license: { id: 'MIT' } },
            { expression: 'Apache-2.0', acknowledgment: 'concluded' },
          ],
          description: 'padding',
        },
        { type: 'file', 'bom-ref': 'f-1', name: './src/app.js', hashes: [{ alg: 'SHA-1', content: 'c'.repeat(40) }] },
      ],
      dependencies: [{ ref: 'root', dependsOn: ['lib-a'] }],
    });
    const { document } = parseDocument(input('acme.cdx.json', text));
    expect(document).not.toBeNull();
    const doc = document!;

    expect(doc.spec).toMatchObject({ model: 'cyclonedx', version: 'CycloneDX-1.6', serialization: 'json' });
    expect(doc.namespace).toBe('urn:cdx:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/1');
    expect(doc.name).toBe('acme-web');
    expect(doc.created).toBe('2026-05-01T00:00:00Z');
    expect(doc.creators).toEqual(['Tool: acme-gen-2.0', 'Person: ACME Security']);
    expect(doc.describes).toEqual(['root']);

    const lib = doc.elements.find((e) => e.name === 'left-pad')!;
    expect(lib).toMatchObject({
      kind: 'package',
      version: '1.3.0',
      purl: 'pkg:npm/left-pad@1.3.0',
      supplier: 'ACME Corp',
      purpose: 'LIBRARY',
      licenseDeclared: 'MIT',
      licenseConcluded: 'Apache-2.0',
    });
    expect(lib.checksums).toEqual([{ algorithm: 'SHA256', value: 'ab'.repeat(32) }]);
    // The CPE lands as a SECURITY external reference — the VEX overlay's
    // CPE matching reads exactly this shape.
    expect(lib.externalRefs).toContainEqual({
      category: 'SECURITY',
      type: 'cpe23Type',
      locator: 'cpe:2.3:a:acme:left-pad:1.3.0:*:*:*:*:*:*:*',
    });

    const file = doc.elements.find((e) => e.name === './src/app.js')!;
    expect(file.kind).toBe('file');
    expect(file.purpose).toBeUndefined();

    expect(doc.relationships).toContainEqual({
      from: { kind: 'local', spdxId: 'root' },
      type: 'DEPENDS_ON',
      to: { kind: 'local', spdxId: 'lib-a' },
    });
  });

  it('reports unmapped dependency refs instead of guessing', () => {
    const text = bom({ components: [], dependencies: [{ ref: 'ghost', dependsOn: ['also-ghost'] }] });
    const { document, diagnostics } = parseDocument(input('deps.cdx.json', text));
    expect(document).not.toBeNull();
    expect(diagnostics.some((d) => d.code === 'CDX_DEPENDENCIES_UNMAPPED')).toBe(true);
  });

  it('turns BOM-Links into external document refs with element fragments', () => {
    const text = bom({
      metadata: { component: { type: 'application', 'bom-ref': 'root', name: 'parent' } },
      components: [
        {
          type: 'library',
          'bom-ref': 'uses-child',
          name: 'child-user',
          externalReferences: [
            { type: 'bom', url: `urn:cdx:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/1#comp-x` },
            { type: 'website', url: 'https://acme.example' },
          ],
        },
      ],
      dependencies: [{ ref: 'root', dependsOn: ['urn:cdx:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/1'] }],
    });
    const { document } = parseDocument(input('parent.cdx.json', text));
    const doc = document!;

    expect(doc.externalDocumentRefs).toHaveLength(1);
    expect(doc.externalDocumentRefs[0]).toMatchObject({
      uri: 'urn:cdx:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/1',
    });
    const docRef = doc.externalDocumentRefs[0]!.docRef;
    // The component carrying the link depends on the element over there...
    expect(doc.relationships).toContainEqual({
      from: { kind: 'local', spdxId: 'uses-child' },
      type: 'DEPENDS_ON',
      to: { kind: 'external', docRef, spdxId: 'comp-x' },
    });
    // ...and a dependsOn BOM-Link points at the document as a whole.
    expect(doc.relationships).toContainEqual({
      from: { kind: 'local', spdxId: 'root' },
      type: 'DEPENDS_ON',
      to: { kind: 'external', docRef, spdxId: null },
    });
  });

  it('resolves a BOM-Link cascade through the existing namespace matcher', () => {
    const parent = bom({
      serialNumber: 'urn:uuid:11111111-2222-3333-4444-555555555555',
      metadata: { component: { type: 'application', 'bom-ref': 'root', name: 'parent-app' } },
      components: [
        {
          type: 'library',
          'bom-ref': 'sub',
          name: 'subsystem',
          externalReferences: [{ type: 'bom', url: `${CHILD_SERIAL.replace('urn:uuid:', 'urn:cdx:')}/1` }],
        },
      ],
    });
    const child = bom({
      serialNumber: CHILD_SERIAL,
      metadata: { component: { type: 'application', 'bom-ref': 'root', name: 'child-app' } },
    });

    const loadedParent = loadedFromText('parent.cdx.json', parent);
    const loadedChild = loadedFromText('child.cdx.json', child);
    const { workspace } = addDocuments(emptyWorkspace, [loadedParent, loadedChild]);

    const resolutions = [...workspace.resolutions.values()];
    expect(resolutions).toHaveLength(1);
    expect(resolutions[0]).toMatchObject({
      status: 'resolved',
      targetDocId: loadedChild.document.id,
    });
  });

  it('fragment ids match the child document verbatim (nesting invariant)', () => {
    // The parent addresses a NON-root element of the child; the fragment
    // must equal the child element's spdxId so the tree nests the addressed
    // element instead of silently falling back to the child's root.
    const parent = bom({
      components: [
        {
          type: 'library',
          'bom-ref': 'edge',
          name: 'edge',
          externalReferences: [{ type: 'bom', url: 'urn:cdx:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/1#jwt-lib' }],
        },
      ],
    });
    const child = bom({
      serialNumber: CHILD_SERIAL,
      metadata: { component: { type: 'application', 'bom-ref': 'auth-root', name: 'auth' } },
      components: [{ type: 'library', 'bom-ref': 'jwt-lib', name: 'jwt-lib', version: '9.2.1' }],
    });
    const loadedParent = loadedFromText('parent.cdx.json', parent);
    const loadedChild = loadedFromText('child.cdx.json', child);

    const externalRel = loadedParent.document.relationships.find((r) => r.to.kind === 'external')!;
    const fragment = externalRel.to.kind === 'external' ? externalRel.to.spdxId : null;
    expect(fragment).toBe('jwt-lib');
    expect(loadedChild.indexes.elementBySpdxId.has(fragment!)).toBe(true);
  });

  it('matches BOM-Link URNs case-insensitively', () => {
    const parent = bom({
      metadata: { component: { type: 'application', 'bom-ref': 'r', name: 'p' } },
      components: [
        {
          type: 'library',
          'bom-ref': 's',
          name: 's',
          externalReferences: [{ type: 'bom', url: 'URN:CDX:AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE/1' }],
        },
      ],
    });
    const child = bom({
      serialNumber: 'urn:uuid:AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE',
      metadata: { component: { type: 'application', 'bom-ref': 'r', name: 'c' } },
    });
    const { workspace } = addDocuments(emptyWorkspace, [
      loadedFromText('p.cdx.json', parent),
      loadedFromText('c.cdx.json', child),
    ]);
    expect([...workspace.resolutions.values()][0]).toMatchObject({ status: 'resolved' });
  });

  it('tolerates a digit-string BOM version and unknown cpe forms', () => {
    const text = bom({
      serialNumber: CHILD_SERIAL,
      version: '2',
      components: [{ type: 'library', 'bom-ref': 'x', name: 'x', cpe: 'cpe:weird' }],
    });
    const { document } = parseDocument(input('v.cdx.json', text));
    expect(document!.namespace).toBe('urn:cdx:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/2');
    expect(document!.elements[0]!.externalRefs).toContainEqual({
      category: 'SECURITY',
      type: 'cpe',
      locator: 'cpe:weird',
    });
  });
});
