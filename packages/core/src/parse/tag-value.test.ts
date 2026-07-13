import { describe, expect, it } from 'vitest';
import { fixtureInput } from '../test-fixtures';
import { parseDocument } from './parser';

function parse(name: string) {
  const { document, diagnostics } = parseDocument(fixtureInput(name));
  expect(document).not.toBeNull();
  return { doc: document!, diagnostics };
}

describe('tag-value parser: minimal', () => {
  it('parses documents, packages, and relationships', () => {
    const { doc } = parse('minimal.spdx');
    expect(doc.spec).toEqual({ model: 'spdx-2', version: 'SPDX-2.3', serialization: 'tag-value' });
    expect(doc.name).toBe('minimal-example');
    expect(doc.namespace).toBe('https://example.org/spdxdocs/minimal-example');
    expect(doc.id).toBe('https://example.org/spdxdocs/minimal-example');
    expect(doc.creators).toEqual(['Tool: sbomlens-fixtures']);
    expect(doc.describes).toEqual(['SPDXRef-Package-app']);

    expect(doc.elements).toHaveLength(2);
    const [app, libfoo] = doc.elements;
    expect(app).toMatchObject({
      kind: 'package',
      spdxId: 'SPDXRef-Package-app',
      name: 'app',
      version: '1.0.0',
      licenseConcluded: 'MIT',
      supplier: 'Organization: Example Corp',
    });
    expect(libfoo).toMatchObject({ name: 'libfoo', purl: 'pkg:generic/libfoo@2.3.4' });

    expect(doc.relationships).toEqual([
      {
        from: { kind: 'local', spdxId: 'SPDXRef-DOCUMENT' },
        type: 'DESCRIBES',
        to: { kind: 'local', spdxId: 'SPDXRef-Package-app' },
      },
      {
        from: { kind: 'local', spdxId: 'SPDXRef-Package-app' },
        type: 'CONTAINS',
        to: { kind: 'local', spdxId: 'SPDXRef-Package-libfoo' },
      },
    ]);
  });

  it('keeps ordered raw pairs per element', () => {
    const { doc } = parse('minimal.spdx');
    const app = doc.elements[0]!;
    expect(app.raw.kind).toBe('tv');
    if (app.raw.kind === 'tv') {
      expect(app.raw.pairs[0]).toEqual(['PackageName', 'app']);
      expect(app.raw.pairs).toContainEqual(['PackageLicenseDeclared', 'MIT']);
    }
  });
});

describe('tag-value parser: real-world quirks', () => {
  const { doc, diagnostics } = parse('quirks.spdx');
  const codes = diagnostics.map((d) => d.code);

  it('tolerates both SHA1 spacings and missing checksums in ExternalDocumentRef', () => {
    expect(doc.externalDocumentRefs).toHaveLength(4);
    const [nospace, spaced, nochecksum] = doc.externalDocumentRefs;
    expect(nospace).toEqual({
      docRef: 'DocumentRef-NOSPACE',
      uri: 'https://example.org/child-a.spdx',
      checksum: { algorithm: 'SHA1', value: 'a'.repeat(40) },
    });
    expect(spaced!.checksum).toEqual({ algorithm: 'SHA1', value: 'b'.repeat(40) });
    expect(nochecksum!.checksum).toBeUndefined();
    expect(codes).toContain('EXTREF_NO_CHECKSUM');
  });

  it('skips comment lines, including commented-out fields', () => {
    const main = doc.elements.find((e) => e.spdxId === 'SPDXRef-Package-main')!;
    if (main.raw.kind === 'tv') {
      const tags = main.raw.pairs.map(([tag]) => tag);
      expect(tags).not.toContain('PackageVerificationCode');
    }
  });

  it('reads multi-line <text> values', () => {
    expect(doc.comment).toBe('Multi-line\ndocument comment.');
    const main = doc.elements.find((e) => e.spdxId === 'SPDXRef-Package-main')!;
    expect(main.description).toBe('Line one\nline two');
  });

  it('extracts purpose and purl', () => {
    const main = doc.elements.find((e) => e.spdxId === 'SPDXRef-Package-main')!;
    expect(main.purpose).toBe('APPLICATION');
    expect(main.purl).toBe('pkg:npm/%40scope/main-product@9.9.9');
  });

  it('dedupes duplicate SPDXIDs with a diagnostic', () => {
    expect(doc.elements.filter((e) => e.spdxId === 'SPDXRef-Package-dup')).toHaveLength(1);
    expect(codes).toContain('DUP_SPDXID');
  });

  it('assigns anonymous SPDXIDs to id-less blocks', () => {
    const anon = doc.elements.find((e) => e.name === 'no-id-package');
    expect(anon?.spdxId).toMatch(/^SPDXRef-sbomlens-anonymous-/);
    expect(codes).toContain('TV_MISSING_SPDXID');
  });

  it('parses file blocks with nested-colon checksums, normalized', () => {
    const file = doc.elements.find((e) => e.kind === 'file')!;
    expect(file.name).toBe('./src/index.js');
    expect(file.licenseConcluded).toBe('MIT');
    expect(file.checksums).toEqual([
      { algorithm: 'SHA1', value: 'd6a770ba38583ed4bb4525bd96e50461655d2758' },
      { algorithm: 'MD5', value: '624c1abb3664f4b35547e7c73864ad24' },
    ]);
  });

  it('skips snippet and extracted-license blocks without dying', () => {
    expect(codes).toContain('TV_BLOCKS_SKIPPED');
    expect(doc.elements.map((e) => e.name)).not.toContain('SPDXRef-Snippet-1');
  });

  it('flags malformed lines and continues', () => {
    const malformed = diagnostics.find((d) => d.code === 'TV_MALFORMED_LINE');
    expect(malformed?.message).toContain('this line is garbage');
  });

  it('parses cross-document, bare-DocumentRef, and NOASSERTION relationship ends', () => {
    expect(doc.relationships).toContainEqual({
      from: { kind: 'local', spdxId: 'SPDXRef-Package-main' },
      type: 'CONTAINS',
      to: { kind: 'external', docRef: 'DocumentRef-NOSPACE', spdxId: 'SPDXRef-Package-child' },
    });
    expect(doc.relationships).toContainEqual({
      from: { kind: 'local', spdxId: 'SPDXRef-Package-main' },
      type: 'DESCRIBED_BY',
      to: { kind: 'external', docRef: 'DocumentRef-SPACED', spdxId: 'SPDXRef-DOCUMENT' },
      comment: 'Cross-document link.',
    });
    expect(doc.relationships).toContainEqual({
      from: { kind: 'external', docRef: 'DocumentRef-NOCHECKSUM', spdxId: null },
      type: 'HAS_QUALITY_ASSERTION',
      to: { kind: 'local', spdxId: 'SPDXRef-Package-main' },
    });
    expect(doc.relationships).toContainEqual({
      from: { kind: 'local', spdxId: 'SPDXRef-Package-main' },
      type: 'DEPENDS_ON',
      to: { kind: 'special', value: 'NOASSERTION' },
    });
  });

  it('warns about relationship DocumentRefs without an ExternalDocumentRef entry', () => {
    const warning = diagnostics.find((d) => d.code === 'REL_UNKNOWN_DOCREF');
    expect(warning?.message).toContain('DocumentRef-MISSING');
  });

  it('computes describes from DESCRIBES relationships', () => {
    expect(doc.describes).toEqual(['SPDXRef-Package-main']);
  });
});

describe('tag-value parser: degenerate inputs', () => {
  it('handles a document with no namespace via content-hash id', () => {
    const text = 'SPDXVersion: SPDX-2.3\nSPDXID: SPDXRef-DOCUMENT\nDocumentName: bare\n';
    const { document } = parseDocument({ fileName: 'bare.spdx', text, sha1: 'ab'.repeat(20), byteSize: text.length });
    expect(document?.id).toBe(`urn:sbomlens:sha1:${'ab'.repeat(20)}`);
    expect(document?.diagnostics.some((d) => d.code === 'DOC_NO_NAMESPACE')).toBe(true);
  });

  it('reports unterminated <text>', () => {
    const text = 'SPDXVersion: SPDX-2.3\nDocumentComment: <text>never closed\nDocumentName: x\n';
    const { document, diagnostics } = parseDocument({ fileName: 'x.spdx', text, sha1: '0'.repeat(40), byteSize: text.length });
    expect(document).not.toBeNull();
    expect(diagnostics.some((d) => d.code === 'TV_UNTERMINATED_TEXT')).toBe(true);
  });
});
