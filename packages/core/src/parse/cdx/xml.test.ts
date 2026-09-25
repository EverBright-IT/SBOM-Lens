import { describe, expect, it } from 'vitest';
import type { SbomDocument } from '../../model/document';
import { loadFixture, loadedFromText } from '../../test-fixtures';
import { detect } from '../detect';
import { parseDocument } from '../parser';

/**
 * CycloneDX XML rides on the JSON mapper, so the contract is parity: the XML
 * and JSON serializations of one BOM must produce the same document, down to
 * the cascade links and the spec findings. Only the serialization tag and
 * the raw source nodes may differ.
 */

function comparable(doc: SbomDocument): unknown {
  return {
    ...doc,
    spec: { ...doc.spec, serialization: 'normalized' },
    elements: doc.elements.map((element) => Object.fromEntries(Object.entries(element).filter(([key]) => key !== 'raw'))),
  };
}

describe('CycloneDX XML', () => {
  it('maps to the same document as the JSON serialization of the same BOM', () => {
    const json = loadedFromText('parity.cdx.json', loadFixture('cdx/parity.cdx.json')).document;
    const xml = loadedFromText('parity.cdx.xml', loadFixture('cdx/parity.cdx.xml')).document;

    expect(xml.spec.serialization).toBe('xml');
    expect(json.spec.serialization).toBe('json');
    expect(comparable(xml)).toEqual(comparable(json));

    // The interesting bits, spelled out so a parity regression names them.
    const lib = xml.elements.find((e) => e.name === 'left-pad')!;
    expect(lib).toMatchObject({
      purl: 'pkg:npm/left-pad@1.3.0',
      supplier: 'Left Pad Authors',
      licenseDeclared: 'MIT',
      licenseConcluded: 'Apache-2.0',
      copyright: '(c) 2026 Left Pad Authors',
    });
    expect(lib.checksums).toEqual([{ algorithm: 'SHA256', value: 'ab'.repeat(32) }]);
    expect(xml.creators).toEqual(['Tool: acme-gen-2.0', 'Person: ACME Security']);
    expect(xml.externalDocumentRefs.map((r) => r.uri)).toEqual(['urn:cdx:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/1']);
    expect(xml.relationships).toContainEqual({
      from: { kind: 'local', spdxId: 'root' },
      type: 'DEPENDS_ON',
      to: { kind: 'local', spdxId: 'lib-a' },
    });
    expect(xml.relationships).toContainEqual({
      from: { kind: 'local', spdxId: 'lib-a' },
      type: 'CONTAINS',
      to: { kind: 'local', spdxId: 'lib-a-inner' },
    });
  });

  it('is detected by content, with the spec version taken from the namespace', () => {
    const detection = detect(loadFixture('cdx/minimal.cdx.xml'));
    expect(detection).toMatchObject({ format: 'cdx-json', serialization: 'xml' });
    if (detection.format !== 'cdx-json') throw new Error('unreachable');
    expect(detection.parsed).toMatchObject({ bomFormat: 'CycloneDX', specVersion: '1.6', version: 1 });
  });

  it('inherits the spec lint: the broken XML twin fires the same findings as the JSON one', () => {
    const codes = (name: string) =>
      parseDocument({ fileName: name, text: loadFixture(name), sha1: 'a'.repeat(40), byteSize: 1 })
        .diagnostics.map((d) => d.code)
        .filter((c) => c.includes('_SCHEMA_'))
        .sort();
    expect(codes('spec-lint/broken.cdx.xml')).toEqual(codes('spec-lint/broken.cdx.json'));
    expect(codes('spec-lint/broken.cdx.xml')).toContain('CDX_SCHEMA_UNKNOWN_SPEC_VERSION');
  });

  it('keeps foreign-namespace elements out of the BOM shape', () => {
    // An enveloped xmldsig signature must not turn into a component field.
    const text =
      '<bom xmlns="http://cyclonedx.org/schema/bom/1.6" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" version="1">' +
      '<components><component type="library"><name>x</name><ds:Signature><ds:SignedInfo/></ds:Signature></component></components>' +
      '<ds:Signature/></bom>';
    const detection = detect(text);
    if (detection.format !== 'cdx-json') throw new Error('expected CycloneDX');
    expect(detection.parsed).not.toHaveProperty('Signature');
    const component = (detection.parsed.components as Record<string, unknown>[])[0]!;
    expect(component).toEqual({ type: 'library', name: 'x' });
  });

  describe('says what it will not read', () => {
    it('SPDX RDF/XML, by name', () => {
      const detection = detect('<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"></rdf:RDF>');
      expect(detection).toMatchObject({ format: 'unsupported', code: 'RDF_NOT_SUPPORTED' });
    });

    it('XML that is not a CycloneDX BOM', () => {
      expect(detect('<project><name>not a bom</name></project>')).toMatchObject({
        format: 'unsupported',
        code: 'XML_NOT_CYCLONEDX',
      });
      expect(detect('<bom version="1"><components/></bom>')).toMatchObject({ code: 'XML_NOT_CYCLONEDX' });
    });

    it('documents with a DTD, before parsing them', () => {
      const detection = detect('<!DOCTYPE bom><bom xmlns="http://cyclonedx.org/schema/bom/1.6"/>');
      expect(detection).toMatchObject({ format: 'unsupported', code: 'XML_DOCTYPE_REJECTED' });
    });

    it('malformed XML, as XML_INVALID rather than a spec finding', () => {
      const detection = detect('<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components></bom>');
      expect(detection).toMatchObject({ format: 'unsupported', code: 'XML_INVALID' });
    });
  });
});
