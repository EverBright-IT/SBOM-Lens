import { describe, expect, it } from 'vitest';
import { XmlError, parseXml } from './tokenizer';

/**
 * The reader covers exactly the XML that CycloneDX documents use, and
 * refuses the parts that are attack surface. Both halves are pinned.
 */
describe('parseXml', () => {
  it('reads elements, attributes, nested children and text', () => {
    const root = parseXml('<?xml version="1.0"?>\n<a x="1" y=\'two\'><b>hello</b><c/><b>world</b></a>');
    expect(root.name).toBe('a');
    expect(root.attrs).toEqual({ x: '1', y: 'two' });
    expect(root.children.map((c) => c.name)).toEqual(['b', 'c', 'b']);
    expect(root.children[0]!.text).toBe('hello');
    expect(root.children[1]!.children).toEqual([]);
    expect(root.text).toBe('');
  });

  it('splits namespace prefixes off element names and keeps xmlns attributes', () => {
    const root = parseXml('<bom xmlns="http://cyclonedx.org/schema/bom/1.6" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature/></bom>');
    expect(root.name).toBe('bom');
    expect(root.prefix).toBeUndefined();
    expect(root.attrs.xmlns).toBe('http://cyclonedx.org/schema/bom/1.6');
    expect(root.children[0]).toMatchObject({ name: 'Signature', prefix: 'ds' });
  });

  it('decodes the predefined entities and numeric character references', () => {
    const root = parseXml('<a t="&quot;q&quot;">&lt;x&gt; &amp; &#65;&#x42; &unknown;</a>');
    expect(root.attrs.t).toBe('"q"');
    expect(root.text).toBe('<x> & AB &unknown;');
  });

  it('keeps CDATA verbatim and skips comments and processing instructions', () => {
    const root = parseXml('<a><!-- note --><?pi x?><![CDATA[<raw> & stuff]]></a>');
    expect(root.text).toBe('<raw> & stuff');
  });

  it('strips a byte order mark and surrounding whitespace', () => {
    const root = parseXml('﻿  \n<a>  padded  </a>\n');
    expect(root.name).toBe('a');
    expect(root.text).toBe('padded');
  });

  describe('refuses what a BOM never needs', () => {
    it('document type declarations, before reading anything else', () => {
      const text = '<!DOCTYPE bom [<!ENTITY lol "lol">]><bom>&lol;</bom>';
      expect(() => parseXml(text)).toThrowError(XmlError);
      try {
        parseXml(text);
      } catch (e) {
        expect((e as XmlError).code).toBe('XML_DOCTYPE_REJECTED');
      }
    });

    it('nesting beyond the cap', () => {
      const deep = '<a>'.repeat(170) + '</a>'.repeat(170);
      try {
        parseXml(deep);
        expect.unreachable();
      } catch (e) {
        expect((e as XmlError).code).toBe('XML_TOO_DEEP');
      }
      expect(() => parseXml(deep, { maxDepth: 200 })).not.toThrow();
    });
  });

  describe('reports malformed input instead of guessing', () => {
    it.each([
      ['mismatched closing tag', '<a><b></a>'],
      ['unclosed element', '<a><b>'],
      ['two roots', '<a/><b/>'],
      ['text outside the root', 'hello<a/>'],
      ['unquoted attribute', '<a x=1/>'],
      ['unterminated comment', '<a><!-- never closed</a>'],
    ])('%s', (_label, text) => {
      try {
        parseXml(text);
        expect.unreachable();
      } catch (e) {
        expect(e).toBeInstanceOf(XmlError);
        expect((e as XmlError).code).toBe('XML_INVALID');
      }
    });
  });
});
