import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { loadFixture } from '../test-fixtures';
import { detect } from './detect';
import { parseDocument } from './parser';
import { isSpecFinding } from './spec-lint';
import { sha1Hex } from '../util/sha1';

/**
 * End-to-end proof that the spec lints actually reach a reader: the three
 * broken fixtures go through content detection and parsing exactly like a
 * dropped file, and every rule this repo ships has to show up in one of them.
 *
 * The detour matters. Two earlier rules could never fire in the app, because
 * detection rejects the document before parsing: SPDX 2 needs an `SPDX-2*`
 * version literal and SPDX 3 an spdx.org/rdf/3.x context. The fixtures below
 * therefore keep their detection anchors intact and break everything else.
 *
 * Both SPDX 2 serializations are covered. Silence has to mean "this document is
 * fine", never "nobody looked" — and the shipped demo cascade is tag-value, so
 * an unchecked serialization would have made the feature invisible exactly
 * where most people meet it first.
 */

async function findings(fixture: string): Promise<string[]> {
  const text = loadFixture(fixture);
  const sha1 = await sha1Hex(new TextEncoder().encode(text).buffer as ArrayBuffer);
  const result = await parseDocument({ fileName: fixture, text, sha1, byteSize: text.length });
  return result.diagnostics.filter((d) => isSpecFinding(d.code)).map((d) => d.code);
}

describe('spec lint, end to end', () => {
  it('the broken SPDX 2.3 fixture is still detected as SPDX 2', () => {
    expect(detect(loadFixture('spec-lint/broken.spdx.json')).format).toBe('spdx2-json');
  });

  it('reports every SPDX 2.3 rule', async () => {
    expect(new Set(await findings('spec-lint/broken.spdx.json'))).toEqual(
      new Set([
        'SPDX2_SCHEMA_BAD_VERSION',
        'SPDX2_SCHEMA_BAD_DATA_LICENSE',
        'SPDX2_SCHEMA_BAD_NAMESPACE',
        'SPDX2_SCHEMA_BAD_CREATED',
        'SPDX2_SCHEMA_BAD_CREATOR',
        'SPDX2_SCHEMA_BAD_SPDXID',
        'SPDX2_SCHEMA_MISSING_DOWNLOAD_LOCATION',
        'SPDX2_SCHEMA_BAD_PACKAGE_PURPOSE',
        'SPDX2_SCHEMA_BAD_CHECKSUM',
        'SPDX2_SCHEMA_BAD_LICENSE_EXPRESSION',
        'SPDX2_SCHEMA_BAD_VERIFICATION_CODE',
        'SPDX2_SCHEMA_BAD_PURL_REF',
        'SPDX2_SCHEMA_UNKNOWN_RELATIONSHIP',
      ]),
    );
  });

  it('reports every SPDX 3 rule', async () => {
    expect(new Set(await findings('spec-lint/broken.spdx3.json'))).toEqual(
      new Set([
        'SPDX3_SCHEMA_MISSING_TYPE',
        'SPDX3_SCHEMA_BAD_SPDXID',
        'SPDX3_SCHEMA_MISSING_CREATION_INFO',
        'SPDX3_SCHEMA_BAD_HASH',
        'SPDX3_SCHEMA_INCOMPLETE_RELATIONSHIP',
        'SPDX3_SCHEMA_BAD_SPEC_VERSION',
        'SPDX3_SCHEMA_DANGLING_REF',
      ]),
    );
  });

  it('reports every CycloneDX rule', async () => {
    expect(new Set(await findings('spec-lint/broken.cdx.json'))).toEqual(
      new Set([
        'CDX_SCHEMA_UNKNOWN_SPEC_VERSION',
        'CDX_SCHEMA_BAD_SERIAL_NUMBER',
        'CDX_SCHEMA_BAD_VERSION',
        'CDX_SCHEMA_BAD_COMPONENT_TYPE',
        'CDX_SCHEMA_DUPLICATE_BOM_REF',
        'CDX_SCHEMA_BAD_HASH',
        'CDX_SCHEMA_BAD_PURL',
        'CDX_SCHEMA_BAD_LICENSE_EXPRESSION',
      ]),
    );
  });

  it('loads all three despite the findings', async () => {
    for (const fixture of ['spec-lint/broken.spdx.json', 'spec-lint/broken.spdx3.json', 'spec-lint/broken.cdx.json']) {
      const text = loadFixture(fixture);
      const sha1 = await sha1Hex(new TextEncoder().encode(text).buffer as ArrayBuffer);
      const result = await parseDocument({ fileName: fixture, text, sha1, byteSize: text.length });
      expect(result.document, `${fixture} must still load`).not.toBeNull();
      expect(result.diagnostics.filter((d) => isSpecFinding(d.code)).every((d) => d.severity === 'warning')).toBe(true);
    }
  });

  it('stays silent on the clean fixtures', async () => {
    for (const fixture of [
      'syft-style.spdx.json',
      'trivy-style.spdx.json',
      'minimal.spdx.json',
      'minimal.spdx.yaml',
      'spdx3/webstack.spdx3.json',
      'cdx/minimal.cdx.json',
      'ocm/cd-v2.yaml',
    ]) {
      expect(await findings(fixture), `${fixture} must produce no spec findings`).toEqual([]);
    }
  });


  it('the broken tag-value fixture is detected as tag-value', () => {
    expect(detect(loadFixture('spec-lint/broken.spdx')).format).toBe('spdx2-tag-value');
  });

  it('reports the serialization-independent rules on tag-value too', async () => {
    expect(new Set(await findings('spec-lint/broken.spdx'))).toEqual(
      new Set([
        'SPDX2_SCHEMA_BAD_VERSION',
        'SPDX2_SCHEMA_BAD_DATA_LICENSE',
        'SPDX2_SCHEMA_BAD_NAMESPACE',
        'SPDX2_SCHEMA_BAD_CREATED',
        'SPDX2_SCHEMA_BAD_CREATOR',
        'SPDX2_SCHEMA_BAD_SPDXID',
        'SPDX2_SCHEMA_MISSING_DOWNLOAD_LOCATION',
        'SPDX2_SCHEMA_BAD_PACKAGE_PURPOSE',
        'SPDX2_SCHEMA_BAD_LICENSE_EXPRESSION',
        'SPDX2_SCHEMA_UNKNOWN_RELATIONSHIP',
      ]),
    );
  });

  it('leaves tag-value checksums to the parser, which reports them with a line', async () => {
    // TV_BAD_CHECKSUM carries a line number; repeating it as a spec finding
    // would be a worse version of the same message.
    expect(await findings('spec-lint/broken.spdx')).not.toContain('SPDX2_SCHEMA_BAD_CHECKSUM');
  });

  it('the shipped example cascade is spec-clean in both serializations', async () => {
    // The demo is what most people see first; it has to model the spec, not
    // violate it. Regression guard for the generator's SPDXID sanitizer.
    for (const example of ['acme-platform-1.0.spdx', 'acme-runtime-image-3.0.spdx', 'acme-webstack-2.1.spdx.json']) {
      const text = readFileSync(new URL(`../../../../apps/web/public/examples/${example}`, import.meta.url), 'utf8');
      const sha1 = await sha1Hex(new TextEncoder().encode(text).buffer as ArrayBuffer);
      const result = await parseDocument({ fileName: example, text, sha1, byteSize: text.length });
      const spec = result.diagnostics.filter((d) => isSpecFinding(d.code)).map((d) => `${d.code}: ${d.message}`);
      expect(spec, `${example} must be spec-clean`).toEqual([]);
    }
  });

  /**
   * The `_SCHEMA_` convention is a contract, not a detail: the viewer splits
   * its diagnostics rows on it and the CLI is meant to make the same split.
   * A parser code that accidentally carried the infix would be mistaken for a
   * spec finding, so the partition is pinned here rather than in prose.
   */
  describe('isSpecFinding partitions the codes we ship', () => {
    it.each([
      'SPDX2_SCHEMA_BAD_VERSION',
      'SPDX3_SCHEMA_MISSING_TYPE',
      'CDX_SCHEMA_BAD_PURL',
      'OCM_SCHEMA_BAD_NAME',
    ])('%s is a spec finding', (code) => {
      expect(isSpecFinding(code)).toBe(true);
    });

    it.each([
      // spdx2 json + tag-value
      'DOC_NO_NAMESPACE',
      'EXTREF_MALFORMED',
      'EXTREF_BAD_CHECKSUM',
      'EXTREF_NO_CHECKSUM',
      'EXTREF_BAD_ID',
      'JSON_MISSING_SPDXID',
      'JSON_SNIPPETS_SKIPPED',
      'REL_MALFORMED',
      'REL_UNKNOWN_DOCREF',
      'DUP_SPDXID',
      'TV_MALFORMED_LINE',
      'TV_UNTERMINATED_TEXT',
      'TV_DUP_ELEMENT_SPDXID',
      'TV_BAD_CHECKSUM',
      'TV_ORPHAN_TAGS',
      'TV_BLOCKS_SKIPPED',
      'TV_MISSING_SPDXID',
      // spdx3
      'SPDX3_NO_GRAPH',
      'SPDX3_NO_DOCUMENT_ELEMENT',
      'SPDX3_ELEMENTS_SKIPPED',
      // cdx
      'CDX_COMPONENT_MALFORMED',
      'CDX_DEPENDENCIES_UNMAPPED',
      'CDX_NESTING_CAPPED',
      // ocm
      'OCM_V3ALPHA1',
      'OCM_DIGEST_MISMATCH',
    ])('%s is a parser note, not a spec finding', (code) => {
      expect(isSpecFinding(code)).toBe(false);
    });

    it('holds for every code the fixtures actually emit', async () => {
      const emitted = new Set<string>();
      for (const fixture of ['spec-lint/broken.spdx.json', 'spec-lint/broken.spdx3.json', 'spec-lint/broken.cdx.json', 'quirks.spdx']) {
        const text = loadFixture(fixture);
        const sha1 = await sha1Hex(new TextEncoder().encode(text).buffer as ArrayBuffer);
        const result = await parseDocument({ fileName: fixture, text, sha1, byteSize: text.length });
        for (const d of result.diagnostics) emitted.add(d.code);
      }
      for (const code of emitted) {
        // A code is a spec finding exactly when it carries the infix.
        expect(isSpecFinding(code)).toBe(code.includes('_SCHEMA_'));
      }
      expect(emitted.size).toBeGreaterThan(20);
    });
  });
});
