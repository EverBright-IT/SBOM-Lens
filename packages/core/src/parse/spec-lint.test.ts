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
});
