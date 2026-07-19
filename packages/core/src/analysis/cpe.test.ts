import { describe, expect, it } from 'vitest';
import { loadedFromText } from '../test-fixtures';
import type { WorkspaceState } from '../workspace/workspace';
import { addDocument, emptyWorkspace } from '../workspace/workspace';
import { cpeMatchKey } from './cpe';
import type { VexDocument } from './vex';
import { matchVex, vexCoverage } from './vex';

/**
 * CPE normalisation and the CPE side of VEX matching: 2.3 formatted strings
 * and 2.2 URIs collapse onto one key, wildcards stay conservative, and an
 * inventory element carrying a CPE (with or without a purl) is matched by a
 * statement that names the product only by CPE — the BSI-advisory case.
 */

describe('cpeMatchKey', () => {
  it('parses a 2.3 formatted string', () => {
    expect(cpeMatchKey('cpe:2.3:a:acme:webstack:3.0.0:*:*:*:*:*:*:*')).toEqual({
      key: 'a:acme:webstack',
      version: '3.0.0',
    });
  });

  it('parses a 2.2 URI onto the same key', () => {
    expect(cpeMatchKey('cpe:/a:acme:webstack:3.0.0')).toEqual({ key: 'a:acme:webstack', version: '3.0.0' });
  });

  it('case-folds and unescapes', () => {
    expect(cpeMatchKey('CPE:2.3:a:Acme:Web\\:Stack:1.0:*:*:*:*:*:*:*')).toEqual({
      key: 'a:acme:web:stack',
      version: '1.0',
    });
    expect(cpeMatchKey('cpe:/a:acme:web%20stack:1.0')).toEqual({ key: 'a:acme:web stack', version: '1.0' });
  });

  it('treats *, - and empty version as ANY', () => {
    expect(cpeMatchKey('cpe:2.3:a:acme:webstack:*:*:*:*:*:*:*:*')).toEqual({ key: 'a:acme:webstack' });
    expect(cpeMatchKey('cpe:2.3:a:acme:webstack:-:*:*:*:*:*:*:*')).toEqual({ key: 'a:acme:webstack' });
    expect(cpeMatchKey('cpe:/a:acme:webstack')).toEqual({ key: 'a:acme:webstack' });
  });

  it('refuses wildcarded vendor/product and non-a/h/o parts', () => {
    expect(cpeMatchKey('cpe:2.3:a:acme:*:1.0:*:*:*:*:*:*:*')).toBeUndefined();
    expect(cpeMatchKey('cpe:2.3:a:*:webstack:1.0:*:*:*:*:*:*:*')).toBeUndefined();
    expect(cpeMatchKey('cpe:2.3:x:acme:webstack:1.0:*:*:*:*:*:*:*')).toBeUndefined();
    expect(cpeMatchKey('pkg:npm/left-pad@1.0.0')).toBeUndefined();
    expect(cpeMatchKey('not a cpe')).toBeUndefined();
  });
});

const WEBSTACK_23 = 'cpe:2.3:a:acme:webstack:3.0.0:*:*:*:*:*:*:*';
const WEBSTACK_22 = 'cpe:/a:acme:webstack:3.0.0';

function wsWith(
  ...packages: [name: string, version: string, refs: [category: string, type: string, locator: string][]][]
): WorkspaceState {
  const lines = [
    'SPDXVersion: SPDX-2.3',
    'SPDXID: SPDXRef-DOCUMENT',
    'DocumentName: cpe-target',
    'DocumentNamespace: https://example.org/spdxdocs/cpe-target',
  ];
  packages.forEach(([name, version, refs], i) => {
    lines.push(
      `PackageName: ${name}`,
      `SPDXID: SPDXRef-P${i}`,
      `PackageVersion: ${version}`,
      'PackageDownloadLocation: NOASSERTION',
    );
    for (const [category, type, locator] of refs) lines.push(`ExternalRef: ${category} ${type} ${locator}`);
  });
  const loaded = loadedFromText('cpe-target.spdx', lines.join('\n') + '\n');
  return addDocument(emptyWorkspace, loaded).workspace;
}

function vexDoc(productId: string, extra: Partial<VexDocument> = {}): VexDocument {
  return {
    id: 'csaf-cpe-1',
    fileName: 'advisory.json',
    format: 'csaf',
    timestamp: '2026-06-01T00:00:00Z',
    statements: [
      {
        vulnerability: 'CVE-2026-50001',
        products: [{ id: productId, subcomponents: [] }],
        status: 'affected',
      },
    ],
    diagnostics: [],
    ...extra,
  };
}

function allFindings(map: ReturnType<typeof matchVex>) {
  return [...map.values()].flat();
}

describe('CPE matching through matchVex', () => {
  it('matches an element that carries only a CPE', () => {
    const ws = wsWith(['webstack', '3.0.0', [['SECURITY', 'cpe23Type', WEBSTACK_23]]]);
    const map = matchVex(ws, [vexDoc(WEBSTACK_23)]);
    const findings = allFindings(map);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ vulnerability: 'CVE-2026-50001', status: 'affected' });
  });

  it('matches across the 2.2/2.3 forms', () => {
    const ws = wsWith(['webstack', '3.0.0', [['SECURITY', 'cpe22Type', WEBSTACK_22]]]);
    const map = matchVex(ws, [vexDoc(WEBSTACK_23)]);
    expect(allFindings(map)).toHaveLength(1);
  });

  it('applies the version rule: exact match or versionless wildcard', () => {
    const ws = wsWith(['webstack', '2.9.0', [['SECURITY', 'cpe23Type', 'cpe:2.3:a:acme:webstack:2.9.0:*:*:*:*:*:*:*']]]);
    // Versioned statement for 3.0.0 must NOT hit the 2.9.0 element.
    expect(allFindings(matchVex(ws, [vexDoc(WEBSTACK_23)]))).toHaveLength(0);
    // A versionless statement covers it.
    expect(allFindings(matchVex(ws, [vexDoc('cpe:2.3:a:acme:webstack:*:*:*:*:*:*:*:*')]))).toHaveLength(1);
  });

  it('does not match a different vendor', () => {
    const ws = wsWith(['webstack', '3.0.0', [['SECURITY', 'cpe23Type', 'cpe:2.3:a:other:webstack:3.0.0:*:*:*:*:*:*:*']]]);
    expect(allFindings(matchVex(ws, [vexDoc(WEBSTACK_23)]))).toHaveLength(0);
  });

  it('collapses an element carrying both CPE forms to one finding', () => {
    const ws = wsWith([
      'webstack',
      '3.0.0',
      [
        ['SECURITY', 'cpe22Type', WEBSTACK_22],
        ['SECURITY', 'cpe23Type', WEBSTACK_23],
      ],
    ]);
    const findings = allFindings(matchVex(ws, [vexDoc(WEBSTACK_23)]));
    expect(findings).toHaveLength(1);
    // One statement reached through two element keys is one finding, not a
    // superseded pair.
    expect(findings[0]!.supersededCount).toBeUndefined();
  });

  it('counts a CPE-only element as matchable in the coverage', () => {
    const ws = wsWith(
      ['webstack', '3.0.0', [['SECURITY', 'cpe23Type', WEBSTACK_23]]],
      ['bare', '1.0.0', []],
    );
    const coverage = vexCoverage(ws, matchVex(ws, [vexDoc(WEBSTACK_23)]));
    expect(coverage).toMatchObject({ covered: 1, uncovered: 0, unmatchable: 1, total: 2 });
  });
});
