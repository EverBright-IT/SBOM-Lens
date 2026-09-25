import { describe, expect, it } from 'vitest';
import { loadedFromText } from '../test-fixtures';
import { addDocument, emptyWorkspace } from '../workspace/workspace';
import { parseCsaf } from './csaf';
import { matchVex } from './vex';

/**
 * One CSAF statement names several products that resolve to the same
 * package (a component installed on two hosts, or a purl product next to a
 * CPE product). The matcher must see ONE statement, attribute the match to
 * the first of purl, CPE, hash, and, when two statements of one document
 * contradict each other about the package, let the more cautious status
 * win rather than the later bucket.
 */

const LIB = 'pkg:generic/lib@1.0';

function ws(extraLines: string[] = []) {
  const lines = [
    'SPDXVersion: SPDX-2.3',
    'SPDXID: SPDXRef-DOCUMENT',
    'DocumentName: t',
    'DocumentNamespace: https://example.org/spdxdocs/t',
    'PackageName: lib',
    'SPDXID: SPDXRef-lib',
    'PackageVersion: 1.0',
    'PackageDownloadLocation: NOASSERTION',
    `ExternalRef: PACKAGE-MANAGER purl ${LIB}`,
    ...extraLines,
    '',
  ];
  return addDocument(emptyWorkspace, loadedFromText('t.spdx', lines.join('\n'))).workspace;
}

function advisory(vulns: unknown[], tree?: unknown, id = 'V-1') {
  return {
    document: {
      csaf_version: '2.0',
      category: 'csaf_vex',
      title: 'x',
      publisher: { category: 'vendor', name: 'V', namespace: 'https://v.example' },
      tracking: { id, version: '1', status: 'final', initial_release_date: '2026-01-01T00:00:00Z', current_release_date: '2026-01-01T00:00:00Z' },
    },
    product_tree: tree ?? {
      full_product_names: [
        { product_id: 'LIB', name: 'lib', product_identification_helper: { purl: LIB } },
        { product_id: 'HOST-A', name: 'host a' },
        { product_id: 'HOST-B', name: 'host b' },
      ],
      relationships: [
        { category: 'installed_on', product_reference: 'LIB', relates_to_product_reference: 'HOST-A', full_product_name: { product_id: 'LIB-ON-A', name: 'lib on a' } },
        { category: 'installed_on', product_reference: 'LIB', relates_to_product_reference: 'HOST-B', full_product_name: { product_id: 'LIB-ON-B', name: 'lib on b' } },
      ],
    },
    vulnerabilities: vulns,
  };
}

const findingsOf = (w: ReturnType<typeof ws>, docs: unknown[]) =>
  [...matchVex(w, docs.map((d, i) => parseCsaf(`${i}.json`, d))).values()].flat();

describe('one statement, several products of one package', () => {
  it('is one finding without a superseded count', () => {
    const f = findingsOf(ws(), [advisory([{ cve: 'CVE-2026-0001', product_status: { known_affected: ['LIB-ON-A', 'LIB-ON-B'] } }])]);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ status: 'affected', matchedBy: 'purl' });
    expect(f[0]!.supersededCount).toBeUndefined();
  });

  it('is attributed to purl before CPE when both products name the same package', () => {
    const tree = {
      full_product_names: [
        { product_id: 'A', name: 'a', product_identification_helper: { purl: LIB } },
        { product_id: 'B', name: 'b', product_identification_helper: { cpe: 'cpe:2.3:a:v:lib:1.0:*:*:*:*:*:*:*' } },
      ],
    };
    const f = findingsOf(ws(['ExternalRef: SECURITY cpe23Type cpe:2.3:a:v:lib:1.0:*:*:*:*:*:*:*']), [
      advisory([{ cve: 'CVE-2026-0007', product_status: { known_affected: ['A', 'B'] } }], tree),
    ]);
    expect(f).toHaveLength(1);
    expect(f[0]!.matchedBy).toBe('purl');
    expect(f[0]!.supersededCount).toBeUndefined();
  });

  it('lets the cautious status win when one document contradicts itself about the package', () => {
    // Affected on host A, fixed on host B, both dated with the document.
    const f = findingsOf(ws(), [advisory([{ cve: 'CVE-2026-0002', product_status: { known_affected: ['LIB-ON-A'], fixed: ['LIB-ON-B'] } }])]);
    expect(f.map((x) => x.status)).toEqual(['affected']);
    expect(f[0]!.supersededCount).toBe(1); // the conflict stays visible
  });

  it('still lets the later-loaded document win a tie across documents', () => {
    const affected = advisory([{ cve: 'CVE-2026-0003', product_status: { known_affected: ['LIB'] } }], undefined, 'V-1');
    const fixed = advisory([{ cve: 'CVE-2026-0003', product_status: { fixed: ['LIB'] } }], undefined, 'V-2');
    expect(findingsOf(ws(), [affected, fixed]).map((x) => x.status)).toEqual(['fixed']);
    expect(findingsOf(ws(), [fixed, affected]).map((x) => x.status)).toEqual(['affected']);
  });
});
