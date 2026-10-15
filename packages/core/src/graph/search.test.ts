import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { loadFixtureDocument, loadedFromText } from '../test-fixtures';
import type { WorkspaceState } from '../workspace/workspace';
import { addDocument, emptyWorkspace } from '../workspace/workspace';
import { inventoryRows } from '../analysis/inventory';
import { emptyFacets, searchWorkspace } from './search';

function loadAll(...names: string[]): WorkspaceState {
  let ws = emptyWorkspace;
  for (const name of names) ws = addDocument(ws, loadFixtureDocument(name)).workspace;
  return ws;
}

describe('searchWorkspace', () => {
  const ws = loadAll('cascade/leaf.spdx.json', 'cascade/mid.spdx', 'cascade/auth.spdx', 'cascade/root.spdx');

  it('finds elements across all loaded documents', () => {
    const { hits, total } = searchWorkspace(ws, 'openssl');
    expect(total).toBe(1);
    expect(hits[0]!.element.name).toBe('openssl');
  });

  it('a purl query that stops at a namespace lists what sits below it', () => {
    const { hits } = searchWorkspace(ws, 'pkg:apk/alpine');
    expect(hits.map((h) => h.element.name)).toEqual(['busybox']);
  });

  it('without the pkg: scheme a purl is searched as text', () => {
    const { hits } = searchWorkspace(ws, 'apk/alpine/busy');
    expect(hits.map((h) => h.element.name)).toEqual(['busybox']);
  });

  it('ranks exact > prefix > substring', () => {
    const extra = loadedFromText(
      'ranking.spdx',
      [
        'SPDXVersion: SPDX-2.3',
        'SPDXID: SPDXRef-DOCUMENT',
        'DocumentName: ranking',
        'DocumentNamespace: https://example.org/spdxdocs/ranking',
        'PackageName: web',
        'SPDXID: SPDXRef-1',
        'PackageName: webby',
        'SPDXID: SPDXRef-2',
        'PackageName: cobweb-tools',
        'SPDXID: SPDXRef-3',
      ].join('\n'),
    );
    const wsr = addDocument(emptyWorkspace, extra).workspace;
    const { hits } = searchWorkspace(wsr, 'web');
    expect(hits.map((h) => h.element.name)).toEqual(['web', 'webby', 'cobweb-tools']);
  });

  it('applies document and kind facets', () => {
    const leafId = [...ws.documents.values()].find((d) => d.source.fileName === 'leaf.spdx.json')!
      .document.id;
    const rootOnly = searchWorkspace(ws, 'openssl', {
      ...emptyFacets,
      docs: new Set([ws.order.find((id) => id !== leafId)!]),
    });
    expect(rootOnly.total).toBe(0);

    const packagesOnly = searchWorkspace(ws, '', { ...emptyFacets, kinds: new Set(['package']) });
    expect(packagesOnly.total).toBe(7); // all packages across the four documents
  });

  it('empty query with facets browses in document order', () => {
    const { hits } = searchWorkspace(ws, '', emptyFacets, 3);
    expect(hits).toHaveLength(3);
    expect(hits[0]!.element.name).toBe('runtime-image');
  });
});

describe('scale smoke test', () => {
  function makeWideDoc(packageCount: number): string {
    const packages = [];
    const relationships = [];
    for (let i = 0; i < packageCount; i++) {
      packages.push({
        name: `pkg-${i}`,
        SPDXID: `SPDXRef-Package-${i}`,
        versionInfo: `1.${i}.0`,
        downloadLocation: 'NOASSERTION',
      });
      if (i > 0) {
        relationships.push({
          spdxElementId: `SPDXRef-Package-${(i / 10) | 0}`,
          relationshipType: 'CONTAINS',
          relatedSpdxElement: `SPDXRef-Package-${i}`,
        });
      }
    }
    return JSON.stringify({
      spdxVersion: 'SPDX-2.3',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: 'wide',
      documentNamespace: 'https://example.org/spdxdocs/wide',
      documentDescribes: ['SPDXRef-Package-0'],
      packages,
      relationships,
    });
  }

  it('parses, indexes, and searches 5k packages within budget', () => {
    const started = performance.now();
    const loaded = loadedFromText('wide.spdx.json', makeWideDoc(5000));
    const ws = addDocument(emptyWorkspace, loaded).workspace;
    const parseAndIndexMs = performance.now() - started;

    const searchStart = performance.now();
    const { hits } = searchWorkspace(ws, 'pkg-4999');
    const searchMs = performance.now() - searchStart;

    expect(hits[0]!.element.name).toBe('pkg-4999');
    expect(parseAndIndexMs).toBeLessThan(2000);
    expect(searchMs).toBeLessThan(50);
  });
});

describe('licenseIds facet', () => {
  it('matches either licence field by identifier, in the SPDX 3.0.1 dialect too', () => {
    const ci = '_:ci';
    const graph = JSON.stringify({
      '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
      '@graph': [
        { type: 'CreationInfo', '@id': ci, specVersion: '3.0.1', created: '2026-06-01T10:00:00Z' },
        { type: 'SpdxDocument', spdxId: 'https://acme.example/doc/facet', creationInfo: ci, name: 'facet' },
        { type: 'software_Package', spdxId: 'https://acme.example/pkg/a', creationInfo: ci, name: 'a' },
        { type: 'software_Package', spdxId: 'https://acme.example/pkg/b', creationInfo: ci, name: 'b' },
        { type: 'simplelicensing_LicenseExpression', spdxId: 'https://acme.example/lic/1', creationInfo: ci, simplelicensing_licenseExpression: 'GPL-2.0-only WITH DocumentRef-d:AdditionRef-x' },
        { type: 'simplelicensing_LicenseExpression', spdxId: 'https://acme.example/lic/2', creationInfo: ci, simplelicensing_licenseExpression: 'MIT' },
        { type: 'Relationship', spdxId: 'https://acme.example/rel/1', creationInfo: ci, from: 'https://acme.example/pkg/a', relationshipType: 'hasDeclaredLicense', to: ['https://acme.example/lic/1'] },
        { type: 'Relationship', spdxId: 'https://acme.example/rel/2', creationInfo: ci, from: 'https://acme.example/pkg/b', relationshipType: 'hasConcludedLicense', to: ['https://acme.example/lic/2'] },
      ],
    });
    const ws = addDocument(emptyWorkspace, loadedFromText('facet.spdx3.json', graph)).workspace;
    const names = (ids: string[]) =>
      searchWorkspace(ws, '', { ...emptyFacets, licenseIds: new Set(ids) }).hits.map((h) => h.element.name).sort();
    expect(names(['GPL-2.0-only'])).toEqual(['a']);
    expect(names(['MIT'])).toEqual(['b']);
    expect(names(['GPL-2.0-only', 'MIT'])).toEqual(['a', 'b']);
    expect(names(['AdditionRef-x'])).toEqual([]); // the addition after WITH is not a licence
  });
});

describe('searchWorkspace: a CPE query matches by identity', () => {
  // The CRA Article 14 question in its first hours: "which of our products
  // contain the component this advisory names?" Advisories name it by CPE,
  // usually versionless, while SBOMs carry concrete versions in either form.
  const lines = [
    'SPDXVersion: SPDX-2.3',
    'SPDXID: SPDXRef-DOCUMENT',
    'DocumentName: cpe-search',
    'DocumentNamespace: https://example.org/spdxdocs/cpe-search',
    'PackageName: libthing',
    'SPDXID: SPDXRef-P0',
    'PackageVersion: 1.0',
    'PackageDownloadLocation: NOASSERTION',
    'ExternalRef: SECURITY cpe23Type cpe:2.3:a:acme:thing:1.0:*:*:*:*:*:*:*',
    'PackageName: thing-legacy',
    'SPDXID: SPDXRef-P1',
    'PackageVersion: 2.0',
    'PackageDownloadLocation: NOASSERTION',
    'ExternalRef: SECURITY cpe22Type cpe:/a:acme:thing:2.0',
    'PackageName: thing-fork',
    'SPDXID: SPDXRef-P2',
    'PackageVersion: 1.0',
    'PackageDownloadLocation: NOASSERTION',
    'ExternalRef: SECURITY cpe23Type cpe:2.3:a:other:thing:1.0:*:*:*:*:*:*:*',
    'PackageName: unrelated',
    'SPDXID: SPDXRef-P3',
    'PackageVersion: 2.3',
    'PackageDownloadLocation: NOASSERTION',
    'PackageName: widget',
    'SPDXID: SPDXRef-P4',
    'PackageVersion: 3.1',
    'PackageDownloadLocation: NOASSERTION',
    'ExternalRef: SECURITY cpe23Type cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*',
  ];
  const ws = addDocument(emptyWorkspace, loadedFromText('cpe-search.spdx', lines.join('\n') + '\n')).workspace;
  const names = (query: string) =>
    searchWorkspace(ws, query)
      .hits.map((h) => h.element.name)
      .sort();

  it('a versionless CPE finds every version, across the 2.2 and 2.3 forms', () => {
    expect(names('cpe:2.3:a:acme:thing:*:*:*:*:*:*:*:*')).toEqual(['libthing', 'thing-legacy']);
    expect(names('cpe:/a:acme:thing')).toEqual(['libthing', 'thing-legacy']);
  });

  it('a versioned CPE finds only that version, whatever form either side uses', () => {
    expect(names('cpe:2.3:a:acme:thing:2.0:*:*:*:*:*:*:*')).toEqual(['thing-legacy']);
    expect(names('CPE:/A:ACME:THING:1.0')).toEqual(['libthing']);
  });

  it('never crosses vendors and treats a wildcarded vendor as no identity at all', () => {
    expect(names('cpe:2.3:a:acme:thing:1.0:*:*:*:*:*:*:*')).not.toContain('thing-fork');
    expect(names('cpe:2.3:a:*:thing:1.0:*:*:*:*:*:*:*')).toEqual([]);
  });

  it('leaves ordinary queries alone: "2.3" is a version, not every cpe:2.3 identifier', () => {
    expect(names('2.3')).toEqual(['unrelated']);
  });

  it('drives the inventory too, so the hits export as the impact list', () => {
    const rows = inventoryRows(ws, 'cpe:2.3:a:acme:thing:*:*:*:*:*:*:*:*', emptyFacets);
    expect(rows.map((r) => r.element.name).sort()).toEqual(['libthing', 'thing-legacy']);
  });

  it("takes the element's own version when its CPE states none", () => {
    expect(names('cpe:2.3:a:acme:widget:3.1:*:*:*:*:*:*:*')).toEqual(['widget']);
    expect(names('cpe:2.3:a:acme:widget:3.2:*:*:*:*:*:*:*')).toEqual([]);
    expect(names('cpe:/a:acme:widget')).toEqual(['widget']);
  });
});

describe('searchWorkspace: a purl query matches by identity', () => {
  // Advisories write purls in the spec's canonical form (encoded npm scopes,
  // qualifiers, often no version), SBOMs in whatever their generator emits.
  // Substring search missed the first and over-matched lodash-es.
  const pkg = (i: number, name: string, version: string, purl: string) => [
    `PackageName: ${name}`,
    `SPDXID: SPDXRef-P${i}`,
    `PackageVersion: ${version}`,
    'PackageDownloadLocation: NOASSERTION',
    `ExternalRef: PACKAGE-MANAGER purl ${purl}`,
  ];
  const lines = [
    'SPDXVersion: SPDX-2.3',
    'SPDXID: SPDXRef-DOCUMENT',
    'DocumentName: purl-search',
    'DocumentNamespace: https://example.org/spdxdocs/purl-search',
    ...pkg(0, 'lodash', '4.17.20', 'pkg:npm/lodash@4.17.20'),
    ...pkg(1, 'lodash-es', '4.17.21', 'pkg:npm/lodash-es@4.17.21'),
    ...pkg(2, '@angular/core', '17.0.0', 'pkg:npm/@angular/core@17.0.0'),
    ...pkg(3, '@angular/common', '17.0.0', 'pkg:npm/%40angular/common@17.0.0'),
    ...pkg(4, 'log4j-core', '2.14.1', 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar'),
    ...pkg(5, 'Newtonsoft.Json', '13.0.1', 'pkg:nuget/Newtonsoft.Json@13.0.1'),
    ...pkg(6, 'typing-extensions', '4.8.0', 'pkg:pypi/typing-extensions@4.8.0'),
    ...pkg(7, 'left-pad', '1.3.0', 'pkg:npm/left-pad'),
  ];
  const ws = addDocument(emptyWorkspace, loadedFromText('purl-search.spdx', lines.join('\n') + '\n')).workspace;
  const elements = [...ws.documents.values()].flatMap((d) => d.document.elements);
  const names = (query: string) =>
    searchWorkspace(ws, query)
      .hits.map((h) => h.element.name)
      .sort();

  it('a versionless purl finds the package, never one whose name merely starts the same', () => {
    expect(names('pkg:npm/lodash')).toEqual(['lodash']);
  });

  it('a versioned purl finds only that version', () => {
    expect(names('pkg:npm/lodash@4.17.20')).toEqual(['lodash']);
    expect(names('pkg:npm/lodash@4.17.21')).toEqual([]);
  });

  it('reads encoded and raw npm scopes alike', () => {
    expect(names('pkg:npm/%40angular/core@17.0.0')).toEqual(['@angular/core']);
    expect(names('pkg:npm/@angular/common')).toEqual(['@angular/common']);
  });

  it('ignores qualifiers and subpath on either side', () => {
    expect(names('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?classifier=sources#src')).toEqual(['log4j-core']);
  });

  it('lists a namespace or a whole type when the query stops there', () => {
    expect(names('pkg:npm/@angular')).toEqual(['@angular/common', '@angular/core']);
    expect(names('pkg:maven/org.apache.logging.log4j')).toEqual(['log4j-core']);
    expect(names('pkg:npm')).toEqual(['@angular/common', '@angular/core', 'left-pad', 'lodash', 'lodash-es']);
    expect(names('pkg:maven/org.apache.logging.log4j@2.14.1')).toEqual([]);
  });

  it('folds letter case and the PyPI name separators', () => {
    expect(names('pkg:nuget/newtonsoft.json@13.0.1')).toEqual(['Newtonsoft.Json']);
    expect(names('pkg:pypi/Typing_Extensions')).toEqual(['typing-extensions']);
  });

  it("takes the element's own version when its purl states none", () => {
    expect(names('pkg:npm/left-pad@1.3.0')).toEqual(['left-pad']);
    expect(names('pkg:npm/left-pad@1.3.1')).toEqual([]);
  });

  it('finds every element by its own purl', () => {
    for (const element of elements) {
      if (element.purl) expect(names(element.purl)).toContain(element.name);
    }
  });

  it('drives the inventory too', () => {
    const rows = inventoryRows(ws, 'pkg:npm/lodash', emptyFacets);
    expect(rows.map((r) => r.element.name)).toEqual(['lodash']);
  });
});

describe('the worked example in docs/cra.md', () => {
  it('finds the CPE-only demo component with the versionless CPE the guide quotes', () => {
    let ws = emptyWorkspace;
    for (const file of ['acme-web.cdx.json', 'acme-auth.cdx.json']) {
      const text = readFileSync(new URL(`../../../../apps/web/public/examples/cdx/${file}`, import.meta.url), 'utf8');
      ws = addDocument(ws, loadedFromText(file, text)).workspace;
    }
    const { hits } = searchWorkspace(ws, 'cpe:2.3:a:acme:thing:*:*:*:*:*:*:*:*');
    expect(hits.map((h) => [h.element.name, h.element.version, h.element.purl])).toEqual([['acme-thing', '1.0', undefined]]);
  });
});
