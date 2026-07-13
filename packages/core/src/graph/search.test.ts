import { describe, expect, it } from 'vitest';
import { loadFixtureDocument, loadedFromText } from '../test-fixtures';
import type { WorkspaceState } from '../workspace/workspace';
import { addDocument, emptyWorkspace } from '../workspace/workspace';
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

  it('matches purls from the blob', () => {
    const { hits } = searchWorkspace(ws, 'pkg:apk/alpine');
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
