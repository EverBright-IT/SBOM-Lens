import { describe, expect, it } from 'vitest';
import type { WorkspaceState } from '@sbomlens/core';
import { addDocument, documentGraph, emptyWorkspace } from '@sbomlens/core';
import { loadFixtureDocument, loadedFromText } from '@sbomlens/core/test-fixtures';
import type { MapMetrics, PlacedDoc } from './mapLayout';
import { buildMapLayout, defaultExpansion } from './mapLayout';

const METRICS: MapMetrics = { nodeW: 100, nodeH: 20, gapX: 40, rowH: 30, pad: 10 };

function loadAll(...names: string[]): WorkspaceState {
  let ws = emptyWorkspace;
  for (const name of names) ws = addDocument(ws, loadFixtureDocument(name)).workspace;
  return ws;
}

function docWithRefs(name: string, refUris: string[]): string {
  const lines = [
    'SPDXVersion: SPDX-2.3',
    'SPDXID: SPDXRef-DOCUMENT',
    `DocumentName: ${name}`,
    `DocumentNamespace: https://example.org/spdxdocs/${name}`,
  ];
  refUris.forEach((uri, i) => lines.push(`ExternalDocumentRef: DocumentRef-R${i} ${uri}`));
  lines.push(
    `PackageName: ${name}-pkg`,
    'SPDXID: SPDXRef-P0',
    'PackageDownloadLocation: NOASSERTION',
    'Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-P0',
  );
  refUris.forEach((_, i) =>
    lines.push(`Relationship: SPDXRef-P0 CONTAINS DocumentRef-R${i}:SPDXRef-DOCUMENT`),
  );
  return lines.join('\n') + '\n';
}

const ns = (n: string) => `https://example.org/spdxdocs/${n}`;

// root2 → {a, b, c}; a → {leaf1, leaf2}; shared: b AND c both reference "shared".
function bigWorkspace(): WorkspaceState {
  let ws = emptyWorkspace;
  ws = addDocument(ws, loadedFromText('leaf1.spdx', docWithRefs('leaf1', []))).workspace;
  ws = addDocument(ws, loadedFromText('leaf2.spdx', docWithRefs('leaf2', []))).workspace;
  ws = addDocument(ws, loadedFromText('shared.spdx', docWithRefs('shared', []))).workspace;
  ws = addDocument(ws, loadedFromText('a.spdx', docWithRefs('comp-a', [ns('leaf1'), ns('leaf2')]))).workspace;
  ws = addDocument(ws, loadedFromText('b.spdx', docWithRefs('comp-b', [ns('shared')]))).workspace;
  ws = addDocument(ws, loadedFromText('c.spdx', docWithRefs('comp-c', [ns('shared')]))).workspace;
  ws = addDocument(ws, loadedFromText('root2.spdx', docWithRefs('root2', [ns('comp-a'), ns('comp-b'), ns('comp-c')]))).workspace;
  return ws;
}

const byName = (ws: WorkspaceState, layoutDocs: PlacedDoc[], name: string) =>
  layoutDocs.find((d) => ws.documents.get(d.docId)!.document.name === name);

describe('buildMapLayout', () => {
  const ws = bigWorkspace();
  const graph = documentGraph(ws);
  const rootId = graph.nodes.find((n) => n.isRoot)!.docId;

  it('shows only roots + level 1 when only roots are expanded', () => {
    const layout = buildMapLayout(graph, new Set([rootId]), METRICS);
    const names = layout.docs.map((d) => ws.documents.get(d.docId)!.document.name).sort();
    expect(names).toEqual(['comp-a', 'comp-b', 'comp-c', 'root2']);
  });

  it('collapsed nodes carry their direct-children count as badge', () => {
    const layout = buildMapLayout(graph, new Set([rootId]), METRICS);
    const compA = byName(ws, layout.docs, 'comp-a')!;
    expect(compA.expanded).toBe(false);
    expect(compA.hasChildren).toBe(true);
    expect(compA.hiddenChildren).toBe(2); // leaf1 + leaf2
  });

  it('parents sit at the midpoint of their visible children block', () => {
    const all = new Set(graph.nodes.map((n) => n.docId));
    const layout = buildMapLayout(graph, all, METRICS);
    const compA = byName(ws, layout.docs, 'comp-a')!;
    const leaf1 = byName(ws, layout.docs, 'leaf1')!;
    const leaf2 = byName(ws, layout.docs, 'leaf2')!;
    expect(compA.y).toBe((leaf1.y + leaf2.y) / 2);
    // Columns: children one level right.
    expect(leaf1.x).toBe(compA.x + METRICS.nodeW + METRICS.gapX);
  });

  it('a shared child is placed once (primary parent) with one extra edge', () => {
    const all = new Set(graph.nodes.map((n) => n.docId));
    const layout = buildMapLayout(graph, all, METRICS);
    const sharedPlacements = layout.docs.filter(
      (d) => ws.documents.get(d.docId)!.document.name === 'shared',
    );
    expect(sharedPlacements).toHaveLength(1);
    expect(layout.extraEdges).toHaveLength(1); // the second parent's edge
  });

  it('forceVisible expands the ancestor chain of matches', () => {
    const leaf1Id = [...ws.documents.values()].find((d) => d.document.name === 'leaf1')!
      .document.id;
    const layout = buildMapLayout(graph, new Set([rootId]), METRICS, new Set([leaf1Id]));
    expect(byName(ws, layout.docs, 'leaf1')).toBeDefined();
    // comp-b stays collapsed — only the chain to the match opens.
    expect(byName(ws, layout.docs, 'shared')).toBeUndefined();
  });

  it('renders stubs as children rows of their owner', () => {
    const cascade = loadAll('cascade/leaf.spdx.json', 'cascade/mid.spdx', 'cascade/root.spdx');
    const g = documentGraph(cascade);
    const all = new Set(g.nodes.map((n) => n.docId));
    const layout = buildMapLayout(g, all, METRICS);
    expect(layout.stubs).toHaveLength(1); // DocumentRef-AUTH-2.0
    const mid = layout.docs.find(
      (d) => cascade.documents.get(d.docId)!.document.name === 'acme-webstack',
    )!;
    expect(layout.stubs[0]!.x).toBe(mid.x + METRICS.nodeW + METRICS.gapX);
  });

  it('content size grows with rows, not columns', () => {
    const all = new Set(graph.nodes.map((n) => n.docId));
    const layout = buildMapLayout(graph, all, METRICS);
    // 4 leaf rows (leaf1, leaf2, shared, …) dominate the height; 3 columns wide.
    expect(layout.contentW).toBe(10 * 2 + 3 * (100 + 40) - 40);
    expect(layout.contentH).toBeGreaterThan(4 * METRICS.rowH);
  });
});

describe('defaultExpansion', () => {
  it('expands everything for small graphs, only roots for large ones', () => {
    const ws = bigWorkspace();
    const graph = documentGraph(ws);
    expect(defaultExpansion(graph, 24).size).toBe(graph.nodes.length);
    expect(defaultExpansion(graph, 3).size).toBe(1); // just the root
  });
});
