import { describe, expect, it } from 'vitest';
import { loadFixtureDocument } from '../test-fixtures';
import type { WorkspaceState } from '../workspace/workspace';
import { addDocument, emptyWorkspace } from '../workspace/workspace';
import { documentGraph } from './documentGraph';

function loadAll(...names: string[]): WorkspaceState {
  let ws = emptyWorkspace;
  for (const name of names) ws = addDocument(ws, loadFixtureDocument(name)).workspace;
  return ws;
}

describe('documentGraph', () => {
  const ws = loadAll('cascade/leaf.spdx.json', 'cascade/mid.spdx', 'cascade/auth.spdx', 'cascade/root.spdx');
  const graph = documentGraph(ws);
  const byName = Object.fromEntries(graph.nodes.map((n) => [n.name, n]));

  it('levels documents by BFS distance from the roots', () => {
    expect(byName['acme-platform']).toMatchObject({ isRoot: true, level: 0 });
    expect(byName['acme-auth-service']).toMatchObject({ isRoot: true, level: 0 });
    expect(byName['acme-webstack']).toMatchObject({ isRoot: false, level: 1 });
    expect(byName['acme-runtime-image']).toMatchObject({ isRoot: false, level: 2 });
    expect(graph.levelCount).toBe(3);
  });

  it('carries resolution edges with their method', () => {
    const edges = graph.edges.map((e) => ({
      from: graph.nodes.find((n) => n.docId === e.from)!.name,
      to: graph.nodes.find((n) => n.docId === e.to)!.name,
      method: e.method,
    }));
    expect(edges).toContainEqual({ from: 'acme-platform', to: 'acme-webstack', method: 'checksum' });
    expect(edges).toContainEqual({ from: 'acme-webstack', to: 'acme-runtime-image', method: 'namespace' });
  });

  it('shows unresolved structural refs as stubs, but not informational ones', () => {
    expect(graph.stubs).toHaveLength(1);
    expect(graph.stubs[0]).toMatchObject({ docRef: 'DocumentRef-AUTH-2.0' });
    // DocumentRef-SCAN-REPORT is informational — no stub for it.
  });

  it('assigns distinct lanes within a level', () => {
    const level0 = graph.nodes.filter((n) => n.level === 0).map((n) => n.lane);
    expect(new Set(level0).size).toBe(level0.length);
  });

  it('reports per-level lane counts (nodes + stubs)', () => {
    expect(graph.laneCounts).toHaveLength(graph.levelCount);
    expect(graph.maxLaneCount).toBe(Math.max(...graph.laneCounts));
    // level 1: webstack + the unresolved AUTH stub (owned by mid)
    expect(graph.laneCounts[1]).toBe(1);
    expect(graph.laneCounts[2]).toBe(2); // runtime-image + AUTH stub (level = mid+1)
  });
});

describe('barycenter ordering', () => {
  function docWithRef(name: string, refUri?: string): string {
    const lines = [
      'SPDXVersion: SPDX-2.3',
      'SPDXID: SPDXRef-DOCUMENT',
      `DocumentName: ${name}`,
      `DocumentNamespace: https://example.org/spdxdocs/${name}`,
    ];
    if (refUri) {
      lines.push(`ExternalDocumentRef: DocumentRef-C ${refUri}`);
    }
    lines.push(
      `PackageName: ${name}-pkg`,
      'SPDXID: SPDXRef-P0',
      'PackageDownloadLocation: NOASSERTION',
      'Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-P0',
    );
    if (refUri) lines.push('Relationship: SPDXRef-P0 CONTAINS DocumentRef-C:SPDXRef-DOCUMENT');
    return lines.join('\n') + '\n';
  }

  it('orders children under their parents even when loaded in crossing order', async () => {
    const { loadedFromText } = await import('../test-fixtures');
    const { addDocument, emptyWorkspace } = await import('../workspace/workspace');
    const ns = (n: string) => `https://example.org/spdxdocs/${n}`;

    let ws = emptyWorkspace;
    // Children load FIRST and in reverse: c1 (child of r2) before c2 (child of r1).
    ws = addDocument(ws, loadedFromText('c1.spdx', docWithRef('c1'))).workspace;
    ws = addDocument(ws, loadedFromText('c2.spdx', docWithRef('c2'))).workspace;
    ws = addDocument(ws, loadedFromText('r1.spdx', docWithRef('r1', ns('c2')))).workspace;
    ws = addDocument(ws, loadedFromText('r2.spdx', docWithRef('r2', ns('c1')))).workspace;

    const graph = documentGraph(ws);
    const lane = Object.fromEntries(graph.nodes.map((n) => [n.name, n.lane]));
    const level = Object.fromEntries(graph.nodes.map((n) => [n.name, n.level]));

    expect(level['r1']).toBe(0);
    expect(level['c2']).toBe(1);
    // Children sit under their parents: same relative order as the parents.
    expect(lane['c2']! < lane['c1']!).toBe(lane['r1']! < lane['r2']!);
  });
});
