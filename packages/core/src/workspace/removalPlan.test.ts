import { describe, expect, it } from 'vitest';
import { reachableDocs } from '../analysis/diff';
import type { DocumentId } from '../model/ids';
import { loadFixtureDocument, loadedFromText } from '../test-fixtures';
import type { WorkspaceState } from './workspace';
import { addDocument, emptyWorkspace, removeDocuments, workspaceRoots } from './workspace';
import { removalPlan } from './removalPlan';

function loadAll(...names: string[]): WorkspaceState {
  let ws = emptyWorkspace;
  for (const name of names) ws = addDocument(ws, loadFixtureDocument(name)).workspace;
  return ws;
}

const byFile = (ws: WorkspaceState, fileName: string): DocumentId =>
  [...ws.documents.values()].find((d) => d.source.fileName === fileName)!.document.id;

const names = (ws: WorkspaceState, ids: readonly DocumentId[]) =>
  ids.map((id) => ws.documents.get(id)!.document.name);

/** Tiny tag-value doc whose refs resolve by namespace (uri == child namespace). */
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

const ns = (name: string) => `https://example.org/spdxdocs/${name}`;

describe('removalPlan', () => {
  // Fixture chain: root →(checksum) mid →(namespace) leaf; auth is a separate root.
  const ws = loadAll('cascade/leaf.spdx.json', 'cascade/mid.spdx', 'cascade/auth.spdx', 'cascade/root.spdx');
  const root = byFile(ws, 'root.spdx');
  const mid = byFile(ws, 'mid.spdx');
  const leaf = byFile(ws, 'leaf.spdx.json');
  const auth = byFile(ws, 'auth.spdx');

  it('removing the root orphans the whole exclusive cascade, never unrelated roots', () => {
    const plan = removalPlan(ws, new Set([root]));
    expect(plan.requested).toEqual([root]);
    expect(names(ws, plan.orphaned).sort()).toEqual(['acme-runtime-image', 'acme-webstack']);
    expect(plan.orphaned).not.toContain(auth);
  });

  it('removing a mid-level document orphans only what hangs below it', () => {
    const plan = removalPlan(ws, new Set([mid]));
    expect(plan.orphaned).toEqual([leaf]);
  });

  it('a child shared with a surviving parent is not orphaned', () => {
    // Synthetic second parent referencing the leaf by namespace.
    const parent2 = loadedFromText('parent2.spdx', docWithRefs('parent2', [ns('acme-runtime-image')]));
    const shared = addDocument(ws, parent2).workspace;

    const one = removalPlan(shared, new Set([mid]));
    expect(one.orphaned).toEqual([]); // leaf still anchored via parent2

    const both = removalPlan(shared, new Set([mid, byFile(shared, 'parent2.spdx')]));
    expect(both.orphaned).toEqual([leaf]);
  });

  it('handles document-level cycles hanging off a removed root', () => {
    let cyc = emptyWorkspace;
    cyc = addDocument(cyc, loadedFromText('a.spdx', docWithRefs('cyc-a', [ns('cyc-b')]))).workspace;
    cyc = addDocument(cyc, loadedFromText('b.spdx', docWithRefs('cyc-b', [ns('cyc-a')]))).workspace;
    cyc = addDocument(cyc, loadedFromText('r.spdx', docWithRefs('cyc-r', [ns('cyc-a')]))).workspace;
    const r = byFile(cyc, 'r.spdx');

    const plan = removalPlan(cyc, new Set([r]));
    expect(names(cyc, plan.orphaned).sort()).toEqual(['cyc-a', 'cyc-b']);
  });

  it('requesting a whole cascade leaves no orphans; stale ids are ignored', () => {
    const plan = removalPlan(ws, new Set([root, mid, leaf, 'urn:not-loaded' as DocumentId]));
    expect(plan.requested).toEqual([leaf, mid, root]); // ws.order
    expect(plan.orphaned).toEqual([]);
  });
});

describe('batch removal', () => {
  it('removeDocuments removes a set with one recompute and re-roots survivors', () => {
    const ws = loadAll('cascade/leaf.spdx.json', 'cascade/mid.spdx', 'cascade/auth.spdx', 'cascade/root.spdx');
    const removed = removeDocuments(ws, new Set([byFile(ws, 'root.spdx'), byFile(ws, 'mid.spdx')]));
    expect(removed.documents.size).toBe(2);
    expect(names(removed, workspaceRoots(removed)).sort()).toEqual([
      'acme-auth-service',
      'acme-runtime-image',
    ]);
  });

  it('reachableDocs honours the exclusion set', () => {
    const ws = loadAll('cascade/leaf.spdx.json', 'cascade/mid.spdx', 'cascade/root.spdx');
    const root = byFile(ws, 'root.spdx');
    const mid = byFile(ws, 'mid.spdx');
    expect(reachableDocs(ws, root)).toHaveLength(3);
    expect(reachableDocs(ws, root, new Set([mid]))).toEqual([root]);
  });
});
