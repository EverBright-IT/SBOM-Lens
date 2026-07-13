import { describe, expect, it } from 'vitest';
import { makeElementId } from '../model/ids';
import { loadFixtureDocument } from '../test-fixtures';
import { refKey } from '../workspace/resolve';
import type { WorkspaceState } from '../workspace/workspace';
import { addDocument, bindRef, emptyWorkspace } from '../workspace/workspace';
import type { TreeNode } from './derive';
import { flattenVisible, getChildren, rootNodes } from './derive';
import { revealPath } from './reveal';

function loadAll(...names: string[]): WorkspaceState {
  let ws = emptyWorkspace;
  for (const name of names) ws = addDocument(ws, loadFixtureDocument(name)).workspace;
  return ws;
}

const byName = (ws: WorkspaceState, fileName: string) =>
  [...ws.documents.values()].find((d) => d.source.fileName === fileName)!.document;

function label(ws: WorkspaceState, node: TreeNode): string {
  const t = node.target;
  switch (t.kind) {
    case 'document':
      return `doc:${ws.documents.get(t.docId)!.document.name}`;
    case 'element': {
      const { documentId, spdxId } = { documentId: t.elementId.slice(0, t.elementId.lastIndexOf('#')), spdxId: t.elementId.slice(t.elementId.lastIndexOf('#') + 1) };
      const doc = ws.documents.get(documentId as never)!;
      return doc.document.elements[doc.indexes.elementBySpdxId.get(spdxId)!]!.name;
    }
    case 'placeholder':
      return `?${t.docRef}`;
    case 'extraRefs':
      return '(external documents)';
    case 'cycle':
      return '(cycle)';
  }
}

describe('cascade tree', () => {
  const ws = loadAll('cascade/leaf.spdx.json', 'cascade/mid.spdx', 'cascade/auth.spdx', 'cascade/root.spdx');

  it('walks release → component → leaf across document boundaries', () => {
    const [authRoot, platformRoot] = rootNodes(ws);
    expect(label(ws, authRoot!)).toBe('doc:acme-auth-service');
    expect(label(ws, platformRoot!)).toBe('doc:acme-platform');

    const [platform] = getChildren(ws, platformRoot!);
    expect(label(ws, platform!)).toBe('platform');

    // platform's child crosses into mid.spdx via checksum-resolved DocumentRef
    const [webstack] = getChildren(ws, platform!);
    expect(label(ws, webstack!)).toBe('webstack');
    expect(webstack!.edgeType).toBe('CONTAINS');

    const webstackChildren = getChildren(ws, webstack!);
    expect(webstackChildren.map((n) => label(ws, n))).toEqual([
      'runtime-image', // element hop into leaf.spdx.json (namespace-resolved)
      '?DocumentRef-AUTH-2.0', // unresolved structural ref → placeholder
      '(external documents)', // informational refs of the (collapsed) mid doc
    ]);

    const [runtimeImage] = webstackChildren;
    const leafChildren = getChildren(ws, runtimeImage!);
    expect(leafChildren.map((n) => label(ws, n))).toEqual(['busybox', 'openssl']);
    expect(leafChildren[1]!.edgeType).toBe('DEPENDENCY_OF');
  });

  it('lists informational refs under the external-documents group', () => {
    const platformRoot = rootNodes(ws)[1]!;
    const platform = getChildren(ws, platformRoot)[0]!;
    const webstack = getChildren(ws, platform)[0]!;
    const group = getChildren(ws, webstack).at(-1)!;
    expect(group.target.kind).toBe('extraRefs');
    const [scanReport] = getChildren(ws, group);
    expect(label(ws, scanReport!)).toBe('?DocumentRef-SCAN-REPORT');
  });

  it('replaces the placeholder with the document roots after a manual bind (collapse rule)', () => {
    const mid = byName(ws, 'mid.spdx');
    const bound = bindRef(ws, refKey(mid.id, 'DocumentRef-AUTH-2.0'), byName(ws, 'auth.spdx').id);

    const platformRoot = rootNodes(bound).find((n) => label(bound, n) === 'doc:acme-platform')!;
    const platform = getChildren(bound, platformRoot)[0]!;
    const webstack = getChildren(bound, platform)[0]!;
    const names = getChildren(bound, webstack).map((n) => label(bound, n));
    // DocumentRef-AUTH-2.0:SPDXRef-DOCUMENT collapses into auth's describes root.
    expect(names).toContain('auth-service');
    expect(names).not.toContain('?DocumentRef-AUTH-2.0');
  });

  it('flattenVisible only descends into expanded paths', () => {
    const roots = rootNodes(ws);
    const platformRoot = roots[1]!;
    const collapsed = flattenVisible(ws, new Set());
    expect(collapsed).toHaveLength(2);

    const platform = getChildren(ws, platformRoot)[0]!;
    const rows = flattenVisible(ws, new Set([platformRoot.path, platform.path]));
    expect(rows.map((n) => label(ws, n))).toEqual([
      'doc:acme-auth-service',
      'doc:acme-platform',
      'platform',
      'webstack',
    ]);
    expect(rows[3]!.depth).toBe(2);
  });

  it('reveals a leaf element through the full cascade path', () => {
    const leaf = byName(ws, 'leaf.spdx.json');
    const target = revealPath(ws, makeElementId(leaf.id, 'SPDXRef-Package-openssl'));
    expect(target).not.toBeNull();
    const rows = flattenVisible(ws, new Set(target!.expand));
    const revealed = rows.find((n) => n.path === target!.path);
    expect(revealed && label(ws, revealed)).toBe('openssl');
    expect(revealed!.depth).toBe(4); // doc → platform → webstack → runtime-image → openssl
  });
});

describe('cycle protection', () => {
  it('renders a repeated ancestor as a cycle leaf', () => {
    const ws = loadAll('cycle.spdx.json');
    const [docNode] = rootNodes(ws);
    const [a] = getChildren(ws, docNode!);
    const [b] = getChildren(ws, a!);
    expect(label(ws, b!)).toBe('b');
    const [aAgain] = getChildren(ws, b!);
    expect(aAgain!.target.kind).toBe('cycle');
    expect(aAgain!.hasChildren).toBe(false);
    expect(getChildren(ws, aAgain!)).toEqual([]);
  });
});

describe('collectSubtreePaths', () => {
  const ws = loadAll('cascade/leaf.spdx.json', 'cascade/mid.spdx', 'cascade/auth.spdx', 'cascade/root.spdx');

  it('expands an entire cascade across document boundaries', async () => {
    const { collectSubtreePaths } = await import('./derive');
    const platformRoot = rootNodes(ws).find((n) => label(ws, n) === 'doc:acme-platform')!;
    const { paths, capped } = collectSubtreePaths(ws, platformRoot);
    expect(capped).toBe(false);
    // Expandable nodes on the platform cascade: doc, platform, webstack,
    // runtime-image, extraRefs group (frontend/api chains are leaf packages).
    expect(paths.length).toBeGreaterThanOrEqual(4);
    const rows = flattenVisible(ws, new Set(paths));
    expect(rows.map((n) => label(ws, n))).toContain('busybox'); // leaf doc reached
  });

  it('respects the cap', async () => {
    const { collectSubtreePaths } = await import('./derive');
    const platformRoot = rootNodes(ws).find((n) => label(ws, n) === 'doc:acme-platform')!;
    const { paths, capped } = collectSubtreePaths(ws, platformRoot, 2);
    expect(paths).toHaveLength(2);
    expect(capped).toBe(true);
  });
});

describe('removal helpers', () => {
  const ws = loadAll('cascade/leaf.spdx.json', 'cascade/mid.spdx', 'cascade/root.spdx');
  const leafId = byName(ws, 'leaf.spdx.json').id;

  it('targetDocId resolves every node target kind', async () => {
    const { targetDocId, PATH_SEP, nodeKey } = await import('./derive');
    void PATH_SEP;
    void nodeKey;
    expect(targetDocId({ kind: 'document', docId: leafId })).toBe(leafId);
    expect(targetDocId({ kind: 'extraRefs', docId: leafId })).toBe(leafId);
    expect(targetDocId({ kind: 'element', elementId: makeElementId(leafId, 'SPDXRef-Package-openssl') })).toBe(leafId);
    expect(targetDocId({ kind: 'cycle', elementId: makeElementId(leafId, 'SPDXRef-Package-openssl') })).toBe(leafId);
    expect(targetDocId({ kind: 'placeholder', owningDocId: leafId, docRef: 'DocumentRef-X', spdxId: null })).toBe(leafId);
  });

  it('pruneExpandedPaths drops paths touching removed docs, keeps identity otherwise', async () => {
    const { pruneExpandedPaths, PATH_SEP } = await import('./derive');
    const rootId = byName(ws, 'root.spdx').id;
    const keepPath = `d:${rootId}`;
    const dropPath = [`d:${rootId}`, `e:${makeElementId(leafId, 'SPDXRef-Package-openssl')}`].join(PATH_SEP);
    const expanded = new Set([keepPath, dropPath]);

    const pruned = pruneExpandedPaths(expanded, new Set([leafId]));
    expect([...pruned]).toEqual([keepPath]);

    const untouched = pruneExpandedPaths(expanded, new Set(['urn:none' as never]));
    expect(untouched).toBe(expanded); // same instance when nothing changed
  });
});

describe('degenerate documents', () => {
  it('a standalone document with no describes falls back to unreferenced packages', () => {
    const ws = loadAll('trivy-style.spdx.json');
    const [docNode] = rootNodes(ws);
    const children = getChildren(ws, docNode!);
    expect(children.map((n) => label(ws, n))).toEqual(['example-image']);
  });
});
