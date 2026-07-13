import { describe, expect, it } from 'vitest';
import { loadFixtureDocument } from '../test-fixtures';
import type { WorkspaceState } from '../workspace/workspace';
import { addDocument, emptyWorkspace } from '../workspace/workspace';
import { filterTree } from './filter';

function loadAll(...names: string[]): WorkspaceState {
  let ws = emptyWorkspace;
  for (const name of names) ws = addDocument(ws, loadFixtureDocument(name)).workspace;
  return ws;
}

const rowNames = (ws: WorkspaceState, result: ReturnType<typeof filterTree>) =>
  result.rows.map((row) => {
    if (row.target.kind === 'document') {
      return `doc:${ws.documents.get(row.target.docId)!.document.name}`;
    }
    if (row.target.kind !== 'element') return `(${row.target.kind})`;
    const id = row.target.elementId;
    const docId = id.slice(0, id.lastIndexOf('#'));
    const spdxId = id.slice(id.lastIndexOf('#') + 1);
    const doc = ws.documents.get(docId as never)!;
    return doc.document.elements[doc.indexes.elementBySpdxId.get(spdxId)!]!.name;
  });

describe('filterTree', () => {
  const ws = loadAll('cascade/leaf.spdx.json', 'cascade/mid.spdx', 'cascade/root.spdx');

  it('keeps matches plus their ancestor chain, in tree order, across documents', () => {
    const result = filterTree(ws, 'busybox', { docs: null, kinds: null, purposes: null, licenses: null });
    // busybox lives in leaf.spdx.json, reached root → platform → webstack → runtime-image
    expect(rowNames(ws, result)).toEqual([
      'doc:acme-platform',
      'platform',
      'webstack',
      'runtime-image',
      'busybox',
    ]);
    expect(result.shown).toBe(1);
    expect(result.total).toBe(1);
    // exactly the match is flagged; the rest are context ancestors
    const matches = result.rows.filter((row) => result.matchPaths.has(row.path));
    expect(matches).toHaveLength(1);
    expect(result.expandedPaths.length).toBeGreaterThanOrEqual(4);
  });

  it('drops siblings that do not match and reports unreachable matches via shown < total', () => {
    const result = filterTree(ws, 'openssl', { docs: null, kinds: null, purposes: null, licenses: null });
    const names = rowNames(ws, result);
    expect(names).toContain('openssl');
    expect(names).not.toContain('busybox');
    expect(result.shown).toBeLessThanOrEqual(result.total);
  });

  it('respects the search limit', () => {
    const result = filterTree(ws, 'a', { docs: null, kinds: null, purposes: null, licenses: null }, 2);
    expect(result.total).toBeGreaterThan(2);
    expect(result.shown).toBeLessThanOrEqual(2);
  });
});
