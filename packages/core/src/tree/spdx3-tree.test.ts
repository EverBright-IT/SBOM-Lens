import { describe, expect, it } from 'vitest';
import { splitElementId } from '../model/ids';
import { loadFixtureDocument } from '../test-fixtures';
import { addDocument, emptyWorkspace } from '../workspace/workspace';
import { getChildren, rootNodes } from './derive';
import type { TreeNode } from './derive';

/**
 * SPDX 3.x element ids are full IRIs with their own '#fragment'. This walks
 * the tree of a 3.x cascade and asserts every element node resolves to a real
 * element — the regression guard for the elementId round-trip that rendered
 * the described root as "(missing element)".
 */
describe('spdx3 cascade tree', () => {
  it('resolves the described root instead of a missing element', () => {
    let ws = addDocument(emptyWorkspace, loadFixtureDocument('spdx3/cascade-platform.spdx3.json')).workspace;
    ws = addDocument(ws, loadFixtureDocument('spdx3/cascade-auth.spdx3.json')).workspace;

    const missing: string[] = [];
    let elementNodes = 0;
    const visit = (nodes: TreeNode[], depth: number) => {
      for (const node of nodes) {
        if (node.target.kind === 'element') {
          elementNodes++;
          const { documentId, spdxId } = splitElementId(node.target.elementId);
          const resolved = ws.documents.get(documentId)?.document.elements.some((e) => e.spdxId === spdxId);
          if (!resolved) missing.push(node.target.elementId);
        }
        if (depth < 5) visit(getChildren(ws, node), depth + 1);
      }
    };
    visit(rootNodes(ws), 0);

    expect(missing).toEqual([]);
    expect(elementNodes).toBeGreaterThan(0); // the tree actually had element rows
  });
});
