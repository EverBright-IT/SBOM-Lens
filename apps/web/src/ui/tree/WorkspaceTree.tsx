import { useVirtualizer } from '@tanstack/react-virtual';
import { useEffect, useMemo, useRef } from 'react';
import type { TreeNode } from '@sbomlens/core';
import { PATH_SEP, collectSubtreePaths, getChildren, splitElementId } from '@sbomlens/core';
import { useFilteredTree, useVisibleRows } from '../../app/selectors';
import { useAppStore } from '../../app/store';
import { formatCount } from '../nodeInfo';

const ROW_HEIGHT = 28;

import { TreeRow } from './TreeRow';

export function WorkspaceTree() {
  const allRows = useVisibleRows();
  const filter = useFilteredTree();
  const rows = filter.active ? filter.result.rows : allRows;
  const ws = useAppStore((s) => s.ws);
  const expanded = useAppStore((s) => s.expanded);
  const selection = useAppStore((s) => s.selection);
  const actions = useAppStore((s) => s.actions);

  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
  });

  // Which rows sit in a different document than their parent row (boundary badge).
  const crossings = useMemo(() => {
    const result = new Array<boolean>(rows.length).fill(false);
    const docAtDepth: (string | null)[] = [];
    rows.forEach((row, i) => {
      const docId = rowDocId(row);
      const parentDoc = row.depth > 0 ? (docAtDepth[row.depth - 1] ?? null) : null;
      result[i] = docId !== null && parentDoc !== null && docId !== parentDoc;
      docAtDepth[row.depth] = docId;
      docAtDepth.length = row.depth + 1;
    });
    return result;
  }, [rows]);

  // Paths rendered as expanded while the in-place filter is active.
  const filterExpanded = useMemo(
    () => new Set(filter.result.expandedPaths),
    [filter.result.expandedPaths],
  );

  const selectedIndex = selection?.path
    ? rows.findIndex((r) => r.path === selection.path)
    : -1;

  // Keep the selected row in view when selection changes (reveal, keyboard).
  useEffect(() => {
    if (selectedIndex >= 0) virtualizer.scrollToIndex(selectedIndex, { align: 'auto' });
  }, [selectedIndex, virtualizer]);

  const select = (node: TreeNode) => actions.select({ path: node.path, target: node.target });

  const expandSubtree = (node: TreeNode) => {
    const { paths, capped } = collectSubtreePaths(ws, node);
    actions.expandPaths(paths);
    if (capped) {
      actions.toast(`Expanded ${paths.length} nodes: large subtree, expansion capped`, 'info');
    }
  };

  const toggle = (node: TreeNode, recursive: boolean) => {
    if (filter.active) {
      // Expanding inside filtered results zooms back out: keep the revealed
      // context, leave filter mode, then expand the node in the full tree.
      actions.setTreeFilter(false);
      actions.expandPaths([
        ...filter.result.expandedPaths,
        ...(node.hasChildren ? [node.path] : []),
      ]);
      if (recursive) expandSubtree(node);
      actions.select({ path: node.path, target: node.target });
      return;
    }
    if (recursive) expandSubtree(node);
    else actions.toggleExpand(node.path);
  };

  const onKeyDown = (event: React.KeyboardEvent) => {
    if (rows.length === 0) return;
    const current = selectedIndex >= 0 ? selectedIndex : 0;
    const node = rows[current];

    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault();
        select(rows[Math.min(current + 1, rows.length - 1)]!);
        break;
      case 'ArrowUp':
        event.preventDefault();
        select(rows[Math.max(current - 1, 0)]!);
        break;
      case 'ArrowRight': {
        event.preventDefault();
        if (!node) break;
        if (filter.active) {
          // Ancestors already show their children; matches zoom out via toggle.
          if (filterExpanded.has(node.path)) select(rows[Math.min(current + 1, rows.length - 1)]!);
          else if (node.hasChildren) toggle(node, false);
          break;
        }
        if (node.hasChildren && !expanded.has(node.path)) actions.toggleExpand(node.path);
        else if (node.hasChildren) {
          const [firstChild] = getChildren(ws, node);
          if (firstChild) select(firstChild);
        }
        break;
      }
      case 'ArrowLeft': {
        event.preventDefault();
        if (!node) break;
        if (!filter.active && node.hasChildren && expanded.has(node.path)) {
          actions.toggleExpand(node.path);
        } else {
          const parentPath = node.path.slice(0, node.path.lastIndexOf(PATH_SEP));
          const parent = rows.find((r) => r.path === parentPath);
          if (parent) select(parent);
        }
        break;
      }
      case 'Enter':
      case ' ':
        event.preventDefault();
        if (node?.hasChildren) toggle(node, false);
        break;
      case '*':
        event.preventDefault();
        if (node?.hasChildren) toggle(node, true);
        break;
      case 'Home':
        event.preventDefault();
        select(rows[0]!);
        break;
      case 'End':
        event.preventDefault();
        select(rows[rows.length - 1]!);
        break;
    }
  };

  const { matchPaths, shown, total } = filter.result;

  return (
    <div className="flex h-full flex-col">
      {filter.active && (
        <div className="flex shrink-0 items-center gap-2 border-b border-accent-100 bg-accent-50/60 px-3 py-1.5 text-[11px] text-accent-800 dark:border-accent-900/60 dark:bg-accent-950/30 dark:text-accent-300">
          <span>
            {formatCount(shown)} match{shown === 1 ? '' : 'es'} in tree
            {total > shown && ` (of ${formatCount(total)})`}
            {rows.length === 0 && ': nothing to show'}
          </span>
          <span className="min-w-0 flex-1" />
          <button
            type="button"
            onClick={() => actions.setTreeFilter(false)}
            className="rounded border border-accent-200 px-1.5 py-0.5 hover:bg-white dark:border-accent-800 dark:hover:bg-slate-900"
          >
            Show all
          </button>
        </div>
      )}
      <div
        ref={scrollRef}
        role="tree"
        aria-label="SBOM cascade"
        tabIndex={0}
        onKeyDown={onKeyDown}
        className="min-h-0 flex-1 overflow-auto overscroll-contain px-1.5 py-1.5 outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent-400/60"
      >
        <div className="relative" style={{ height: virtualizer.getTotalSize() }}>
          {virtualizer.getVirtualItems().map((item) => {
            const node = rows[item.index]!;
            const isContext = filter.active && !matchPaths.has(node.path);
            return (
              <div
                key={node.path}
                className={isContext ? 'absolute inset-x-0 opacity-60' : 'absolute inset-x-0'}
                style={{ top: item.start, height: ROW_HEIGHT }}
              >
                <TreeRow
                  ws={ws}
                  node={node}
                  expanded={filter.active ? filterExpanded.has(node.path) : expanded.has(node.path)}
                  selected={selection?.path === node.path}
                  crossesDocument={crossings[item.index] ?? false}
                  onSelect={select}
                  onToggle={toggle}
                />
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function rowDocId(node: TreeNode): string | null {
  switch (node.target.kind) {
    case 'document':
    case 'extraRefs':
      return node.target.docId;
    case 'element':
    case 'cycle':
      return splitElementId(node.target.elementId).documentId;
    case 'placeholder':
      return node.target.owningDocId;
  }
}
