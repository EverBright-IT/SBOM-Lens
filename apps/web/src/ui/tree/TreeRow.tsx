import clsx from 'clsx';
import type { TreeNode, WorkspaceState } from '@sbomlens/core';
import { docAccent } from '../docColors';
import { describeTarget } from '../nodeInfo';
import {
  ChevronIcon,
  CycleIcon,
  DocumentIcon,
  FileIcon,
  GroupIcon,
  PackageIcon,
  PlaceholderIcon,
} from '../icons';

const ICONS = {
  document: DocumentIcon,
  package: PackageIcon,
  file: FileIcon,
  placeholder: PlaceholderIcon,
  group: GroupIcon,
  cycle: CycleIcon,
} as const;

/** Edge types so expected they'd be noise as labels. */
const QUIET_EDGES = new Set(['CONTAINS', 'DESCRIBES']);

interface TreeRowProps {
  ws: WorkspaceState;
  node: TreeNode;
  expanded: boolean;
  selected: boolean;
  /** Document changed relative to the parent row — show a boundary badge. */
  crossesDocument: boolean;
  onSelect: (node: TreeNode) => void;
  /** recursive=true (Shift+click) expands the entire subtree. */
  onToggle: (node: TreeNode, recursive: boolean) => void;
}

export function TreeRow({ ws, node, expanded, selected, crossesDocument, onSelect, onToggle }: TreeRowProps) {
  const info = describeTarget(ws, node.target);
  const Icon = ICONS[info.icon];
  const isPlaceholder = node.target.kind === 'placeholder';
  const isCycle = node.target.kind === 'cycle';
  const edgeLabel = node.edgeType && !QUIET_EDGES.has(node.edgeType) ? node.edgeType : null;

  return (
    <div
      role="treeitem"
      aria-selected={selected}
      aria-level={node.depth + 1}
      aria-expanded={node.hasChildren ? expanded : undefined}
      className={clsx(
        'flex h-7 w-full cursor-pointer items-center gap-1.5 rounded pr-2 text-[13px]',
        selected
          ? 'bg-sky-100 text-sky-950 dark:bg-sky-900/40 dark:text-sky-100'
          : 'hover:bg-slate-100 dark:hover:bg-slate-800/60',
        (isPlaceholder || isCycle) && 'text-slate-400 dark:text-slate-500',
      )}
      style={{ paddingLeft: node.depth * 16 + 6 }}
      onClick={() => onSelect(node)}
      onDoubleClick={() => node.hasChildren && onToggle(node, false)}
    >
      <span
        title={node.hasChildren ? 'Click: toggle · Shift+click: expand entire subtree' : undefined}
        className={clsx(
          'grid size-4 shrink-0 place-items-center rounded text-slate-400 dark:text-slate-500',
          node.hasChildren && 'hover:bg-slate-200 hover:text-slate-600 dark:hover:bg-slate-700 dark:hover:text-slate-300',
        )}
        onClick={(e) => {
          if (!node.hasChildren) return;
          e.stopPropagation();
          onToggle(node, e.shiftKey);
        }}
      >
        {node.hasChildren && (
          <ChevronIcon className={clsx('transition-transform duration-75', expanded && 'rotate-90')} />
        )}
      </span>
      <Icon
        className={clsx(
          'shrink-0',
          info.icon === 'document' && 'text-sky-600 dark:text-sky-400',
          info.icon === 'package' && !isCycle && 'text-slate-500 dark:text-slate-400',
          (info.icon === 'file' || info.icon === 'group') && 'text-slate-400 dark:text-slate-500',
          (isPlaceholder || isCycle) && 'text-slate-400 dark:text-slate-600',
        )}
      />
      <span className={clsx('min-w-12 flex-1 truncate', isPlaceholder && 'italic')} title={info.title}>
        {info.title}
        {isCycle && <span className="ml-1 text-[11px]">(shown above)</span>}
        {info.version && (
          <span className="ml-1.5 font-mono text-[11px] text-slate-400 dark:text-slate-500">
            {info.version}
          </span>
        )}
      </span>
      {isPlaceholder && (
        <span className="shrink-0 rounded border border-dashed border-slate-300 px-1 text-[10px] text-slate-400 dark:border-slate-600 dark:text-slate-500">
          not loaded
        </span>
      )}
      {edgeLabel && (
        <span className="shrink-0 text-[9px] tracking-wide text-slate-300 dark:text-slate-600">
          {edgeLabel}
        </span>
      )}
      {crossesDocument && info.docName && node.target.kind === 'element' && (
        <span
          className={clsx(
            'max-w-24 shrink-0 truncate rounded-sm border px-1 text-[10px]',
            docAccent(info.docName).chip,
          )}
          title={`from document ${info.docName}`}
        >
          {info.docName}
        </span>
      )}
    </div>
  );
}
