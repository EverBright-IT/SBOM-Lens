import { useMemo, useState } from 'react';
import type { DocumentId } from '@sbomlens/core';
import { documentGraph, splitElementId } from '@sbomlens/core';
import { pref } from '../../app/brand';
import { useAppStore } from '../../app/store';
import { host } from '../../host/adapter';
import { docAccent } from '../docColors';
import { selectTarget } from '../navigate';
import { ChevronIcon } from '../icons';

const NODE_W = 108;
const NODE_H = 22;
const GAP_X = 14;
const GAP_Y = 18;
const PAD = 10;

const OPEN_KEY = pref('docmap');

/** Above this the inline minimap degrades into a postage stamp — link out. */
const INLINE_LIMIT = 12;

/**
 * Document-level minimap: documents as nodes, resolved references as edges,
 * unresolved structural references as dashed stubs. Package-level graphs
 * drown at thousands of nodes; the document topology stays readable.
 * Beyond INLINE_LIMIT documents this collapses into a link to the Map view.
 */
export function DocumentMap() {
  const ws = useAppStore((s) => s.ws);
  const selection = useAppStore((s) => s.selection);
  const actions = useAppStore((s) => s.actions);
  const [open, setOpen] = useState(() => host().readPref(OPEN_KEY) !== 'closed');

  const graph = useMemo(() => documentGraph(ws), [ws]);
  if (ws.documents.size < 2) return null;

  if (ws.documents.size > INLINE_LIMIT) {
    return (
      <div className="shrink-0 border-t border-slate-200 dark:border-slate-800">
        <button
          type="button"
          onClick={() => actions.setView('map')}
          className="flex h-8 w-full items-center gap-1.5 px-2 text-[11px] font-medium tracking-wide text-slate-400 uppercase hover:text-accent-600 dark:hover:text-accent-400"
        >
          Document map
          <span className="ml-auto font-normal normal-case">
            {graph.nodes.length} docs — open Map view →
          </span>
        </button>
      </div>
    );
  }

  const toggle = () => {
    setOpen((o) => {
      host().persistPref(OPEN_KEY, o ? 'closed' : 'open');
      return !o;
    });
  };

  const selectedDocId: DocumentId | null = (() => {
    const target = selection?.target;
    if (!target) return null;
    if (target.kind === 'document' || target.kind === 'extraRefs') return target.docId;
    if (target.kind === 'element' || target.kind === 'cycle') {
      return splitElementId(target.elementId).documentId;
    }
    return target.owningDocId;
  })();

  const x = (lane: number) => PAD + lane * (NODE_W + GAP_X);
  const y = (level: number) => PAD + level * (NODE_H + GAP_Y);
  const width = PAD * 2 + graph.maxLaneCount * (NODE_W + GAP_X) - GAP_X;
  const height = PAD * 2 + graph.levelCount * (NODE_H + GAP_Y) - GAP_Y;

  const positions = new Map(graph.nodes.map((n) => [n.docId, n]));

  return (
    <div className="shrink-0 border-t border-slate-200 dark:border-slate-800">
      <button
        type="button"
        onClick={toggle}
        className="flex h-7 w-full items-center gap-1 px-2 text-[11px] font-medium tracking-wide text-slate-400 uppercase hover:text-slate-600 dark:hover:text-slate-300"
      >
        <ChevronIcon className={`transition-transform duration-75 ${open ? 'rotate-90' : ''}`} />
        Document map
        <span className="ml-auto font-normal normal-case">
          {graph.nodes.length} docs{graph.stubs.length > 0 && ` · ${graph.stubs.length} missing`}
        </span>
      </button>

      {open && (
        <div className="max-h-44 overflow-auto px-1 pb-2">
          <svg width={Math.max(width, 1)} height={Math.max(height, 1)} className="block">
            {graph.edges.map((edge) => {
              const from = positions.get(edge.from);
              const to = positions.get(edge.to);
              if (!from || !to) return null;
              const x1 = x(from.lane) + NODE_W / 2;
              const y1 = y(from.level) + NODE_H;
              const x2 = x(to.lane) + NODE_W / 2;
              const y2 = y(to.level);
              return (
                <path
                  key={`${edge.from}-${edge.to}`}
                  d={`M ${x1} ${y1} C ${x1} ${y1 + GAP_Y / 2}, ${x2} ${y2 - GAP_Y / 2}, ${x2} ${y2}`}
                  fill="none"
                  className="stroke-slate-300 dark:stroke-slate-600"
                  strokeWidth={1.2}
                >
                  <title>{`resolved by ${edge.method}`}</title>
                </path>
              );
            })}
            {graph.stubs.map((stub) => {
              const from = positions.get(stub.owningDocId);
              if (!from) return null;
              const x1 = x(from.lane) + NODE_W / 2;
              const y1 = y(from.level) + NODE_H;
              const x2 = x(stub.lane) + NODE_W / 2;
              const y2 = y(stub.level);
              return (
                <path
                  key={`stub-edge-${stub.owningDocId}-${stub.docRef}`}
                  d={`M ${x1} ${y1} C ${x1} ${y1 + GAP_Y / 2}, ${x2} ${y2 - GAP_Y / 2}, ${x2} ${y2}`}
                  fill="none"
                  strokeDasharray="3 3"
                  className="stroke-slate-300 dark:stroke-slate-600"
                  strokeWidth={1.2}
                />
              );
            })}

            {graph.nodes.map((node) => (
              <g
                key={node.docId}
                transform={`translate(${x(node.lane)}, ${y(node.level)})`}
                className="cursor-pointer"
                onClick={() => selectTarget({ kind: 'document', docId: node.docId })}
              >
                <title>{`${node.name} — ${node.packageCount} packages${node.isRoot ? ' (root)' : ''}`}</title>
                <rect
                  width={NODE_W}
                  height={NODE_H}
                  rx={4}
                  strokeWidth={node.docId === selectedDocId ? 1.6 : 1}
                  className={
                    node.docId === selectedDocId
                      ? 'fill-accent-100 stroke-accent-500 dark:fill-accent-900/50 dark:stroke-accent-400'
                      : 'fill-slate-50 stroke-slate-300 hover:fill-slate-100 dark:fill-slate-800/80 dark:stroke-slate-600 dark:hover:fill-slate-800'
                  }
                />
                <rect
                  x={2.5}
                  y={2.5}
                  width={3}
                  height={NODE_H - 5}
                  rx={1.5}
                  className={docAccent(node.name).fill}
                />
                <text
                  x={NODE_W / 2 + 2}
                  y={NODE_H / 2 + 3.5}
                  textAnchor="middle"
                  className={
                    node.docId === selectedDocId
                      ? 'fill-accent-900 text-[10px] dark:fill-accent-100'
                      : 'fill-slate-600 text-[10px] dark:fill-slate-300'
                  }
                >
                  {node.name.length > 17 ? `${node.name.slice(0, 16)}…` : node.name}
                </text>
              </g>
            ))}

            {graph.stubs.map((stub) => (
              <g
                key={`stub-${stub.owningDocId}-${stub.docRef}`}
                transform={`translate(${x(stub.lane)}, ${y(stub.level)})`}
                className="cursor-pointer"
                onClick={() =>
                  selectTarget({
                    kind: 'placeholder',
                    owningDocId: stub.owningDocId,
                    docRef: stub.docRef,
                    spdxId: null,
                  })
                }
              >
                <title>{`${stub.docRef} — not loaded`}</title>
                <rect
                  width={NODE_W}
                  height={NODE_H}
                  rx={4}
                  strokeDasharray="3 3"
                  className="fill-transparent stroke-slate-300 hover:stroke-amber-400 dark:stroke-slate-600"
                />
                <text
                  x={NODE_W / 2}
                  y={NODE_H / 2 + 3.5}
                  textAnchor="middle"
                  className="fill-slate-400 text-[10px] italic dark:fill-slate-500"
                >
                  {stub.docRef.replace(/^DocumentRef-/, '').slice(0, 16)}
                </text>
              </g>
            ))}
          </svg>
        </div>
      )}
    </div>
  );
}
