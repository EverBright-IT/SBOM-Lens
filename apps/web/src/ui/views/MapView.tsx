import clsx from 'clsx';
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { DocumentId, ResolutionMethod, WorkspaceState } from '@sbomlens/core';
import { documentGraph } from '@sbomlens/core';
import { useAppStore } from '../../app/store';
import { DetailPane } from '../detail/DetailPane';
import { revealDocument, selectTarget } from '../navigate';
import { docAccent } from '../docColors';
import { formatCount } from '../nodeInfo';
import type { MapLayout, MapMetrics, PlacedDoc } from './mapLayout';
import { buildMapLayout, defaultExpansion } from './mapLayout';

/**
 * Full-canvas document map, left-to-right: levels are columns, children stack
 * vertically, nodes collapse/expand. Readable at 77+ documents because wide
 * levels grow downward (scrollable column) instead of into a mile-wide row.
 */

const MIN_SCALE = 0.15;
const MAX_SCALE = 4;
const COMPACT_THRESHOLD = 60;
const EDGE_DIM_THRESHOLD = 60;

const NORMAL: MapMetrics = { nodeW: 180, nodeH: 34, gapX: 56, rowH: 44, pad: 24 };
const COMPACT: MapMetrics = { nodeW: 150, nodeH: 22, gapX: 44, rowH: 28, pad: 24 };

interface ViewBox {
  x: number;
  y: number;
  w: number;
  h: number;
}

export function MapView() {
  const ws = useAppStore((s) => s.ws);
  const selection = useAppStore((s) => s.selection);
  const query = useAppStore((s) => s.query);
  const [hovered, setHovered] = useState<DocumentId | null>(null);

  const graph = useMemo(() => documentGraph(ws), [ws]);

  // Expansion state, re-initialized when the workspace changes shape.
  const [expandedDocs, setExpandedDocs] = useState<ReadonlySet<DocumentId>>(() =>
    defaultExpansion(graph),
  );
  const wsRef = useRef(ws);
  useEffect(() => {
    if (wsRef.current !== ws) {
      wsRef.current = ws;
      setExpandedDocs((current) => {
        // Keep user expansions that still exist; add default roots.
        const next = defaultExpansion(graph);
        for (const id of current) if (ws.documents.has(id)) next.add(id);
        return next;
      });
    }
  }, [ws, graph]);

  const q = query.trim().toLowerCase();
  const matches = useMemo(() => {
    if (q === '') return null;
    const set = new Set<DocumentId>();
    for (const node of graph.nodes) {
      const fileName = ws.documents.get(node.docId)?.source.fileName ?? '';
      if (node.name.toLowerCase().includes(q) || fileName.toLowerCase().includes(q)) {
        set.add(node.docId);
      }
    }
    return set;
  }, [q, graph, ws]);

  // Two-pass metrics: compact when many rows are visible.
  const layout: MapLayout & { metrics: MapMetrics } = useMemo(() => {
    const force = matches ?? new Set<DocumentId>();
    const first = buildMapLayout(graph, expandedDocs, NORMAL, force);
    if (first.visibleCount <= COMPACT_THRESHOLD) return { ...first, metrics: NORMAL };
    return { ...buildMapLayout(graph, expandedDocs, COMPACT, force), metrics: COMPACT };
  }, [graph, expandedDocs, matches]);
  const metrics = layout.metrics;

  const { svgRef, viewBox, fit, zoomBy, wasDrag, handlers } = useSvgPanZoom(
    layout.contentW,
    layout.contentH,
  );

  const positions = useMemo(() => {
    const map = new Map<string, { x: number; y: number }>();
    for (const doc of layout.docs) map.set(doc.docId, { x: doc.x, y: doc.y });
    layout.stubs.forEach((stub, i) => map.set(`stub:${i}`, { x: stub.x, y: stub.y }));
    return map;
  }, [layout]);

  const selectedDocId = selection ? docIdOfSelection(selection.target) : null;
  const emphasisDoc = hovered ?? selectedDocId;
  const dimEdges = layout.treeEdges.length + layout.extraEdges.length > EDGE_DIM_THRESHOLD;

  const toggleExpand = (docId: DocumentId) => {
    setExpandedDocs((current) => {
      const next = new Set(current);
      if (next.has(docId)) next.delete(docId);
      else next.add(docId);
      return next;
    });
  };

  const edgePath = (fromId: DocumentId, toKey: string) => {
    const a = positions.get(fromId);
    const b = positions.get(toKey);
    if (!a || !b) return null;
    const x1 = a.x + metrics.nodeW;
    const y1 = a.y + metrics.nodeH / 2;
    const x2 = b.x;
    const y2 = b.y + metrics.nodeH / 2;
    const c = metrics.gapX * 0.55;
    return `M ${x1} ${y1} C ${x1 + c} ${y1}, ${x2 - c} ${y2}, ${x2} ${y2}`;
  };

  const methodDash = (method: ResolutionMethod) =>
    method === 'namespace' ? '5 4' : method === 'manual' ? '2 3' : undefined;

  const renderEdge = (edge: { from: DocumentId; to: DocumentId; method: ResolutionMethod }, extra: boolean) => {
    const d = edgePath(edge.from, edge.to);
    if (!d) return null;
    const emphasized = edge.from === emphasisDoc || edge.to === emphasisDoc;
    return (
      <path
        key={`${extra ? 'x' : 't'}-${edge.from}->${edge.to}`}
        d={d}
        fill="none"
        strokeDasharray={methodDash(edge.method)}
        strokeWidth={emphasized ? 1.8 : extra ? 1 : 1.2}
        className={emphasized ? 'stroke-accent-500' : 'stroke-slate-300 dark:stroke-slate-600'}
        opacity={emphasized ? 1 : extra ? 0.35 : dimEdges ? 0.5 : 0.9}
      >
        <title>{`resolved by ${edge.method}`}</title>
      </path>
    );
  };

  const compact = metrics === COMPACT;
  const truncate = (name: string) => {
    const max = compact ? 20 : 23;
    return name.length > max ? `${name.slice(0, max - 1)}…` : name;
  };

  return (
    <div className="flex h-full min-w-0">
      <div className="relative min-w-0 flex-1">
        <svg
          ref={svgRef}
          className="h-full w-full cursor-grab touch-none select-none active:cursor-grabbing"
          viewBox={viewBox ? `${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}` : undefined}
          {...handlers}
        >
          {layout.treeEdges.map((e) => renderEdge(e, false))}
          {layout.extraEdges.map((e) => renderEdge(e, true))}
          {layout.stubs.map((stub, i) => {
            const d = edgePath(stub.owningDocId, `stub:${i}`);
            return d ? (
              <path
                key={`stub-edge-${i}`}
                d={d}
                fill="none"
                strokeDasharray="3 3"
                strokeWidth={1.2}
                className="stroke-slate-300 dark:stroke-slate-600"
                opacity={dimEdges ? 0.5 : 0.9}
              />
            ) : null;
          })}

          {layout.docs.map((doc) => (
            <MapNode
              key={doc.docId}
              ws={ws}
              doc={doc}
              metrics={metrics}
              compact={compact}
              selected={doc.docId === selectedDocId}
              highlighted={matches?.has(doc.docId) ?? false}
              dimmed={matches !== null && !matches.has(doc.docId)}
              truncate={truncate}
              onHover={setHovered}
              onSelect={() => {
                if (!wasDrag()) selectTarget({ kind: 'document', docId: doc.docId });
              }}
              onOpen={() => revealDocument(doc.docId)}
              onToggle={() => toggleExpand(doc.docId)}
            />
          ))}

          {layout.stubs.map((stub, i) => (
            <g
              key={`stub-${i}`}
              transform={`translate(${stub.x}, ${stub.y})`}
              className="cursor-pointer"
              onClick={() => {
                if (!wasDrag()) {
                  selectTarget({
                    kind: 'placeholder',
                    owningDocId: stub.owningDocId,
                    docRef: stub.docRef,
                    spdxId: null,
                  });
                }
              }}
            >
              <title>{`${stub.docRef} — not loaded`}</title>
              <rect
                width={metrics.nodeW}
                height={metrics.nodeH}
                rx={5}
                strokeDasharray="3 3"
                className="fill-transparent stroke-slate-300 hover:stroke-amber-400 dark:stroke-slate-600"
              />
              <text
                x={10}
                y={metrics.nodeH / 2 + 3.5}
                className="fill-slate-400 text-[10px] italic dark:fill-slate-500"
              >
                {truncate(stub.docRef.replace(/^DocumentRef-/, ''))}
              </text>
            </g>
          ))}
        </svg>

        <div className="absolute top-3 left-3 flex items-center gap-2">
          <div className="flex gap-1">
            <ToolButton onClick={() => zoomBy(1 / 1.3)} title="Zoom in" label="+" />
            <ToolButton onClick={() => zoomBy(1.3)} title="Zoom out" label="−" />
            <ToolButton onClick={fit} title="Fit graph to view" label="Fit" wide />
            <ToolButton
              onClick={() => setExpandedDocs(new Set(graph.nodes.map((n) => n.docId)))}
              title="Expand all documents"
              label="Expand all"
              wide
            />
            <ToolButton
              onClick={() => setExpandedDocs(defaultExpansion(graph, 0))}
              title="Collapse to roots"
              label="Collapse"
              wide
            />
          </div>
          <div className="rounded border border-slate-200 bg-white/90 px-2 py-1 text-[10px] text-slate-400 dark:border-slate-700 dark:bg-slate-900/90 dark:text-slate-500">
            {formatCount(layout.docs.length)}/{formatCount(graph.nodes.length)} docs
            {graph.stubs.length > 0 && ` · ${formatCount(graph.stubs.length)} missing`}
            <span className="mx-1.5 text-slate-200 dark:text-slate-700">|</span>
            <LegendLine dash={undefined} /> checksum
            <LegendLine dash="5 4" /> namespace
            <LegendLine dash="2 3" /> manual
          </div>
        </div>
      </div>

      <aside className="w-[22rem] shrink-0 border-l border-slate-200 dark:border-slate-800">
        <DetailPane />
      </aside>
    </div>
  );
}

function MapNode({
  ws,
  doc,
  metrics,
  compact,
  selected,
  highlighted,
  dimmed,
  truncate,
  onHover,
  onSelect,
  onOpen,
  onToggle,
}: {
  ws: WorkspaceState;
  doc: PlacedDoc;
  metrics: MapMetrics;
  compact: boolean;
  selected: boolean;
  highlighted: boolean;
  dimmed: boolean;
  truncate: (s: string) => string;
  onHover: (id: DocumentId | null) => void;
  onSelect: () => void;
  onOpen: () => void;
  onToggle: () => void;
}) {
  const loaded = ws.documents.get(doc.docId);
  if (!loaded) return null;
  const name = loaded.document.name;
  const pkgs = loaded.indexes.packageCount;
  const isRoot = doc.level === 0;

  return (
    <g
      transform={`translate(${doc.x}, ${doc.y})`}
      className="cursor-pointer"
      opacity={dimmed ? 0.35 : 1}
      onPointerEnter={() => onHover(doc.docId)}
      onPointerLeave={() => onHover(null)}
      onClick={onSelect}
      onDoubleClick={onOpen}
    >
      <title>{`${name} — ${formatCount(pkgs)} packages${isRoot ? ' (root)' : ''}\nDouble-click: open in Explore${doc.hasChildren ? ' · chevron: expand/collapse' : ''}`}</title>
      <rect
        width={metrics.nodeW}
        height={metrics.nodeH}
        rx={5}
        strokeWidth={selected ? 1.8 : highlighted ? 1.6 : 1}
        className={clsx(
          selected
            ? 'fill-accent-100 stroke-accent-500 dark:fill-accent-900/50 dark:stroke-accent-400'
            : highlighted
              ? 'fill-amber-50 stroke-amber-400 dark:fill-amber-950/40 dark:stroke-amber-500'
              : 'fill-white stroke-slate-300 hover:fill-slate-50 dark:fill-slate-900 dark:stroke-slate-600 dark:hover:fill-slate-800',
        )}
      />
      <rect
        x={3}
        y={3}
        width={3.5}
        height={metrics.nodeH - 6}
        rx={1.75}
        className={docAccent(name).fill}
      />
      <text
        x={10}
        y={compact ? metrics.nodeH / 2 + 3.5 : 15}
        className={clsx(
          'text-[11px]',
          selected ? 'fill-accent-900 font-medium dark:fill-accent-100' : 'fill-slate-700 dark:fill-slate-200',
        )}
      >
        {truncate(name)}
      </text>
      {!compact && (
        <text x={10} y={28} className="fill-slate-400 text-[9px] dark:fill-slate-500">
          {formatCount(pkgs)} pkgs{isRoot ? ' · root' : ''}
        </text>
      )}

      {doc.hasChildren && (
        <g
          transform={`translate(${metrics.nodeW - 1}, ${metrics.nodeH / 2})`}
          onClick={(e) => {
            e.stopPropagation();
            onToggle();
          }}
          onDoubleClick={(e) => e.stopPropagation()}
        >
          <circle
            r={compact ? 8 : 9}
            className="fill-white stroke-slate-300 hover:stroke-accent-500 dark:fill-slate-900 dark:stroke-slate-600"
            strokeWidth={1}
          />
          {doc.expanded ? (
            <path d="M -3 0 L 3 0" className="stroke-slate-500 dark:stroke-slate-400" strokeWidth={1.4} />
          ) : (
            <text
              y={3}
              textAnchor="middle"
              className="fill-slate-500 text-[8px] font-medium dark:fill-slate-400"
            >
              +{doc.hiddenChildren}
            </text>
          )}
        </g>
      )}
    </g>
  );
}

function ToolButton({
  onClick,
  title,
  label,
  wide = false,
}: {
  onClick: () => void;
  title: string;
  label: string;
  wide?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      className={clsx(
        'grid h-7 place-items-center rounded border border-slate-200 bg-white text-slate-500 hover:text-slate-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400 dark:hover:text-slate-200',
        wide ? 'px-2 text-[11px]' : 'w-7 text-sm',
      )}
    >
      {label}
    </button>
  );
}

function LegendLine({ dash }: { dash: string | undefined }) {
  return (
    <svg width="18" height="6" className="ml-1.5 inline first:ml-0">
      <line x1="0" y1="3" x2="18" y2="3" className="stroke-slate-400" strokeWidth="1.4" strokeDasharray={dash} />
    </svg>
  );
}

function docIdOfSelection(target: { kind: string } & Record<string, unknown>): DocumentId | null {
  switch (target.kind) {
    case 'document':
    case 'extraRefs':
      return target.docId as DocumentId;
    case 'placeholder':
      return target.owningDocId as DocumentId;
    default:
      return null;
  }
}

function useSvgPanZoom(contentW: number, contentH: number) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [viewBox, setViewBox] = useState<ViewBox | null>(null);
  const moved = useRef(false);
  const drag = useRef<{ px: number; py: number; pointerId: number; start: ViewBox } | null>(null);

  const fit = useCallback(() => {
    const el = svgRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;
    const scale = Math.min(rect.width / (contentW + 48), rect.height / (contentH + 48), 1.25);
    const w = rect.width / scale;
    const h = rect.height / scale;
    setViewBox({ x: (contentW - w) / 2, y: (contentH - h) / 2, w, h });
  }, [contentW, contentH]);

  useLayoutEffect(fit, [fit]);

  const onPointerDown = (e: React.PointerEvent<SVGSVGElement>) => {
    if (e.button !== 0 || !viewBox) return;
    moved.current = false;
    drag.current = { px: e.clientX, py: e.clientY, pointerId: e.pointerId, start: viewBox };
    // Capture starts lazily on first movement — capturing here would retarget
    // the click event to the svg and break node selection.
  };
  const onPointerMove = (e: React.PointerEvent<SVGSVGElement>) => {
    const d = drag.current;
    const el = svgRef.current;
    if (!d || !el) return;
    if (!moved.current && Math.abs(e.clientX - d.px) + Math.abs(e.clientY - d.py) > 4) {
      moved.current = true;
      el.setPointerCapture(d.pointerId);
    }
    if (!moved.current) return;
    const k = d.start.w / el.clientWidth;
    setViewBox({
      ...d.start,
      x: d.start.x - (e.clientX - d.px) * k,
      y: d.start.y - (e.clientY - d.py) * k,
    });
  };
  const onPointerUp = () => {
    drag.current = null;
  };

  // Wheel zoom keeping the point under the cursor fixed. Native non-passive
  // listener — React root wheel handlers are passive.
  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      setViewBox((vb) => {
        if (!vb) return vb;
        const rect = el.getBoundingClientRect();
        const factor = Math.exp(e.deltaY * 0.0015);
        const w = clamp(vb.w * factor, rect.width / MAX_SCALE, rect.width / MIN_SCALE);
        const f = w / vb.w;
        const cx = vb.x + ((e.clientX - rect.left) / rect.width) * vb.w;
        const cy = vb.y + ((e.clientY - rect.top) / rect.height) * vb.h;
        return { x: cx - (cx - vb.x) * f, y: cy - (cy - vb.y) * f, w, h: vb.h * f };
      });
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, []);

  const zoomBy = (factor: number) => {
    setViewBox((vb) => {
      const el = svgRef.current;
      if (!vb || !el) return vb;
      const rect = el.getBoundingClientRect();
      const w = clamp(vb.w * factor, rect.width / MAX_SCALE, rect.width / MIN_SCALE);
      const f = w / vb.w;
      const cx = vb.x + vb.w / 2;
      const cy = vb.y + vb.h / 2;
      return { x: cx - (cx - vb.x) * f, y: cy - (cy - vb.y) * f, w, h: vb.h * f };
    });
  };

  return {
    svgRef,
    viewBox,
    fit,
    zoomBy,
    wasDrag: () => moved.current,
    handlers: { onPointerDown, onPointerMove, onPointerUp },
  };
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}
