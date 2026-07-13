import { useVirtualizer } from '@tanstack/react-virtual';
import { useEffect, useMemo, useRef } from 'react';
import type { NodeTarget, WorkspaceState } from '@sbomlens/core';
import { splitElementId } from '@sbomlens/core';
import { useAppStore } from '../../app/store';

const LINE_HEIGHT = 20;

/**
 * Virtualized raw-source view. Document nodes show the whole file (44k-line
 * documents included); elements show just their own slice.
 */
export function SourceView({ ws, target }: { ws: WorkspaceState; target: NodeTarget }) {
  const jumpLine = useAppStore((s) => s.sourceJumpLine);
  const clearSourceJump = useAppStore((s) => s.actions.clearSourceJump);

  const lines = useMemo(() => sourceLines(ws, target), [ws, target]);

  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: lines.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => LINE_HEIGHT,
    overscan: 30,
  });

  useEffect(() => {
    if (jumpLine !== null && jumpLine >= 1 && jumpLine <= lines.length) {
      virtualizer.scrollToIndex(jumpLine - 1, { align: 'center' });
    }
  }, [jumpLine, lines.length, virtualizer]);

  useEffect(() => () => clearSourceJump(), [clearSourceJump]);

  if (lines.length === 0) {
    return <p className="p-4 text-sm text-slate-400">No source available for this node.</p>;
  }

  const gutterWidth = `${Math.max(String(lines.length).length, 3)}ch`;

  return (
    <div ref={scrollRef} className="h-full overflow-auto font-mono text-xs leading-5">
      <div className="relative min-w-max" style={{ height: virtualizer.getTotalSize() }}>
        {virtualizer.getVirtualItems().map((item) => {
          const lineNo = item.index + 1;
          const highlighted = jumpLine === lineNo;
          return (
            <div
              key={item.index}
              className={`absolute inset-x-0 flex whitespace-pre ${
                highlighted ? 'bg-amber-100 dark:bg-amber-500/15' : ''
              }`}
              style={{ top: item.start, height: LINE_HEIGHT }}
            >
              <span
                className="sticky left-0 shrink-0 bg-white pr-3 pl-3 text-right text-slate-300 select-none dark:bg-slate-950 dark:text-slate-600"
                style={{ width: `calc(${gutterWidth} + 1.5rem)` }}
              >
                {lineNo}
              </span>
              <span className="pr-4 text-slate-700 dark:text-slate-300">{lines[item.index]}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function sourceLines(ws: WorkspaceState, target: NodeTarget): string[] {
  if (target.kind === 'document' || target.kind === 'extraRefs') {
    return ws.documents.get(target.docId)?.source.text.split(/\r\n|\r|\n/) ?? [];
  }
  if (target.kind === 'element' || target.kind === 'cycle') {
    const { documentId, spdxId } = splitElementId(target.elementId);
    const loaded = ws.documents.get(documentId);
    const index = loaded?.indexes.elementBySpdxId.get(spdxId);
    if (!loaded || index === undefined) return [];
    const raw = loaded.document.elements[index]!.raw;
    if (raw.kind === 'json') return JSON.stringify(raw.value, null, 2).split('\n');
    return raw.pairs.flatMap(([tag, value]) => {
      const valueLines = value.split('\n');
      return valueLines.length === 1
        ? [`${tag}: ${value}`]
        : [`${tag}: <text>`, ...valueLines.map((l) => `  ${l}`), '  </text>'];
    });
  }
  return [];
}
