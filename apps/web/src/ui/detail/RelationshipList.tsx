import type { EdgeRec, ElementRef, LoadedDocument, WorkspaceState } from '@sbomlens/core';
import { makeElementId, refKey, refToString } from '@sbomlens/core';
import { revealElement, selectTarget } from '../navigate';
import { Section } from './FieldRow';
import { docsFor } from './specDocs';

interface RelationshipListProps {
  ws: WorkspaceState;
  loaded: LoadedDocument;
  spdxId: string;
}

export function RelationshipList({ ws, loaded, spdxId }: RelationshipListProps) {
  const outgoing = loaded.indexes.outgoing.get(spdxId) ?? [];
  const incoming = loaded.indexes.incoming.get(spdxId) ?? [];
  if (outgoing.length === 0 && incoming.length === 0) return null;

  return (
    <Section
      title={`Relationships (${outgoing.length + incoming.length})`}
      info={docsFor(loaded.document).relationshipType}
    >
      <div className="space-y-0.5">
        {outgoing.map((edge, i) => (
          <RelationshipRow key={`out-${i}`} ws={ws} loaded={loaded} edge={edge} direction="out" />
        ))}
        {incoming.map((edge, i) => (
          <RelationshipRow key={`in-${i}`} ws={ws} loaded={loaded} edge={edge} direction="in" />
        ))}
      </div>
    </Section>
  );
}

function RelationshipRow({
  ws,
  loaded,
  edge,
  direction,
}: {
  ws: WorkspaceState;
  loaded: LoadedDocument;
  edge: EdgeRec;
  direction: 'in' | 'out';
}) {
  const counterpart = direction === 'out' ? edge.to : edge.from;
  const { label, onClick } = describeCounterpart(ws, loaded, counterpart);

  return (
    <div className="flex items-baseline gap-2 text-[13px]" title={edge.type}>
      <span className="w-8 shrink-0 text-[10px] tracking-wide text-slate-300 uppercase dark:text-slate-600">
        {direction === 'out' ? 'out' : 'in'}
      </span>
      <span className="shrink-0 font-mono text-[11px] text-slate-400 dark:text-slate-500">
        {edge.type}
      </span>
      {onClick ? (
        <button
          type="button"
          onClick={onClick}
          className="min-w-0 truncate text-left text-accent-700 hover:underline dark:text-accent-400"
        >
          {label}
        </button>
      ) : (
        <span className="min-w-0 truncate text-slate-500 dark:text-slate-400">{label}</span>
      )}
    </div>
  );
}

function describeCounterpart(
  ws: WorkspaceState,
  loaded: LoadedDocument,
  ref: ElementRef,
): { label: string; onClick?: () => void } {
  if (ref.kind === 'special') return { label: ref.value === 'NOASSERTION' ? '—' : 'NONE' };

  if (ref.kind === 'local') {
    if (ref.spdxId === loaded.document.spdxId) return { label: `${loaded.document.name} (document)` };
    const index = loaded.indexes.elementBySpdxId.get(ref.spdxId);
    if (index === undefined) return { label: ref.spdxId };
    const element = loaded.document.elements[index]!;
    return {
      label: element.version ? `${element.name} ${element.version}` : element.name,
      onClick: () => revealElement(element.id),
    };
  }

  // External reference: resolved → jump into the target document; unresolved → placeholder.
  const resolution = ws.resolutions.get(refKey(loaded.document.id, ref.docRef));
  if (resolution?.status === 'resolved') {
    const target = ws.documents.get(resolution.targetDocId);
    if (target) {
      if (ref.spdxId && target.indexes.elementBySpdxId.has(ref.spdxId)) {
        const element =
          target.document.elements[target.indexes.elementBySpdxId.get(ref.spdxId)!]!;
        return {
          label: `${element.name} · ${target.document.name}`,
          onClick: () => revealElement(makeElementId(target.document.id, element.spdxId)),
        };
      }
      return {
        label: `${target.document.name} (document)`,
        onClick: () => selectTarget({ kind: 'document', docId: target.document.id }),
      };
    }
  }
  return {
    label: `${refToString(ref)} (not loaded)`,
    onClick: () =>
      selectTarget({
        kind: 'placeholder',
        owningDocId: loaded.document.id,
        docRef: ref.docRef,
        spdxId: ref.spdxId,
      }),
  };
}
