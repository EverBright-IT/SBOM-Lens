import { useRef, useState } from 'react';
import type { DocumentId, NodeTarget, WorkspaceState } from '@sbomlens/core';
import { refKey, refToString } from '@sbomlens/core';
import { makeElementId } from '@sbomlens/core';
import { HAS_DELIVERIES } from '../../app/brand';
import { ingestFiles, ingestUrl } from '../../app/ingest';
import { useAppStore } from '../../app/store';
import { revealElement, selectTarget } from '../navigate';
import { LinkIcon, UploadIcon } from '../icons';
import { CopyButton, FieldRow, Section } from './FieldRow';

type PlaceholderTarget = Extract<NodeTarget, { kind: 'placeholder' }>;

/** Fetching only works for web URLs — ocm:// refs resolve by loading the delivery. */
function isFetchableUri(uri: string): boolean {
  const scheme = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(uri)?.[1];
  return scheme === undefined || scheme === 'http' || scheme === 'https';
}

/**
 * An external document reference whose file isn't loaded yet. First-class UX:
 * everything needed to resolve it — fetch its URL, drop/pick the file, or
 * confirm a suggested match.
 */
export function PlaceholderDetail({ ws, target }: { ws: WorkspaceState; target: PlaceholderTarget }) {
  const actions = useAppStore((s) => s.actions);
  const [fetchState, setFetchState] = useState<'idle' | 'busy' | string>('idle');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const owning = ws.documents.get(target.owningDocId);
  const ref = owning?.document.externalDocumentRefs.find((r) => r.docRef === target.docRef);
  const key = refKey(target.owningDocId, target.docRef);
  const resolution = ws.resolutions.get(key);
  const suggestion = resolution?.status === 'unresolved' ? resolution.suggestion : undefined;
  const suggestedDoc = suggestion ? ws.documents.get(suggestion.docId) : undefined;

  const bindTo = (docId: typeof target.owningDocId) => {
    actions.bindManualRef(key, docId);
    actions.toast(`Bound ${target.docRef}`, 'success');
  };

  const revealResolved = () => {
    const state = useAppStore.getState();
    const res = state.ws.resolutions.get(key);
    if (res?.status !== 'resolved') return;
    const targetDoc = state.ws.documents.get(res.targetDocId);
    const rootSpdxId = target.spdxId ?? targetDoc?.document.describes[0];
    if (!targetDoc) return;
    if (rootSpdxId && targetDoc.indexes.elementBySpdxId.has(rootSpdxId)) {
      revealElement(makeElementId(targetDoc.document.id, rootSpdxId));
    } else if (targetDoc.document.describes[0]) {
      revealElement(makeElementId(targetDoc.document.id, targetDoc.document.describes[0]));
    }
  };

  const afterLoad = (addedIds: readonly DocumentId[]) => {
    const state = useAppStore.getState();
    const nowResolved = state.ws.resolutions.get(key)?.status === 'resolved';
    if (!nowResolved) {
      const added = addedIds[0];
      if (added && state.ws.documents.has(added)) {
        actions.bindManualRef(key, added);
        actions.toast(
          `Bound ${target.docRef} manually. Its checksum does not match the reference`,
          'info',
        );
      }
    }
    revealResolved();
  };

  const fetchNow = async () => {
    if (!ref?.uri) return;
    setFetchState('busy');
    const result = await ingestUrl(ref.uri);
    if (!result.ok) {
      setFetchState(result.message ?? 'Fetch failed.');
      return;
    }
    setFetchState('idle');
    afterLoad(result.documentId ? [result.documentId] : []);
  };

  return (
    <div className="space-y-3">
      <Section title="Unresolved external document">
        <FieldRow label="Reference id" value={target.docRef} mono />
        {target.spdxId && <FieldRow label="Referenced element" value={target.spdxId} mono />}
        <FieldRow label="Referenced from" value={owning?.document.name} />
        {ref?.checksum && (
          <FieldRow label={`Expected ${ref.checksum.algorithm}`} value={ref.checksum.value} mono copyable />
        )}
        {ref?.uri && (
          <div className="grid grid-cols-[9rem_1fr] items-baseline gap-x-3 py-1">
            <div className="text-xs text-slate-400 dark:text-slate-500">Location</div>
            <div className="flex min-w-0 items-baseline gap-1 font-mono text-xs break-all text-slate-600 dark:text-slate-300">
              {ref.uri}
              <CopyButton text={ref.uri} />
            </div>
          </div>
        )}
      </Section>

      <Section title="Resolve it">
        {HAS_DELIVERIES && ref?.uri.startsWith('ocm://') && (
          <p className="mb-2 text-xs text-slate-500 dark:text-slate-400">
            This is an OCM component reference — load the delivery (CTF/component archive)
            or the referenced component descriptor to resolve it.
          </p>
        )}
        <div className="flex flex-wrap items-center gap-2">
          {ref?.uri && isFetchableUri(ref.uri) && (
            <button
              type="button"
              disabled={fetchState === 'busy'}
              onClick={() => void fetchNow()}
              className="inline-flex items-center gap-1.5 rounded border border-accent-300 bg-accent-50 px-2.5 py-1.5 text-xs font-medium text-accent-800 hover:bg-accent-100 disabled:opacity-50 dark:border-accent-800 dark:bg-accent-950/60 dark:text-accent-200 dark:hover:bg-accent-900/50"
            >
              <LinkIcon /> {fetchState === 'busy' ? 'Fetching...' : 'Fetch from URL'}
            </button>
          )}
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="inline-flex items-center gap-1.5 rounded border border-slate-300 px-2.5 py-1.5 text-xs font-medium text-slate-600 hover:border-slate-400 dark:border-slate-700 dark:text-slate-300 dark:hover:border-slate-500"
          >
            <UploadIcon /> Load the file...
          </button>
          <input
            ref={fileInputRef}
            type="file"
            hidden
            multiple
            accept=".spdx,.json,.yaml,.yml,.tar,.tgz,.gz,.ctf"
            onChange={(e) => {
              const files = [...(e.target.files ?? [])];
              e.target.value = '';
              void ingestFiles(files).then(afterLoad);
            }}
          />
        </div>

        {typeof fetchState === 'string' && fetchState !== 'idle' && fetchState !== 'busy' && (
          <div className="mt-2 rounded border border-amber-200 bg-amber-50 p-2 text-xs text-amber-800 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-200">
            {fetchState}
            {ref?.uri && (
              <button
                type="button"
                className="mt-1 block text-amber-900 underline dark:text-amber-100"
                onClick={() => actions.openUrlDialog(ref.uri)}
              >
                Retry with an access token…
              </button>
            )}
          </div>
        )}

        {suggestedDoc && (
          <div className="mt-2 rounded border border-slate-200 bg-slate-50 p-2 text-xs dark:border-slate-700 dark:bg-slate-900">
            <span className="text-slate-500 dark:text-slate-400">
              Already loaded and {suggestion!.reason}:
            </span>{' '}
            <span className="font-medium">{suggestedDoc.document.name}</span>
            <button
              type="button"
              onClick={() => bindTo(suggestion!.docId)}
              className="ml-2 rounded border border-slate-300 px-1.5 py-0.5 text-[11px] hover:border-accent-400 hover:text-accent-700 dark:border-slate-600 dark:hover:border-accent-600 dark:hover:text-accent-400"
            >
              Use this document
            </button>
          </div>
        )}
      </Section>

      {owning && <IncomingRefRelationships ws={ws} owningDocId={target.owningDocId} docRef={target.docRef} />}
    </div>
  );
}

function IncomingRefRelationships({
  ws,
  owningDocId,
  docRef,
}: {
  ws: WorkspaceState;
  owningDocId: PlaceholderTarget['owningDocId'];
  docRef: string;
}) {
  const owning = ws.documents.get(owningDocId);
  if (!owning) return null;
  const edges = owning.indexes.externalEdges.filter(
    (e) =>
      (e.from.kind === 'external' && e.from.docRef === docRef) ||
      (e.to.kind === 'external' && e.to.docRef === docRef),
  );
  if (edges.length === 0) {
    return (
      <Section title="Relationships">
        <p className="text-xs text-slate-400">
          No relationship points into this reference — it is informational (a scan report,
          attestation, or similar).
        </p>
      </Section>
    );
  }
  return (
    <Section title={`Referenced by (${edges.length})`}>
      <div className="space-y-0.5">
        {edges.map((edge, i) => (
          <div key={i} className="flex items-baseline gap-2 truncate text-xs">
            <button
              type="button"
              className="shrink-0 font-medium text-accent-700 hover:underline dark:text-accent-400"
              onClick={() => selectTarget({ kind: 'document', docId: owningDocId })}
            >
              {refToString(edge.from)}
            </button>
            <span className="shrink-0 font-mono text-[11px] text-slate-400">{edge.type}</span>
            <span className="truncate text-slate-500">{refToString(edge.to)}</span>
          </div>
        ))}
      </div>
    </Section>
  );
}
