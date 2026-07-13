import type { DocumentIndexes } from '../graph/indexes';
import type { SbomDocument } from '../model/document';
import { diag } from '../model/diagnostics';
import type { DocumentId } from '../model/ids';
import { makeElementId } from '../model/ids';
import type { RefResolution } from './resolve';
import { computeResolutions, splitRefKey } from './resolve';

export interface DocumentSource {
  fileName: string;
  byteSize: number;
  /** Lowercase hex SHA-1 of the raw bytes. */
  sha1: string;
  /** Original text, retained for the source view. */
  text: string;
}

export interface LoadedDocument {
  document: SbomDocument;
  indexes: DocumentIndexes;
  source: DocumentSource;
}

/**
 * Immutable snapshot of everything loaded. Mutations return a new snapshot
 * with resolutions recomputed — a late-arriving child document re-parents
 * automatically, with no incremental bookkeeping to get wrong.
 */
export interface WorkspaceState {
  documents: ReadonlyMap<DocumentId, LoadedDocument>;
  /** Insertion order, for stable roots and suggestion precedence. */
  order: readonly DocumentId[];
  bySha1: ReadonlyMap<string, DocumentId>;
  /** refKey → user-chosen target document. */
  manualBindings: ReadonlyMap<string, DocumentId>;
  /** refKey → resolution, recomputed on every change. */
  resolutions: ReadonlyMap<string, RefResolution>;
}

export const emptyWorkspace: WorkspaceState = {
  documents: new Map(),
  order: [],
  bySha1: new Map(),
  manualBindings: new Map(),
  resolutions: new Map(),
};

export interface AddResult {
  workspace: WorkspaceState;
  outcome: 'added' | 'duplicate';
  documentId: DocumentId;
}

export interface BatchAddResult {
  workspace: WorkspaceState;
  added: DocumentId[];
  /** Byte-identical re-drops, skipped. */
  duplicates: number;
}

/**
 * Adds many documents with a single resolution recompute — loading a whole
 * cascade folder is one workspace commit, not N.
 */
export function addDocuments(
  ws: WorkspaceState,
  incoming: readonly LoadedDocument[],
): BatchAddResult {
  const documents = new Map(ws.documents);
  const order = [...ws.order];
  const bySha1 = new Map(ws.bySha1);
  const added: DocumentId[] = [];
  let duplicates = 0;

  for (const candidate of incoming) {
    const sha1 = candidate.source.sha1;
    if (bySha1.has(sha1)) {
      duplicates++;
      continue;
    }
    let loaded = candidate;
    if (documents.has(loaded.document.id)) {
      // Same namespace, different content — a producer bug worth surfacing,
      // but both documents stay usable under distinct ids.
      const newId = `${loaded.document.id}~dup-${sha1.slice(0, 8)}` as DocumentId;
      loaded = remapDocumentId(loaded, newId);
      loaded.document.diagnostics.push(
        diag(
          'warning',
          'DOC_NAMESPACE_COLLISION',
          'Another loaded document has the same namespace but different content; this one was given a distinct id.',
        ),
      );
    }
    documents.set(loaded.document.id, loaded);
    order.push(loaded.document.id);
    bySha1.set(sha1, loaded.document.id);
    added.push(loaded.document.id);
  }

  if (added.length === 0) {
    return { workspace: ws, added, duplicates };
  }
  return {
    workspace: withResolutions({ ...ws, documents, order, bySha1 }),
    added,
    duplicates,
  };
}

export function addDocument(ws: WorkspaceState, incoming: LoadedDocument): AddResult {
  const existing = ws.bySha1.get(incoming.source.sha1);
  if (existing) {
    return { workspace: ws, outcome: 'duplicate', documentId: existing };
  }
  const result = addDocuments(ws, [incoming]);
  return { workspace: result.workspace, outcome: 'added', documentId: result.added[0]! };
}

/** Batch removal with a single resolution recompute. */
export function removeDocuments(
  ws: WorkspaceState,
  docIds: ReadonlySet<DocumentId>,
): WorkspaceState {
  const removed = [...docIds].filter((id) => ws.documents.has(id));
  if (removed.length === 0) return ws;
  const removedSet = new Set(removed);

  const documents = new Map(ws.documents);
  const bySha1 = new Map(ws.bySha1);
  for (const docId of removed) {
    const loaded = ws.documents.get(docId)!;
    documents.delete(docId);
    bySha1.delete(loaded.source.sha1);
  }
  const order = ws.order.filter((id) => !removedSet.has(id));
  const manualBindings = new Map(ws.manualBindings);
  for (const [key, target] of manualBindings) {
    if (removedSet.has(target) || removedSet.has(splitRefKey(key).docId)) {
      manualBindings.delete(key);
    }
  }

  return withResolutions({ ...ws, documents, order, bySha1, manualBindings });
}

export function removeDocument(ws: WorkspaceState, docId: DocumentId): WorkspaceState {
  return removeDocuments(ws, new Set([docId]));
}

/** Binds (or with null, unbinds) an external ref to a loaded document. */
export function bindRef(
  ws: WorkspaceState,
  key: string,
  targetDocId: DocumentId | null,
): WorkspaceState {
  const manualBindings = new Map(ws.manualBindings);
  if (targetDocId === null) manualBindings.delete(key);
  else manualBindings.set(key, targetDocId);
  return withResolutions({ ...ws, manualBindings });
}

/** Documents that no resolved ref of another document points to — the tree roots. */
export function workspaceRoots(ws: WorkspaceState): DocumentId[] {
  const children = new Set<DocumentId>();
  for (const [key, resolution] of ws.resolutions) {
    if (resolution.status !== 'resolved') continue;
    if (splitRefKey(key).docId === resolution.targetDocId) continue;
    children.add(resolution.targetDocId);
  }
  return ws.order.filter((id) => !children.has(id));
}

function withResolutions(ws: WorkspaceState): WorkspaceState {
  return {
    ...ws,
    resolutions: computeResolutions(ws.documents, ws.order, ws.bySha1, ws.manualBindings),
  };
}

function remapDocumentId(loaded: LoadedDocument, newId: DocumentId): LoadedDocument {
  const document: SbomDocument = {
    ...loaded.document,
    id: newId,
    elements: loaded.document.elements.map((el) => ({
      ...el,
      id: makeElementId(newId, el.spdxId),
      documentId: newId,
    })),
  };
  // Indexes key by spdxId only, so they survive the remap unchanged.
  return { document, indexes: loaded.indexes, source: loaded.source };
}
