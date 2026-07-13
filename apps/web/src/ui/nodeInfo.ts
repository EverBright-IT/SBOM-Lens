import type {
  DocumentId,
  ElementId,
  LoadedDocument,
  NodeTarget,
  SbomElement,
  WorkspaceState,
} from '@sbomlens/core';
import { splitElementId, splitRefKey } from '@sbomlens/core';

export function lookupDoc(ws: WorkspaceState, docId: DocumentId): LoadedDocument | null {
  return ws.documents.get(docId) ?? null;
}

export function lookupElement(
  ws: WorkspaceState,
  elementId: ElementId,
): { element: SbomElement; loaded: LoadedDocument } | null {
  const { documentId, spdxId } = splitElementId(elementId);
  const loaded = ws.documents.get(documentId);
  if (!loaded) return null;
  const index = loaded.indexes.elementBySpdxId.get(spdxId);
  if (index === undefined) return null;
  return { element: loaded.document.elements[index]!, loaded };
}

export type IconKind = 'document' | 'package' | 'file' | 'placeholder' | 'group' | 'cycle';

export interface TargetInfo {
  icon: IconKind;
  title: string;
  version?: string;
  /** Name of the owning document, for boundary badges. */
  docName?: string;
  docId?: DocumentId;
}

export function describeTarget(ws: WorkspaceState, target: NodeTarget): TargetInfo {
  switch (target.kind) {
    case 'document': {
      const loaded = lookupDoc(ws, target.docId);
      return {
        icon: 'document',
        title: loaded?.document.name ?? '(missing document)',
        docId: target.docId,
      };
    }
    case 'element': {
      const found = lookupElement(ws, target.elementId);
      if (!found) return { icon: 'package', title: '(missing element)' };
      return {
        icon: found.element.kind === 'file' ? 'file' : 'package',
        title: found.element.name,
        version: found.element.version,
        docName: found.loaded.document.name,
        docId: found.loaded.document.id,
      };
    }
    case 'placeholder':
      return { icon: 'placeholder', title: target.docRef, docId: target.owningDocId };
    case 'extraRefs':
      return { icon: 'group', title: 'External documents', docId: target.docId };
    case 'cycle': {
      const found = lookupElement(ws, target.elementId);
      return { icon: 'cycle', title: found ? found.element.name : '(cycle)' };
    }
  }
}

/** Rebuilds a selectable target from a tree-path node key (for breadcrumbs). */
export function targetFromKey(key: string): NodeTarget | null {
  const kind = key.slice(0, 2);
  const rest = key.slice(2);
  switch (kind) {
    case 'd:':
      return { kind: 'document', docId: rest as DocumentId };
    case 'e:':
      return { kind: 'element', elementId: rest as ElementId };
    case 'p:': {
      const { docId, docRef } = splitRefKey(rest);
      return { kind: 'placeholder', owningDocId: docId, docRef, spdxId: null };
    }
    case 'x:':
      return { kind: 'extraRefs', docId: rest as DocumentId };
    case 'c:':
      return { kind: 'cycle', elementId: rest as ElementId };
    default:
      return null;
  }
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatCount(n: number): string {
  return n.toLocaleString('en-US');
}
