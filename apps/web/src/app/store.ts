import { create } from 'zustand';
import type {
  Diagnostic,
  DocumentId,
  ElementId,
  LoadedDocument,
  NodeTarget,
  WorkspaceState,
} from '@sbomlens/core';
import {
  addDocuments,
  bindRef,
  emptyWorkspace,
  pruneExpandedPaths,
  removalPlan,
  removeDocuments,
  splitElementId,
  targetDocId,
} from '@sbomlens/core';
import type { Catalog } from './catalog';
import type { StoredProfile } from './profiles';

export interface Selection {
  /** Tree path when the target is (also) visible in the tree. */
  path: string | null;
  target: NodeTarget;
}

export interface ToastItem {
  id: number;
  message: string;
  kind: 'info' | 'success' | 'error';
}

export interface IngestFailure {
  fileName: string;
  diagnostics: Diagnostic[];
}

/** Inventory filtered to one package's transitive subtree (across documents). */
export interface InventoryScope {
  rootId: ElementId;
  rootLabel: string;
  ids: ReadonlySet<ElementId>;
  capped: boolean;
}

interface AppState {
  ws: WorkspaceState;
  /** Monotonic counter — memoization key for everything derived from ws. */
  wsVersion: number;
  parsing: { active: number; total: number };
  /** Progress of a running "fetch all references" pass, null when idle. */
  refFetch: { done: number; total: number } | null;
  failures: IngestFailure[];

  view: 'explore' | 'map' | 'inventory' | 'conflicts' | 'diff';
  selection: Selection | null;
  expanded: ReadonlySet<string>;
  detailTab: 'overview' | 'source';
  sourceJumpLine: number | null;

  query: string;
  /** Explore: filter the tree in place instead of showing the results dropdown. */
  treeFilter: boolean;
  facetDocs: ReadonlySet<DocumentId> | null;
  facetKinds: ReadonlySet<'package' | 'file'> | null;
  facetPurposes: ReadonlySet<string> | null;
  facetLicenses: ReadonlySet<string> | null;
  /** When set, the Inventory shows only this package subtree. */
  inventoryScope: InventoryScope | null;

  diffA: DocumentId | null;
  diffB: DocumentId | null;

  diagnosticsOpen: boolean;
  helpOpen: boolean;
  urlDialogOpen: boolean;
  urlDialogPrefill: string;
  toasts: ToastItem[];
  /** Deployment catalog (sbomlens.catalog.json), when the host ships one. */
  catalog: Catalog | null;
  /** Imported/catalog compliance profiles (builtin NTIA lives in core). */
  profiles: StoredProfile[];
  /** Active profile id; null = builtin NTIA. */
  activeProfileId: string | null;
  /** Pending cascade-removal confirmation. */
  removalPrompt: { docIds: readonly DocumentId[] } | null;
  /** Manage-documents dialog visibility. */
  manageOpen: boolean;

  actions: {
    /** Batch commit: one workspace swap, one resolution recompute, one toast. */
    addLoadedBatch(loaded: readonly LoadedDocument[]): { added: DocumentId[]; duplicates: number };
    recordFailure(failure: IngestFailure): void;
    removeDoc(docId: DocumentId): void;
    removeDocs(docIds: readonly DocumentId[]): void;
    requestRemoval(docIds: readonly DocumentId[]): void;
    confirmRemoval(includeOrphans: boolean): void;
    cancelRemoval(): void;
    setManageOpen(open: boolean): void;
    clearAll(): void;
    bindManualRef(refKeyStr: string, target: DocumentId): void;

    select(selection: Selection | null): void;
    toggleExpand(path: string): void;
    expandPaths(paths: string[]): void;
    collapseAll(): void;
    setDetailTab(tab: 'overview' | 'source'): void;
    jumpToSource(target: NodeTarget, line: number): void;
    clearSourceJump(): void;

    setView(view: AppState['view']): void;
    setDiffSides(a: DocumentId | null, b: DocumentId | null): void;

    setQuery(query: string): void;
    setTreeFilter(on: boolean): void;
    toggleFacetDoc(docId: DocumentId): void;
    setFacetDocs(docIds: readonly DocumentId[] | null): void;
    setInventoryScope(scope: InventoryScope | null): void;
    toggleFacetKind(kind: 'package' | 'file'): void;
    toggleFacetPurpose(purpose: string): void;
    toggleFacetLicense(license: string): void;
    clearFacets(): void;

    parsingBegin(count: number): void;
    parsingDone(): void;
    setRefFetch(progress: { done: number; total: number } | null): void;

    setDiagnosticsOpen(open: boolean): void;
    setHelpOpen(open: boolean): void;
    openUrlDialog(prefill?: string): void;
    closeUrlDialog(): void;
    toast(message: string, kind?: ToastItem['kind']): void;
    dismissToast(id: number): void;
    setCatalog(catalog: Catalog): void;
    setProfiles(profiles: StoredProfile[]): void;
    setActiveProfileId(id: string | null): void;
  };
}

let toastCounter = 0;

export const useAppStore = create<AppState>()((set, get) => ({
  ws: emptyWorkspace,
  wsVersion: 0,
  parsing: { active: 0, total: 0 },
  refFetch: null,
  failures: [],

  view: 'explore',
  selection: null,
  expanded: new Set<string>(),
  detailTab: 'overview',
  sourceJumpLine: null,

  query: '',
  treeFilter: false,
  facetDocs: null,
  facetKinds: null,
  facetPurposes: null,
  facetLicenses: null,
  inventoryScope: null,

  diffA: null,
  diffB: null,

  diagnosticsOpen: false,
  helpOpen: false,
  urlDialogOpen: false,
  urlDialogPrefill: '',
  toasts: [],
  catalog: null,
  profiles: [],
  activeProfileId: null,
  removalPrompt: null,
  manageOpen: false,

  actions: {
    addLoadedBatch(loaded) {
      const { ws } = get();
      const resolvedBefore = countResolved(ws);
      const result = addDocuments(ws, loaded);
      if (result.added.length === 0) {
        return { added: [], duplicates: result.duplicates };
      }
      const resolvedAfter = countResolved(result.workspace);
      set((s) => ({ ws: result.workspace, wsVersion: s.wsVersion + 1 }));
      const gained = resolvedAfter - resolvedBefore;
      if (gained > 0) {
        get().actions.toast(
          `Resolved ${gained} external document reference${gained === 1 ? '' : 's'}`,
          'success',
        );
      }
      return { added: result.added, duplicates: result.duplicates };
    },
    recordFailure(failure) {
      set((s) => ({ failures: [...s.failures, failure] }));
    },
    removeDoc(docId) {
      get().actions.removeDocs([docId]);
    },
    removeDocs(docIds) {
      const removedSet = new Set(docIds);
      if (removedSet.size === 0) return;
      set((s) => {
        const ws = removeDocuments(s.ws, removedSet);
        if (ws === s.ws) return s;
        const selection =
          s.selection && !removedSet.has(targetDocId(s.selection.target)) ? s.selection : null;
        const facetDocs = s.facetDocs
          ? new Set([...s.facetDocs].filter((id) => !removedSet.has(id)))
          : null;
        const inventoryScope =
          s.inventoryScope &&
          removedSet.has(splitElementId(s.inventoryScope.rootId).documentId)
            ? null
            : s.inventoryScope;
        return {
          ws,
          wsVersion: s.wsVersion + 1,
          selection,
          expanded: pruneExpandedPaths(s.expanded, removedSet),
          facetDocs: facetDocs && facetDocs.size > 0 ? facetDocs : null,
          inventoryScope,
          diffA: s.diffA && removedSet.has(s.diffA) ? null : s.diffA,
          diffB: s.diffB && removedSet.has(s.diffB) ? null : s.diffB,
        };
      });
    },
    requestRemoval(docIds) {
      const plan = removalPlan(get().ws, new Set(docIds));
      if (plan.requested.length === 0) return;
      if (plan.orphaned.length > 0 || plan.requested.length > 1) {
        set({ removalPrompt: { docIds: plan.requested } });
      } else {
        get().actions.removeDocs(plan.requested);
        get().actions.toast('Removed 1 document', 'info');
      }
    },
    confirmRemoval(includeOrphans) {
      const prompt = get().removalPrompt;
      if (!prompt) return;
      const plan = removalPlan(get().ws, new Set(prompt.docIds));
      const ids = includeOrphans ? [...plan.requested, ...plan.orphaned] : plan.requested;
      set({ removalPrompt: null });
      get().actions.removeDocs(ids);
      const kept =
        !includeOrphans && plan.orphaned.length > 0
          ? `. Kept ${plan.orphaned.length} as new root${plan.orphaned.length === 1 ? '' : 's'}`
          : '';
      get().actions.toast(`Removed ${ids.length} document${ids.length === 1 ? '' : 's'}${kept}`, 'info');
    },
    cancelRemoval() {
      set({ removalPrompt: null });
    },
    setManageOpen(open) {
      set({ manageOpen: open });
    },
    clearAll() {
      set((s) => ({
        ws: emptyWorkspace,
        wsVersion: s.wsVersion + 1,
        failures: [],
        selection: null,
        expanded: new Set<string>(),
        query: '',
        facetDocs: null,
        facetKinds: null,
        facetPurposes: null,
        facetLicenses: null,
        inventoryScope: null,
        diffA: null,
        diffB: null,
      }));
    },
    bindManualRef(refKeyStr, target) {
      set((s) => ({ ws: bindRef(s.ws, refKeyStr, target), wsVersion: s.wsVersion + 1 }));
    },

    select(selection) {
      set({ selection, detailTab: 'overview', sourceJumpLine: null });
    },
    toggleExpand(path) {
      set((s) => {
        const expanded = new Set(s.expanded);
        if (expanded.has(path)) expanded.delete(path);
        else expanded.add(path);
        return { expanded };
      });
    },
    expandPaths(paths) {
      if (paths.length === 0) return;
      set((s) => {
        const expanded = new Set(s.expanded);
        for (const p of paths) expanded.add(p);
        return { expanded };
      });
    },
    collapseAll() {
      set({ expanded: new Set<string>() });
    },
    setDetailTab(tab) {
      set({ detailTab: tab });
    },
    jumpToSource(target, line) {
      set({ selection: { path: null, target }, detailTab: 'source', sourceJumpLine: line, diagnosticsOpen: false });
    },
    clearSourceJump() {
      set({ sourceJumpLine: null });
    },

    setView(view) {
      set({ view });
    },
    setDiffSides(a, b) {
      set({ diffA: a, diffB: b });
    },

    setQuery(query) {
      set({ query });
    },
    setTreeFilter(on) {
      set({ treeFilter: on });
    },
    toggleFacetDoc(docId) {
      set((s) => ({ facetDocs: toggleInSet(s.facetDocs, docId) }));
    },
    setFacetDocs(docIds) {
      set({ facetDocs: docIds && docIds.length > 0 ? new Set(docIds) : null });
    },
    setInventoryScope(scope) {
      set({ inventoryScope: scope });
    },
    toggleFacetKind(kind) {
      set((s) => ({ facetKinds: toggleInSet(s.facetKinds, kind) }));
    },
    toggleFacetPurpose(purpose) {
      set((s) => ({ facetPurposes: toggleInSet(s.facetPurposes, purpose) }));
    },
    toggleFacetLicense(license) {
      set((s) => ({ facetLicenses: toggleInSet(s.facetLicenses, license) }));
    },
    clearFacets() {
      set({ facetDocs: null, facetKinds: null, facetPurposes: null, facetLicenses: null });
    },

    parsingBegin(count) {
      set((s) => ({
        parsing: { active: s.parsing.active + count, total: s.parsing.total + count },
      }));
    },
    parsingDone() {
      set((s) => {
        const active = s.parsing.active - 1;
        return { parsing: { active, total: active === 0 ? 0 : s.parsing.total } };
      });
    },
    setRefFetch(progress) {
      set({ refFetch: progress });
    },

    setDiagnosticsOpen(open) {
      set({ diagnosticsOpen: open });
    },
    setHelpOpen(open) {
      set({ helpOpen: open });
    },
    openUrlDialog(prefill = '') {
      set({ urlDialogOpen: true, urlDialogPrefill: prefill });
    },
    closeUrlDialog() {
      set({ urlDialogOpen: false, urlDialogPrefill: '' });
    },
    toast(message, kind = 'info') {
      const id = ++toastCounter;
      set((s) => ({ toasts: [...s.toasts, { id, message, kind }] }));
      setTimeout(() => get().actions.dismissToast(id), 5000);
    },
    dismissToast(id) {
      set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
    },
    setCatalog(catalog) {
      set({ catalog });
    },
    setProfiles(profiles) {
      set({ profiles });
    },
    setActiveProfileId(id) {
      set({ activeProfileId: id });
    },
  },
}));

function toggleInSet<T>(current: ReadonlySet<T> | null, value: T): ReadonlySet<T> | null {
  const next = new Set(current ?? []);
  if (next.has(value)) next.delete(value);
  else next.add(value);
  return next.size === 0 ? null : next;
}

function countResolved(ws: WorkspaceState): number {
  let n = 0;
  for (const r of ws.resolutions.values()) if (r.status === 'resolved') n++;
  return n;
}
