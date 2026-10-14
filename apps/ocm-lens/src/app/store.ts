import { create } from 'zustand';
import type { Diagnostic } from '@sbomlens/core';
import type { AcceptanceSignatureEntry, OcmArtifact, OcmBundle, OcmCv, OcmCvId } from '@sbomlens/core/ocm';
import type { DigestCheckResult } from '../worker/protocol';

/**
 * One delivery at a time: the product's job is understanding THIS bundle.
 * Opening another delivery replaces the current one (the UI says so).
 */

export interface LoadedDelivery {
  bundle: OcmBundle;
  extracted: { fileName: string; bytes: Uint8Array }[];
  diagnostics: Diagnostic[];
}

/** Where the delivery's bytes can be re-read for on-demand blob extraction. */
export type SourceRef = { kind: 'blob'; blob: Blob } | { kind: 'url'; url: string };

export type MainView = 'dashboard' | 'components' | 'resources' | 'verify';

export interface ArtifactRef {
  cvId: OcmCvId;
  role: 'resource' | 'source';
  index: number;
}

export interface VerificationRun {
  at: string;
  entries: AcceptanceSignatureEntry[];
}

interface AppState {
  delivery: LoadedDelivery | null;
  sourceRef: SourceRef | null;
  /** File name while the worker is parsing; null when idle. */
  loading: string | null;
  /** The last open attempt that produced no bundle. */
  loadError: { fileName: string; diagnostics: Diagnostic[] } | null;
  view: MainView;
  selectedCv: OcmCvId | null;
  selectedArtifact: ArtifactRef | null;
  /** Results of the last signature verification run for this delivery. */
  verification: VerificationRun | null;
  actions: {
    loadStarted(fileName: string): void;
    loadSucceeded(delivery: LoadedDelivery, sourceRef: SourceRef | null): void;
    loadFailed(fileName: string, diagnostics: Diagnostic[]): void;
    setView(view: MainView): void;
    selectCv(id: OcmCvId | null): void;
    selectArtifact(ref: ArtifactRef | null): void;
    setVerification(run: VerificationRun | null): void;
    /** Fold on-demand digest verdicts back into the loaded bundle. */
    applyDigestResults(results: DigestCheckResult[]): void;
    reset(): void;
  };
}

export const useAppStore = create<AppState>((set) => ({
  delivery: null,
  sourceRef: null,
  loading: null,
  loadError: null,
  view: 'dashboard',
  selectedCv: null,
  selectedArtifact: null,
  verification: null,
  actions: {
    loadStarted(fileName) {
      set({ loading: fileName, loadError: null });
    },
    loadSucceeded(delivery, sourceRef) {
      set({
        delivery,
        sourceRef,
        loading: null,
        loadError: null,
        view: 'dashboard',
        selectedCv: delivery.bundle.roots[0] ?? delivery.bundle.componentVersions[0]?.id ?? null,
        selectedArtifact: null,
        verification: null,
      });
    },
    loadFailed(fileName, diagnostics) {
      set({ loading: null, loadError: { fileName, diagnostics } });
    },
    setView(view) {
      set({ view });
    },
    selectCv(id) {
      set({ selectedCv: id, view: 'components' });
    },
    selectArtifact(ref) {
      set((s) => ({ selectedArtifact: ref, view: ref ? 'resources' : s.view }));
    },
    setVerification(run) {
      set({ verification: run });
    },
    applyDigestResults(results) {
      set((s) => {
        if (!s.delivery || results.length === 0) return {};
        const verdicts = new Map(
          results.map((r) => [`${r.cvId}\u0000${r.role}\u0000${r.index}`, r.verdict]),
        );
        const patch = (cv: OcmCv, role: 'resource' | 'source', artifacts: OcmArtifact[]): OcmArtifact[] =>
          artifacts.map((artifact, index) => {
            const verdict = verdicts.get(`${cv.id}\u0000${role}\u0000${index}`);
            if (!verdict || !artifact.blob) return artifact;
            return { ...artifact, blob: { ...artifact.blob, digestCheck: verdict } };
          });
        const componentVersions = s.delivery.bundle.componentVersions.map((cv) => ({
          ...cv,
          resources: patch(cv, 'resource', cv.resources),
          sources: patch(cv, 'source', cv.sources),
        }));
        let blobs = 0;
        let bytes = 0;
        for (const cv of componentVersions) {
          for (const artifact of [...cv.resources, ...cv.sources]) {
            if (artifact.blob?.digestCheck === 'pending') {
              blobs++;
              bytes += artifact.blob.size;
            }
          }
        }
        const bundle: OcmBundle = {
          ...s.delivery.bundle,
          componentVersions,
          ...(blobs > 0 ? { digestsDeferred: { blobs, bytes } } : { digestsDeferred: undefined }),
        };
        return { delivery: { ...s.delivery, bundle } };
      });
    },
    reset() {
      set({
        delivery: null,
        sourceRef: null,
        loading: null,
        loadError: null,
        view: 'dashboard',
        selectedCv: null,
        selectedArtifact: null,
        verification: null,
      });
    },
  },
}));
