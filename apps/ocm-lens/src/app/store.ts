import { create } from 'zustand';
import type { Diagnostic } from '@sbomlens/core';
import type {
  AcceptanceSignatureEntry,
  OcmArtifact,
  OcmBundle,
  OcmCv,
  OcmCvId,
  PackageFilter,
  SbomAnalysis,
  SbomPackageList,
} from '@sbomlens/core/ocm';
import type { DigestCheckResult } from '../worker/protocol';

/**
 * One delivery at a time: the product's job is understanding THIS bundle.
 * Opening another delivery replaces the current one (the UI says so).
 */

export interface LoadedDelivery {
  bundle: OcmBundle;
  extracted: { fileName: string; bytes: Uint8Array }[];
  /** What the worker learned about each extracted SBOM, by its SHA-1. */
  sbomAnalyses: Record<string, SbomAnalysis>;
  /**
   * Package lists of analysed SBOMs, by SHA-1, read when the package views
   * or the report need them (null: the SBOM gave none).
   */
  sbomPackages: Record<string, SbomPackageList | null>;
  diagnostics: Diagnostic[];
}

/** Where the delivery's bytes can be re-read for on-demand blob extraction. */
export type SourceRef = { kind: 'blob'; blob: Blob } | { kind: 'url'; url: string };

export type MainView = 'dashboard' | 'components' | 'resources' | 'sboms' | 'packages' | 'verify';

export type PackageTab = 'packages' | 'licenses' | 'versions';

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
  /** The SBOM resource the SBOMs view details. */
  selectedSbom: ArtifactRef | null;
  /** A running SBOM analysis (after opening, or "Analyse now"). */
  sbomRun: { done: number; total: number } | null;
  /** Why the last SBOM analysis stopped, if it did. */
  sbomError: string | null;
  /** Package lists being read. */
  packageRun: { done: number; total: number } | null;
  /** Why reading package lists stopped, if it did. */
  packageError: string | null;
  /** The Packages view's filter and tab, kept while other views are visited. */
  packageFilter: PackageFilter;
  packageTab: PackageTab;
  /** Results of the last signature verification run for this delivery. */
  verification: VerificationRun | null;
  actions: {
    loadStarted(fileName: string): void;
    loadSucceeded(delivery: LoadedDelivery, sourceRef: SourceRef | null): void;
    loadFailed(fileName: string, diagnostics: Diagnostic[]): void;
    setView(view: MainView): void;
    selectCv(id: OcmCvId | null): void;
    selectArtifact(ref: ArtifactRef | null): void;
    /** Detail one SBOM resource in the SBOMs view. */
    selectSbom(ref: ArtifactRef | null): void;
    setVerification(run: VerificationRun | null): void;
    /** Fold on-demand digest verdicts back into the loaded bundle. */
    applyDigestResults(results: DigestCheckResult[]): void;
    /**
     * Fold SBOM analyses into the loaded delivery. `forExtracted` names the
     * delivery they were started for (its extracted list, replaced on every
     * open): results that arrive after another delivery opened are dropped.
     */
    applySbomAnalyses(analyses: Record<string, SbomAnalysis>, forExtracted?: LoadedDelivery['extracted']): void;
    setSbomRun(run: { done: number; total: number } | null): void;
    setSbomError(message: string | null): void;
    /** Fold package lists into the delivery they were read for (see applySbomAnalyses). */
    applySbomPackages(lists: Record<string, SbomPackageList | null>, forExtracted: LoadedDelivery['extracted']): void;
    setPackageRun(run: { done: number; total: number } | null): void;
    setPackageError(message: string | null): void;
    setPackageFilter(filter: PackageFilter): void;
    setPackageTab(tab: PackageTab): void;
    /** Open the package list with a filter (an artifact, an SBOM, a license). */
    showPackages(filter: PackageFilter): void;
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
  selectedSbom: null,
  sbomRun: null,
  sbomError: null,
  packageRun: null,
  packageError: null,
  packageFilter: {},
  packageTab: 'packages',
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
        selectedSbom: null,
        sbomRun: null,
        sbomError: null,
        packageRun: null,
        packageError: null,
        packageFilter: {},
        packageTab: 'packages',
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
    selectSbom(ref) {
      set((s) => ({ selectedSbom: ref, view: ref ? 'sboms' : s.view }));
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
    applySbomAnalyses(analyses, forExtracted) {
      set((s) =>
        s.delivery && (!forExtracted || s.delivery.extracted === forExtracted)
          ? { delivery: { ...s.delivery, sbomAnalyses: { ...s.delivery.sbomAnalyses, ...analyses } } }
          : {},
      );
    },
    setSbomRun(run) {
      set({ sbomRun: run });
    },
    setSbomError(message) {
      set({ sbomError: message });
    },
    applySbomPackages(lists, forExtracted) {
      set((s) =>
        s.delivery && s.delivery.extracted === forExtracted
          ? { delivery: { ...s.delivery, sbomPackages: { ...s.delivery.sbomPackages, ...lists } } }
          : {},
      );
    },
    setPackageRun(run) {
      set({ packageRun: run });
    },
    setPackageError(message) {
      set({ packageError: message });
    },
    setPackageFilter(filter) {
      set({ packageFilter: filter });
    },
    setPackageTab(tab) {
      set({ packageTab: tab });
    },
    showPackages(filter) {
      set({ packageFilter: filter, packageTab: 'packages', view: 'packages' });
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
        selectedSbom: null,
        sbomRun: null,
        sbomError: null,
        packageRun: null,
        packageError: null,
        packageFilter: {},
        packageTab: 'packages',
        verification: null,
      });
    },
  },
}));
