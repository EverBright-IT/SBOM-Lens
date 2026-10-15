import { useMemo } from 'react';
import type { SbomEvidence } from '@sbomlens/core/ocm';
import { sbomEvidence } from '@sbomlens/core/ocm';
import { useAppStore } from './store';

/**
 * SBOM evidence of the loaded delivery: which SBOM describes which
 * artifact, and how strongly. Recomputed only when the bundle or the SBOM
 * analyses change (both are replaced, never mutated, by the store).
 */
export function useSbomEvidence(): SbomEvidence | null {
  const bundle = useAppStore((s) => s.delivery?.bundle);
  const analyses = useAppStore((s) => s.delivery?.sbomAnalyses);
  return useMemo(
    () => (bundle && analyses ? sbomEvidence(bundle, analyses) : null),
    [bundle, analyses],
  );
}
