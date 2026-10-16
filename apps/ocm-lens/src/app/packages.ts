import { useMemo } from 'react';
import type { DeliveryPackages, SbomPackageList } from '@sbomlens/core/ocm';
import { deliveryPackages, packageWorkspace } from '@sbomlens/core/ocm';
import { useSbomEvidence } from './evidence';
import { useAppStore } from './store';

/**
 * The packages of the loaded delivery with where they ship. The workspace
 * is rebuilt only when package lists arrive, the places only when the
 * SBOM evidence changes (both are replaced, never mutated, by the store).
 */
export function useDeliveryPackages(): DeliveryPackages | null {
  const lists = useAppStore((s) => s.delivery?.sbomPackages);
  const evidence = useSbomEvidence();
  const ws = useMemo(
    () =>
      lists
        ? packageWorkspace(
            Object.values(lists).filter((list): list is SbomPackageList => list !== null),
          )
        : null,
    [lists],
  );
  return useMemo(
    () => (evidence && lists && ws ? deliveryPackages(evidence, lists, ws) : null),
    [evidence, lists, ws],
  );
}
