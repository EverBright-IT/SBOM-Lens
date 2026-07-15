import type { SbomDocument, SpecFieldDoc } from '@sbomlens/core';
import { SPDX23_DOCS } from '@sbomlens/core';
import { OCM_DOCS } from '@sbomlens/core/ocm';
import { HAS_DELIVERIES } from '../../app/brand';

/**
 * Field documentation per document model: SPDX documents get the SPDX-2.3
 * texts (deep links into spdx.github.io), OCM component descriptors get the
 * hand-curated OCM set (links into the ocm-spec). Keys mirror the SPDX
 * lookups, so call sites stay one-liners; a missing key simply renders no ⓘ.
 * A product without deliveries can never hold a descriptor, so its build
 * folds this to the SPDX set and drops the OCM texts.
 */
export interface SpecDocs {
  document: Record<string, SpecFieldDoc>;
  package: Record<string, SpecFieldDoc>;
  file: Record<string, SpecFieldDoc>;
  relationshipType?: SpecFieldDoc;
}

export function docsFor(doc: SbomDocument): SpecDocs {
  return HAS_DELIVERIES && doc.spec.model === 'ocm' ? OCM_DOCS : SPDX23_DOCS;
}
