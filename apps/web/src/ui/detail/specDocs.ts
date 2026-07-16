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

const NO_DOCS: SpecDocs = { document: {}, package: {}, file: {} };

export function docsFor(doc: SbomDocument): SpecDocs {
  if (HAS_DELIVERIES && doc.spec.model === 'ocm') return OCM_DOCS;
  // SPDX 3.x documents get no tooltips yet: linking a 3.0 field into the
  // 2.3 spec chapter would be confidently wrong. Curated 3.0.1 texts are a
  // follow-up; no icon beats a misleading one.
  if (doc.spec.model === 'spdx-3') return NO_DOCS;
  return SPDX23_DOCS;
}
