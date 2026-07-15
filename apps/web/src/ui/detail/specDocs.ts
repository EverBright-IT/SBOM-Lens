import type { SbomDocument, SpecFieldDoc } from '@sbomlens/core';
import { OCM_DOCS, SPDX23_DOCS } from '@sbomlens/core';

/**
 * Field documentation per document model: SPDX documents get the SPDX-2.3
 * texts (deep links into spdx.github.io), OCM component descriptors get the
 * hand-curated OCM set (links into the ocm-spec). Keys mirror the SPDX
 * lookups, so call sites stay one-liners; a missing key simply renders no ⓘ.
 */
export interface SpecDocs {
  document: Record<string, SpecFieldDoc>;
  package: Record<string, SpecFieldDoc>;
  file: Record<string, SpecFieldDoc>;
  relationshipType?: SpecFieldDoc;
}

export function docsFor(doc: SbomDocument): SpecDocs {
  return doc.spec.model === 'ocm' ? OCM_DOCS : SPDX23_DOCS;
}
