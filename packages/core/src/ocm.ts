/**
 * OCM surface — component descriptors, delivery archives, and the tar/gzip
 * plumbing they need. Deliberately NOT part of `@sbomlens/core`: nothing here
 * is reachable from the main barrel, so an SPDX-only product carries none of
 * it. Import it, then `registerOcmParser(parseOcmComponentDescriptor)` to
 * teach `parseDocument` about descriptors.
 *
 * The shared model keeps its `ocm?:` extension fields — types erase at build
 * time, so that costs a product that never imports this module nothing.
 */
export type { OcmParser } from './parse/parser';
export { registerOcmParser } from './parse/parser';

export type { OcmBlobContext } from './parse/ocm/cd';
export { ocmNamespace, parseOcmComponentDescriptor } from './parse/ocm/cd';
export type { DeliveryResult, PreparsedDoc } from './parse/ocm/archive';
export { readOcmDelivery } from './parse/ocm/archive';

export { gunzip } from './util/binary';
export type { TarEntry, TarResult } from './util/tar';
export { readTar } from './util/tar';

export type { OcmFieldDoc } from './spec/ocm-field-docs';
export { OCM_DOCS } from './spec/ocm-field-docs';
export { OCM_ESSENTIALS_PROFILE } from './profile/ocm';

export type {
  OcmAccessInfo,
  OcmDigest,
  OcmDocumentExt,
  OcmElementExt,
  OcmLabel,
  OcmReferenceExt,
  OcmRepositoryContext,
  OcmSignatureInfo,
} from './model/ocm';
