/**
 * SPDXIDs are only unique within one document. Global identity is therefore
 * always (document, spdxId), flattened into a string for Map keys and
 * structured-clone-friendly transport.
 */
export type DocumentId = string & { readonly __brand: 'DocumentId' };
export type ElementId = string & { readonly __brand: 'ElementId' };

/**
 * A document is identified by its namespace. Documents without a namespace
 * get a synthetic-but-stable id derived from their content hash.
 */
export function makeDocumentId(namespace: string | null, sha1: string): DocumentId {
  const ns = namespace?.trim();
  return (ns ? ns : `urn:sbomlens:sha1:${sha1}`) as DocumentId;
}

export function makeElementId(documentId: DocumentId, spdxId: string): ElementId {
  return `${documentId}#${spdxId}` as ElementId;
}

export function splitElementId(id: ElementId): { documentId: DocumentId; spdxId: string } {
  // The documentId is a namespace URI (or urn:) and never carries a fragment,
  // so the FIRST '#' is our separator. The spdxId itself may be a full IRI
  // with its own '#fragment' (SPDX 3.x elements are IRIs), which is exactly
  // why lastIndexOf would split in the wrong place and lose the element.
  const i = id.indexOf('#');
  return { documentId: id.slice(0, i) as DocumentId, spdxId: id.slice(i + 1) };
}
