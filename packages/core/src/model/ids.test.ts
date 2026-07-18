import { describe, expect, it } from 'vitest';
import { makeElementId, splitElementId } from './ids';
import type { DocumentId } from './ids';

/**
 * The (document, spdxId) round-trip. The trap: an SPDX 3.x element's spdxId is
 * itself a full IRI carrying a '#fragment', so the elementId holds two '#'.
 * The documentId (a namespace URI or urn:) never carries a fragment, so the
 * FIRST '#' is always the separator.
 */
describe('makeElementId / splitElementId', () => {
  it('round-trips a plain SPDX 2.x SPDXID', () => {
    const doc = 'https://example.org/spdxdocs/app' as DocumentId;
    const id = makeElementId(doc, 'SPDXRef-Package');
    expect(splitElementId(id)).toEqual({ documentId: doc, spdxId: 'SPDXRef-Package' });
  });

  it('round-trips an SPDX 3.x IRI spdxId that contains its own fragment', () => {
    const doc = 'https://acme.example/doc/platform3-1.0.0' as DocumentId;
    const spdxId = 'https://acme.example/doc/platform3-1.0.0#pkg-platform';
    const id = makeElementId(doc, spdxId);
    // lastIndexOf('#') would have split here and lost the element in the tree.
    expect(splitElementId(id)).toEqual({ documentId: doc, spdxId });
  });

  it('round-trips a urn: document id', () => {
    const doc = 'urn:sbomlens:sha1:abc123' as DocumentId;
    const spdxId = 'https://other.example/doc#thing';
    expect(splitElementId(makeElementId(doc, spdxId))).toEqual({ documentId: doc, spdxId });
  });
});
