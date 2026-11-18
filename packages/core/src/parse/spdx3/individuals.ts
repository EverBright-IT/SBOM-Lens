/**
 * Named individuals of the SPDX 3 vocabulary: NoneElement and
 * NoAssertionElement as relationship ends, NoneLicense and NoAssertionLicense
 * as licences, SpdxOrganization as an agent.
 *
 * A document names one either by its IRI on spdx.org or by the short term
 * the official JSON-LD context defines for it ("NoneElement",
 * "expandedlicensing_NoneLicense"). `to`, the licence ends and the members of
 * a licence set are @vocab-typed in that context, so a compacting serializer
 * writes the short term. Anything else is an IRI of the document's own, even
 * when it happens to end in one of these names.
 */

const SPDX_HOST = /^https?:\/\/(?:rdf\.)?spdx\.org\//;
/** A context term: a bare name, with an optional profile prefix such as `expandedlicensing_`. */
const COMPACT_TERM = /^(?:[a-z]+_)?([A-Za-z]+)$/;

/** The vocabulary name a reference stands for ("NoneElement"), or undefined for a document's own IRI. */
export function vocabularyTerm(ref: string): string | undefined {
  if (SPDX_HOST.test(ref)) return ref.slice(Math.max(ref.lastIndexOf('/'), ref.lastIndexOf('#')) + 1);
  return COMPACT_TERM.exec(ref)?.[1];
}

const INDIVIDUALS = new Set(['NoneElement', 'NoAssertionElement', 'SpdxOrganization', 'NoneLicense', 'NoAssertionLicense']);

/** Whether a reference names an individual the vocabulary defines: such a reference never dangles. */
export function isVocabularyIndividual(ref: string): boolean {
  const term = vocabularyTerm(ref);
  return term !== undefined && INDIVIDUALS.has(term);
}
