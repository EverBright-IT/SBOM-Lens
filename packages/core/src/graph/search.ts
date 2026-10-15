import type { CpeMatchKey } from '../analysis/cpe';
import { cpeCovers, cpeMatchKey, elementCpeKeys } from '../analysis/cpe';
import { splitPurl } from '../analysis/purl';
import type { SbomDocument, SbomElement } from '../model/document';
import { effectiveLicense } from '../model/document';
import type { LicenseExpressionOptions } from '../parse/spec-lint';
import { licenseIdsInExpression } from '../parse/spec-lint';
import type { DocumentId } from '../model/ids';
import type { WorkspaceState } from '../workspace/workspace';

export interface SearchFacets {
  docs: ReadonlySet<DocumentId> | null;
  kinds: ReadonlySet<'package' | 'file'> | null;
  purposes: ReadonlySet<string> | null;
  licenses: ReadonlySet<string> | null;
  /**
   * Licence identifiers (the Licenses view drills down with these): an
   * element matches when its declared or concluded expression names one.
   */
  licenseIds: ReadonlySet<string> | null;
}

export const emptyFacets: SearchFacets = {
  docs: null,
  kinds: null,
  purposes: null,
  licenses: null,
  licenseIds: null,
};

export interface SearchHit {
  element: SbomElement;
  docId: DocumentId;
  score: number;
}

export interface SearchResult {
  hits: SearchHit[];
  /** Total matches before the limit cap. */
  total: number;
}

/** An identifier hit ranks just below an exact name: the query named this element. */
const IDENTITY_SCORE = 900;
/** A purl query that stops at a namespace (`pkg:apk/alpine`) lists what sits below it. */
const BELOW_PURL_SCORE = 700;

/** A query that names a component by identifier. Lowercased, like the query. */
type IdentifierQuery =
  | { kind: 'cpe'; key: CpeMatchKey }
  | { kind: 'purl'; segments: readonly string[]; version?: string };

/** What an element can be found by through an identifier query. Lowercased throughout. */
interface ElementIdentity {
  /** Purl path segments, type first and name last. */
  purl?: readonly string[];
  /** The purl's version, else the element's own. */
  purlVersion?: string;
  cpes: readonly CpeMatchKey[];
  /** The element's own version, standing in for a CPE that states none. */
  version?: string;
}

/**
 * Per-document element identities, built on the first identifier query only,
 * so a document that is never searched by purl or CPE never pays for parsing
 * them. Keyed by the immutable document object: a reload rebuilds the entry
 * and a removed document's entry is garbage-collected with it.
 */
const identityCache = new WeakMap<SbomDocument, readonly ElementIdentity[]>();

function identitiesOf(doc: SbomDocument): readonly ElementIdentity[] {
  let identities = identityCache.get(doc);
  if (!identities) {
    identities = doc.elements.map(elementIdentity);
    identityCache.set(doc, identities);
  }
  return identities;
}

/**
 * One linear pass over precomputed lowercase blobs. At ~50k elements this is
 * single-digit milliseconds — the old implementation's jank came from
 * re-rendering, not from scanning. Kept behind a small interface so an
 * inverted index could replace it if profiling ever demands one.
 *
 * A query that is an identifier searches by identity instead of substring,
 * because an advisory names a component by purl or CPE, mostly without a
 * version, and must find it whatever spelling the SBOM uses:
 * - a `pkg:` query compares whole path segments after percent-decoding,
 *   ignoring qualifiers and subpath: `pkg:npm/lodash` is lodash, never
 *   lodash-es, and a query that stops at a namespace (`pkg:apk/alpine`)
 *   lists everything below it;
 * - a CPE query (2.3 formatted string or 2.2 URI) compares part, vendor and
 *   product.
 * A versionless identifier covers every version; a versioned one needs the
 * same version string, from the element's identifier or, when that states
 * none, from the element itself. The parsers and the version rule are the
 * VEX overlay's, with letter case folded on top (and PyPI names normalised
 * as the purl spec demands), so search finds every element the overlay
 * matches by purl or CPE, and never fewer.
 */
export function searchWorkspace(
  ws: WorkspaceState,
  query: string,
  facets: SearchFacets = emptyFacets,
  limit = 500,
): SearchResult {
  const q = query.trim().toLowerCase();
  const idQuery = q === '' ? undefined : identifierQuery(q);
  const hits: SearchHit[] = [];

  for (const docId of ws.order) {
    if (facets.docs && !facets.docs.has(docId)) continue;
    const loaded = ws.documents.get(docId);
    if (!loaded) continue;
    const { elements } = loaded.document;
    const blobs = loaded.indexes.searchBlobs;
    const identities = idQuery ? identitiesOf(loaded.document) : null;
    const dialect = { spdx3: loaded.document.spec.model === 'spdx-3' };

    for (let i = 0; i < elements.length; i++) {
      const element = elements[i]!;
      if (facets.kinds && !facets.kinds.has(element.kind)) continue;
      if (facets.purposes && (!element.purpose || !facets.purposes.has(element.purpose))) continue;
      if (facets.licenses) {
        const license = effectiveLicense(element);
        if (!license || !facets.licenses.has(license)) continue;
      }
      if (facets.licenseIds && !namesLicenseId(element, facets.licenseIds, dialect)) continue;

      if (q === '') {
        hits.push({ element, docId, score: 0 });
        continue;
      }
      const score =
        idQuery && identities
          ? identifierScore(idQuery, identities[i]!, element.name)
          : scoreMatch(q, element.name.toLowerCase(), blobs[i]!);
      if (score > 0) hits.push({ element, docId, score });
    }
  }

  const total = hits.length;
  if (q !== '') hits.sort((a, b) => b.score - a.score);
  return { hits: hits.slice(0, limit), total };
}

function identifierQuery(q: string): IdentifierQuery | undefined {
  if (q.startsWith('pkg:')) {
    const purl = searchPurl(q);
    return purl ? { kind: 'purl', ...purl } : undefined;
  }
  const cpe = cpeMatchKey(q);
  return cpe ? { kind: 'cpe', key: cpe } : undefined;
}

/**
 * A purl as search compares it: segments and version lowercased (the overlay
 * keeps the name's case; a person pasting a purl should not have to match
 * the SBOM's capitalisation), and a PyPI name with its runs of `-`, `_` and
 * `.` collapsed to one `-`, as the purl spec defines the PyPI name.
 */
function searchPurl(purl: string): { segments: string[]; version?: string } | undefined {
  const parts = splitPurl(purl);
  if (!parts) return undefined;
  const segments = parts.segments.map((s) => s.toLowerCase());
  if (segments.length >= 2 && segments[0] === 'pypi') {
    segments[segments.length - 1] = segments[segments.length - 1]!.replace(/[-_.]+/g, '-');
  }
  const version = parts.version?.toLowerCase();
  return version !== undefined ? { segments, version } : { segments };
}

function elementIdentity(element: SbomElement): ElementIdentity {
  const identity: ElementIdentity = { cpes: elementCpeKeys(element) };
  const version = element.version?.toLowerCase();
  if (version) identity.version = version;
  const purl = element.purl ? searchPurl(element.purl) : undefined;
  if (purl) {
    identity.purl = purl.segments;
    const purlVersion = purl.version ?? version;
    if (purlVersion) identity.purlVersion = purlVersion;
  }
  return identity;
}

function identifierScore(query: IdentifierQuery, identity: ElementIdentity, name: string): number {
  const base =
    query.kind === 'cpe'
      ? identity.cpes.some((held) => cpeCovers(query.key, withElementVersion(held, identity.version)))
        ? IDENTITY_SCORE
        : 0
      : purlScore(query, identity);
  if (base === 0) return 0;
  return base - Math.min(name.length, 200) / 1000;
}

function withElementVersion(held: CpeMatchKey, version: string | undefined): CpeMatchKey {
  return held.version === undefined && version !== undefined ? { ...held, version } : held;
}

function purlScore(query: { segments: readonly string[]; version?: string }, identity: ElementIdentity): number {
  const held = identity.purl;
  if (!held || held.length < query.segments.length) return 0;
  for (let i = 0; i < query.segments.length; i++) {
    if (held[i] !== query.segments[i]) return 0;
  }
  if (held.length === query.segments.length) {
    return query.version === undefined || identity.purlVersion === query.version ? IDENTITY_SCORE : 0;
  }
  return query.version === undefined ? BELOW_PURL_SCORE : 0;
}

function scoreMatch(q: string, name: string, blob: string): number {
  let base = 0;
  if (name === q) base = 1000;
  else if (name.startsWith(q)) base = 800;
  else if (name.includes(q)) base = 600;
  else if (blob.includes(q)) base = 400;
  else if (q.length >= 3 && isSubsequence(q, name)) base = 100;
  if (base === 0) return 0;
  // Tie-break toward shorter names.
  return base - Math.min(name.length, 200) / 1000;
}

/** Either licence field names one of the wanted identifiers (exceptions after WITH excluded). */
function namesLicenseId(element: SbomElement, wanted: ReadonlySet<string>, dialect: LicenseExpressionOptions): boolean {
  for (const value of [element.licenseConcluded, element.licenseDeclared]) {
    if (!value) continue;
    for (const id of licenseIdsInExpression(value, dialect)) if (wanted.has(id)) return true;
  }
  return false;
}

function isSubsequence(q: string, s: string): boolean {
  let i = 0;
  for (let j = 0; j < s.length && i < q.length; j++) {
    if (s[j] === q[i]) i++;
  }
  return i === q.length;
}
