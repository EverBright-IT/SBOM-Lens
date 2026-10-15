/**
 * The one purl splitter behind both identity rules: the VEX overlay's
 * purlMatchKey and the search's identity query. Keeping a single parser is
 * what lets search promise to find every element the overlay matches.
 */

export interface PurlSegments {
  /** Percent-decoded path segments: the type first, the name last, the namespace between. */
  segments: string[];
  /** Percent-decoded version, when the purl states one. */
  version?: string;
}

/**
 * Splits `pkg:type/namespace/name@version?qualifiers#subpath`, dropping
 * qualifiers and subpath. Returns undefined for anything that is not a purl.
 *
 * An `@` opening a segment belongs to an unencoded npm scope
 * (`pkg:npm/@angular/core`), and an `@` followed by a raw `/` cannot start a
 * version either: a purl version part never contains a raw slash. Without
 * these guards the scoped forms would split into garbage and silently never
 * match.
 */
export function splitPurl(purl: string): PurlSegments | undefined {
  if (!purl.startsWith('pkg:')) return undefined;
  let rest = purl.slice('pkg:'.length);
  const hash = rest.indexOf('#');
  if (hash !== -1) rest = rest.slice(0, hash);
  const question = rest.indexOf('?');
  if (question !== -1) rest = rest.slice(0, question);
  const at = rest.lastIndexOf('@');
  let version: string | undefined;
  if (at > 0 && rest[at - 1] !== '/' && !rest.slice(at + 1).includes('/')) {
    version = decodeSegment(rest.slice(at + 1));
    rest = rest.slice(0, at);
  }
  const segments = rest
    .replace(/^\/+/, '')
    .split('/')
    .filter((s) => s !== '')
    .map(decodeSegment);
  if (segments.length === 0) return undefined;
  return version !== undefined && version !== '' ? { segments, version } : { segments };
}

function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}
