/**
 * Package-URL construction, spec-conformant for a deliberate whitelist of
 * types. A viewer can afford a lenient ad-hoc purl (dedupe key); a COMPOSER
 * cannot: an off-spec purl is a silent hole in every downstream CVE match.
 * Unknown types are therefore a hard error, not a best effort — the list
 * grows with proven need, each addition with its own canonicalization
 * rules and tests against the purl-spec examples.
 */

export type PurlType = 'oci' | 'generic' | 'maven' | 'npm';

export interface PurlParts {
  type: PurlType;
  /** Slash-separated namespace (maven groupId, npm scope). */
  namespace?: string;
  name: string;
  version?: string;
  qualifiers?: Record<string, string>;
  subpath?: string;
}

export class PurlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PurlError';
  }
}

const SUPPORTED: ReadonlySet<string> = new Set(['oci', 'generic', 'maven', 'npm']);
const QUALIFIER_KEY = /^[a-z0-9._-]+$/;

export function buildPurl(parts: PurlParts): string {
  const type = parts.type;
  if (!SUPPORTED.has(type)) {
    throw new PurlError(`unsupported purl type "${type}": this composer builds ${[...SUPPORTED].join(', ')}`);
  }
  let namespace = parts.namespace?.trim() || undefined;
  let name = parts.name.trim();
  let version = parts.version?.trim() || undefined;
  if (!name) throw new PurlError('purl name must not be empty');

  // Per-type canonicalization, straight from the purl-spec type definitions.
  switch (type) {
    case 'oci':
      // oci purls have NO namespace; the registry rides in repository_url.
      if (namespace) throw new PurlError('purl type "oci" takes no namespace: put the registry into the repository_url qualifier');
      name = name.toLowerCase();
      version = version?.toLowerCase();
      break;
    case 'npm':
      namespace = namespace?.toLowerCase();
      name = name.toLowerCase();
      break;
    case 'maven':
      if (!namespace) throw new PurlError('purl type "maven" requires a namespace (the groupId)');
      break;
    case 'generic':
      break;
  }

  let purl = `pkg:${type}`;
  if (namespace) {
    purl += '/' + namespace.split('/').filter(Boolean).map(encodeSegment).join('/');
  }
  purl += '/' + encodeSegment(name);
  if (version) purl += '@' + encodeSegment(version);

  const qualifiers = Object.entries(parts.qualifiers ?? {})
    .map(([key, value]) => [key.toLowerCase(), value] as const)
    .filter(([, value]) => value !== '');
  if (qualifiers.length > 0) {
    for (const [key] of qualifiers) {
      if (!QUALIFIER_KEY.test(key)) throw new PurlError(`invalid qualifier key "${key}"`);
    }
    const seen = new Set<string>();
    for (const [key] of qualifiers) {
      if (seen.has(key)) throw new PurlError(`duplicate qualifier key "${key}"`);
      seen.add(key);
    }
    purl +=
      '?' +
      qualifiers
        .sort(([a], [b]) => (a < b ? -1 : 1))
        .map(([key, value]) => `${key}=${encodeQualifierValue(value)}`)
        .join('&');
  }

  if (parts.subpath) {
    const cleaned = parts.subpath
      .split('/')
      .filter((segment) => segment !== '' && segment !== '.' && segment !== '..')
      .map(encodeSegment)
      .join('/');
    if (cleaned) purl += '#' + cleaned;
  }
  return purl;
}

/**
 * Percent-encoding for name/namespace-segment/version/subpath-segment: the
 * spec demands everything outside unreserved-plus-permitted be encoded.
 * encodeURIComponent covers the separators that matter ('@', '/', '?', '#',
 * ':') and never under-encodes; the characters it leaves bare (~ . - _ ! *
 * ' ( )) are all legal in these positions.
 */
function encodeSegment(segment: string): string {
  return encodeURIComponent(segment);
}

/** Qualifier values additionally keep ':' and '/' readable (spec examples: repository_url=ghcr.io/acme). */
function encodeQualifierValue(value: string): string {
  return encodeURIComponent(value).replace(/%3A/gi, ':').replace(/%2F/gi, '/');
}
