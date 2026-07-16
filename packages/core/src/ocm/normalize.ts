import { isRecord } from '../util/narrow';

/**
 * OCM component-descriptor normalisation for signature verification.
 *
 * The signed payload is the descriptor put through a canonical form and
 * hashed; the signature covers that hash. We reimplement the OCM
 * `jsonNormalisation/*` algorithms: a subset of RFC 8785 (JCS) — recursively
 * sort object keys, minimal JSON serialisation — over a v2 descriptor from
 * which the non-signed parts are excluded. Verified byte-for-byte against the
 * `ocm` CLI (v0.9.0, jsonNormalisation/v4alpha1): the SHA-256 of our output
 * equals the digest the CLI recorded in the signature block.
 *
 * Deliberately conservative: a value we cannot canonicalise exactly (a
 * non-integer or non-finite number) throws `NormalizationError`, so the
 * caller reports "unverifiable" instead of risking a wrong verdict.
 */

export class NormalizationError extends Error {}

export type NormalisationAlgorithm =
  | 'jsonNormalisation/v4alpha1'
  | 'jsonNormalisation/v3'
  | 'jsonNormalisation/v2';

export const SUPPORTED_NORMALISATIONS: readonly string[] = [
  'jsonNormalisation/v4alpha1',
  'jsonNormalisation/v3',
  'jsonNormalisation/v2',
];

/**
 * Normalise a full component descriptor (`{ meta?, component }`, or a
 * v3alpha1 `{ metadata, spec }` already mapped by the caller) into the
 * canonical bytes the signature digest is computed over.
 */
export function normalizeDescriptor(
  root: Record<string, unknown>,
  algorithm: string,
): Uint8Array {
  if (!SUPPORTED_NORMALISATIONS.includes(algorithm)) {
    throw new NormalizationError(`unsupported normalisation "${algorithm}"`);
  }
  const component = isRecord(root.component) ? root.component : null;
  if (!component) {
    throw new NormalizationError('descriptor has no v2 component node (v3alpha1 signing is not supported)');
  }

  // v2/v3/v4alpha1 differ only in details we do not hit for the common
  // descriptor shape; the exclusion set and empty-array defaulting below
  // match v4alpha1 (the current CLI default) and were the ones the CLI
  // gold-check validated. v3 shares them; v2 predates nestedDigests.
  const normalizedComponent = normalizeComponent(component);
  const canonical = { component: normalizedComponent };
  return new TextEncoder().encode(serialize(canonical));
}

function normalizeComponent(component: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(component)) {
    if (key === 'repositoryContexts') continue; // excluded
    if (key === 'provider') {
      out.provider = providerAsMap(value);
      continue;
    }
    if (key === 'labels') {
      const labels = signedLabels(value);
      if (labels.length > 0) out.labels = labels;
      continue;
    }
    if (key === 'resources' || key === 'sources') {
      out[key] = normalizeArtifacts(value, key === 'resources');
      continue;
    }
    if (key === 'componentReferences' || key === 'references') {
      out[key] = normalizeReferences(value);
      continue;
    }
    out[key] = value;
  }
  // Empty-array defaulting (v4alpha1 DefaultComponent): these must be present
  // as [] so a descriptor with no sources hashes the same whether the field
  // was absent or an empty list.
  for (const key of ['componentReferences', 'sources', 'resources'] as const) {
    if (out[key] === undefined) out[key] = [];
  }
  return out;
}

/** Resources/sources: drop access, srcRefs, and unsigned labels; keep digest. */
function normalizeArtifacts(value: unknown, isResource: boolean): unknown[] {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => {
    if (!isRecord(entry)) return entry;
    const out: Record<string, unknown> = {};
    for (const [key, v] of Object.entries(entry)) {
      if (key === 'access' || key === 'srcRefs') continue;
      if (key === 'labels') {
        const labels = signedLabels(v);
        if (labels.length > 0) out.labels = labels;
        continue;
      }
      out[key] = v;
    }
    void isResource;
    return out;
  });
}

function normalizeReferences(value: unknown): unknown[] {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => {
    if (!isRecord(entry)) return entry;
    const out: Record<string, unknown> = {};
    for (const [key, v] of Object.entries(entry)) {
      if (key === 'labels') {
        const labels = signedLabels(v);
        if (labels.length > 0) out.labels = labels;
        continue;
      }
      out[key] = v;
    }
    return out;
  });
}

/** Only labels marked `signing: true` are part of the signed payload. */
function signedLabels(value: unknown): unknown[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((label): label is Record<string, unknown> => isRecord(label) && isSigning(label.signing))
    .map((label) => {
      const out: Record<string, unknown> = {};
      for (const key of ['name', 'version', 'value', 'signing'] as const) {
        if (label[key] !== undefined) out[key] = label[key];
      }
      return out;
    });
}

function isSigning(v: unknown): boolean {
  return v === true || v === 'true';
}

/** provider is serialised as a map; a bare string becomes `{ name }`. */
function providerAsMap(value: unknown): Record<string, unknown> {
  if (typeof value === 'string') return { name: value };
  if (isRecord(value)) return value;
  return { name: value };
}

/**
 * Minimal JCS serialisation: recursively key-sorted, no whitespace.
 * `JSON.stringify` already emits RFC 8785-conformant string escaping and
 * number formatting; we only add stable key ordering and the number guard.
 */
function serialize(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) out[key] = sortKeys(value[key]);
    return out;
  }
  if (typeof value === 'number' && !Number.isInteger(value)) {
    // Non-integer numbers risk a formatting mismatch with the signer's
    // canonicalisation; refuse rather than emit a maybe-wrong byte string.
    throw new NormalizationError('non-integer number in signed payload');
  }
  return value;
}
