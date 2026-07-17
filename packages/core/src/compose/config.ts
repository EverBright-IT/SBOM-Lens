import { asArray, asString, isRecord } from '../util/narrow';
import type { PurlParts, PurlType } from '../util/purl';
import { buildPurl } from '../util/purl';

/**
 * The compose configuration: a declarative description of a product-level
 * SBOM — metadata, artifacts with type→purpose/purl rules, and child SBOM
 * attachments. Validation is fail-closed AND closed-world: unknown keys are
 * errors, not noise. A profile checker that under-checks reports a false
 * pass; a composer that ignores a typo EMITS a wrong document — stricter
 * stakes, stricter validation.
 */

export const COMPOSE_SCHEMA_V1 = 'sbomloom-compose/v1';

export interface ComposePurl {
  type: PurlType;
  namespace?: string;
  /** Defaults to the artifact/product name. */
  name?: string;
  /** Defaults to the artifact/product version. */
  version?: string;
  qualifiers?: Record<string, string>;
  subpath?: string;
}

export interface ComposeArtifact {
  name: string;
  version?: string;
  /** Artifact type, mapped to primaryPackagePurpose (see TYPE_TO_PURPOSE). */
  type?: string;
  /** Explicit primaryPackagePurpose; wins over the type mapping. */
  purpose?: string;
  supplier?: string;
  license?: string;
  copyright?: string;
  downloadLocation?: string;
  comment?: string;
  checksums?: { algorithm: string; value: string }[];
  purl?: ComposePurl;
  /** Path to a child SBOM (resolved by the caller relative to the config). */
  sbom?: string;
  /** Root→artifact edge; overrides the config-level default. */
  relationship?: 'CONTAINS' | 'DEPENDS_ON';
}

export interface ComposeConfig {
  schema: typeof COMPOSE_SCHEMA_V1;
  product: {
    name: string;
    version: string;
    /** SPDX documentNamespace — mandatory here so the output never invents one. */
    namespace: string;
    supplier?: string;
    license?: string;
    copyright?: string;
    purpose?: string;
    comment?: string;
    purl?: ComposePurl;
  };
  /** Appended after the generated tool creator. */
  creators?: string[];
  artifacts: ComposeArtifact[];
  /** Default root→artifact edge. */
  relationshipType?: 'CONTAINS' | 'DEPENDS_ON';
}

/** Artifact `type` → SPDX 2.3 primaryPackagePurpose. */
export const TYPE_TO_PURPOSE: Readonly<Record<string, string>> = {
  application: 'APPLICATION',
  framework: 'FRAMEWORK',
  library: 'LIBRARY',
  container: 'CONTAINER',
  'operating-system': 'OPERATING-SYSTEM',
  os: 'OPERATING-SYSTEM',
  device: 'DEVICE',
  firmware: 'FIRMWARE',
  source: 'SOURCE',
  archive: 'ARCHIVE',
  file: 'FILE',
  install: 'INSTALL',
  other: 'OTHER',
};

const PURPOSES = new Set(Object.values(TYPE_TO_PURPOSE));
const PURL_TYPES = new Set<PurlType>(['oci', 'generic', 'maven', 'npm']);
/**
 * Qualifier keys the purl spec knows; everything else must carry the `x-`
 * prefix so custom parameters are visibly custom instead of colliding with
 * future spec keys.
 */
const KNOWN_QUALIFIERS = new Set([
  'repository_url',
  'download_url',
  'vcs_url',
  'tag',
  'arch',
  'os',
  'type',
  'classifier',
  'checksum',
  'channel',
]);

const MAX_ARTIFACTS = 500;

export type ComposeValidation = { ok: true; config: ComposeConfig } | { ok: false; errors: string[] };

export function validateComposeConfig(raw: unknown): ComposeValidation {
  const errors: string[] = [];
  if (!isRecord(raw)) return { ok: false, errors: ['config must be a YAML/JSON object'] };

  if (raw.schema !== COMPOSE_SCHEMA_V1) {
    return { ok: false, errors: [`missing or invalid "schema": expected "${COMPOSE_SCHEMA_V1}"`] };
  }
  rejectUnknownKeys(raw, ['schema', 'product', 'creators', 'artifacts', 'relationshipType'], '', errors);

  const productRaw = isRecord(raw.product) ? raw.product : undefined;
  if (!productRaw) errors.push('missing "product" object');
  const product = productRaw
    ? validateProduct(productRaw, errors)
    : undefined;

  const creators = raw.creators === undefined ? undefined : asArray(raw.creators).map((c) => asString(c) ?? '');
  if (creators?.some((c) => !c)) errors.push('"creators" must be an array of strings');

  const relationshipType = validateEdge(raw.relationshipType, 'relationshipType', errors);

  const artifactsRaw = asArray(raw.artifacts);
  if (artifactsRaw.length === 0) errors.push('"artifacts" must be a non-empty array');
  if (artifactsRaw.length > MAX_ARTIFACTS) errors.push(`more than ${MAX_ARTIFACTS} artifacts`);
  const seenNames = new Set<string>();
  const artifacts = artifactsRaw.slice(0, MAX_ARTIFACTS).map((entry, index) => {
    const artifact = validateArtifact(entry, index, errors);
    if (artifact) {
      if (seenNames.has(artifact.name)) errors.push(`artifacts[${index}]: duplicate artifact name "${artifact.name}"`);
      seenNames.add(artifact.name);
    }
    return artifact;
  });

  if (errors.length > 0) return { ok: false, errors };
  return {
    ok: true,
    config: {
      schema: COMPOSE_SCHEMA_V1,
      product: product!,
      ...(creators ? { creators } : {}),
      artifacts: artifacts as ComposeArtifact[],
      ...(relationshipType ? { relationshipType } : {}),
    },
  };
}

function validateProduct(raw: Record<string, unknown>, errors: string[]): ComposeConfig['product'] | undefined {
  rejectUnknownKeys(
    raw,
    ['name', 'version', 'namespace', 'supplier', 'license', 'copyright', 'purpose', 'comment', 'purl'],
    'product.',
    errors,
  );
  const name = asString(raw.name)?.trim();
  const version = asString(raw.version)?.trim();
  const namespace = asString(raw.namespace)?.trim();
  if (!name) errors.push('product.name is required');
  if (!version) errors.push('product.version is required');
  if (!namespace) {
    errors.push('product.namespace is required (the SPDX documentNamespace; nothing is invented for you)');
  } else if (!/^[a-z][a-z0-9+.-]*:/i.test(namespace) || namespace.includes('#')) {
    errors.push('product.namespace must be an absolute URI without a fragment');
  }
  const purpose = validatePurpose(asString(raw.purpose), 'product.purpose', errors);
  const purl = raw.purl === undefined ? undefined : validatePurl(raw.purl, 'product.purl', errors);
  if (purl && name) tryBuildPurl(purl, name, version, 'product.purl', errors);
  if (errors.length > 0) return undefined;
  return {
    name: name!,
    version: version!,
    namespace: namespace!,
    supplier: asString(raw.supplier),
    license: asString(raw.license),
    copyright: asString(raw.copyright),
    ...(purpose ? { purpose } : {}),
    comment: asString(raw.comment),
    ...(purl ? { purl } : {}),
  };
}

function validateArtifact(entry: unknown, index: number, errors: string[]): ComposeArtifact | null {
  const at = `artifacts[${index}]`;
  if (!isRecord(entry)) {
    errors.push(`${at}: must be an object`);
    return null;
  }
  rejectUnknownKeys(
    entry,
    ['name', 'version', 'type', 'purpose', 'supplier', 'license', 'copyright', 'downloadLocation', 'comment', 'checksums', 'purl', 'sbom', 'relationship'],
    `${at}.`,
    errors,
  );
  const name = asString(entry.name)?.trim();
  if (!name) {
    errors.push(`${at}: "name" is required`);
    return null;
  }

  let purpose = validatePurpose(asString(entry.purpose), `${at}.purpose`, errors);
  const type = asString(entry.type)?.trim();
  if (!purpose && type) {
    purpose = TYPE_TO_PURPOSE[type.toLowerCase()];
    if (!purpose) {
      errors.push(
        `${at}.type: unknown artifact type "${type}" (known: ${Object.keys(TYPE_TO_PURPOSE).join(', ')}); set an explicit "purpose" to override`,
      );
    }
  }

  const checksums = entry.checksums === undefined ? undefined : validateChecksums(entry.checksums, at, errors);
  const purl = entry.purl === undefined ? undefined : validatePurl(entry.purl, `${at}.purl`, errors);
  if (purl) tryBuildPurl(purl, name, asString(entry.version), `${at}.purl`, errors);
  const relationship = validateEdge(entry.relationship, `${at}.relationship`, errors);
  const sbom = asString(entry.sbom)?.trim();

  return {
    name,
    version: asString(entry.version),
    type,
    ...(purpose ? { purpose } : {}),
    supplier: asString(entry.supplier),
    license: asString(entry.license),
    copyright: asString(entry.copyright),
    downloadLocation: asString(entry.downloadLocation),
    comment: asString(entry.comment),
    ...(checksums ? { checksums } : {}),
    ...(purl ? { purl } : {}),
    ...(sbom ? { sbom } : {}),
    ...(relationship ? { relationship } : {}),
  };
}

function validatePurl(raw: unknown, at: string, errors: string[]): ComposePurl | undefined {
  if (!isRecord(raw)) {
    errors.push(`${at}: must be an object`);
    return undefined;
  }
  rejectUnknownKeys(raw, ['type', 'namespace', 'name', 'version', 'qualifiers', 'subpath'], `${at}.`, errors);
  const type = asString(raw.type);
  if (!type || !PURL_TYPES.has(type as PurlType)) {
    errors.push(`${at}.type: must be one of ${[...PURL_TYPES].join(', ')}`);
    return undefined;
  }
  let qualifiers: Record<string, string> | undefined;
  if (raw.qualifiers !== undefined) {
    if (!isRecord(raw.qualifiers)) {
      errors.push(`${at}.qualifiers: must be an object of strings`);
    } else {
      qualifiers = {};
      for (const [key, value] of Object.entries(raw.qualifiers)) {
        const lower = key.toLowerCase();
        if (!KNOWN_QUALIFIERS.has(lower) && !lower.startsWith('x-')) {
          errors.push(`${at}.qualifiers: unknown key "${key}" — custom qualifiers must use the "x-" prefix`);
        }
        const text = typeof value === 'string' ? value : typeof value === 'number' ? String(value) : undefined;
        if (text === undefined) errors.push(`${at}.qualifiers.${key}: must be a string`);
        else qualifiers[lower] = text;
      }
    }
  }
  return {
    type: type as PurlType,
    namespace: asString(raw.namespace),
    name: asString(raw.name),
    version: asString(raw.version),
    ...(qualifiers ? { qualifiers } : {}),
    subpath: asString(raw.subpath),
  };
}

function validateChecksums(
  raw: unknown,
  at: string,
  errors: string[],
): { algorithm: string; value: string }[] | undefined {
  const list = asArray(raw);
  const out: { algorithm: string; value: string }[] = [];
  for (const [i, entry] of list.entries()) {
    const algorithm = isRecord(entry) ? asString(entry.algorithm)?.toUpperCase().replace(/-/g, '') : undefined;
    const value = isRecord(entry) ? asString(entry.value)?.toLowerCase() : undefined;
    if (!algorithm || !value || !/^[0-9a-f]+$/.test(value)) {
      errors.push(`${at}.checksums[${i}]: needs { algorithm, value(hex) }`);
      continue;
    }
    out.push({ algorithm, value });
  }
  return out;
}

function validatePurpose(value: string | undefined, at: string, errors: string[]): string | undefined {
  if (value === undefined) return undefined;
  const upper = value.toUpperCase();
  if (!PURPOSES.has(upper)) {
    errors.push(`${at}: "${value}" is not an SPDX 2.3 primaryPackagePurpose`);
    return undefined;
  }
  return upper;
}

function validateEdge(
  value: unknown,
  at: string,
  errors: string[],
): 'CONTAINS' | 'DEPENDS_ON' | undefined {
  if (value === undefined) return undefined;
  if (value === 'CONTAINS' || value === 'DEPENDS_ON') return value;
  errors.push(`${at}: must be "CONTAINS" or "DEPENDS_ON"`);
  return undefined;
}

/**
 * Dry-run the purl builder at validation time: an oci namespace or a missing
 * maven groupId should fail the CONFIG, not blow up mid-composition.
 */
function tryBuildPurl(spec: ComposePurl, name: string, version: string | undefined, at: string, errors: string[]): void {
  try {
    buildPurl(purlPartsFor(spec, name, version));
  } catch (error) {
    errors.push(`${at}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function rejectUnknownKeys(raw: Record<string, unknown>, known: string[], prefix: string, errors: string[]): void {
  for (const key of Object.keys(raw)) {
    if (!known.includes(key)) errors.push(`unknown key "${prefix}${key}"`);
  }
}

export function purlPartsFor(spec: ComposePurl, fallbackName: string, fallbackVersion?: string): PurlParts {
  return {
    type: spec.type,
    namespace: spec.namespace,
    name: spec.name ?? fallbackName,
    version: spec.version ?? fallbackVersion,
    qualifiers: spec.qualifiers,
    subpath: spec.subpath,
  };
}
