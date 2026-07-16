import type { Diagnostic } from '../../model/diagnostics';
import { diag } from '../../model/diagnostics';
import { asString, isRecord } from '../../util/narrow';

/**
 * Structural lint for component descriptors: spec-shaped WARNINGS on top of
 * the tolerant parser, so a descriptor's problems are visible before it hits
 * a pipeline. Hand-rolled checks instead of schema validation on purpose:
 * ocm-spec ships no vendorable JSON schema, and the tolerant-parser
 * philosophy wants human sentences, not schema paths. Every rule cites the
 * spec passage it enforces; everything stays a warning — the document still
 * loads.
 */

interface CdShape {
  name: string;
  version: string;
  provider?: string;
  providerLabels?: unknown;
  creationTime?: string;
  resources: Record<string, unknown>[];
  sources: Record<string, unknown>[];
  references: Record<string, unknown>[];
  v3: boolean;
}

/**
 * Component names per ocm-spec (01-model/02-elements-toplevel.md): a
 * lowercase DNS-style domain followed by at least one path segment, e.g.
 * `acme.org/products/webstack`.
 */
const COMPONENT_NAME = /^[a-z][-a-z0-9]*([.][a-z][-a-z0-9]*)*[.][a-z]{2,}(\/[a-z][-a-z0-9_]*([.][a-z][-a-z0-9_]*)*)+$/;

/**
 * Versions per ocm-spec: SHOULD follow (relaxed) semver, optionally prefixed
 * with `v`. Pre-release/build suffixes are fine; anything else is worth a
 * warning, not a rejection.
 */
const RELAXED_SEMVER = /^v?\d+(\.\d+){0,2}([-+][0-9A-Za-z.-]+)?$/;

export function validateCdStructure(root: Record<string, unknown>, cd: CdShape): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const warn = (code: string, message: string) => diagnostics.push(diag('warning', code, message));

  // NOTE: meta.schemaVersion is not checked here — content detection already
  // requires it, so a descriptor without it never reaches this parser.

  // provider is a required component attribute in both schema flavors.
  if (!cd.provider && !cd.providerLabels) {
    warn('OCM_SCHEMA_MISSING_FIELD', 'component.provider is missing.');
  }

  if (!COMPONENT_NAME.test(cd.name)) {
    warn(
      'OCM_SCHEMA_BAD_NAME',
      `Component name "${cd.name}" does not follow the spec pattern (lowercase domain plus path, e.g. acme.org/webstack).`,
    );
  }

  if (!RELAXED_SEMVER.test(cd.version)) {
    warn('OCM_SCHEMA_BAD_VERSION', `Component version "${cd.version}" is not (relaxed) semver.`);
  }

  if (cd.creationTime !== undefined && Number.isNaN(Date.parse(cd.creationTime))) {
    warn('OCM_SCHEMA_BAD_TIMESTAMP', `creationTime "${cd.creationTime}" is not a parseable timestamp.`);
  }

  validateArtifacts(cd.resources, 'resource', warn);
  validateArtifacts(cd.sources, 'source', warn);
  validateDuplicates(cd, warn);
  validateLabels(root, cd, warn);

  return diagnostics;
}

type Warn = (code: string, message: string) => void;

function validateArtifacts(items: Record<string, unknown>[], kind: 'resource' | 'source', warn: Warn): void {
  const badRelation: string[] = [];
  const missingAccessType: string[] = [];
  const incompleteDigest: string[] = [];
  const badVersion: string[] = [];

  for (const item of items) {
    const name = asString(item.name) ?? '?';
    // relation must be `local` or `external` (ocm-spec artifact attributes).
    const relation = asString(item.relation);
    if (relation !== undefined && relation !== 'local' && relation !== 'external') badRelation.push(name);
    // every access specification carries a `type` discriminator.
    if (isRecord(item.access) && !asString(item.access.type)) missingAccessType.push(name);
    // a digest is the (hashAlgorithm, normalisationAlgorithm, value) triple;
    // a partial one can neither be displayed honestly nor verified.
    if (isRecord(item.digest)) {
      const d = item.digest;
      if (!asString(d.hashAlgorithm) || !asString(d.normalisationAlgorithm) || !asString(d.value)) {
        incompleteDigest.push(name);
      }
    }
    const version = asString(item.version);
    if (version !== undefined && !RELAXED_SEMVER.test(version)) badVersion.push(name);
  }

  const list = (names: string[]) => `${names.slice(0, 3).join(', ')}${names.length > 3 ? ', ...' : ''}`;
  if (badRelation.length > 0) {
    warn('OCM_SCHEMA_BAD_RELATION', `${badRelation.length} ${kind}(s) with a relation other than local/external: ${list(badRelation)}.`);
  }
  if (missingAccessType.length > 0) {
    warn('OCM_SCHEMA_ACCESS_MISSING_TYPE', `${missingAccessType.length} ${kind}(s) with an access node without a type: ${list(missingAccessType)}.`);
  }
  if (incompleteDigest.length > 0) {
    warn('OCM_SCHEMA_DIGEST_INCOMPLETE', `${incompleteDigest.length} ${kind}(s) with an incomplete digest triple: ${list(incompleteDigest)}.`);
  }
  if (badVersion.length > 0) {
    warn('OCM_SCHEMA_BAD_VERSION', `${badVersion.length} ${kind}(s) with a non-semver version: ${list(badVersion)}.`);
  }
}

/**
 * Artifact identity = name + extraIdentity (+ version); duplicates within
 * one collection are ambiguous (ocm-spec: element identities must be unique
 * within their set).
 */
function validateDuplicates(cd: CdShape, warn: Warn): void {
  const check = (items: Record<string, unknown>[], kind: string) => {
    const seen = new Set<string>();
    const dupes = new Set<string>();
    for (const item of items) {
      const name = asString(item.name);
      if (!name) continue;
      const extra = isRecord(item.extraIdentity)
        ? Object.entries(item.extraIdentity)
            .filter((e): e is [string, string] => typeof e[1] === 'string')
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([k, v]) => `${k}=${v}`)
            .join(',')
        : '';
      const key = `${name}#${extra}#${asString(item.version) ?? ''}`;
      if (seen.has(key)) dupes.add(name);
      else seen.add(key);
    }
    if (dupes.size > 0) {
      warn(
        'OCM_SCHEMA_DUPLICATE_IDENTITY',
        `${dupes.size} duplicate ${kind} identit${dupes.size === 1 ? 'y' : 'ies'} (same name, extraIdentity, and version): ${[...dupes].slice(0, 3).join(', ')}${dupes.size > 3 ? ', ...' : ''}.`,
      );
    }
  };
  check(cd.resources, 'resource');
  check(cd.sources, 'source');
  check(cd.references, 'componentReference');
}

/** Labels are `{name, value}` entries; a label without a string name is noise. */
function validateLabels(root: Record<string, unknown>, cd: CdShape, warn: Warn): void {
  let malformed = 0;
  const scan = (value: unknown) => {
    if (!Array.isArray(value)) return;
    for (const label of value) {
      if (!isRecord(label) || !asString(label.name)) malformed++;
    }
  };
  const component = isRecord(root.component) ? root.component : {};
  scan(component.labels);
  for (const item of [...cd.resources, ...cd.sources, ...cd.references]) scan(item.labels);
  if (malformed > 0) {
    warn('OCM_SCHEMA_LABEL_MALFORMED', `${malformed} label(s) without a name were found (labels are {name, value} pairs).`);
  }
}
