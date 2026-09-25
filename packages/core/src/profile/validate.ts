import { asArray, asString, isRecord } from '../util/narrow';
import type { ComplianceProfile, ProfileSpecBaseline, DocumentField, PackageField, ProfileCheck } from './model';
import {
  LICENSE_PACKAGE_FIELDS,
  MAX_PROFILE_BYTES,
  PROFILE_SCHEMA_V1,
  PROFILE_SCHEMA_V2,
  PROFILE_SCHEMA_V3,
  PROFILE_SCHEMA_V4,
  STRING_PACKAGE_FIELDS,
  V4_DOCUMENT_FIELDS,
  V4_PACKAGE_FIELDS,
} from './model';

/**
 * Fail-closed validation — deliberately NOT the catalog's silent tolerance.
 * A profile is compliance policy: silently dropping an unparseable check
 * would silently weaken a gate, and an old app must never half-evaluate a
 * newer profile and report "pass". Errors are collected, not thrown.
 */

const MAX_CHECKS = 200;
const MAX_NAME = 120;
const MAX_PATTERN = 500;
const MAX_VALUES = 100;
const MAX_VALUE_LENGTH = 200;
const MAX_ID = 64;
const MAX_AGE_DAYS = 36500;

const DOCUMENT_FIELDS: readonly DocumentField[] = [
  'name',
  'namespace',
  'created',
  'creators',
  'dataLicense',
  'comment',
  ...V4_DOCUMENT_FIELDS,
];
const PACKAGE_FIELDS: readonly PackageField[] = [
  'version',
  'supplier',
  'purl',
  'uniqueId',
  'checksum',
  'license',
  'downloadLocation',
  'purpose',
  'copyright',
  'originator',
  ...V4_PACKAGE_FIELDS,
];

/** Schema generations, ordered; a feature introduced at level n needs schema >= n. */
const SCHEMA_LEVEL: Record<string, number> = {
  [PROFILE_SCHEMA_V1]: 1,
  [PROFILE_SCHEMA_V2]: 2,
  [PROFILE_SCHEMA_V3]: 3,
  [PROFILE_SCHEMA_V4]: 4,
};

export type ProfileValidation =
  | { ok: true; profile: ComplianceProfile }
  | { ok: false; errors: string[] };

export function validateProfile(raw: unknown): ProfileValidation {
  const errors: string[] = [];
  if (!isRecord(raw)) return { ok: false, errors: ['profile must be a JSON object'] };

  const schema = raw.schema;
  const level = typeof schema === 'string' ? SCHEMA_LEVEL[schema] : undefined;
  if (
    level === undefined ||
    (schema !== PROFILE_SCHEMA_V1 && schema !== PROFILE_SCHEMA_V2 && schema !== PROFILE_SCHEMA_V3 && schema !== PROFILE_SCHEMA_V4)
  ) {
    const known = `${PROFILE_SCHEMA_V1}, ${PROFILE_SCHEMA_V2}, ${PROFILE_SCHEMA_V3}, and ${PROFILE_SCHEMA_V4}`;
    return {
      ok: false,
      errors: [
        typeof schema === 'string' && schema.startsWith('sbomlens-profile/')
          ? `unsupported profile schema "${schema}": this build understands ${known}`
          : `missing or invalid "schema": expected one of ${known}`,
      ],
    };
  }

  // `requires` gates the whole profile, so it validates fail-closed: only
  // the shapes this engine can enforce are accepted, and only from v3 on (an
  // older engine would ignore the field and silently under-check).
  let requires: ComplianceProfile['requires'];
  if (raw.requires !== undefined) {
    if (level < 3) {
      errors.push(`"requires" needs schema "${PROFILE_SCHEMA_V3}" or later`);
    } else if (!isRecord(raw.requires)) {
      errors.push('"requires" must be an object');
    } else {
      const keys = Object.keys(raw.requires);
      const value: unknown = raw.requires.spec;
      const tokens = Array.isArray(value) ? value : [value];
      const isBaseline = (t: unknown): t is ProfileSpecBaseline => t === 'spdx-3' || t === 'cdx-1.6';
      const valid =
        keys.length === 1 &&
        keys[0] === 'spec' &&
        tokens.length > 0 &&
        tokens.every(isBaseline) &&
        new Set(tokens).size === tokens.length;
      if (!valid) {
        errors.push('"requires" supports exactly { "spec": "spdx-3" | "cdx-1.6" | [<those>] }');
      } else {
        requires = { spec: Array.isArray(value) ? (value as ProfileSpecBaseline[]) : (value as ProfileSpecBaseline) };
      }
    }
  }

  const name = asString(raw.name)?.trim();
  if (!name) errors.push('missing "name"');
  else if (name.length > MAX_NAME) errors.push(`"name" exceeds ${MAX_NAME} characters`);

  const checksRaw = asArray(raw.checks);
  if (checksRaw.length === 0) errors.push('"checks" must be a non-empty array');
  if (checksRaw.length > MAX_CHECKS) errors.push(`more than ${MAX_CHECKS} checks`);

  const checks: ProfileCheck[] = [];
  const seenIds = new Set<string>();
  checksRaw.slice(0, MAX_CHECKS).forEach((entry, index) => {
    const check = validateCheck(entry, index, errors, seenIds, level);
    if (check) checks.push(check);
  });

  if (errors.length > 0) return { ok: false, errors };
  return {
    ok: true,
    profile: {
      schema,
      name: name!,
      description: asString(raw.description),
      specUrl: asString(raw.specUrl),
      ...(requires ? { requires } : {}),
      checks,
    },
  };
}

function validateCheck(
  entry: unknown,
  index: number,
  errors: string[],
  seenIds: Set<string>,
  level: number,
): ProfileCheck | null {
  const at = `checks[${index}]`;
  if (!isRecord(entry)) {
    errors.push(`${at}: must be an object`);
    return null;
  }

  const id = asString(entry.id);
  if (id !== undefined) {
    if (id.length > MAX_ID) errors.push(`${at}: "id" exceeds ${MAX_ID} characters`);
    else if (seenIds.has(id)) errors.push(`${at}: duplicate id "${id}"`);
    else seenIds.add(id);
  }
  const label = asString(entry.label);
  const base = { ...(id !== undefined && { id }), ...(label !== undefined && { label }) };

  const pattern = validatePattern(entry.pattern, at, errors);
  const values = validateValues(entry.values, at, errors);
  const informational = validateInformational(entry.informational, entry.type, at, errors, level);

  switch (entry.type) {
    case 'document-field': {
      const field = entry.field as DocumentField;
      if (!DOCUMENT_FIELDS.includes(field)) {
        errors.push(`${at}: unknown document field "${String(entry.field)}"`);
        return null;
      }
      if (level < 4 && V4_DOCUMENT_FIELDS.includes(field)) {
        errors.push(`${at}: document field "${field}" requires schema "${PROFILE_SCHEMA_V4}"`);
        return null;
      }
      return {
        ...base,
        type: 'document-field',
        field,
        ...(pattern && { pattern }),
        ...(values && { values }),
        ...(informational && { informational }),
      };
    }
    case 'relationships': {
      let minCount: number | undefined;
      if (entry.minCount !== undefined) {
        if (!Number.isInteger(entry.minCount) || (entry.minCount as number) < 1) {
          errors.push(`${at}: "minCount" must be a positive integer`);
          return null;
        }
        minCount = entry.minCount as number;
      }
      if (pattern || values) errors.push(`${at}: pattern/values do not apply to "relationships"`);
      return {
        ...base,
        type: 'relationships',
        ...(minCount !== undefined && { minCount }),
        ...(informational && { informational }),
      };
    }
    case 'created-recency': {
      const days = entry.maxAgeDays;
      if (typeof days !== 'number' || !Number.isFinite(days) || days <= 0 || days > MAX_AGE_DAYS) {
        errors.push(`${at}: "maxAgeDays" must be a number in (0, ${MAX_AGE_DAYS}]`);
        return null;
      }
      if (pattern || values) errors.push(`${at}: pattern/values do not apply to "created-recency"`);
      return { ...base, type: 'created-recency', maxAgeDays: days, ...(informational && { informational }) };
    }
    case 'package-coverage': {
      const field = entry.field as PackageField;
      if (!PACKAGE_FIELDS.includes(field)) {
        errors.push(`${at}: unknown package field "${String(entry.field)}"`);
        return null;
      }
      if (level < 4 && V4_PACKAGE_FIELDS.includes(field)) {
        errors.push(`${at}: package field "${field}" requires schema "${PROFILE_SCHEMA_V4}"`);
        return null;
      }
      if ((pattern || values) && !STRING_PACKAGE_FIELDS.includes(field)) {
        errors.push(`${at}: pattern/values do not apply to non-string field "${field}"`);
        return null;
      }
      let threshold: number | undefined;
      if (entry.threshold !== undefined) {
        if (typeof entry.threshold !== 'number' || !Number.isFinite(entry.threshold) || entry.threshold < 0 || entry.threshold > 100) {
          errors.push(`${at}: "threshold" must be a number in [0, 100]`);
          return null;
        }
        threshold = entry.threshold;
      }
      const algorithms = validateAlgorithms(entry.algorithms, field, at, errors, level);
      const licence = validateLicenseIds(entry.licenseIds, entry.allowDeprecated, field, at, errors, level);
      return {
        ...base,
        type: 'package-coverage',
        field,
        ...(threshold !== undefined && { threshold }),
        ...(pattern && { pattern }),
        ...(values && { values }),
        ...(algorithms && { algorithms }),
        ...(licence?.licenseIds && { licenseIds: licence.licenseIds }),
        ...(licence?.allowDeprecated !== undefined && { allowDeprecated: licence.allowDeprecated }),
      };
    }
    default:
      // Fail closed: an unknown check type rejects the whole profile.
      errors.push(`${at}: unknown check type "${String(entry.type)}"`);
      return null;
  }
}

function validatePattern(raw: unknown, at: string, errors: string[]): string | undefined {
  if (raw === undefined) return undefined;
  const pattern = typeof raw === 'string' ? raw : null;
  if (pattern === null) {
    errors.push(`${at}: "pattern" must be a string`);
    return undefined;
  }
  if (pattern.length > MAX_PATTERN) {
    errors.push(`${at}: "pattern" exceeds ${MAX_PATTERN} characters`);
    return undefined;
  }
  try {
    new RegExp(pattern);
  } catch {
    errors.push(`${at}: "pattern" is not a valid regular expression`);
    return undefined;
  }
  return pattern;
}

const MAX_ALGORITHMS = 8;
const MAX_ALGORITHM_LENGTH = 32;

/**
 * v4: `informational` on a boolean check. Rejected below v4 (an older engine
 * would drop the flag and gate a check the author meant as a meter) and on
 * coverage checks (there, "no threshold" already means informational).
 */
function validateInformational(
  raw: unknown,
  type: unknown,
  at: string,
  errors: string[],
  level: number,
): boolean | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== 'boolean') {
    errors.push(`${at}: "informational" must be a boolean`);
    return undefined;
  }
  if (level < 4) {
    errors.push(`${at}: "informational" requires schema "${PROFILE_SCHEMA_V4}"`);
    return undefined;
  }
  if (type === 'package-coverage') {
    errors.push(`${at}: "informational" does not apply to "package-coverage" (omit "threshold" instead)`);
    return undefined;
  }
  return raw ? true : undefined;
}

/** v4, licence fields only: identifier validity against the SPDX License List. */
function validateLicenseIds(
  rawIds: unknown,
  rawDeprecated: unknown,
  field: PackageField,
  at: string,
  errors: string[],
  level: number,
): { licenseIds?: 'known' | 'known-or-ref'; allowDeprecated?: boolean } | undefined {
  if (rawIds === undefined && rawDeprecated === undefined) return undefined;
  if (level < 4) {
    errors.push(`${at}: "licenseIds"/"allowDeprecated" require schema "${PROFILE_SCHEMA_V4}"`);
    return undefined;
  }
  if (!LICENSE_PACKAGE_FIELDS.includes(field)) {
    errors.push(`${at}: "licenseIds"/"allowDeprecated" only apply to licence fields`);
    return undefined;
  }
  if (rawIds === undefined) {
    errors.push(`${at}: "allowDeprecated" needs "licenseIds"`);
    return undefined;
  }
  if (rawIds !== 'known' && rawIds !== 'known-or-ref') {
    errors.push(`${at}: "licenseIds" must be "known" or "known-or-ref"`);
    return undefined;
  }
  if (rawDeprecated !== undefined && typeof rawDeprecated !== 'boolean') {
    errors.push(`${at}: "allowDeprecated" must be a boolean`);
    return undefined;
  }
  return { licenseIds: rawIds, ...(rawDeprecated !== undefined && { allowDeprecated: rawDeprecated }) };
}

/** v2+, checksum-only. Fail closed on anything else — see module header. */
function validateAlgorithms(
  raw: unknown,
  field: PackageField,
  at: string,
  errors: string[],
  level: number,
): string[] | undefined {
  if (raw === undefined) return undefined;
  if (level < 2) {
    errors.push(`${at}: "algorithms" requires schema "sbomlens-profile/v2" or later`);
    return undefined;
  }
  if (field !== 'checksum') {
    errors.push(`${at}: "algorithms" only applies to the "checksum" field`);
    return undefined;
  }
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > MAX_ALGORITHMS) {
    errors.push(`${at}: "algorithms" must be a non-empty array of at most ${MAX_ALGORITHMS} strings`);
    return undefined;
  }
  const algorithms = raw.filter(
    (v): v is string => typeof v === 'string' && v.length > 0 && v.length <= MAX_ALGORITHM_LENGTH,
  );
  if (algorithms.length !== raw.length) {
    errors.push(`${at}: "algorithms" entries must be strings of at most ${MAX_ALGORITHM_LENGTH} characters`);
    return undefined;
  }
  return algorithms;
}

function validateValues(raw: unknown, at: string, errors: string[]): string[] | undefined {
  if (raw === undefined) return undefined;
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > MAX_VALUES) {
    errors.push(`${at}: "values" must be a non-empty array of at most ${MAX_VALUES} strings`);
    return undefined;
  }
  const values = raw.filter(
    (v): v is string => typeof v === 'string' && v.length > 0 && v.length <= MAX_VALUE_LENGTH,
  );
  if (values.length !== raw.length) {
    errors.push(`${at}: "values" entries must be strings of at most ${MAX_VALUE_LENGTH} characters`);
    return undefined;
  }
  return values;
}

/**
 * Two-stage content sniff (never extension-based): a cheap marker check that
 * false-positives are then killed by an actual parse + schema check. A miss
 * falls through to the normal SBOM pipeline.
 */
export function sniffProfile(text: string): { isProfile: true; raw: unknown } | { isProfile: false } {
  if (text.length > MAX_PROFILE_BYTES) return { isProfile: false };
  const head = text.trimStart();
  if (!head.startsWith('{') || !text.includes('"sbomlens-profile/')) return { isProfile: false };
  try {
    const raw: unknown = JSON.parse(text);
    if (isRecord(raw) && typeof raw.schema === 'string' && raw.schema.startsWith('sbomlens-profile/')) {
      return { isProfile: true, raw };
    }
  } catch {
    // Marker present but not valid JSON — let the SBOM pipeline report it.
  }
  return { isProfile: false };
}
