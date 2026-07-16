import { asArray, asString, isRecord } from '../util/narrow';
import type { ComplianceProfile, DocumentField, PackageField, ProfileCheck } from './model';
import { MAX_PROFILE_BYTES, PROFILE_SCHEMA_V1, PROFILE_SCHEMA_V2, STRING_PACKAGE_FIELDS } from './model';

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
];

export type ProfileValidation =
  | { ok: true; profile: ComplianceProfile }
  | { ok: false; errors: string[] };

export function validateProfile(raw: unknown): ProfileValidation {
  const errors: string[] = [];
  if (!isRecord(raw)) return { ok: false, errors: ['profile must be a JSON object'] };

  const schema = raw.schema;
  if (schema !== PROFILE_SCHEMA_V1 && schema !== PROFILE_SCHEMA_V2) {
    return {
      ok: false,
      errors: [
        typeof schema === 'string' && schema.startsWith('sbomlens-profile/')
          ? `unsupported profile schema "${schema}": this build understands ${PROFILE_SCHEMA_V1} and ${PROFILE_SCHEMA_V2}`
          : `missing or invalid "schema": expected "${PROFILE_SCHEMA_V1}" or "${PROFILE_SCHEMA_V2}"`,
      ],
    };
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
    const check = validateCheck(entry, index, errors, seenIds, schema === PROFILE_SCHEMA_V2);
    if (check) checks.push(check);
  });

  if (errors.length > 0) return { ok: false, errors };
  return {
    ok: true,
    profile: {
      schema,
      name: name!,
      description: asString(raw.description),
      checks,
    },
  };
}

function validateCheck(
  entry: unknown,
  index: number,
  errors: string[],
  seenIds: Set<string>,
  v2: boolean,
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

  switch (entry.type) {
    case 'document-field': {
      const field = entry.field as DocumentField;
      if (!DOCUMENT_FIELDS.includes(field)) {
        errors.push(`${at}: unknown document field "${String(entry.field)}"`);
        return null;
      }
      return { ...base, type: 'document-field', field, ...(pattern && { pattern }), ...(values && { values }) };
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
      return { ...base, type: 'relationships', ...(minCount !== undefined && { minCount }) };
    }
    case 'created-recency': {
      const days = entry.maxAgeDays;
      if (typeof days !== 'number' || !Number.isFinite(days) || days <= 0 || days > MAX_AGE_DAYS) {
        errors.push(`${at}: "maxAgeDays" must be a number in (0, ${MAX_AGE_DAYS}]`);
        return null;
      }
      if (pattern || values) errors.push(`${at}: pattern/values do not apply to "created-recency"`);
      return { ...base, type: 'created-recency', maxAgeDays: days };
    }
    case 'package-coverage': {
      const field = entry.field as PackageField;
      if (!PACKAGE_FIELDS.includes(field)) {
        errors.push(`${at}: unknown package field "${String(entry.field)}"`);
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
      const algorithms = validateAlgorithms(entry.algorithms, field, at, errors, v2);
      return {
        ...base,
        type: 'package-coverage',
        field,
        ...(threshold !== undefined && { threshold }),
        ...(pattern && { pattern }),
        ...(values && { values }),
        ...(algorithms && { algorithms }),
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

/** v2-only, checksum-only. Fail closed on anything else — see module header. */
function validateAlgorithms(
  raw: unknown,
  field: PackageField,
  at: string,
  errors: string[],
  v2: boolean,
): string[] | undefined {
  if (raw === undefined) return undefined;
  if (!v2) {
    errors.push(`${at}: "algorithms" requires schema "sbomlens-profile/v2"`);
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
