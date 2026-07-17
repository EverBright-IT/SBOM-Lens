/**
 * Compliance profiles: declarative, enterprise-authored minimum requirements
 * for SBOM documents — pure data, no code execution. The built-in NTIA
 * report is expressed in this same format (see ntia.ts), which keeps the
 * engine honest: one evaluator serves every profile.
 */

export const PROFILE_SCHEMA_V1 = 'sbomlens-profile/v1';
/**
 * v2 = v1 plus the `algorithms` modifier on checksum coverage. A separate
 * schema id on purpose: this validator silently ignores unknown keys, so an
 * older engine would evaluate an `algorithms` profile as a weaker
 * presence-check and report pass — the schema gate turns that into a clean
 * rejection instead.
 */
export const PROFILE_SCHEMA_V2 = 'sbomlens-profile/v2';
/**
 * v3 = v2 plus the profile-level `requires` precondition. Separate id for
 * the same fail-closed reason: an older engine would silently ignore
 * `requires` and evaluate a format-gated profile as if the format did not
 * matter — exactly the overstatement the field exists to prevent.
 */
export const PROFILE_SCHEMA_V3 = 'sbomlens-profile/v3';

/** Profiles larger than this are never sniffed or imported. */
export const MAX_PROFILE_BYTES = 65536;

export type DocumentField =
  | 'name'
  | 'namespace'
  | 'created'
  | 'creators'
  | 'dataLicense'
  | 'comment';

export type PackageField =
  | 'version'
  | 'supplier'
  | 'purl'
  | 'uniqueId'
  | 'checksum'
  | 'license'
  | 'downloadLocation'
  | 'purpose'
  | 'copyright'
  | 'originator';

/** Package fields whose extracted value is a string (pattern/values apply). */
export const STRING_PACKAGE_FIELDS: readonly PackageField[] = [
  'version',
  'supplier',
  'purl',
  'license',
  'downloadLocation',
  'purpose',
  'copyright',
  'originator',
];

interface CheckBase {
  /** Stable id for reports; defaults to `${type}-${index}`. Unique when present. */
  id?: string;
  /** Display label; a default is derived from type + field. */
  label?: string;
}

export type ProfileCheck =
  | (CheckBase & {
      type: 'document-field';
      field: DocumentField;
      /** Regex the value must match (RegExp.test — anchor with ^…$ for full match). */
      pattern?: string;
      /** Exact-match allow-list; combined with pattern via AND. */
      values?: string[];
    })
  | (CheckBase & { type: 'relationships'; minCount?: number })
  | (CheckBase & { type: 'created-recency'; maxAgeDays: number })
  | (CheckBase & {
      type: 'package-coverage';
      field: PackageField;
      /** 0..100. Absent = informational meter, never gates. */
      threshold?: number;
      pattern?: string;
      values?: string[];
      /**
       * v2, `field: 'checksum'` only: a package satisfies the check only
       * with a checksum whose algorithm is in this list (case/dash
       * insensitive, e.g. "SHA512" or "SHA-512").
       */
      algorithms?: string[];
    });

/**
 * Hard preconditions of the requirement source itself, evaluated as a
 * leading GATED check. A compliance text that only accepts a format is not
 * approximated by field checks alone: without this, an SPDX 2.x document
 * with complete fields would render an all-green report and quietly
 * overstate conformance.
 */
export interface ProfileRequires {
  /** The document model this profile's requirement source is defined against. */
  spec: 'spdx-3';
}

export interface ComplianceProfile {
  schema: typeof PROFILE_SCHEMA_V1 | typeof PROFILE_SCHEMA_V2 | typeof PROFILE_SCHEMA_V3;
  name: string;
  description?: string;
  requires?: ProfileRequires;
  checks: ProfileCheck[];
}
