/**
 * Compliance profiles: declarative, enterprise-authored minimum requirements
 * for SBOM documents — pure data, no code execution. The built-in NTIA
 * report is expressed in this same format (see ntia.ts), which keeps the
 * engine honest: one evaluator serves every profile.
 */

export const PROFILE_SCHEMA_V1 = 'sbomlens-profile/v1';

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
    });

export interface ComplianceProfile {
  schema: typeof PROFILE_SCHEMA_V1;
  name: string;
  description?: string;
  checks: ProfileCheck[];
}
