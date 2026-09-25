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
/**
 * v4 = v3 plus the lifecycle and licensing fields the 2026 requirement
 * sources ask for (FDA 524B support level and end-of-support date, the
 * OpenChain Automotive file name and concluded licence, BSI TR-03183-2 §6.1
 * declared/original licences), the `informational` flag on boolean checks,
 * and the `licenseIds` / `allowDeprecated` modifiers on licence coverage.
 * New field tokens are already fail-closed through the whitelist; the id
 * exists for the two modifiers, which an older engine would silently drop.
 */
export const PROFILE_SCHEMA_V4 = 'sbomlens-profile/v4';

/** Profiles larger than this are never sniffed or imported. */
export const MAX_PROFILE_BYTES = 65536;

export type DocumentField =
  | 'name'
  | 'namespace'
  | 'created'
  | 'creators'
  | 'dataLicense'
  | 'comment'
  // v4
  | 'sbomType'
  | 'describes'
  | 'externalDocumentRefs';

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
  | 'originator'
  // v4
  | 'fileName'
  | 'supportLevel'
  | 'validUntil'
  | 'licenseDeclared'
  | 'licenseConcluded'
  | 'properties';

/** Fields that exist only from schema v4 on; the validator rejects them below it. */
export const V4_DOCUMENT_FIELDS: readonly DocumentField[] = ['sbomType', 'describes', 'externalDocumentRefs'];
export const V4_PACKAGE_FIELDS: readonly PackageField[] = [
  'fileName',
  'supportLevel',
  'validUntil',
  'licenseDeclared',
  'licenseConcluded',
  'properties',
];

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
  'fileName',
  'supportLevel',
  'validUntil',
  'licenseDeclared',
  'licenseConcluded',
  'properties',
];

/** Licence fields that accept the v4 `licenseIds` / `allowDeprecated` modifiers. */
export const LICENSE_PACKAGE_FIELDS: readonly PackageField[] = ['license', 'licenseDeclared', 'licenseConcluded'];

interface CheckBase {
  /** Stable id for reports; defaults to `${type}-${index}`. Unique when present. */
  id?: string;
  /** Display label; a default is derived from type + field. */
  label?: string;
}

/**
 * v4: a boolean check that reports pass/fail but never gates. Guidance
 * documents describe facts worth showing without turning them into a
 * verdict; before v4 every boolean check gated by construction.
 */
interface Informational {
  informational?: boolean;
}

export type ProfileCheck =
  | (CheckBase &
      Informational & {
        type: 'document-field';
        field: DocumentField;
        /** Regex the value must match (RegExp.test — anchor with ^…$ for full match). */
        pattern?: string;
        /** Exact-match allow-list; combined with pattern via AND. */
        values?: string[];
      })
  | (CheckBase & Informational & { type: 'relationships'; minCount?: number })
  | (CheckBase & Informational & { type: 'created-recency'; maxAgeDays: number })
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
      /**
       * v4, licence fields only: every licence identifier in the expression
       * must be on the SPDX License List ('known'), or on the list OR a
       * `LicenseRef-` ('known-or-ref'). Identifier validity, nothing more:
       * the list carries ids and their deprecation flag, no texts, no
       * obligations, no judgement.
       */
      licenseIds?: 'known' | 'known-or-ref';
      /** v4, with `licenseIds`: whether deprecated identifiers still satisfy the check (default true). */
      allowDeprecated?: boolean;
    });

/**
 * Hard preconditions of the requirement source itself, evaluated as a
 * leading GATED check. A compliance text that only accepts a format is not
 * approximated by field checks alone: without this, an SPDX 2.x document
 * with complete fields would render an all-green report and quietly
 * overstate conformance.
 */
/** A format baseline a requirement source accepts. */
export type ProfileSpecBaseline = 'spdx-3' | 'cdx-1.6';

export interface ProfileRequires {
  /**
   * The document model(s) this profile's requirement source is defined
   * against; a list means any of them satisfies the baseline. Values are a
   * strict whitelist on purpose: an older engine rejects unknown tokens
   * outright (fail-closed) instead of silently under-checking.
   */
  spec: ProfileSpecBaseline | ProfileSpecBaseline[];
}

export interface ComplianceProfile {
  schema: typeof PROFILE_SCHEMA_V1 | typeof PROFILE_SCHEMA_V2 | typeof PROFILE_SCHEMA_V3 | typeof PROFILE_SCHEMA_V4;
  name: string;
  description?: string;
  /**
   * The requirement source itself. A profile that approximates a published
   * standard must let the reader check the mapping against that standard,
   * the same way field tooltips link the SPDX spec. Display only: no schema
   * bump, because an engine that ignores it loses a link, never a check.
   */
  specUrl?: string;
  requires?: ProfileRequires;
  checks: ProfileCheck[];
}
