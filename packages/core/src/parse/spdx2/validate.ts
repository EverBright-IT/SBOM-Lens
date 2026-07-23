import type { Diagnostic } from '../../model/diagnostics';
import { SPDX23_DOCS } from '../../spec/spdx23-field-docs';
import { asRecordArray, asString, asStringArray, isRecord } from '../../util/narrow';
import { checksumProblem, createLint, isAbsoluteUri, licenseExpressionError } from '../spec-lint';
import { normalizeRelType } from './common';

/**
 * Spec lint for SPDX 2.x documents: does this document follow SPDX 2.3, beyond
 * being readable? The parser is tolerant by design and only reports what stops
 * it from mapping; these checks report what stops a CONSUMER downstream — a
 * relationship type outside the vocabulary, a digest that cannot be a digest,
 * a license expression no tool can parse.
 *
 * Deliberately NOT here: whether enough fields are present for a policy. That
 * is what the NTIA and BSI profiles measure. The line is spec legality vs.
 * policy coverage, with one exception: fields the spec itself declares
 * mandatory (downloadLocation) are conformance, so they belong here.
 *
 * Runs on the raw JSON/YAML root, so it sees the document as written.
 */

/** SPDX 2.3 § 6.3 / 7.2: "SPDXRef-" plus an idstring (letters, digits, `.`, `-`). */
const SPDX_ID = /^SPDXRef-[0-9A-Za-z.-]+$/;

/**
 * § 6.9: a UTC timestamp, `YYYY-MM-DDThh:mm:ssZ`. Fractional seconds are
 * tolerated (generators emit them and nothing downstream trips over it); an
 * offset other than Z is not, because it silently shifts the creation time.
 */
const CREATED = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

/** § 6.8: every creator is prefixed with its kind. */
const CREATOR = /^(Person|Organization|Tool):\s*\S/;

const RELATIONSHIP_TYPES = new Set(SPDX23_DOCS.relationshipType?.enum ?? []);
const PACKAGE_PURPOSES = new Set(SPDX23_DOCS.package.primaryPackagePurpose?.enum ?? []);

export function validateSpdx2Structure(root: Record<string, unknown>): Diagnostic[] {
  const lint = createLint();
  const { warn, warnAll } = lint;

  // § 6.1: the version literal drives how everything else is read.
  const version = asString(root.spdxVersion);
  if (version !== undefined && !/^SPDX-2\.\d+$/.test(version)) {
    warn('SPDX2_SCHEMA_BAD_VERSION', `spdxVersion "${version}" is not an SPDX-2.x version literal.`);
  }

  // § 6.2: the data license of an SPDX document shall be CC0-1.0.
  const dataLicense = asString(root.dataLicense);
  if (dataLicense !== undefined && dataLicense !== 'CC0-1.0') {
    warn('SPDX2_SCHEMA_BAD_DATA_LICENSE', `dataLicense is "${dataLicense}"; SPDX 2.3 requires CC0-1.0.`);
  }

  // § 6.5: an absolute URI without a fragment, so other documents can point here.
  // (Absence is already reported by the parser as DOC_NO_NAMESPACE.)
  const namespace = asString(root.documentNamespace);
  if (namespace !== undefined && namespace !== '') {
    if (!isAbsoluteUri(namespace)) {
      warn('SPDX2_SCHEMA_BAD_NAMESPACE', `documentNamespace "${namespace}" is not an absolute URI.`);
    } else if (namespace.includes('#')) {
      warn('SPDX2_SCHEMA_BAD_NAMESPACE', `documentNamespace "${namespace}" contains a fragment ("#"), which SPDX forbids.`);
    }
  }

  const creationInfo = isRecord(root.creationInfo) ? root.creationInfo : {};

  const created = asString(creationInfo.created);
  if (created !== undefined && !CREATED.test(created)) {
    warn('SPDX2_SCHEMA_BAD_CREATED', `created "${created}" is not a UTC timestamp of the form YYYY-MM-DDThh:mm:ssZ.`);
  }

  warnAll(
    'SPDX2_SCHEMA_BAD_CREATOR',
    asStringArray(creationInfo.creators).filter((c) => !CREATOR.test(c)),
    (count, list) => `${count} creator entr${count === 1 ? 'y' : 'ies'} without a Person:/Organization:/Tool: prefix: ${list}.`,
  );

  validateIdentifiers(root, warnAll);
  validatePackages(root, warnAll);
  validateFiles(root, warnAll);
  validateRelationships(root, warnAll);

  return lint.diagnostics;
}

type WarnAll = (code: string, subjects: string[], render: (count: number, sample: string) => string) => void;

/** § 6.3 / 7.2: the identifier shape every reference in the document relies on. */
function validateIdentifiers(root: Record<string, unknown>, warnAll: WarnAll): void {
  const bad: string[] = [];
  const check = (value: unknown) => {
    const id = asString(value);
    // A missing SPDXID is the parser's business (JSON_MISSING_SPDXID).
    if (id !== undefined && !SPDX_ID.test(id)) bad.push(id);
  };
  check(root.SPDXID);
  for (const pkg of asRecordArray(root.packages)) check(pkg.SPDXID);
  for (const file of asRecordArray(root.files)) check(file.SPDXID);
  warnAll(
    'SPDX2_SCHEMA_BAD_SPDXID',
    bad,
    (count, list) => `${count} identifier(s) do not follow the SPDXRef-<idstring> form: ${list}.`,
  );
}

function validatePackages(root: Record<string, unknown>, warnAll: WarnAll): void {
  const noDownloadLocation: string[] = [];
  const badPurpose: string[] = [];
  const badChecksum: string[] = [];
  const badLicense: string[] = [];
  const badVerificationCode: string[] = [];
  const badPurl: string[] = [];

  for (const pkg of asRecordArray(root.packages)) {
    const name = asString(pkg.name) ?? '(unnamed package)';

    // § 7.7: downloadLocation is mandatory — NOASSERTION/NONE are the escape
    // hatches the spec itself provides, so an absent field is a real gap.
    const downloadLocation = asString(pkg.downloadLocation);
    if (downloadLocation === undefined || downloadLocation.trim() === '') noDownloadLocation.push(name);

    // § 7.24: primaryPackagePurpose comes from a closed vocabulary.
    const purpose = asString(pkg.primaryPackagePurpose);
    if (purpose !== undefined && !PACKAGE_PURPOSES.has(purpose)) badPurpose.push(`${name} (${purpose})`);

    for (const problem of checksumProblems(pkg.checksums)) badChecksum.push(`${name}: ${problem}`);

    for (const field of ['licenseConcluded', 'licenseDeclared'] as const) {
      const expr = asString(pkg[field]);
      if (expr === undefined) continue;
      const problem = licenseExpressionError(expr);
      if (problem) badLicense.push(`${name} ${field}: ${problem}`);
    }

    // § 7.9: the verification code is a SHA-1 over the package's files.
    if (isRecord(pkg.packageVerificationCode)) {
      const value = asString(pkg.packageVerificationCode.packageVerificationCodeValue);
      if (value !== undefined && !/^[0-9a-fA-F]{40}$/.test(value)) badVerificationCode.push(name);
    }

    // § 7.21: a PACKAGE-MANAGER/purl reference must carry an actual purl.
    for (const ref of asRecordArray(pkg.externalRefs)) {
      const type = asString(ref.referenceType);
      const locator = asString(ref.referenceLocator);
      if (type?.toLowerCase() === 'purl' && locator !== undefined && !locator.startsWith('pkg:')) {
        badPurl.push(`${name} (${locator})`);
      }
    }
  }

  warnAll(
    'SPDX2_SCHEMA_MISSING_DOWNLOAD_LOCATION',
    noDownloadLocation,
    (count, list) => `${count} package(s) without the mandatory downloadLocation (use NOASSERTION when unknown): ${list}.`,
  );
  warnAll(
    'SPDX2_SCHEMA_BAD_PACKAGE_PURPOSE',
    badPurpose,
    (count, list) => `${count} package(s) with a primaryPackagePurpose outside the SPDX vocabulary: ${list}.`,
  );
  warnAll(
    'SPDX2_SCHEMA_BAD_CHECKSUM',
    badChecksum,
    (count, list) => `${count} package checksum(s) do not match their algorithm: ${list}.`,
  );
  warnAll(
    'SPDX2_SCHEMA_BAD_LICENSE_EXPRESSION',
    badLicense,
    (count, list) => `${count} license expression(s) do not parse as SPDX expressions: ${list}.`,
  );
  warnAll(
    'SPDX2_SCHEMA_BAD_VERIFICATION_CODE',
    badVerificationCode,
    (count, list) => `${count} package(s) with a packageVerificationCodeValue that is not 40 hex characters: ${list}.`,
  );
  warnAll(
    'SPDX2_SCHEMA_BAD_PURL_REF',
    badPurl,
    (count, list) => `${count} external reference(s) typed purl whose locator does not start with "pkg:": ${list}.`,
  );
}

function validateFiles(root: Record<string, unknown>, warnAll: WarnAll): void {
  const badChecksum: string[] = [];
  const badLicense: string[] = [];

  for (const file of asRecordArray(root.files)) {
    const name = asString(file.fileName) ?? '(unnamed file)';
    for (const problem of checksumProblems(file.checksums)) badChecksum.push(`${name}: ${problem}`);
    const expr = asString(file.licenseConcluded);
    if (expr !== undefined) {
      const problem = licenseExpressionError(expr);
      if (problem) badLicense.push(`${name}: ${problem}`);
    }
  }

  warnAll(
    'SPDX2_SCHEMA_BAD_CHECKSUM',
    badChecksum,
    (count, list) => `${count} file checksum(s) do not match their algorithm: ${list}.`,
  );
  warnAll(
    'SPDX2_SCHEMA_BAD_LICENSE_EXPRESSION',
    badLicense,
    (count, list) => `${count} file license expression(s) do not parse as SPDX expressions: ${list}.`,
  );
}

/** § 11.1: relationshipType comes from a closed vocabulary of 45 values. */
function validateRelationships(root: Record<string, unknown>, warnAll: WarnAll): void {
  const unknown = new Set<string>();
  for (const rel of asRecordArray(root.relationships)) {
    const type = asString(rel.relationshipType);
    if (type === undefined) continue; // absence is REL_MALFORMED, the parser's business
    if (!RELATIONSHIP_TYPES.has(normalizeRelType(type))) unknown.add(type);
  }
  warnAll(
    'SPDX2_SCHEMA_UNKNOWN_RELATIONSHIP',
    [...unknown],
    (count, list) => `${count} relationship type(s) outside the SPDX 2.3 vocabulary: ${list}.`,
  );
}

function checksumProblems(value: unknown): string[] {
  const problems: string[] = [];
  for (const checksum of asRecordArray(value)) {
    const algorithm = asString(checksum.algorithm);
    const checksumValue = asString(checksum.checksumValue);
    if (algorithm === undefined || checksumValue === undefined) continue; // dropped by the parser
    const problem = checksumProblem(algorithm, checksumValue);
    if (problem) problems.push(problem);
  }
  return problems;
}
