import type { Diagnostic } from '../../model/diagnostics';
import { SPDX23_DOCS } from '../../spec/spdx23-field-docs';
import { asRecordArray, asString, asStringArray, isRecord } from '../../util/narrow';
import type { SpecLint, Tally } from '../spec-lint';
import { checksumProblem, createLint, createTally, isAbsoluteUri, licenseExpressionError } from '../spec-lint';
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
 * Both serializations run the same rules. The two entry points differ only in
 * where they read from — the raw JSON/YAML root, or the intermediates the
 * tag-value parser builds — while every rule below is stated once. That split
 * exists because tag-value has no object tree to walk, not because the spec
 * says anything different about it.
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

/** What both serializations look like once the differences are stripped away. */
interface DocumentFacts {
  spdxVersion?: string;
  dataLicense?: string;
  documentNamespace?: string;
  created?: string;
  creators: string[];
}

interface ElementFacts {
  kind: 'package' | 'file';
  label: string;
  spdxId?: string;
  /** Packages only; § 7.7 makes it mandatory there. */
  downloadLocation?: string;
  purpose?: string;
  licenses: string[];
  /** Absent for tag-value, where the parser already reports TV_BAD_CHECKSUM. */
  checksums?: { algorithm: string; value: string }[];
  verificationCode?: string;
  purlRefs?: string[];
}

/** One tally per rule, so a rule never yields two rows even with two passes. */
interface Tallies {
  badId: Tally;
  noDownloadLocation: Tally;
  badPurpose: Tally;
  badChecksum: Tally;
  badLicense: Tally;
  badVerificationCode: Tally;
  badPurl: Tally;
  unknownRelationship: Tally;
}

function createTallies(): Tallies {
  return {
    badId: createTally(),
    noDownloadLocation: createTally(),
    badPurpose: createTally(),
    badChecksum: createTally(),
    badLicense: createTally(),
    badVerificationCode: createTally(),
    badPurl: createTally(),
    unknownRelationship: createTally({ unique: true }),
  };
}

/** SPDX 2.x as JSON or YAML (both parse to the same object shape). */
export function validateSpdx2Structure(root: Record<string, unknown>): Diagnostic[] {
  const lint = createLint();
  const tallies = createTallies();
  const creationInfo = isRecord(root.creationInfo) ? root.creationInfo : {};

  checkDocument(lint, {
    spdxVersion: asString(root.spdxVersion),
    dataLicense: asString(root.dataLicense),
    documentNamespace: asString(root.documentNamespace),
    created: asString(creationInfo.created),
    creators: asStringArray(creationInfo.creators),
  });

  checkId(tallies, asString(root.SPDXID));
  for (const pkg of asRecordArray(root.packages)) checkElement(tallies, packageFacts(pkg));
  for (const file of asRecordArray(root.files)) checkElement(tallies, fileFacts(file));
  for (const rel of asRecordArray(root.relationships)) checkRelationship(tallies, asString(rel.relationshipType));

  emit(lint, tallies);
  return lint.diagnostics;
}

/**
 * SPDX 2.x as tag-value. Runs on the parser's intermediates, since there is no
 * object tree to read. Checksums are left out on purpose: the tag-value parser
 * validates them while reading and reports TV_BAD_CHECKSUM with a line number,
 * which is strictly more useful than repeating the finding here.
 */
export function validateSpdx2TagValue(
  doc: {
    spdxId?: string;
    version?: string;
    dataLicense?: string;
    namespace?: string;
    created?: string;
    creators: string[];
  },
  elements: {
    kind: 'package' | 'file';
    name: string;
    spdxId?: string;
    downloadLocation?: string;
    purpose?: string;
    licenseConcluded?: string;
    licenseDeclared?: string;
  }[],
  relationshipTypes: string[],
): Diagnostic[] {
  const lint = createLint();
  const tallies = createTallies();

  checkDocument(lint, {
    spdxVersion: doc.version,
    dataLicense: doc.dataLicense,
    documentNamespace: doc.namespace,
    created: doc.created,
    creators: doc.creators,
  });

  checkId(tallies, doc.spdxId);
  for (const element of elements) {
    checkElement(tallies, {
      kind: element.kind,
      label: element.name,
      spdxId: element.spdxId,
      downloadLocation: element.downloadLocation,
      purpose: element.purpose,
      licenses: [element.licenseConcluded, element.licenseDeclared].filter((l): l is string => l !== undefined),
    });
  }
  for (const type of relationshipTypes) checkRelationship(tallies, type);

  emit(lint, tallies);
  return lint.diagnostics;
}

// --- rules ------------------------------------------------------------------

function checkDocument(lint: SpecLint, facts: DocumentFacts): void {
  // § 6.1: the version literal drives how everything else is read.
  if (facts.spdxVersion !== undefined && !/^SPDX-2\.\d+$/.test(facts.spdxVersion)) {
    warn(lint, 'SPDX2_SCHEMA_BAD_VERSION', `spdxVersion "${facts.spdxVersion}" is not an SPDX-2.x version literal.`);
  }

  // § 6.2: the data license of an SPDX document shall be CC0-1.0.
  if (facts.dataLicense !== undefined && facts.dataLicense !== 'CC0-1.0') {
    warn(lint, 'SPDX2_SCHEMA_BAD_DATA_LICENSE', `dataLicense is "${facts.dataLicense}"; SPDX 2.3 requires CC0-1.0.`);
  }

  // § 6.5: an absolute URI without a fragment, so other documents can point
  // here. (Absence is already reported by the parser as DOC_NO_NAMESPACE.)
  const namespace = facts.documentNamespace;
  if (namespace !== undefined && namespace !== '') {
    if (!isAbsoluteUri(namespace)) {
      warn(lint, 'SPDX2_SCHEMA_BAD_NAMESPACE', `documentNamespace "${namespace}" is not an absolute URI.`);
    } else if (namespace.includes('#')) {
      warn(lint, 'SPDX2_SCHEMA_BAD_NAMESPACE', `documentNamespace "${namespace}" contains a fragment ("#"), which SPDX forbids.`);
    }
  }

  if (facts.created !== undefined && !CREATED.test(facts.created)) {
    warn(lint, 'SPDX2_SCHEMA_BAD_CREATED', `created "${facts.created}" is not a UTC timestamp of the form YYYY-MM-DDThh:mm:ssZ.`);
  }

  const badCreators = createTally();
  for (const creator of facts.creators) {
    if (!CREATOR.test(creator)) badCreators.add(creator);
  }
  lint.warnTally(
    'SPDX2_SCHEMA_BAD_CREATOR',
    badCreators,
    (count, list) => `${count} creator entr${count === 1 ? 'y' : 'ies'} without a Person:/Organization:/Tool: prefix: ${list}.`,
  );
}

/** § 6.3 / 7.2: the identifier shape every reference in the document relies on. */
function checkId(tallies: Tallies, id: string | undefined): void {
  // A missing SPDXID is the parser's business (JSON_MISSING_SPDXID/TV_MISSING_SPDXID).
  if (id !== undefined && !SPDX_ID.test(id)) tallies.badId.add(id);
}

function checkElement(tallies: Tallies, facts: ElementFacts): void {
  checkId(tallies, facts.spdxId);

  // § 7.7: downloadLocation is mandatory on packages — NOASSERTION/NONE are the
  // escape hatches the spec itself provides, so an absent field is a real gap.
  if (facts.kind === 'package' && (facts.downloadLocation === undefined || facts.downloadLocation.trim() === '')) {
    tallies.noDownloadLocation.add(facts.label);
  }

  // § 7.24: primaryPackagePurpose comes from a closed vocabulary.
  if (facts.purpose !== undefined && !PACKAGE_PURPOSES.has(facts.purpose)) {
    tallies.badPurpose.add(`${facts.label} (${facts.purpose})`);
  }

  for (const checksum of facts.checksums ?? []) {
    const problem = checksumProblem(checksum.algorithm, checksum.value);
    if (problem) tallies.badChecksum.add(`${facts.label}: ${problem}`);
  }

  for (const expression of facts.licenses) {
    const problem = licenseExpressionError(expression);
    if (problem) tallies.badLicense.add(`${facts.label}: ${problem}`);
  }

  // § 7.9: the verification code is a SHA-1 over the package's files.
  if (facts.verificationCode !== undefined && !/^[0-9a-fA-F]{40}$/.test(facts.verificationCode)) {
    tallies.badVerificationCode.add(facts.label);
  }

  // § 7.21: a purl-typed reference must carry an actual purl.
  for (const locator of facts.purlRefs ?? []) {
    if (!locator.startsWith('pkg:')) tallies.badPurl.add(`${facts.label} (${locator})`);
  }
}

/** § 11.1: relationshipType comes from a closed vocabulary of 45 values. */
function checkRelationship(tallies: Tallies, type: string | undefined): void {
  // Absence is REL_MALFORMED, the parser's business.
  if (type === undefined) return;
  if (!RELATIONSHIP_TYPES.has(normalizeRelType(type))) tallies.unknownRelationship.add(type);
}

function emit(lint: SpecLint, t: Tallies): void {
  lint.warnTally('SPDX2_SCHEMA_BAD_SPDXID', t.badId, (count, list) => `${count} identifier(s) do not follow the SPDXRef-<idstring> form: ${list}.`);
  lint.warnTally(
    'SPDX2_SCHEMA_MISSING_DOWNLOAD_LOCATION',
    t.noDownloadLocation,
    (count, list) => `${count} package(s) without the mandatory downloadLocation (use NOASSERTION when unknown): ${list}.`,
  );
  lint.warnTally('SPDX2_SCHEMA_BAD_PACKAGE_PURPOSE', t.badPurpose, (count, list) => `${count} package(s) with a primaryPackagePurpose outside the SPDX vocabulary: ${list}.`);
  lint.warnTally('SPDX2_SCHEMA_BAD_CHECKSUM', t.badChecksum, (count, list) => `${count} checksum(s) do not match their algorithm: ${list}.`);
  lint.warnTally('SPDX2_SCHEMA_BAD_LICENSE_EXPRESSION', t.badLicense, (count, list) => `${count} license expression(s) do not parse as SPDX expressions: ${list}.`);
  lint.warnTally('SPDX2_SCHEMA_BAD_VERIFICATION_CODE', t.badVerificationCode, (count, list) => `${count} package(s) with a packageVerificationCodeValue that is not 40 hex characters: ${list}.`);
  lint.warnTally('SPDX2_SCHEMA_BAD_PURL_REF', t.badPurl, (count, list) => `${count} external reference(s) typed purl whose locator does not start with "pkg:": ${list}.`);
  lint.warnTally('SPDX2_SCHEMA_UNKNOWN_RELATIONSHIP', t.unknownRelationship, (count, list) => `${count} relationship type(s) outside the SPDX 2.3 vocabulary: ${list}.`);
}

function warn(lint: SpecLint, code: string, message: string): void {
  lint.warn(code, message);
}

// --- JSON/YAML field extraction ---------------------------------------------

function packageFacts(pkg: Record<string, unknown>): ElementFacts {
  const purlRefs: string[] = [];
  for (const ref of asRecordArray(pkg.externalRefs)) {
    const type = asString(ref.referenceType);
    const locator = asString(ref.referenceLocator);
    if (type?.toLowerCase() === 'purl' && locator !== undefined) purlRefs.push(locator);
  }
  return {
    kind: 'package',
    label: asString(pkg.name) ?? '(unnamed package)',
    spdxId: asString(pkg.SPDXID),
    downloadLocation: asString(pkg.downloadLocation),
    purpose: asString(pkg.primaryPackagePurpose),
    licenses: [asString(pkg.licenseConcluded), asString(pkg.licenseDeclared)].filter((l): l is string => l !== undefined),
    checksums: readChecksums(pkg.checksums),
    verificationCode: isRecord(pkg.packageVerificationCode)
      ? asString(pkg.packageVerificationCode.packageVerificationCodeValue)
      : undefined,
    purlRefs,
  };
}

function fileFacts(file: Record<string, unknown>): ElementFacts {
  return {
    kind: 'file',
    label: asString(file.fileName) ?? '(unnamed file)',
    spdxId: asString(file.SPDXID),
    licenses: [asString(file.licenseConcluded)].filter((l): l is string => l !== undefined),
    checksums: readChecksums(file.checksums),
  };
}

function readChecksums(value: unknown): { algorithm: string; value: string }[] {
  const out: { algorithm: string; value: string }[] = [];
  for (const checksum of asRecordArray(value)) {
    const algorithm = asString(checksum.algorithm);
    const checksumValue = asString(checksum.checksumValue);
    // A half-written checksum is dropped by the parser, not a spec finding.
    if (algorithm !== undefined && checksumValue !== undefined) out.push({ algorithm, value: checksumValue });
  }
  return out;
}
