import type { CryptoElementExt } from '../model/crypto';
import type { SbomDocument, SbomElement } from '../model/document';
import { effectiveLicense } from '../model/document';
import { licenseIdsInExpression } from '../parse/spec-lint';
import { isDeprecatedLicenseId, isKnownLicenseId } from '../spec/spdx-license-ids';
import type { LoadedDocument, WorkspaceState } from '../workspace/workspace';
import type { ComplianceProfile, CryptoField, DocumentField, PackageField, ProfileCheck, ProfileSpecBaseline } from './model';

/**
 * Profile evaluation. Field semantics live in the two extractors below and
 * mirror analysis/quality.ts EXACTLY — the NTIA parity test pins them
 * against each other, so a predicate change must touch both or CI fails.
 */

export interface CoverageStat {
  satisfied: number;
  total: number;
  /** Rounded for display; gating uses exact cross-multiplication. */
  percent: number;
  /** Absent = informational meter (never gates). */
  threshold?: number;
}

export interface ProfileCheckResult {
  id: string;
  label: string;
  kind: 'boolean' | 'coverage';
  pass: boolean;
  /** Boolean checks: the observed value, truncated, for tooltips/reports. */
  actual?: string;
  coverage?: CoverageStat;
  /** v4: a boolean check the profile marked as a meter; reported, never gated. */
  informational?: boolean;
}

export interface ProfileReport {
  profileName: string;
  /** Carried so every rendering path can show what the profile is and is not. */
  profileDescription?: string;
  /** The requirement source, so a reader can check the mapping themselves. */
  profileSpecUrl?: string;
  packagesTotal: number;
  results: ProfileCheckResult[];
  gatedPassed: number;
  gatedFailed: number;
  informational: number;
}

const MS_PER_DAY = 86_400_000;
const ACTUAL_MAX = 120;

/**
 * `ws` is unused by v1 checks but stays in the signature for future
 * resolution-based checks; `opts.now` makes created-recency deterministic.
 */
export function evaluateProfile(
  ws: WorkspaceState,
  loaded: LoadedDocument,
  profile: ComplianceProfile,
  opts?: { now?: number },
): ProfileReport {
  void ws;
  const doc = loaded.document;
  const now = opts?.now ?? Date.now();
  const packages = doc.elements.filter((el) => el.kind === 'package');
  const cryptoAssets = doc.elements.map((el) => el.crypto).filter((c): c is CryptoElementExt => c !== undefined);

  // Preconditions gate FIRST: a requirement source that only accepts a
  // format must show that mismatch as a failing check, not bury it in the
  // profile description. Boolean kind = gated by the tally below.
  const preconditions: ProfileCheckResult[] = [];
  if (profile.requires?.spec !== undefined) {
    const accepted = Array.isArray(profile.requires.spec) ? profile.requires.spec : [profile.requires.spec];
    preconditions.push({
      id: 'format-baseline',
      label: `Format baseline: ${accepted.map((t) => BASELINE_LABEL[t]).join(' or ')}`,
      kind: 'boolean',
      pass: accepted.some((t) => baselineSatisfied(t, doc)),
      actual: doc.spec.version,
    });
  }

  const checkResults = profile.checks.map((check, index): ProfileCheckResult => {
    const id = check.id ?? `${check.type}-${index}`;
    const label = check.label ?? defaultLabel(check);

    const meter = 'informational' in check && check.informational ? { informational: true } : {};
    switch (check.type) {
      case 'document-field': {
        const value = extractDocumentField(doc, check.field);
        const present = Array.isArray(value) ? value.length > 0 : Boolean(value);
        const pass = present && matchesModifiers(value, check.pattern, check.values);
        return { id, label, kind: 'boolean', pass, actual: renderActual(value), ...meter };
      }
      case 'relationships': {
        const count = doc.relationships.length;
        return {
          id,
          label,
          kind: 'boolean',
          pass: count >= (check.minCount ?? 1),
          actual: String(count),
          ...meter,
        };
      }
      case 'created-recency': {
        const created = doc.created ? Date.parse(doc.created) : Number.NaN;
        const pass = Number.isFinite(created) && now - created <= check.maxAgeDays * MS_PER_DAY;
        return { id, label, kind: 'boolean', pass, actual: doc.created ?? 'missing', ...meter };
      }
      case 'package-coverage': {
        // v5: a purpose filter scopes the meter; the total is what is in scope.
        const scope = check.purposes ? packagesWithPurpose(packages, check.purposes) : packages;
        let satisfied = 0;
        for (const element of scope) {
          const value =
            check.field === 'checksum' && check.algorithms
              ? hasChecksumAlgorithm(element, check.algorithms)
              : extractPackageField(element, check.field);
          const present = typeof value === 'boolean' ? value : Boolean(value);
          if (
            present &&
            matchesModifiers(value, check.pattern, check.values) &&
            licenseIdsSatisfied(value, check.licenseIds, check.allowDeprecated)
          ) {
            satisfied++;
          }
        }
        const total = scope.length;
        const percent = total === 0 ? 100 : Math.round((satisfied / total) * 100);
        // Cross-multiplication: no float division decides a gate.
        const pass = check.threshold === undefined || satisfied * 100 >= check.threshold * total;
        return {
          id,
          label,
          kind: 'coverage',
          pass,
          coverage: { satisfied, total, percent, threshold: check.threshold },
        };
      }
      case 'crypto-coverage': {
        // v5: the scope is every element carrying cryptoProperties, narrowed
        // by asset type, primitive and family; the total is what is in scope.
        const scope = cryptoAssets.filter(
          (c) =>
            matchesFilter(c.assetType, check.assetTypes) &&
            matchesFilter(c.algorithm?.primitive, check.primitives) &&
            matchesFilter(c.algorithm?.family, check.families),
        );
        let satisfied = 0;
        for (const asset of scope) {
          const value = extractCryptoField(asset, check.field);
          const present = typeof value === 'boolean' ? value : Boolean(value);
          if (present && matchesModifiers(value, check.pattern, check.values)) satisfied++;
        }
        const total = scope.length;
        const percent = total === 0 ? 100 : Math.round((satisfied / total) * 100);
        const pass = check.threshold === undefined || satisfied * 100 >= check.threshold * total;
        return {
          id,
          label,
          kind: 'coverage',
          pass,
          coverage: { satisfied, total, percent, threshold: check.threshold },
        };
      }
    }
  });

  const results = [...preconditions, ...checkResults];

  let gatedPassed = 0;
  let gatedFailed = 0;
  let informational = 0;
  for (const result of results) {
    const gated = (result.kind === 'boolean' && !result.informational) || result.coverage?.threshold !== undefined;
    if (!gated) informational++;
    else if (result.pass) gatedPassed++;
    else gatedFailed++;
  }

  return {
    profileName: profile.name,
    ...(profile.description ? { profileDescription: profile.description } : {}),
    ...(profile.specUrl ? { profileSpecUrl: profile.specUrl } : {}),
    packagesTotal: packages.length,
    results,
    gatedPassed,
    gatedFailed,
    informational,
  };
}

/** Case-insensitive purpose match; a package without a purpose is never in scope. */
function packagesWithPurpose(packages: SbomElement[], purposes: string[]): SbomElement[] {
  const wanted = new Set(purposes.map((p) => p.toUpperCase()));
  return packages.filter((p) => p.purpose !== undefined && wanted.has(p.purpose.toUpperCase()));
}

/** No filter: everything is in scope. A filter: the value must be stated and listed (case-insensitive). */
function matchesFilter(value: string | undefined, wanted: string[] | undefined): boolean {
  if (wanted === undefined) return true;
  if (value === undefined) return false;
  const lower = value.toLowerCase();
  return wanted.some((w) => w.toLowerCase() === lower);
}

/** What a crypto asset states for a field: a value for string fields, presence for the rest. */
function extractCryptoField(c: CryptoElementExt, field: CryptoField): string | boolean | undefined {
  switch (field) {
    case 'assetType':
      return c.assetType;
    case 'primitive':
      return c.algorithm?.primitive;
    case 'family':
      return c.algorithm?.family;
    case 'parameterSet':
      return c.algorithm?.parameterSet;
    case 'curve':
      return c.algorithm?.ellipticCurve ?? c.algorithm?.curve;
    case 'mode':
      return c.algorithm?.mode;
    case 'padding':
      return c.algorithm?.padding;
    case 'executionEnvironment':
      return c.algorithm?.executionEnvironment;
    case 'securityLevel':
      return c.algorithm?.classicalSecurityLevel !== undefined || c.algorithm?.nistQuantumSecurityLevel !== undefined;
    case 'certificateSubject':
      return c.certificate?.subjectName;
    case 'certificateIssuer':
      return c.certificate?.issuerName;
    case 'certificateValidity':
      return c.certificate?.notValidAfter !== undefined;
    case 'certificateState':
      return c.certificate?.states && c.certificate.states.length > 0 ? c.certificate.states.join(', ') : undefined;
    case 'certificateSignature':
      return (c.related ?? []).some((r) => /signature/i.test(r.type));
    case 'materialState':
      return c.material?.state;
    case 'materialExpiration':
      return c.material?.expirationDate !== undefined;
    case 'materialSecuredBy':
      return c.material?.securedBy?.mechanism;
    case 'protocolVersion':
      return c.protocol?.version;
    case 'cipherSuites':
      return (c.protocol?.cipherSuites?.length ?? 0) > 0;
    case 'related':
      return (c.related?.length ?? 0) > 0;
    case 'oid':
      return c.oid;
  }
}

/** Mirrors documentQuality's document block. */
function extractDocumentField(
  doc: LoadedDocument['document'],
  field: DocumentField,
): string | string[] | undefined {
  switch (field) {
    case 'name':
      return doc.name || undefined;
    case 'namespace':
      return doc.namespace ?? undefined;
    case 'created':
      return doc.created;
    case 'creators':
      return doc.creators;
    case 'dataLicense':
      return doc.dataLicense;
    case 'comment':
      return doc.comment;
    // v4
    case 'sbomType':
      return doc.sbomType;
    case 'describes':
      return doc.describes;
    case 'externalDocumentRefs':
      return doc.externalDocumentRefs.map((ref) => ref.uri);
  }
}

const EMPTYISH = new Set(['NOASSERTION', 'NONE']);

/**
 * CycloneDX property names accepted as the FDA lifecycle fields. CycloneDX
 * has no normative field for either (taxonomy issue #104 is still open), so
 * these are the conventions this engine reads, spelled out in the FDA
 * profile description. Matched on the property name, case-insensitively.
 */
const SUPPORT_LEVEL_PROPERTY = /^(?:fda:)?(?:lifecycle:)?support[-_]?level$/i;
const END_OF_SUPPORT_PROPERTY = /^(?:fda:)?(?:lifecycle:)?(?:end[-_]?of[-_]?(?:support|life)|eos|eol|valid[-_]?until)$/i;

function propertyValue(element: SbomElement, name: RegExp): string | undefined {
  return element.properties?.find((p) => name.test(p.name) && p.value.trim() !== '')?.value;
}

/**
 * v4 `licenseIds`: every identifier in the expression must be on the SPDX
 * License List ('known') or on the list or a LicenseRef ('known-or-ref');
 * deprecated identifiers fail unless `allowDeprecated` (default true).
 * Non-string values (booleans, absent) are not this modifier's business.
 */
function licenseIdsSatisfied(
  value: string | boolean | undefined,
  licenseIds: 'known' | 'known-or-ref' | undefined,
  allowDeprecated: boolean | undefined,
): boolean {
  if (licenseIds === undefined || typeof value !== 'string') return true;
  const ids = licenseIdsInExpression(value);
  if (ids.length === 0) return false; // NOASSERTION/NONE or nothing parseable
  return ids.every((id) => {
    if (/^(DocumentRef-[^:]+:)?LicenseRef-/.test(id)) return licenseIds === 'known-or-ref';
    if (!isKnownLicenseId(id)) return false;
    return allowDeprecated !== false || !isDeprecatedLicenseId(id);
  });
}

/** v2 `algorithms` modifier: only a checksum in the allow-list satisfies. */
function hasChecksumAlgorithm(element: SbomElement, algorithms: string[]): boolean {
  const allowed = new Set(algorithms.map(normalizeAlgorithm));
  return (element.checksums ?? []).some((checksum) => allowed.has(normalizeAlgorithm(checksum.algorithm)));
}

function normalizeAlgorithm(algorithm: string): string {
  return algorithm.toUpperCase().replace(/-/g, '');
}

/**
 * Mirrors documentQuality's package predicates. Boolean returns are
 * present/absent facts (pattern/values never apply — enforced by validation).
 */
function extractPackageField(
  element: SbomElement,
  field: PackageField,
): string | boolean | undefined {
  switch (field) {
    case 'version':
      return element.version;
    case 'supplier':
      return element.supplier && !EMPTYISH.has(element.supplier) ? element.supplier : undefined;
    case 'purl':
      return element.purl;
    case 'uniqueId':
      return Boolean(element.purl) || (element.externalRefs?.length ?? 0) > 0;
    case 'checksum':
      return (element.checksums?.length ?? 0) > 0;
    case 'license':
      return effectiveLicense(element);
    case 'downloadLocation':
      return element.downloadLocation && !EMPTYISH.has(element.downloadLocation)
        ? element.downloadLocation
        : undefined;
    case 'purpose':
      return element.purpose;
    case 'copyright':
      return element.copyright && !EMPTYISH.has(element.copyright) ? element.copyright : undefined;
    case 'originator':
      return element.originator && !EMPTYISH.has(element.originator)
        ? element.originator
        : undefined;
    // v4
    case 'fileName':
      return element.fileName;
    case 'supportLevel': {
      // The model field (SPDX 3 supportLevel) first; CycloneDX has no
      // normative field, so the documented property names are read as the
      // fallback. Anything spelled differently is deliberately not guessed.
      const level = element.supportLevel ?? propertyValue(element, SUPPORT_LEVEL_PROPERTY);
      return level && level.toLowerCase() !== 'noassertion' ? level : undefined;
    }
    case 'validUntil':
      return element.validUntil ?? propertyValue(element, END_OF_SUPPORT_PROPERTY);
    case 'licenseDeclared':
      return element.licenseDeclared && !EMPTYISH.has(element.licenseDeclared) ? element.licenseDeclared : undefined;
    case 'licenseConcluded':
      return element.licenseConcluded && !EMPTYISH.has(element.licenseConcluded) ? element.licenseConcluded : undefined;
    case 'properties':
      // Rendered as "name=value" lines so a pattern can target one property,
      // e.g. ^fda:lifecycle:support-level=.
      return element.properties && element.properties.length > 0
        ? element.properties.map((p) => `${p.name}=${p.value}`).join('\n')
        : undefined;
    // v5
    case 'description':
      return element.description && element.description.trim() !== '' ? element.description : undefined;
  }
}

/**
 * pattern/values apply to string values (AND-ed); on arrays (creators) the
 * quantifier is SOME — at least one entry must satisfy both modifiers.
 */
function matchesModifiers(
  value: string | string[] | boolean | undefined,
  pattern?: string,
  values?: string[],
): boolean {
  if (pattern === undefined && values === undefined) return true;
  if (typeof value === 'boolean' || value === undefined) return true;
  const candidates = Array.isArray(value) ? value : [value];
  const regex = safeRegex(pattern);
  return candidates.some(
    (candidate) =>
      (regex === null || regex.test(candidate)) &&
      (values === undefined || values.includes(candidate)),
  );
}

function safeRegex(pattern: string | undefined): RegExp | null {
  if (pattern === undefined) return null;
  try {
    return new RegExp(pattern);
  } catch {
    return null; // validation already rejected this; defensive only
  }
}

function renderActual(value: string | string[] | undefined): string {
  const text = Array.isArray(value) ? value.join(' · ') : (value ?? '');
  if (!text) return 'missing';
  return text.length > ACTUAL_MAX ? `${text.slice(0, ACTUAL_MAX - 3)}...` : text;
}

function defaultLabel(check: ProfileCheck): string {
  switch (check.type) {
    case 'document-field':
      return `Document ${check.field}`;
    case 'relationships':
      return 'Relationships';
    case 'created-recency':
      return `Created within ${check.maxAgeDays} days`;
    case 'package-coverage':
      return `Packages with ${check.field}`;
    case 'crypto-coverage':
      return `Cryptographic assets with ${check.field}`;
  }
}

const BASELINE_LABEL: Record<ProfileSpecBaseline, string> = {
  'spdx-3': 'SPDX 3.0.1 or later',
  'cdx-1.6': 'CycloneDX 1.6 or later',
};

/** cdx-1.6 means CycloneDX with specVersion >= 1.6 (major.minor compare). */
function baselineSatisfied(token: ProfileSpecBaseline, doc: SbomDocument): boolean {
  if (token === 'spdx-3') return doc.spec.model === 'spdx-3';
  if (doc.spec.model !== 'cyclonedx') return false;
  const match = /^CycloneDX-(\d+)\.(\d+)/.exec(doc.spec.version);
  if (!match) return false;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  return major > 1 || (major === 1 && minor >= 6);
}
