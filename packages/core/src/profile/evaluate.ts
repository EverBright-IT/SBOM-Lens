import type { SbomDocument, SbomElement } from '../model/document';
import { effectiveLicense } from '../model/document';
import type { LoadedDocument, WorkspaceState } from '../workspace/workspace';
import type { ComplianceProfile, DocumentField, PackageField, ProfileCheck, ProfileSpecBaseline } from './model';

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
}

export interface ProfileReport {
  profileName: string;
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

    switch (check.type) {
      case 'document-field': {
        const value = extractDocumentField(doc, check.field);
        const present = Array.isArray(value) ? value.length > 0 : Boolean(value);
        const pass = present && matchesModifiers(value, check.pattern, check.values);
        return { id, label, kind: 'boolean', pass, actual: renderActual(value) };
      }
      case 'relationships': {
        const count = doc.relationships.length;
        return {
          id,
          label,
          kind: 'boolean',
          pass: count >= (check.minCount ?? 1),
          actual: String(count),
        };
      }
      case 'created-recency': {
        const created = doc.created ? Date.parse(doc.created) : Number.NaN;
        const pass = Number.isFinite(created) && now - created <= check.maxAgeDays * MS_PER_DAY;
        return { id, label, kind: 'boolean', pass, actual: doc.created ?? 'missing' };
      }
      case 'package-coverage': {
        let satisfied = 0;
        for (const element of packages) {
          const value =
            check.field === 'checksum' && check.algorithms
              ? hasChecksumAlgorithm(element, check.algorithms)
              : extractPackageField(element, check.field);
          const present = typeof value === 'boolean' ? value : Boolean(value);
          if (present && matchesModifiers(value, check.pattern, check.values)) satisfied++;
        }
        const total = packages.length;
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
    }
  });

  const results = [...preconditions, ...checkResults];

  let gatedPassed = 0;
  let gatedFailed = 0;
  let informational = 0;
  for (const result of results) {
    const gated = result.kind === 'boolean' || result.coverage?.threshold !== undefined;
    if (!gated) informational++;
    else if (result.pass) gatedPassed++;
    else gatedFailed++;
  }

  return {
    profileName: profile.name,
    packagesTotal: packages.length,
    results,
    gatedPassed,
    gatedFailed,
    informational,
  };
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
  }
}

const EMPTYISH = new Set(['NOASSERTION', 'NONE']);

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
