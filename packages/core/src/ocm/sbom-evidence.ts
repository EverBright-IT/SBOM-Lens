import type { Diagnostic } from '../model/diagnostics';
import { diag } from '../model/diagnostics';
import type { OcmArtifact, OcmBundle, OcmCv, OcmCvId } from '../model/ocm-bundle';
import type { ProfileReport } from '../profile/evaluate';

/**
 * SBOM evidence for one delivery: which embedded SBOM describes which
 * artifact, how strongly the delivery supports that claim, and which
 * artifacts that should carry an SBOM do not.
 *
 * OCM has no formal link from an SBOM resource to the artifact it
 * describes, so the binding is read from the SBOM's own subject (SPDX
 * DESCRIBES, CycloneDX metadata.component) and graded like the transport
 * and digest verdicts, by what actually matched:
 * - digest: a digest the SBOM states for its subject is one of the
 *   artifact's (manifest digest, declared digest, image config digest);
 * - reference: same repository path and tag, but no shared digest (an
 *   image scanned from a local build before the push carries a local
 *   identity, not the pushed digest);
 * - component: the SBOM names the component version (product-level SBOMs
 *   built from source or published with a release);
 * - none: the subject matches nothing in this delivery.
 *
 * This module is pure and holds no parser: the worker turns SBOM bytes into
 * an SbomAnalysis (sbom-analyze.ts), the UI and the report grade them here.
 */

export type SbomBindingStrength = 'digest' | 'reference' | 'component' | 'none';
export type SbomBindingNote = 'digest-differs' | 'other-component' | 'ambiguous' | 'inferred-subject';

/** A resource of the bundle: component version plus resource index. */
export interface ResourceRef {
  cvId: OcmCvId;
  index: number;
}

export interface SbomSubject {
  /**
   * describes: the SBOM names its subject (SPDX DESCRIBES, CycloneDX
   * metadata.component). inferred: it does not, and the top-level packages
   * stand in (at most three).
   */
  source: 'describes' | 'inferred';
  /** Display name and version of the first subject element. */
  name?: string;
  version?: string;
  /** Lowercase hex SHA-256 digests the SBOM states for its subject. */
  digests: string[];
  /** Repository paths (no scheme, no tag), with the tag where stated. */
  references: { repository: string; tag?: string }[];
  /** Normalized name/version pairs for component-level matching. */
  components: { name: string; version?: string }[];
}

/** One SBOM's fact sheet: what it is, who made it, how complete it is. */
export interface SbomSummary {
  /** "SPDX 2.3", "CycloneDX 1.6", ... */
  spec: string;
  documentName: string;
  creators: string[];
  created?: string;
  packages: number;
  /** Packages carrying each field. */
  fields: { version: number; supplier: number; uniqueId: number; checksum: number; license: number };
  relationships: number;
  subject: SbomSubject;
  /** NTIA minimum elements and the BSI TR-03183-2 approximation (format-gated). */
  profiles: { ntia: ProfileReport; bsi: ProfileReport };
  /** Parser findings: counts plus the first few. */
  parse: { errors: number; warnings: number; first: Diagnostic[] };
}

/**
 * What the worker learned about one extracted SBOM. deferred: past the
 * load-time budget, analysable on demand. unreadable: the parser gave up.
 */
export type SbomAnalysis =
  | { state: 'analyzed'; summary: SbomSummary }
  | { state: 'deferred'; size: number }
  | { state: 'unreadable'; reason: string };

export interface SbomBinding {
  /** The SBOM resource. */
  sbom: ResourceRef;
  /** SHA-1 of the extracted SBOM bytes (the analysis key). */
  sha1: string;
  subject: SbomSubject;
  strength: SbomBindingStrength;
  /** The artifact a digest or reference binding found. */
  target?: ResourceRef;
  /** The component version a component binding names. */
  targetCv?: OcmCvId;
  notes: SbomBindingNote[];
}

/**
 * bound: an SBOM is tied to this artifact (see the strength).
 * unverified: an analysed SBOM sits in the same component version, but
 *   nothing in it identifies this artifact.
 * declared: an SBOM is declared next to it but could not be used (see the
 *   reason).
 * missing: no SBOM at all.
 */
export type SbomCoverageStatus = 'bound' | 'unverified' | 'declared' | 'missing';
export type SbomDeclaredReason = 'external' | 'unreadable' | 'deferred';

export interface SbomCoverageRow {
  artifact: ResourceRef;
  /** Whether an SBOM is expected for this artifact (see sbomExpected). */
  expected: boolean;
  status: SbomCoverageStatus;
  /** Best binding strength when bound. */
  strength?: Exclude<SbomBindingStrength, 'none'>;
  /** Why a declared SBOM could not be used. */
  reason?: SbomDeclaredReason;
  /** The SBOM resources behind the status. */
  sboms: ResourceRef[];
}

/** Every SBOM resource of the bundle with its state. */
export interface SbomOccurrence {
  at: ResourceRef;
  name: string;
  presence: 'analyzed' | SbomDeclaredReason;
  sha1?: string;
  binding?: SbomBinding;
}

export interface SbomEvidenceCounts {
  /** Artifacts an SBOM is expected for, and how they fare. */
  expected: number;
  covered: number;
  byDigest: number;
  byReference: number;
  byComponent: number;
  unverified: number;
  declared: number;
  missing: number;
  /** SBOM resources: declared, analysed, deferred, bound to nothing. */
  sboms: number;
  analyzed: number;
  deferred: number;
  unbound: number;
}

export interface SbomEvidence {
  sboms: SbomOccurrence[];
  /** One row per non-SBOM resource, in bundle order. */
  coverage: SbomCoverageRow[];
  counts: SbomEvidenceCounts;
  findings: Diagnostic[];
}

/**
 * Resource types that ship software and so should come with an SBOM.
 * Charts, configuration and plain blobs are optional: their contents are
 * described by the images and binaries they deploy or configure. A generic
 * `ociArtifact` counts when its stored config says it is an image.
 */
export const SBOM_EXPECTED_TYPES: ReadonlySet<string> = new Set([
  'ociImage',
  'executable',
  'npmPackage',
  'mavenArtifact',
  'maven',
  'wasm',
  'vscodeExtension',
]);

const IMAGE_CONFIGS = new Set([
  'application/vnd.oci.image.config.v1+json',
  'application/vnd.docker.container.image.v1+json',
]);

export function sbomExpected(artifact: OcmArtifact): boolean {
  if (!artifact.type) return false;
  if (SBOM_EXPECTED_TYPES.has(artifact.type)) return true;
  return artifact.type === 'ociArtifact' && IMAGE_CONFIGS.has(artifact.blob?.oci?.config?.mediaType ?? '');
}

const SHA256_HEX = /^[0-9a-f]{64}$/;

/** Lowercase hex of a `sha256:<hex>`, `sha256.<hex>` or bare 64-hex digest. */
export function digestHex(value: string): string | undefined {
  const hex = value
    .trim()
    .toLowerCase()
    .replace(/^sha-?256[:.]/, '');
  return SHA256_HEX.test(hex) ? hex : undefined;
}

/** `[scheme://]host[:port]/path[:tag][@digest]` split into its parts. */
export function parseImageReference(reference: string): { repository: string; tag?: string; digest?: string } {
  let rest = reference.trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  let digest: string | undefined;
  const at = rest.indexOf('@');
  if (at !== -1) {
    digest = rest.slice(at + 1);
    rest = rest.slice(0, at);
  }
  let tag: string | undefined;
  const colon = rest.lastIndexOf(':');
  if (colon > rest.lastIndexOf('/')) {
    tag = rest.slice(colon + 1);
    rest = rest.slice(0, colon);
  }
  return {
    repository: normalizeRepository(rest),
    ...(tag ? { tag } : {}),
    ...(digest ? { digest } : {}),
  };
}

export function normalizeRepository(repository: string): string {
  return repository
    .trim()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
    .replace(/\/+$/, '')
    .replace(/^(docker\.io|index\.docker\.io)\/(library\/)?/, '')
    .toLowerCase();
}

export function normalizeName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, '');
}

export function normalizeVersion(version: string): string {
  return version
    .trim()
    .toLowerCase()
    .replace(/^v(?=\d)/, '');
}

/**
 * The NTIA minimum elements at package level, by the profile's check ids
 * (component name is always present). Checksums and licenses are measured
 * too, but they are not NTIA minimum elements.
 */
const NTIA_FIELD_CHECKS = new Set(['pkg-version', 'pkg-supplier', 'pkg-unique-id']);

/** The NTIA reading of one SBOM: document checks plus the weakest package field. */
export interface NtiaSummary {
  /** Document-level elements: author, timestamp, dependency relationships, ... */
  documentPassed: number;
  documentTotal: number;
  /** The package-level minimum element with the lowest coverage. */
  weakestField?: { label: string; percent: number; satisfied: number; total: number };
  /** Every document check passes and every package carries every element. */
  complete: boolean;
}

/**
 * The profile engine gates the NTIA document checks and only meters the
 * package fields (no threshold), so its gated count alone overstates an
 * SBOM whose packages lack suppliers. This reads both levels.
 */
export function ntiaSummary(report: ProfileReport): NtiaSummary {
  const documentChecks = report.results.filter((r) => r.kind === 'boolean' && !r.informational);
  const fields = report.results.filter((r) => NTIA_FIELD_CHECKS.has(r.id) && r.coverage);
  const weakest = fields.reduce<(typeof fields)[number] | undefined>(
    (min, r) => (!min || r.coverage!.satisfied * min.coverage!.total < min.coverage!.satisfied * r.coverage!.total ? r : min),
    undefined,
  );
  const documentPassed = documentChecks.filter((r) => r.pass).length;
  const fieldsComplete = fields.every((r) => r.coverage!.satisfied === r.coverage!.total);
  return {
    documentPassed,
    documentTotal: documentChecks.length,
    ...(weakest
      ? {
          weakestField: {
            label: weakest.label,
            percent: weakest.coverage!.percent,
            satisfied: weakest.coverage!.satisfied,
            total: weakest.coverage!.total,
          },
        }
      : {}),
    complete: documentPassed === documentChecks.length && fieldsComplete,
  };
}

/** "complete", or "document 4 of 4, supplier 64 %" naming the weakest field. */
export function ntiaLabel(summary: NtiaSummary): string {
  if (summary.complete) return 'complete';
  const document = `document ${summary.documentPassed} of ${summary.documentTotal}`;
  const field = summary.weakestField;
  if (!field || field.satisfied === field.total) return document;
  const label = field.label.replace(/\s*\(.*\)$/, '');
  return `${document}, ${label.charAt(0).toLowerCase()}${label.slice(1)} ${field.percent} %`;
}

/** What identifies an artifact in this delivery: digests and image references. */
export interface ArtifactIdentity {
  digests: Set<string>;
  references: { repository: string; tag?: string }[];
}

export function artifactIdentity(artifact: OcmArtifact): ArtifactIdentity {
  const digests = new Set<string>();
  const references: { repository: string; tag?: string }[] = [];
  const addDigest = (value: unknown) => {
    const hex = typeof value === 'string' ? digestHex(value) : undefined;
    if (hex) digests.add(hex);
  };
  const addReference = (value: unknown) => {
    if (typeof value !== 'string' || value === '') return;
    const parsed = parseImageReference(value);
    if (parsed.digest) addDigest(parsed.digest);
    references.push(parsed.tag ? { repository: parsed.repository, tag: parsed.tag } : { repository: parsed.repository });
  };
  if (artifact.digest?.value && /sha-?256/i.test(artifact.digest.hashAlgorithm ?? 'sha256')) addDigest(artifact.digest.value);
  addDigest(artifact.blob?.oci?.config?.digest);
  const access = artifact.access?.raw ?? {};
  addReference(access.imageReference);
  const storedOci = artifact.blob?.kind === 'oci-artifact';
  if (storedOci) {
    // A stored image's localReference is its manifest digest, and its
    // referenceName the image reference it was copied from. For any other
    // blob the CLI fills referenceName with the plain resource name.
    addDigest(access.localReference);
    addReference(access.referenceName);
  }
  const globalAccess = access.globalAccess;
  if (globalAccess && typeof globalAccess === 'object') addReference((globalAccess as Record<string, unknown>).imageReference);
  return { digests, references };
}

/**
 * Same repository path, whatever registry serves it: an image scanned as
 * "localhost:5000/team/app" and shipped as "registry.example.org/team/app"
 * or copied to "team/app" is the same repository. Whole path segments only,
 * and a path that is a suffix needs a namespace, so a bare "app" never
 * matches every ".../app".
 */
export function sameRepository(a: string, b: string): boolean {
  const pa = repositoryPath(a);
  const pb = repositoryPath(b);
  if (pa === pb) return true;
  const [shorter, longer] = pa.length <= pb.length ? [pa, pb] : [pb, pa];
  return shorter.includes('/') && longer.endsWith(`/${shorter}`);
}

/** The repository path without its registry host (a first segment with a dot, a port, or "localhost"). */
function repositoryPath(repository: string): string {
  const [first, ...rest] = repository.split('/');
  const isHost = rest.length > 0 && first !== undefined && (first.includes('.') || first.includes(':') || first === 'localhost');
  return isHost ? rest.join('/') : repository;
}

function referenceMatches(
  subject: { repository: string; tag?: string }[],
  artifact: { repository: string; tag?: string }[],
): boolean {
  return subject.some((s) =>
    artifact.some((a) => sameRepository(s.repository, a.repository) && (!s.tag || !a.tag || s.tag === a.tag)),
  );
}

function componentMatches(subject: SbomSubject, cv: OcmCv): boolean {
  const names = new Set([normalizeName(cv.name.split('/').pop() ?? cv.name), normalizeName(cv.name)]);
  const version = normalizeVersion(cv.version);
  return subject.components.some((c) => names.has(c.name) && c.version === version);
}

interface Candidate {
  ref: ResourceRef;
  cv: OcmCv;
  artifact: OcmArtifact;
  identity: ArtifactIdentity;
}

const RANK: Record<SbomBindingStrength, number> = { digest: 3, reference: 2, component: 1, none: 0 };

/**
 * Bind every analysed SBOM to what it describes and grade the coverage of
 * every artifact. `analyses` maps the extracted SBOM's SHA-1 to what the
 * worker learned; an SBOM without an analysis counts as declared, unread.
 */
export function sbomEvidence(bundle: OcmBundle, analyses: Readonly<Record<string, SbomAnalysis>>): SbomEvidence {
  const candidates: Candidate[] = [];
  const sboms: SbomOccurrence[] = [];
  const sbomCv = new Map<SbomOccurrence, OcmCv>();
  for (const cv of bundle.componentVersions) {
    cv.resources.forEach((artifact, index) => {
      const ref = { cvId: cv.id, index };
      if (artifact.isSbom || artifact.sbom) {
        const analysis = artifact.sbom ? analyses[artifact.sbom.sha1] : undefined;
        // Extracted but not analysed (yet) is deferred, never unreadable:
        // the app analyses after the delivery is open, and past a budget
        // only on request. Not extracted is external or unreadable.
        const presence: SbomOccurrence['presence'] = artifact.sbom
          ? analysis === undefined || analysis.state === 'deferred'
            ? 'deferred'
            : analysis.state === 'analyzed'
              ? 'analyzed'
              : 'unreadable'
          : artifact.transport === 'external'
            ? 'external'
            : 'unreadable';
        const occurrence: SbomOccurrence = {
          at: ref,
          name: artifact.name,
          presence,
          ...(artifact.sbom ? { sha1: artifact.sbom.sha1 } : {}),
        };
        sboms.push(occurrence);
        sbomCv.set(occurrence, cv);
      } else {
        candidates.push({ ref, cv, artifact, identity: artifactIdentity(artifact) });
      }
    });
  }

  for (const occurrence of sboms) {
    const analysis = occurrence.sha1 ? analyses[occurrence.sha1] : undefined;
    if (analysis?.state !== 'analyzed') continue;
    occurrence.binding = bindOne(
      occurrence.at,
      sbomCv.get(occurrence)!,
      occurrence.sha1!,
      analysis.summary.subject,
      candidates,
      bundle.componentVersions,
    );
  }
  const bindings = sboms.flatMap((s) => (s.binding ? [s.binding] : []));

  const coverage: SbomCoverageRow[] = [];
  const counts: SbomEvidenceCounts = {
    expected: 0,
    covered: 0,
    byDigest: 0,
    byReference: 0,
    byComponent: 0,
    unverified: 0,
    declared: 0,
    missing: 0,
    sboms: sboms.length,
    analyzed: bindings.length,
    deferred: sboms.filter((s) => s.presence === 'deferred').length,
    unbound: bindings.filter((b) => b.strength === 'none').length,
  };
  for (const { ref, cv, artifact } of candidates) {
    const expected = sbomExpected(artifact);
    const direct = bindings.filter((b) => b.target && sameRef(b.target, ref));
    // A product-level SBOM speaks for the software of its component
    // version, not for its charts and configuration.
    const viaComponent = expected ? bindings.filter((b) => b.strength === 'component' && b.targetCv === cv.id) : [];
    const bound = [...direct, ...viaComponent];
    let row: SbomCoverageRow;
    if (bound.length > 0) {
      const best = bound.reduce((a, b) => (RANK[b.strength] > RANK[a.strength] ? b : a));
      row = {
        artifact: ref,
        expected,
        status: 'bound',
        strength: best.strength as Exclude<SbomBindingStrength, 'none'>,
        sboms: bound.map((b) => b.sbom),
      };
    } else {
      // Siblings speak for this artifact only while they are not bound to
      // something else: an analysed SBOM that identifies nothing leaves the
      // artifact unverified, one we could not use leaves it declared.
      const siblings = sboms.filter((s) => s.at.cvId === cv.id);
      const unbound = siblings.filter((s) => s.binding?.strength === 'none');
      const unused = siblings.filter((s) => s.presence !== 'analyzed');
      if (unbound.length > 0) {
        row = { artifact: ref, expected, status: 'unverified', sboms: unbound.map((s) => s.at) };
      } else if (unused.length > 0) {
        const reason = unused.some((s) => s.presence === 'deferred')
          ? 'deferred'
          : unused.some((s) => s.presence === 'unreadable')
            ? 'unreadable'
            : 'external';
        row = { artifact: ref, expected, status: 'declared', reason, sboms: unused.map((s) => s.at) };
      } else {
        row = { artifact: ref, expected, status: 'missing', sboms: [] };
      }
    }
    coverage.push(row);
    if (!expected) continue;
    counts.expected++;
    if (row.status === 'bound') {
      counts.covered++;
      if (row.strength === 'digest') counts.byDigest++;
      else if (row.strength === 'reference') counts.byReference++;
      else counts.byComponent++;
    } else if (row.status === 'unverified') counts.unverified++;
    else if (row.status === 'declared') counts.declared++;
    else counts.missing++;
  }

  return { sboms, coverage, counts, findings: evidenceFindings(bundle, sboms, coverage) };
}

function bindOne(
  sbom: ResourceRef,
  ownCv: OcmCv,
  sha1: string,
  subject: SbomSubject,
  candidates: Candidate[],
  cvs: OcmCv[],
): SbomBinding {
  // Same component version first: that is where producers put the SBOM of
  // an artifact, and where a tie is resolved.
  const ordered = [
    ...candidates.filter((c) => c.cv.id === ownCv.id),
    ...candidates.filter((c) => c.cv.id !== ownCv.id),
  ];
  const base = { sbom, sha1, subject };
  const inferred: SbomBindingNote[] = subject.source === 'inferred' ? ['inferred-subject'] : [];
  const notesFor = (hit: Candidate, all: Candidate[]): SbomBindingNote[] => {
    const notes: SbomBindingNote[] = [...inferred];
    if (hit.cv.id !== ownCv.id) notes.push('other-component');
    const sameScope = all.filter((c) => (c.cv.id === ownCv.id) === (hit.cv.id === ownCv.id));
    if (sameScope.length > 1) notes.push('ambiguous');
    return notes;
  };

  const byDigest = ordered.filter((c) => subject.digests.some((d) => c.identity.digests.has(d)));
  if (byDigest.length > 0) {
    const hit = byDigest[0]!;
    // Several artifacts with the same digest are the same bytes: no tie.
    const notes = notesFor(hit, [hit]);
    return { ...base, strength: 'digest', target: hit.ref, notes };
  }
  const byReference = ordered.filter((c) => referenceMatches(subject.references, c.identity.references));
  if (byReference.length > 0) {
    const hit = byReference[0]!;
    const notes = notesFor(hit, byReference);
    if (subject.digests.length > 0) notes.unshift('digest-differs');
    return { ...base, strength: 'reference', target: hit.ref, notes };
  }
  const byComponent = [ownCv, ...cvs.filter((cv) => cv.id !== ownCv.id)].filter((cv) => componentMatches(subject, cv));
  if (byComponent.length > 0) {
    const hit = byComponent[0]!;
    const notes: SbomBindingNote[] = [...inferred];
    if (hit.id !== ownCv.id) notes.push('other-component');
    return { ...base, strength: 'component', targetCv: hit.id, notes };
  }
  return { ...base, strength: 'none', notes: inferred };
}

function sameRef(a: ResourceRef, b: ResourceRef): boolean {
  return a.cvId === b.cvId && a.index === b.index;
}

/** One aggregated finding per code, naming what it is about. */
function evidenceFindings(bundle: OcmBundle, sboms: SbomOccurrence[], coverage: SbomCoverageRow[]): Diagnostic[] {
  const label = (ref: ResourceRef) => {
    const cv = bundle.componentVersions.find((c) => c.id === ref.cvId);
    return `${ref.cvId}: ${cv?.resources[ref.index]?.name ?? '?'}`;
  };
  const list = (refs: ResourceRef[]) => {
    const shown = refs.slice(0, 5).map(label).join('; ');
    return refs.length > 5 ? `${shown}; and ${refs.length - 5} more` : shown;
  };
  const findings: Diagnostic[] = [];
  const missing = coverage.filter((r) => r.expected && r.status === 'missing').map((r) => r.artifact);
  if (missing.length > 0) {
    // Most deliveries carry no SBOM at all: that is worth noting, not a
    // warning on every dashboard. A delivery that ships SBOMs and leaves
    // some software out has a gap.
    findings.push(
      sboms.length === 0
        ? diag(
            'info',
            'OCM_SBOM_MISSING',
            `This delivery carries no SBOMs; ${missing.length} artifact(s) ship software: ${list(missing)}.`,
          )
        : diag('warning', 'OCM_SBOM_MISSING', `${missing.length} artifact(s) that ship software carry no SBOM: ${list(missing)}.`),
    );
  }
  const unbound = sboms.filter((s) => s.binding?.strength === 'none').map((s) => s.at);
  if (unbound.length > 0) {
    findings.push(
      diag('info', 'OCM_SBOM_UNBOUND', `${unbound.length} SBOM(s) describe nothing found in this delivery: ${list(unbound)}.`),
    );
  }
  const ambiguous = sboms.filter((s) => s.binding?.notes.includes('ambiguous')).map((s) => s.at);
  if (ambiguous.length > 0) {
    findings.push(
      diag('info', 'OCM_SBOM_AMBIGUOUS', `${ambiguous.length} SBOM(s) match more than one artifact equally well: ${list(ambiguous)}.`),
    );
  }
  const external = sboms.filter((s) => s.presence === 'external').map((s) => s.at);
  if (external.length > 0) {
    findings.push(
      diag('info', 'OCM_SBOM_EXTERNAL', `${external.length} SBOM(s) live outside the delivery and were not analysed: ${list(external)}.`),
    );
  }
  const deferred = sboms.filter((s) => s.presence === 'deferred').map((s) => s.at);
  if (deferred.length > 0) {
    findings.push(
      diag('info', 'OCM_SBOM_ANALYSIS_DEFERRED', `${deferred.length} SBOM(s) are not analysed yet: ${list(deferred)}.`),
    );
  }
  return findings;
}
