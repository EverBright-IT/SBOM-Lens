import { documentQuality } from '../analysis/quality';
import { splitPurl } from '../analysis/purl';
import { buildIndexes } from '../graph/indexes';
import type { RawFields, SbomDocument, SbomElement } from '../model/document';
import { parseDocument } from '../parse/parser';
import { BSI_TR_03183_PROFILE } from '../profile/bsi';
import { evaluateProfile } from '../profile/evaluate';
import { NTIA_PROFILE } from '../profile/ntia';
import { sha1Hex } from '../util/sha1';
import type { LoadedDocument, WorkspaceState } from '../workspace/workspace';
import { addDocuments, emptyWorkspace } from '../workspace/workspace';
import type { SbomAnalysis, SbomSubject, SbomSummary } from './sbom-evidence';
import { digestHex, normalizeName, normalizeRepository, normalizeVersion, parseImageReference } from './sbom-evidence';
import type { SbomPackageList } from './sbom-packages';

/**
 * The worker half of SBOM evidence and the package views: parse an
 * extracted SBOM with the core's SBOM parsers and keep a small summary
 * (sbom-evidence.ts grades it), or, when the package views ask, its
 * packages without files and raw JSON (sbom-packages.ts reads them).
 * Full documents never leave here.
 */

/** Load-time budget for SBOM analysis, in bytes of SBOM text. */
export const SBOM_ANALYSIS_BUDGET_DEFAULT = 64 * 1024 * 1024;

export interface SbomAnalysisInput {
  fileName: string;
  bytes: Uint8Array;
  /** SHA-1 of the bytes when the caller already has it. */
  sha1?: string;
}

const MAX_INFERRED_SUBJECTS = 3;
const RELATION_CHILD_FIRST = new Set(['CONTAINED_BY', 'DEPENDENCY_OF']);
const RELATION_PARENT_FIRST = new Set(['CONTAINS', 'DEPENDS_ON']);

/** The subject an SBOM claims to describe. */
export function sbomSubject(doc: SbomDocument): SbomSubject {
  let roots = doc.elements.filter((el) => doc.describes.includes(el.spdxId));
  let source: SbomSubject['source'] = 'describes';
  if (roots.length === 0) {
    // No DESCRIBES: the packages nothing contains or depends on stand in,
    // but only while they are few enough to be the subject at all.
    const children = new Set<string>();
    for (const rel of doc.relationships) {
      if (RELATION_PARENT_FIRST.has(rel.type) && rel.to.kind === 'local') children.add(rel.to.spdxId);
      if (RELATION_CHILD_FIRST.has(rel.type) && rel.from.kind === 'local') children.add(rel.from.spdxId);
    }
    const top = doc.elements.filter((el) => el.kind === 'package' && !children.has(el.spdxId));
    roots = top.length <= MAX_INFERRED_SUBJECTS ? top : [];
    source = 'inferred';
  }
  const subject: SbomSubject = { source, digests: [], references: [], components: [] };
  const first = roots[0];
  if (first) {
    subject.name = first.name;
    if (first.version) subject.version = first.version;
  }
  for (const root of roots) addRoot(subject, root);
  subject.digests = [...new Set(subject.digests)];
  return subject;
}

function addRoot(subject: SbomSubject, root: SbomElement): void {
  for (const checksum of root.checksums ?? []) {
    if (/^sha-?256$/i.test(checksum.algorithm)) addDigest(subject, checksum.value);
  }
  const version = root.version;
  const versionIsDigest = version !== undefined && digestHex(version) !== undefined;
  if (versionIsDigest) addDigest(subject, version);

  const purls = [root.purl, ...(root.externalRefs ?? []).filter((r) => r.type === 'purl').map((r) => r.locator)];
  for (const purl of new Set(purls)) {
    if (!purl) continue;
    const oci = imagePurl(purl);
    if (!oci) continue;
    if (oci.digest) addDigest(subject, oci.digest);
    subject.references.push(oci.tag ? { repository: oci.repository, tag: oci.tag } : { repository: oci.repository });
  }

  // Image scanners name the root after the image: "registry/repo" with the
  // tag (or a digest) as its version.
  if (root.name.includes('/')) {
    const parsed = parseImageReference(root.name);
    const tag = parsed.tag ?? (version && !versionIsDigest ? version : undefined);
    subject.references.push(tag ? { repository: parsed.repository, tag } : { repository: parsed.repository });
    if (parsed.digest) addDigest(subject, parsed.digest);
  }
  addComponent(subject, root.name, versionIsDigest ? undefined : version);
}

function addDigest(subject: SbomSubject, value: string): void {
  const hex = digestHex(value);
  if (hex) subject.digests.push(hex);
}

function addComponent(subject: SbomSubject, name: string, version?: string): void {
  if (!version) return;
  const last = name.split('/').pop() ?? name;
  for (const candidate of new Set([normalizeName(last), normalizeName(name)])) {
    if (candidate) subject.components.push({ name: candidate, version: normalizeVersion(version) });
  }
}

/**
 * An oci (or docker) purl's repository, tag and digest. The purl spec puts
 * the last path segment into the name and the rest into `repository_url`;
 * syft encodes the whole repository path in the name instead. Both read the
 * same here.
 */
function imagePurl(purl: string): { repository: string; tag?: string; digest?: string } | undefined {
  const split = splitPurl(purl);
  const type = split?.segments[0]?.toLowerCase();
  if (!split || (type !== 'oci' && type !== 'docker')) return undefined;
  const name = split.segments.slice(1).join('/');
  const qualifiers = purlQualifiers(purl);
  const repositoryUrl = qualifiers.get('repository_url');
  const repository = name.includes('/') || !repositoryUrl ? name : repositoryUrl;
  const tag = qualifiers.get('tag') ?? (split.version && !digestHex(split.version) ? split.version : undefined);
  const digest = split.version && digestHex(split.version) ? split.version : undefined;
  return {
    repository: normalizeRepository(repository),
    ...(tag ? { tag } : {}),
    ...(digest ? { digest } : {}),
  };
}

function purlQualifiers(purl: string): Map<string, string> {
  const result = new Map<string, string>();
  const question = purl.indexOf('?');
  if (question === -1) return result;
  const query = purl.slice(question + 1).split('#')[0] ?? '';
  for (const pair of query.split('&')) {
    const eq = pair.indexOf('=');
    if (eq <= 0) continue;
    const key = pair.slice(0, eq).toLowerCase();
    try {
      result.set(key, decodeURIComponent(pair.slice(eq + 1)));
    } catch {
      result.set(key, pair.slice(eq + 1));
    }
  }
  return result;
}

export function sbomSummary(ws: WorkspaceState, loaded: LoadedDocument, now?: number): SbomSummary {
  const doc = loaded.document;
  const quality = documentQuality(ws, loaded);
  const opts = now === undefined ? {} : { now };
  const errors = doc.diagnostics.filter((d) => d.severity === 'error');
  const warnings = doc.diagnostics.filter((d) => d.severity === 'warning');
  return {
    spec: specLabel(doc),
    documentName: doc.name,
    creators: doc.creators,
    ...(doc.created ? { created: doc.created } : {}),
    packages: quality.packages.total,
    fields: {
      version: quality.packages.withVersion,
      supplier: quality.packages.withSupplier,
      uniqueId: quality.packages.withUniqueId,
      checksum: quality.packages.withChecksum,
      license: quality.packages.withLicense,
    },
    relationships: doc.relationships.length,
    subject: sbomSubject(doc),
    profiles: {
      ntia: evaluateProfile(ws, loaded, NTIA_PROFILE, opts),
      bsi: evaluateProfile(ws, loaded, BSI_TR_03183_PROFILE, opts),
    },
    parse: { errors: errors.length, warnings: warnings.length, first: [...errors, ...warnings].slice(0, 5) },
  };
}

function specLabel(doc: SbomDocument): string {
  const family = doc.spec.model === 'cyclonedx' ? 'CycloneDX' : 'SPDX';
  const version = doc.spec.version.replace(/^(SPDX|CycloneDX)-/i, '');
  return version ? `${family} ${version}` : family;
}

async function parseSbom(input: SbomAnalysisInput): Promise<{ document: SbomDocument; sha1: string } | { reason: string }> {
  const text = new TextDecoder().decode(input.bytes);
  const sha1 = input.sha1 ?? (await sha1Hex(input.bytes.slice().buffer as ArrayBuffer));
  const result = parseDocument({ fileName: input.fileName, text, sha1, byteSize: input.bytes.byteLength });
  if (!result.document) {
    return { reason: result.diagnostics.find((d) => d.severity === 'error')?.message ?? 'not an SBOM the parsers accept' };
  }
  return { document: result.document, sha1 };
}

/** Parse one SBOM and keep its summary. Never throws. */
export async function analyzeSbom(input: SbomAnalysisInput, opts: { now?: number } = {}): Promise<SbomAnalysis> {
  try {
    const parsed = await parseSbom(input);
    if ('reason' in parsed) return { state: 'unreadable', reason: parsed.reason };
    const loaded: LoadedDocument = {
      document: parsed.document,
      indexes: buildIndexes(parsed.document),
      // The text stays out of the workspace: only the summary leaves here.
      source: { fileName: input.fileName, byteSize: input.bytes.byteLength, sha1: parsed.sha1, text: '' },
    };
    const ws = addDocuments(emptyWorkspace, [loaded]).workspace;
    return { state: 'analyzed', summary: sbomSummary(ws, loaded, opts.now) };
  } catch (e) {
    return { state: 'unreadable', reason: e instanceof Error ? e.message : String(e) };
  }
}

/** Parse one SBOM and keep its packages (see packageList). Never throws; null when it cannot be read. */
export async function readSbomPackages(input: SbomAnalysisInput): Promise<SbomPackageList | null> {
  try {
    const parsed = await parseSbom(input);
    return 'reason' in parsed ? null : packageList(parsed.document, parsed.sha1, input.fileName);
  } catch {
    return null;
  }
}

const EMPTY_RAW: RawFields = { kind: 'json', value: {} };

/**
 * An SBOM document cut down to what the package views read: its package
 * elements, each with identity, version, supplier, licenses and CPEs. Files
 * (image scanners list thousands), the raw JSON and the relationships stay
 * behind; how many files were left out travels along.
 *
 * Every package stays, the SBOM's subject included: the image or product
 * an SBOM describes ships too, and a search must find it. The subject is
 * only marked, and only while the SBOM names at most three: some
 * generators list every package as described, and then none of them is
 * the subject.
 */
export function packageList(doc: SbomDocument, sha1: string, fileName: string): SbomPackageList {
  const elements: SbomElement[] = [];
  let files = 0;
  for (const element of doc.elements) {
    if (element.kind === 'file') files++;
    else elements.push(slimElement(element));
  }
  const described = new Set(doc.describes);
  const subjects = elements.filter((el) => described.has(el.spdxId)).map((el) => el.spdxId);
  return {
    sha1,
    fileName,
    document: {
      id: doc.id,
      spec: doc.spec,
      spdxId: doc.spdxId,
      name: doc.name,
      namespace: doc.namespace,
      creators: [],
      describes: [],
      externalDocumentRefs: [],
      elements,
      relationships: [],
      diagnostics: [],
    },
    subjects: subjects.length <= MAX_INFERRED_SUBJECTS ? subjects : [],
    omitted: { files },
  };
}

function slimElement(element: SbomElement): SbomElement {
  // Search matches CPEs from the external references; the other
  // references (often a dozen per package) are not needed here.
  const cpes = (element.externalRefs ?? []).filter((ref) => ref.locator.toLowerCase().startsWith('cpe:'));
  return {
    id: element.id,
    documentId: element.documentId,
    spdxId: element.spdxId,
    kind: element.kind,
    name: element.name,
    ...(element.version !== undefined ? { version: element.version } : {}),
    ...(element.purl !== undefined ? { purl: element.purl } : {}),
    ...(element.supplier !== undefined ? { supplier: element.supplier } : {}),
    ...(element.licenseConcluded !== undefined ? { licenseConcluded: element.licenseConcluded } : {}),
    ...(element.licenseDeclared !== undefined ? { licenseDeclared: element.licenseDeclared } : {}),
    ...(cpes.length > 0 ? { externalRefs: cpes } : {}),
    raw: EMPTY_RAW,
  };
}

/**
 * Analyse the SBOMs of a delivery in order until the budget is spent; the
 * rest stays `deferred`, analysable on demand like deferred digests.
 */
export async function analyzeDeliverySboms(
  entries: readonly (SbomAnalysisInput & { sha1: string })[],
  opts: { budget?: number; now?: number } = {},
): Promise<Record<string, SbomAnalysis>> {
  let remaining = opts.budget ?? SBOM_ANALYSIS_BUDGET_DEFAULT;
  const result: Record<string, SbomAnalysis> = {};
  for (const entry of entries) {
    if (result[entry.sha1]) continue;
    if (entry.bytes.byteLength > remaining) {
      result[entry.sha1] = { state: 'deferred', size: entry.bytes.byteLength };
      continue;
    }
    remaining -= entry.bytes.byteLength;
    result[entry.sha1] = await analyzeSbom(entry, opts.now === undefined ? {} : { now: opts.now });
  }
  return result;
}
