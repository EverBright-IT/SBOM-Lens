import { NO_VERSION, packageKey } from '../analysis/conflicts';
import { cpeMatchKey } from '../analysis/cpe';
import type { LicenseIdKind } from '../analysis/licenses';
import { kindOf } from '../analysis/licenses';
import type { VexStatus } from '../analysis/vex';
import { worstVexStatus } from '../analysis/vex';
import { splitPurl } from '../analysis/purl';
import { buildIndexes } from '../graph/indexes';
import { emptyFacets, searchWorkspace } from '../graph/search';
import type { SbomDocument, SbomElement } from '../model/document';
import { effectiveLicense } from '../model/document';
import type { DocumentId, ElementId } from '../model/ids';
import type { OcmArtifact, OcmBundle, OcmCvId } from '../model/ocm-bundle';
import { licenseExpressionError, licenseIdsInExpression } from '../parse/spec-lint';
import { csvCell } from '../util/csv';
import type { LoadedDocument, WorkspaceState } from '../workspace/workspace';
import { addDocuments, emptyWorkspace } from '../workspace/workspace';
import type {
  ResourceRef,
  SbomBindingNote,
  SbomBindingStrength,
  SbomCoverageRow,
  SbomDeclaredReason,
  SbomEvidence,
  SbomOccurrence,
} from './sbom-evidence';
import type { DeliveryVex, VexOrigin } from './sbom-vex';

/**
 * The packages of a delivery: every package the analysed SBOMs list,
 * deduplicated across SBOMs, each with where it ships (the artifact or
 * component version its SBOM is bound to, and how strongly), plus search
 * by name, purl or CPE, the license identifiers, versions that differ
 * between artifacts, and an export.
 *
 * Built on the core's workspace: the worker parses each SBOM and hands
 * over its package list (sbom-analyze.ts: packageList), the UI and the
 * report load those into one workspace and read them here. Pure and
 * synchronous; no parser in here.
 *
 * A search can only find what the SBOMs list. Every answer therefore
 * carries the other half (searchAnswer): which artifacts that ship software
 * were not searched, and why (no SBOM, an SBOM outside the delivery, not
 * analysed), and which were searched only through an SBOM that does not
 * identify them or states a different digest.
 */

/**
 * The packages of one SBOM as the worker hands them over: its package
 * elements, the subject included, without files, raw JSON or relationships.
 */
export interface SbomPackageList {
  /** SHA-1 of the SBOM bytes (the analysis key). */
  sha1: string;
  fileName: string;
  document: SbomDocument;
  /**
   * SPDX ids of the elements that are the SBOM's subject (the image or
   * product it describes); empty when the SBOM names more than three.
   */
  subjects: string[];
  /** File elements left out. */
  omitted: { files: number };
}

/**
 * Where packages of an SBOM ship: the artifact it is bound to (by digest or
 * reference), the component version it names, or, when it is bound to
 * nothing, only the SBOM resource itself.
 */
export interface PackagePlace {
  /** Stable key: the artifact, the component version, or the SBOM resource. */
  key: string;
  kind: 'artifact' | 'component' | 'unbound';
  /** The artifact's component version, the named component version, or the SBOM's. */
  cvId: OcmCvId;
  /** The bound artifact (artifact), or the SBOM resource (unbound). */
  ref?: ResourceRef;
  strength: SbomBindingStrength;
  notes: SbomBindingNote[];
  /** The SBOM resources whose packages ship here. */
  sboms: ResourceRef[];
}

/** One analysed SBOM in the package workspace. */
export interface PackageSource {
  sha1: string;
  docId: DocumentId;
  fileName: string;
  /** Package elements in its list. */
  packages: number;
  omitted: { files: number };
  places: PackagePlace[];
}

/** A package of the delivery: one identity in one version, however many SBOMs list it. */
export interface DeliveryPackage {
  /** `key@version`. */
  id: string;
  /** The identity across versions: the purl without version, else the lowercased name (packageKey). */
  key: string;
  name: string;
  version?: string;
  purl?: string;
  /** The purl type, lowercase; absent without a purl. */
  ecosystem?: string;
  supplier?: string;
  /** License values as the SBOMs state them (concluded, else declared), distinct. */
  licenses: string[];
  /** The SPDX license identifiers those values name. */
  licenseIds: string[];
  /** Values that are not SPDX expressions (a license name or text). */
  licensesUnparsed: string[];
  /** Every SBOM element behind this package. */
  occurrences: { element: SbomElement; docId: DocumentId }[];
  places: PackagePlace[];
  /** The subject (the described image or product) of every SBOM that lists it. */
  subject: boolean;
}

export type NotListedReason = 'no-sbom' | SbomDeclaredReason | 'not-loaded';

/** Which artifacts that ship software the package list speaks for. */
export interface PackageScope {
  /** Artifacts whose bound SBOM's packages are in the list. */
  listed: SbomCoverageRow[];
  /**
   * Artifacts with only an SBOM in their component version that identifies
   * nothing: its packages are listed, under that SBOM, not this artifact.
   */
  unverified: SbomCoverageRow[];
  /** Artifacts whose packages are not in the list, and why. */
  notListed: { row: SbomCoverageRow; reason: NotListedReason }[];
  /**
   * Listed artifacts whose SBOM matches only by repository and tag and
   * states a different digest: it may describe a local build, not the
   * delivered bytes.
   */
  digestDiffers: SbomCoverageRow[];
}

export interface DeliveryPackages {
  ws: WorkspaceState;
  sources: PackageSource[];
  /** By name, then version. */
  packages: DeliveryPackage[];
  byElement: ReadonlyMap<ElementId, DeliveryPackage>;
  /** Every place packages ship to, in bundle order, with its package count. */
  places: { place: PackagePlace; packages: number }[];
  /** Ecosystems (purl types) by package count; `undefined` collects packages without a purl. */
  ecosystems: { ecosystem: string | undefined; packages: number }[];
  scope: PackageScope;
  /** Packages that are an SBOM's subject. */
  subjects: number;
  /** File elements left out across all lists. */
  omitted: { files: number };
}

/** Load package lists into one workspace (search, licenses and conflicts run on it). */
export function packageWorkspace(lists: readonly SbomPackageList[]): WorkspaceState {
  const loaded: LoadedDocument[] = lists.map((list) => {
    // A fresh document per build: the workspace may give a colliding id a
    // suffix and note it, which must not touch the stored list.
    const document = { ...list.document, diagnostics: [] };
    return {
      document,
      indexes: buildIndexes(document),
      source: { fileName: list.fileName, byteSize: 0, sha1: list.sha1, text: '' },
    };
  });
  return addDocuments(emptyWorkspace, loaded).workspace;
}

const RANK: Record<SbomBindingStrength, number> = {
  digest: 3,
  reference: 2,
  component: 1,
  none: 0,
};

const refKey = (ref: ResourceRef) => `${ref.cvId}#${ref.index}`;

function placeOf(occurrence: SbomOccurrence): PackagePlace {
  const binding = occurrence.binding;
  const sboms = [occurrence.at];
  if (binding?.target && (binding.strength === 'digest' || binding.strength === 'reference')) {
    return {
      key: `artifact:${refKey(binding.target)}`,
      kind: 'artifact',
      cvId: binding.target.cvId,
      ref: binding.target,
      strength: binding.strength,
      notes: binding.notes,
      sboms,
    };
  }
  if (binding?.targetCv && binding.strength === 'component') {
    return {
      key: `component:${binding.targetCv}`,
      kind: 'component',
      cvId: binding.targetCv,
      strength: 'component',
      notes: binding.notes,
      sboms,
    };
  }
  return {
    key: `sbom:${refKey(occurrence.at)}`,
    kind: 'unbound',
    cvId: occurrence.at.cvId,
    ref: occurrence.at,
    strength: 'none',
    notes: binding?.notes ?? [],
    sboms,
  };
}

/** Merge a place into a keyed set: the stronger binding wins, the SBOMs add up. */
function mergePlace(into: Map<string, PackagePlace>, place: PackagePlace): void {
  const held = into.get(place.key);
  if (!held) {
    into.set(place.key, { ...place, sboms: [...place.sboms] });
    return;
  }
  if (RANK[place.strength] > RANK[held.strength]) {
    held.strength = place.strength;
    held.notes = place.notes;
  }
  for (const sbom of place.sboms) {
    if (!held.sboms.some((s) => refKey(s) === refKey(sbom))) held.sboms.push(sbom);
  }
}

/**
 * The delivery's packages with their places. `lists` maps an SBOM's SHA-1 to
 * its package list (null: it could not be read for the list); `ws` is
 * packageWorkspace of the lists, passed in when the caller keeps it.
 */
export function deliveryPackages(
  evidence: SbomEvidence,
  lists: Readonly<Record<string, SbomPackageList | null>>,
  ws: WorkspaceState = packageWorkspace(presentLists(lists)),
): DeliveryPackages {
  const order = new Map<string, number>();
  const placesBySha1 = new Map<string, Map<string, PackagePlace>>();
  for (const occurrence of evidence.sboms) {
    if (!occurrence.sha1) continue;
    const place = placeOf(occurrence);
    if (!order.has(place.key)) order.set(place.key, order.size);
    let places = placesBySha1.get(occurrence.sha1);
    if (!places) {
      places = new Map();
      placesBySha1.set(occurrence.sha1, places);
    }
    mergePlace(places, place);
  }
  const byOrder = (a: PackagePlace, b: PackagePlace) =>
    (order.get(a.key) ?? 0) - (order.get(b.key) ?? 0);

  const sources: PackageSource[] = [];
  const subjectIds = new Map<DocumentId, ReadonlySet<string>>();
  const omitted = { files: 0 };
  for (const docId of ws.order) {
    const loaded = ws.documents.get(docId)!;
    const list = lists[loaded.source.sha1];
    const source: PackageSource = {
      sha1: loaded.source.sha1,
      docId,
      fileName: loaded.source.fileName,
      packages: loaded.indexes.packageCount,
      omitted: { files: list?.omitted.files ?? 0 },
      places: [...(placesBySha1.get(loaded.source.sha1)?.values() ?? [])].sort(byOrder),
    };
    omitted.files += source.omitted.files;
    subjectIds.set(docId, new Set(list?.subjects ?? []));
    sources.push(source);
  }

  const byId = new Map<string, DeliveryPackage>();
  const placeMaps = new Map<DeliveryPackage, Map<string, PackagePlace>>();
  const byElement = new Map<ElementId, DeliveryPackage>();
  // Few distinct license values, many packages: parse each value once.
  const parsedLicenses = new Map<string, { unparsed: boolean; ids: string[] }>();
  const parseLicense = (value: string, spdx3: boolean) => {
    const cacheKey = `${spdx3 ? '3' : '2'}${value}`;
    let parsed = parsedLicenses.get(cacheKey);
    if (!parsed) {
      const dialect = { spdx3 };
      parsed = {
        unparsed: licenseExpressionError(value, dialect) !== undefined,
        ids: licenseIdsInExpression(value, dialect),
      };
      parsedLicenses.set(cacheKey, parsed);
    }
    return parsed;
  };
  for (const source of sources) {
    const loaded = ws.documents.get(source.docId)!;
    const spdx3 = loaded.document.spec.model === 'spdx-3';
    const subjects = subjectIds.get(source.docId)!;
    for (const element of loaded.document.elements) {
      if (element.kind !== 'package') continue;
      const isSubject = subjects.has(element.spdxId);
      const key = packageKey(element);
      const id = `${key}@${element.version ?? ''}`;
      let pkg = byId.get(id);
      if (!pkg) {
        const ecosystem = element.purl
          ? splitPurl(element.purl)?.segments[0]?.toLowerCase()
          : undefined;
        pkg = {
          id,
          key,
          name: element.name,
          ...(element.version !== undefined ? { version: element.version } : {}),
          ...(element.purl ? { purl: element.purl } : {}),
          ...(ecosystem ? { ecosystem } : {}),
          licenses: [],
          licenseIds: [],
          licensesUnparsed: [],
          occurrences: [],
          places: [],
          subject: isSubject,
        };
        byId.set(id, pkg);
        placeMaps.set(pkg, new Map());
      } else if (!isSubject) {
        pkg.subject = false;
      }
      if (
        !pkg.supplier &&
        element.supplier &&
        element.supplier !== 'NOASSERTION' &&
        element.supplier !== 'NONE'
      ) {
        pkg.supplier = element.supplier;
      }
      pkg.occurrences.push({ element, docId: source.docId });
      const license = effectiveLicense(element);
      if (license && !pkg.licenses.includes(license)) {
        pkg.licenses.push(license);
        const parsed = parseLicense(license, spdx3);
        if (parsed.unparsed) pkg.licensesUnparsed.push(license);
        for (const lid of parsed.ids) {
          if (!pkg.licenseIds.includes(lid)) pkg.licenseIds.push(lid);
        }
      }
      for (const place of source.places) mergePlace(placeMaps.get(pkg)!, place);
      byElement.set(element.id, pkg);
    }
  }

  const packages = [...byId.values()];
  const placeCounts = new Map<string, { place: PackagePlace; packages: number }>();
  const ecosystemCounts = new Map<string | undefined, number>();
  for (const pkg of packages) {
    pkg.places = [...placeMaps.get(pkg)!.values()].sort(byOrder);
    for (const place of pkg.places) {
      const count = placeCounts.get(place.key);
      if (count) count.packages++;
      else placeCounts.set(place.key, { place, packages: 1 });
    }
    ecosystemCounts.set(pkg.ecosystem, (ecosystemCounts.get(pkg.ecosystem) ?? 0) + 1);
  }
  packages.sort(comparePackages);

  return {
    ws,
    sources,
    packages,
    byElement,
    places: [...placeCounts.values()].sort((a, b) => byOrder(a.place, b.place)),
    ecosystems: [...ecosystemCounts.entries()]
      .map(([ecosystem, count]) => ({ ecosystem, packages: count }))
      // Most packages first; packages without a purl last among equals.
      .sort(
        (a, b) =>
          b.packages - a.packages ||
          Number(a.ecosystem === undefined) - Number(b.ecosystem === undefined) ||
          (a.ecosystem ?? '').localeCompare(b.ecosystem ?? '', 'en'),
      ),
    scope: packageScope(evidence, lists),
    subjects: packages.filter((pkg) => pkg.subject).length,
    omitted,
  };
}

function presentLists(lists: Readonly<Record<string, SbomPackageList | null>>): SbomPackageList[] {
  return Object.values(lists).filter((list): list is SbomPackageList => list !== null);
}

// Collators, not localeCompare with options: sorting tens of thousands of
// packages calls these hundreds of thousands of times. A fixed locale keeps
// the report's order the same on every machine.
const BY_NAME = new Intl.Collator('en', { sensitivity: 'base' });
const BY_VERSION = new Intl.Collator('en', { numeric: true });

function comparePackages(a: DeliveryPackage, b: DeliveryPackage): number {
  return (
    BY_NAME.compare(a.name, b.name) ||
    BY_VERSION.compare(a.version ?? '', b.version ?? '') ||
    (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)
  );
}

function packageScope(
  evidence: SbomEvidence,
  lists: Readonly<Record<string, SbomPackageList | null>>,
): PackageScope {
  const occurrences = new Map(evidence.sboms.map((s) => [refKey(s.at), s]));
  const scope: PackageScope = { listed: [], unverified: [], notListed: [], digestDiffers: [] };
  for (const row of evidence.coverage) {
    if (row.status === 'bound') {
      // Bound and analysed, but its list may still be loading, or failed.
      const states = row.sboms.map((ref) => {
        const sha1 = occurrences.get(refKey(ref))?.sha1;
        return sha1 === undefined ? undefined : lists[sha1];
      });
      if (states.some((list) => list)) {
        scope.listed.push(row);
        // Only bound by reference, and every SBOM behind it states another
        // digest: a "not found" there is weaker than the binding suggests.
        const differs =
          row.strength === 'reference' &&
          row.sboms.every((ref) =>
            occurrences.get(refKey(ref))?.binding?.notes.includes('digest-differs'),
          );
        if (differs && row.expected) scope.digestDiffers.push(row);
      } else if (row.expected) {
        scope.notListed.push({
          row,
          reason: states.some((list) => list === null) ? 'unreadable' : 'not-loaded',
        });
      }
      continue;
    }
    if (!row.expected) continue;
    if (row.status === 'unverified') scope.unverified.push(row);
    else if (row.status === 'declared')
      scope.notListed.push({ row, reason: row.reason ?? 'unreadable' });
    else scope.notListed.push({ row, reason: 'no-sbom' });
  }
  return scope;
}

export interface PackageFilter {
  /** A name or any text, or a purl or CPE (matched by identity). */
  text?: string;
  /** A purl type; '' selects packages without a purl. */
  ecosystem?: string;
  /** A place key. */
  place?: string;
  /** An SPDX license identifier; '' selects packages without a license. */
  licenseId?: string;
  /** The SHA-1 of an SBOM: the packages it lists. */
  sbom?: string;
  /** The worst status VEX statements give a package; 'none': no statement. Needs the VEX model. */
  vex?: VexStatus | 'none';
}

export interface PackageSearch {
  rows: DeliveryPackage[];
  /** The text is a purl or a CPE: packages match by identity, not by spelling. */
  identity: boolean;
  /** Where the matches ship, in bundle order: the answer to "is it in this delivery, and where?". */
  places: { place: PackagePlace; packages: DeliveryPackage[] }[];
}

/**
 * Filter the delivery's packages. Text goes through the workspace search:
 * a purl (`pkg:deb/debian/openssl`, with or without version) or a CPE
 * matches by identity, anything else by name, version and purl text.
 * Matches by relevance, otherwise by name.
 */
export function searchPackages(
  model: DeliveryPackages,
  filter: PackageFilter,
  vex?: DeliveryVex,
): PackageSearch {
  const text = filter.text?.trim() ?? '';
  let rows: DeliveryPackage[];
  if (text === '') {
    rows = model.packages;
  } else {
    // A package matches when any of its elements does, and then ships in
    // all of its places: one SBOM stating a CPE that another leaves out
    // must not hide the other image from the answer.
    const best = new Map<DeliveryPackage, number>();
    const { hits } = searchWorkspace(model.ws, text, emptyFacets, Number.MAX_SAFE_INTEGER);
    for (const hit of hits) {
      const pkg = model.byElement.get(hit.element.id);
      if (pkg && (best.get(pkg) ?? -Infinity) < hit.score) best.set(pkg, hit.score);
    }
    // Ties keep the model's order (by name, then version) without
    // comparing strings again.
    const position = positions(model);
    rows = [...best.keys()].sort(
      (a, b) => best.get(b)! - best.get(a)! || position.get(a)! - position.get(b)!,
    );
  }
  const sbomSource =
    filter.sbom === undefined ? undefined : model.sources.find((s) => s.sha1 === filter.sbom);
  rows = rows.filter((pkg) => {
    if (filter.sbom !== undefined && !pkg.occurrences.some((o) => o.docId === sbomSource?.docId))
      return false;
    if (filter.ecosystem !== undefined && (pkg.ecosystem ?? '') !== filter.ecosystem) return false;
    if (filter.vex !== undefined && vex) {
      const worst = worstVexStatus(vex.byPackage.get(pkg));
      if ((worst ?? 'none') !== filter.vex) return false;
    }
    if (filter.place !== undefined && !pkg.places.some((p) => p.key === filter.place)) return false;
    if (filter.licenseId !== undefined) {
      if (
        filter.licenseId === ''
          ? pkg.licenses.length > 0
          : !pkg.licenseIds.includes(filter.licenseId)
      )
        return false;
    }
    return true;
  });

  // Grouped by place; a place or SBOM filter narrows the places too.
  const sbomPlaces = sbomSource && new Set(sbomSource.places.map((p) => p.key));
  const grouped = new Map<string, { place: PackagePlace; packages: DeliveryPackage[] }>();
  for (const pkg of rows) {
    for (const place of pkg.places) {
      if (filter.place !== undefined && place.key !== filter.place) continue;
      if (sbomPlaces && !sbomPlaces.has(place.key)) continue;
      const group = grouped.get(place.key);
      if (group) group.packages.push(pkg);
      else grouped.set(place.key, { place, packages: [pkg] });
    }
  }
  const placeOrder = new Map(model.places.map((p, i) => [p.place.key, i]));
  return {
    rows,
    identity: text !== '' && isIdentifier(text),
    places: [...grouped.values()].sort(
      (a, b) => (placeOrder.get(a.place.key) ?? 0) - (placeOrder.get(b.place.key) ?? 0),
    ),
  };
}

const positionCache = new WeakMap<DeliveryPackages, Map<DeliveryPackage, number>>();

function positions(model: DeliveryPackages): Map<DeliveryPackage, number> {
  let position = positionCache.get(model);
  if (!position) {
    position = new Map(model.packages.map((pkg, i) => [pkg, i]));
    positionCache.set(model, position);
  }
  return position;
}

/** A purl or a CPE (2.3 formatted string or 2.2 URI), as the workspace search reads them. */
export function isIdentifier(text: string): boolean {
  const q = text.trim().toLowerCase();
  return q.startsWith('pkg:') ? splitPurl(q) !== undefined : cpeMatchKey(q) !== undefined;
}

/**
 * What an answer to "is X in this delivery?" has to say besides the matches.
 * A match is a fact; a miss is only as good as what was searched, so the
 * answer names every qualifier: artifacts not searched (and why), artifacts
 * searched only through an SBOM that does not identify them or states a
 * different digest, packages an identity search cannot find, and filters
 * that narrow the search.
 */
export interface PackageAnswer {
  /** The text is a purl or a CPE, matched by identity. */
  identifier?: 'purl' | 'cpe';
  /** Matching packages. */
  found: number;
  /** Where they ship, in bundle order. */
  places: PackageSearch['places'];
  /** Artifacts that ship software whose packages are not in the list, and why. */
  notSearched: PackageScope['notListed'];
  /** Artifacts searched only through an SBOM that does not identify them. */
  unverified: SbomCoverageRow[];
  /** Artifacts searched through an SBOM that states a different digest. */
  digestDiffers: SbomCoverageRow[];
  /** Packages that state no identifier of the queried kind: only a name search finds them. */
  withoutIdentifier: number;
  /** A filter besides the text limits the search to part of the delivery. */
  narrowed: boolean;
  /**
   * No filter narrows the search, and every artifact that ships software
   * was searched through an SBOM bound to it whose digest does not
   * contradict the delivery.
   */
  everyArtifactSearched: boolean;
}

export function searchAnswer(
  model: DeliveryPackages,
  filter: PackageFilter,
  search: PackageSearch = searchPackages(model, filter),
): PackageAnswer {
  const text = filter.text?.trim().toLowerCase() ?? '';
  const identifier =
    text === '' || !isIdentifier(text) ? undefined : text.startsWith('pkg:') ? 'purl' : 'cpe';
  const statesCpe = (pkg: DeliveryPackage) =>
    pkg.occurrences.some((o) =>
      o.element.externalRefs?.some((ref) => ref.locator.toLowerCase().startsWith('cpe:')),
    );
  const withoutIdentifier =
    identifier === undefined
      ? 0
      : model.packages.filter((pkg) => (identifier === 'purl' ? !pkg.purl : !statesCpe(pkg)))
          .length;
  const narrowed =
    filter.ecosystem !== undefined ||
    filter.place !== undefined ||
    filter.licenseId !== undefined ||
    filter.sbom !== undefined ||
    filter.vex !== undefined;
  const { notListed, unverified, digestDiffers } = model.scope;
  return {
    ...(identifier ? { identifier } : {}),
    found: search.rows.length,
    places: search.places,
    notSearched: notListed,
    unverified,
    digestDiffers,
    withoutIdentifier,
    narrowed,
    everyArtifactSearched:
      !narrowed && notListed.length === 0 && unverified.length === 0 && digestDiffers.length === 0,
  };
}

export interface DeliveryLicenseRow {
  id: string;
  kind: LicenseIdKind;
  /** Packages naming this identifier. */
  packages: number;
  places: PackagePlace[];
}

/**
 * The license identifiers the delivery's packages name. Counts and facts:
 * what a license obliges, or whether two are compatible, is not computed.
 */
export interface DeliveryLicenses {
  rows: DeliveryLicenseRow[];
  packages: number;
  /** Packages without a license in any SBOM that lists them (missing, NONE or NOASSERTION). */
  withoutLicense: number;
  /** Of those, SBOM subjects: an image rarely states a license of its own. */
  subjectsWithoutLicense: number;
  /** License values that are not SPDX expressions, with how many packages state them. */
  unparsed: { value: string; packages: number }[];
  /** Distinct identifiers per kind. */
  kinds: Record<LicenseIdKind, number>;
}

export function deliveryLicenses(model: DeliveryPackages): DeliveryLicenses {
  const rows = new Map<string, { packages: number; places: Map<string, PackagePlace> }>();
  const unparsed = new Map<string, number>();
  let withoutLicense = 0;
  let subjectsWithoutLicense = 0;
  for (const pkg of model.packages) {
    if (pkg.licenses.length === 0) {
      withoutLicense++;
      if (pkg.subject) subjectsWithoutLicense++;
    }
    for (const value of pkg.licensesUnparsed) unparsed.set(value, (unparsed.get(value) ?? 0) + 1);
    for (const id of pkg.licenseIds) {
      let row = rows.get(id);
      if (!row) {
        row = { packages: 0, places: new Map() };
        rows.set(id, row);
      }
      row.packages++;
      for (const place of pkg.places) mergePlace(row.places, place);
    }
  }
  const placeOrder = new Map(model.places.map((p, i) => [p.place.key, i]));
  const kinds: Record<LicenseIdKind, number> = { listed: 0, deprecated: 0, ref: 0, unknown: 0 };
  const out: DeliveryLicenseRow[] = [...rows.entries()].map(([id, row]) => {
    const kind = kindOf(id);
    kinds[kind]++;
    return {
      id,
      kind,
      packages: row.packages,
      places: [...row.places.values()].sort(
        (a, b) => (placeOrder.get(a.key) ?? 0) - (placeOrder.get(b.key) ?? 0),
      ),
    };
  });
  out.sort((a, b) => b.packages - a.packages || a.id.localeCompare(b.id, 'en'));
  return {
    rows: out,
    packages: model.packages.length,
    withoutLicense,
    subjectsWithoutLicense,
    unparsed: [...unparsed.entries()]
      .map(([value, packages]) => ({ value, packages }))
      .sort((a, b) => b.packages - a.packages || a.value.localeCompare(b.value, 'en')),
    kinds,
  };
}

/** One package identity in more than one version. */
export interface DeliveryConflict {
  key: string;
  name: string;
  /** By version, numeric order. */
  versions: { version: string; package: DeliveryPackage }[];
  /** Where the versions ship, together. */
  places: PackagePlace[];
  /** The versions ship in more than one place (artifact, component version or SBOM). */
  acrossPlaces: boolean;
}

/**
 * Packages the delivery ships in more than one version, identified as the
 * core's version-conflict view does (purl without version, else the name).
 * Across places first: one image carrying two versions of a library is
 * common, two images disagreeing about it is the finding.
 */
export function deliveryConflicts(model: DeliveryPackages): DeliveryConflict[] {
  const byKey = new Map<string, DeliveryPackage[]>();
  for (const pkg of model.packages) {
    const group = byKey.get(pkg.key);
    if (group) group.push(pkg);
    else byKey.set(pkg.key, [pkg]);
  }
  const placeOrder = new Map(model.places.map((p, i) => [p.place.key, i]));
  const conflicts: DeliveryConflict[] = [];
  for (const [key, group] of byKey) {
    if (group.length < 2) continue;
    const places = new Map<string, PackagePlace>();
    for (const pkg of group) for (const place of pkg.places) mergePlace(places, place);
    conflicts.push({
      key,
      name: group[0]!.name,
      versions: group
        .map((pkg) => ({ version: pkg.version ?? NO_VERSION, package: pkg }))
        .sort((a, b) => BY_VERSION.compare(a.version, b.version)),
      places: [...places.values()].sort(
        (a, b) => (placeOrder.get(a.key) ?? 0) - (placeOrder.get(b.key) ?? 0),
      ),
      acrossPlaces: places.size > 1,
    });
  }
  return conflicts.sort(
    (a, b) =>
      Number(b.acrossPlaces) - Number(a.acrossPlaces) ||
      b.versions.length - a.versions.length ||
      BY_NAME.compare(a.name, b.name),
  );
}

/** The place a bound artifact's packages are listed under, for filtering by it. */
export function coveragePlaceKey(row: SbomCoverageRow): string | undefined {
  if (row.status !== 'bound') return undefined;
  return row.strength === 'component'
    ? `component:${row.artifact.cvId}`
    : `artifact:${refKey(row.artifact)}`;
}

/** "api · image", "shop-cli (component version)", "obs · sbom (bound to nothing)". */
export function placeLabel(bundle: OcmBundle, place: PackagePlace): string {
  const cv = bundle.componentVersions.find((c) => c.id === place.cvId);
  const short = cv ? (cv.name.split('/').pop() ?? cv.name) : place.cvId;
  if (place.kind === 'component') return `${short} (component version)`;
  const name = place.ref ? (artifactAt(bundle, place.ref)?.name ?? '?') : '?';
  return place.kind === 'artifact' ? `${short} · ${name}` : `${short} · ${name} (bound to nothing)`;
}

function artifactAt(bundle: OcmBundle, ref: ResourceRef): OcmArtifact | undefined {
  return bundle.componentVersions.find((cv) => cv.id === ref.cvId)?.resources[ref.index];
}

const NOTE_LABEL: Record<SbomBindingNote, string> = {
  'digest-differs': 'digest differs',
  'other-component': 'in another component version',
  ambiguous: 'ambiguous',
  'inferred-subject': 'subject inferred',
};

/** "digest", "reference (digest differs)", "none". */
export function placeBinding(place: PackagePlace): string {
  const notes = place.notes.map((n) => NOTE_LABEL[n]);
  return notes.length > 0 ? `${place.strength} (${notes.join(', ')})` : place.strength;
}

export const NOT_LISTED_LABEL: Record<NotListedReason, string> = {
  'no-sbom': 'no SBOM',
  external: 'SBOM outside the delivery',
  unreadable: 'SBOM unreadable',
  deferred: 'SBOM not analysed yet',
  'not-loaded': 'packages not loaded yet',
};

const CSV_COLUMNS = [
  'name',
  'version',
  'ecosystem',
  'purl',
  'license',
  'supplier',
  'component_version',
  'artifact',
  'artifact_type',
  'binding',
  'sbom',
  'sbom_subject',
] as const;

/**
 * One line per package and place: a package that ships in two images is
 * two lines, so a spreadsheet can filter by artifact. With VEX documents
 * loaded, two columns say what the supplier states about the package.
 */
export function packagesToCsv(
  bundle: OcmBundle,
  rows: readonly DeliveryPackage[],
  vex?: DeliveryVex,
): string {
  const withVex = vex !== undefined && vex.documents.length > 0;
  const lines = [
    [...CSV_COLUMNS, ...(withVex ? ['vex_status', 'vex_vulnerabilities'] : [])].join(','),
  ];
  for (const pkg of rows) {
    const findings = withVex ? (vex.byPackage.get(pkg) ?? []) : [];
    const vexCells = withVex
      ? [
          worstVexStatus(findings) ?? '',
          findings.map((f) => `${f.vulnerability} (${f.status})`).join('; '),
        ]
      : [];
    // A package always gets a line, even one no place could be found for.
    for (const place of pkg.places.length > 0 ? pkg.places : [undefined]) {
      const artifact =
        place?.kind === 'artifact' && place.ref ? artifactAt(bundle, place.ref) : undefined;
      lines.push(
        [
          pkg.name,
          pkg.version ?? '',
          pkg.ecosystem ?? '',
          pkg.purl ?? '',
          pkg.licenses.join('; '),
          pkg.supplier ?? '',
          place?.cvId ?? '',
          artifact?.name ?? '',
          artifact?.type ?? '',
          place ? placeBinding(place) : '',
          (place?.sboms ?? [])
            .map((ref) => `${artifactAt(bundle, ref)?.name ?? '?'} (${ref.cvId})`)
            .join('; '),
          pkg.subject ? 'yes' : '',
          ...vexCells,
        ]
          .map(csvCell)
          .join(','),
      );
    }
  }
  return lines.join('\r\n') + '\r\n';
}

export interface PackagesExportMeta {
  generatedAt: string;
  toolVersion: string;
  /** The filter the rows came from, when they are not the whole list. */
  filter?: PackageFilter;
}

/**
 * The rows with every place, plus what the list does not speak for. With
 * VEX documents loaded, each package carries what they state about it.
 */
export function packagesToJson(
  bundle: OcmBundle,
  model: DeliveryPackages,
  rows: readonly DeliveryPackage[],
  meta: PackagesExportMeta,
  vex?: DeliveryVex,
): string {
  const named = (ref: ResourceRef) => ({
    componentVersion: ref.cvId,
    resource: artifactAt(bundle, ref)?.name ?? null,
  });
  const withVex = vex !== undefined && vex.documents.length > 0;
  const origin = (o: VexOrigin) => (o.kind === 'resource' ? named(o.ref) : { file: o.fileName });
  return (
    JSON.stringify(
      {
        schema: 'ocm-lens-packages/v1',
        generatedAt: meta.generatedAt,
        tool: { name: 'OCM Lens', version: meta.toolVersion },
        delivery: bundle.fileName,
        filter: meta.filter && Object.keys(meta.filter).length > 0 ? meta.filter : null,
        packages: rows.map((pkg) => ({
          name: pkg.name,
          version: pkg.version ?? null,
          ecosystem: pkg.ecosystem ?? null,
          purl: pkg.purl ?? null,
          licenses: pkg.licenses,
          supplier: pkg.supplier ?? null,
          sbomSubject: pkg.subject,
          ...(withVex
            ? {
                vex: (vex.byPackage.get(pkg) ?? []).map((f) => ({
                  vulnerability: f.vulnerability,
                  status: f.status,
                  ...(f.justification ? { justification: f.justification } : {}),
                  ...(f.impactStatement ? { impactStatement: f.impactStatement } : {}),
                  ...(f.actionStatement ? { actionStatement: f.actionStatement } : {}),
                  document: f.sourceFile,
                })),
              }
            : {}),
          foundIn: pkg.places.map((place) => {
            const artifact =
              place.kind === 'artifact' && place.ref ? artifactAt(bundle, place.ref) : undefined;
            return {
              componentVersion: place.cvId,
              artifact: artifact?.name ?? null,
              type: artifact?.type ?? null,
              binding: place.strength,
              notes: place.notes,
              sboms: place.sboms.map(named),
            };
          }),
        })),
        notListed: model.scope.notListed.map(({ row, reason }) => ({
          ...named(row.artifact),
          type: artifactAt(bundle, row.artifact)?.type ?? null,
          reason,
        })),
        unverified: model.scope.unverified.map((row) => named(row.artifact)),
        digestDiffers: model.scope.digestDiffers.map((row) => named(row.artifact)),
        omitted: model.omitted,
        ...(withVex
          ? {
              vexDocuments: vex.documents.map((d) => ({
                name: d.name,
                id: d.document.id,
                format: d.document.format ?? null,
                origin: origin(d.origin),
              })),
            }
          : {}),
      },
      null,
      2,
    ) + '\n'
  );
}
