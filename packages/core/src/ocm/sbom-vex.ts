import type { VexDocument, VexFinding, VexStatement, VexStatus } from '../analysis/vex';
import { matchVex, VEX_STATUS_ORDER, worstVexStatus } from '../analysis/vex';
import type { OcmBundle } from '../model/ocm-bundle';
import type { ResourceRef } from './sbom-evidence';
import type { DeliveryPackage, DeliveryPackages, PackagePlace } from './sbom-packages';

/**
 * Vulnerability communication for a delivery: what the supplier's OpenVEX
 * and CSAF documents state about known vulnerabilities in the packages the
 * delivery ships. Offline only: the documents come from the delivery or are
 * added by the reader; nothing is looked up, nothing is scanned.
 *
 * Matching is the core's (matchVex: purl, CPE and file hash, the OpenVEX
 * time rule), run against the delivery's package workspace. On top of it,
 * this module adds what a delivery needs: the statements per package with
 * the places it ships, the vulnerabilities with every package and place
 * they reach, and the statements that name no package of the delivery,
 * because a product the package list does not hold may still ship in an
 * artifact nobody could look into.
 */

/** Where a VEX or CSAF document came from. */
export type VexOrigin = { kind: 'resource'; ref: ResourceRef } | { kind: 'file'; fileName: string };

/**
 * A VEX or CSAF document of the delivery or added to it: loaded, or why
 * not. Pending: stored in the delivery, not read yet.
 */
export type VexSource =
  | { origin: VexOrigin; name: string; state: 'loaded'; document: VexDocument }
  | {
      origin: VexOrigin;
      name: string;
      state: 'pending' | 'external' | 'unreadable';
      reason?: string;
    };

/** A resource of the delivery that holds or declares a VEX or CSAF document. */
export interface VexResource {
  ref: ResourceRef;
  name: string;
  /** Stored in the delivery (read offline), or declared with an external access (never fetched). */
  presence: 'local' | 'external';
  /** The blob a local one is read from. */
  localReference?: string;
  size?: number;
  /**
   * Found by a marker in its content only (no VEX type or media type): if
   * it does not read as VEX after all, it was never meant as one.
   */
  byContent: boolean;
}

const VEX_TYPE = /vex|csaf|advisor/i;
const VEX_MEDIA_TYPE = /openvex|csaf/i;
/** OpenVEX names its @context, CSAF its version: both sit in the first bytes of the document. */
const VEX_MARKERS = ['openvex.dev', 'csaf_version'];

/**
 * The resources that hold or declare a VEX or CSAF document: by resource
 * type or media type, or, for any JSON or text blob, by the marker in its
 * content preview. SBOMs are never candidates.
 */
export function vexResources(bundle: OcmBundle): VexResource[] {
  const found: VexResource[] = [];
  for (const cv of bundle.componentVersions) {
    cv.resources.forEach((artifact, index) => {
      if (artifact.isSbom || artifact.sbom) return;
      const access = artifact.access?.raw ?? {};
      const declaredMedia = typeof access.mediaType === 'string' ? access.mediaType : '';
      const typed =
        VEX_TYPE.test(artifact.type ?? '') ||
        VEX_MEDIA_TYPE.test(artifact.blob?.mediaType ?? declaredMedia);
      const preview = artifact.blob?.previews?.[0]?.text ?? '';
      if (!typed && !VEX_MARKERS.some((marker) => preview.includes(marker))) return;
      const ref = { cvId: cv.id, index };
      if (artifact.transport === 'transported' && artifact.blob) {
        const localReference =
          typeof access.localReference === 'string'
            ? access.localReference
            : typeof access.filename === 'string'
              ? access.filename
              : undefined;
        if (localReference) {
          found.push({
            ref,
            name: artifact.name,
            presence: 'local',
            localReference,
            size: artifact.blob.size,
            byContent: !typed,
          });
        }
      } else if (artifact.transport === 'external' && typed) {
        found.push({ ref, name: artifact.name, presence: 'external', byContent: false });
      }
    });
  }
  return found;
}

/** A statement that names no package of the delivery. */
export interface VexUnmatched {
  vulnerability: string;
  status: VexStatus;
  /** The products it names: purls, CPEs, file hashes, subcomponents. */
  products: string[];
  origin: VexOrigin;
  /** The document's title, else its id. */
  document: string;
}

/** One vulnerability the documents speak about. */
export interface VexVulnerability {
  id: string;
  aliases: string[];
  description?: string;
  /** Worst status over the packages it reaches; without any, over its statements. */
  status: VexStatus;
  /** The packages it reaches, with the statement that applies to each; alarming first. */
  packages: { pkg: DeliveryPackage; finding: VexFinding }[];
  /** Where those packages ship, each with the worst status there. */
  places: { place: PackagePlace; status: VexStatus }[];
  /** Its statements that name no package of the delivery. */
  unmatched: VexUnmatched[];
}

export type VexStatusCounts = Record<VexStatus, number>;

export interface DeliveryVex {
  /** The loaded documents, in order. */
  documents: { origin: VexOrigin; name: string; document: VexDocument }[];
  statements: number;
  /** Findings per package, merged over the SBOMs that list it, alarming first. */
  byPackage: ReadonlyMap<DeliveryPackage, VexFinding[]>;
  /** Alarming first, then by id. */
  vulnerabilities: VexVulnerability[];
  unmatched: VexUnmatched[];
  /**
   * Packages by the worst status a statement gives them; `without`: a purl
   * or CPE but no statement; `unmatchable`: neither, so no VEX statement
   * can name them.
   */
  counts: VexStatusCounts & { without: number; unmatchable: number };
  /** Per place: its packages by worst status. */
  places: { place: PackagePlace; counts: VexStatusCounts }[];
}

const rank = (status: VexStatus) => VEX_STATUS_ORDER.indexOf(status);
const emptyCounts = (): VexStatusCounts => ({
  affected: 0,
  under_investigation: 0,
  fixed: 0,
  not_affected: 0,
});

/**
 * Match the loaded documents against the delivery's packages. A package
 * listed by several SBOMs gets the most cautious statement any of its
 * elements received.
 */
export function deliveryVex(model: DeliveryPackages, sources: readonly VexSource[]): DeliveryVex {
  const documents = sources.flatMap((s) =>
    s.state === 'loaded' ? [{ origin: s.origin, name: s.name, document: s.document }] : [],
  );
  const reached = new Set<VexStatement>();
  const findings = matchVex(
    model.ws,
    documents.map((d) => d.document),
    reached,
  );

  const byPackage = new Map<DeliveryPackage, VexFinding[]>();
  for (const [elementId, list] of findings) {
    const pkg = model.byElement.get(elementId);
    if (!pkg) continue;
    const held = byPackage.get(pkg);
    byPackage.set(pkg, held ? mergeFindings(held, list) : list);
  }

  const unmatched: VexUnmatched[] = [];
  const facts = new Map<string, { aliases: Set<string>; description?: string }>();
  let statements = 0;
  for (const { origin, document } of documents) {
    for (const statement of document.statements) {
      statements++;
      let fact = facts.get(statement.vulnerability);
      if (!fact) {
        fact = { aliases: new Set() };
        facts.set(statement.vulnerability, fact);
      }
      for (const alias of statement.aliases ?? []) fact.aliases.add(alias);
      fact.description ??= statement.description;
      if (reached.has(statement)) continue;
      unmatched.push({
        vulnerability: statement.vulnerability,
        status: statement.status,
        products: statement.products.flatMap((p) => [p.id, ...p.subcomponents]),
        origin,
        document: document.title ?? document.id,
      });
    }
  }

  const placeOrder = new Map(model.places.map((p, i) => [p.place.key, i]));
  const byPlaceOrder = (a: PackagePlace, b: PackagePlace) =>
    (placeOrder.get(a.key) ?? 0) - (placeOrder.get(b.key) ?? 0);

  const rows = new Map<string, VexVulnerability>();
  const row = (id: string): VexVulnerability => {
    let held = rows.get(id);
    if (!held) {
      const fact = facts.get(id);
      held = {
        id,
        aliases: [...(fact?.aliases ?? [])].sort(),
        ...(fact?.description ? { description: fact.description } : {}),
        status: 'not_affected',
        packages: [],
        places: [],
        unmatched: [],
      };
      rows.set(id, held);
    }
    return held;
  };
  for (const pkg of model.packages) {
    for (const finding of byPackage.get(pkg) ?? [])
      row(finding.vulnerability).packages.push({ pkg, finding });
  }
  for (const statement of unmatched) row(statement.vulnerability).unmatched.push(statement);
  for (const vulnerability of rows.values()) {
    // Alarming first; the package order (name, version) breaks ties.
    vulnerability.packages.sort((x, y) => rank(x.finding.status) - rank(y.finding.status));
    const statuses = vulnerability.packages.length
      ? vulnerability.packages.map((p) => p.finding.status)
      : vulnerability.unmatched.map((u) => u.status);
    vulnerability.status = statuses.reduce((worst, s) => (rank(s) < rank(worst) ? s : worst));
    const places = new Map<string, { place: PackagePlace; status: VexStatus }>();
    for (const { pkg, finding } of vulnerability.packages) {
      for (const place of pkg.places) {
        const held = places.get(place.key);
        if (!held || rank(finding.status) < rank(held.status))
          places.set(place.key, { place, status: finding.status });
      }
    }
    vulnerability.places = [...places.values()].sort((a, b) => byPlaceOrder(a.place, b.place));
  }
  const vulnerabilities = [...rows.values()].sort(
    (a, b) => rank(a.status) - rank(b.status) || a.id.localeCompare(b.id, 'en'),
  );

  const counts = { ...emptyCounts(), without: 0, unmatchable: 0 };
  const placeCounts = new Map<string, { place: PackagePlace; counts: VexStatusCounts }>();
  for (const pkg of model.packages) {
    const worst = worstVexStatus(byPackage.get(pkg));
    if (!worst) {
      if (isMatchable(pkg)) counts.without++;
      else counts.unmatchable++;
      continue;
    }
    counts[worst]++;
    for (const place of pkg.places) {
      let held = placeCounts.get(place.key);
      if (!held) {
        held = { place, counts: emptyCounts() };
        placeCounts.set(place.key, held);
      }
      held.counts[worst]++;
    }
  }

  return {
    documents,
    statements,
    byPackage,
    vulnerabilities,
    unmatched,
    counts,
    places: [...placeCounts.values()].sort((a, b) => byPlaceOrder(a.place, b.place)),
  };
}

/** Per vulnerability, the most cautious statement wins. */
function mergeFindings(held: readonly VexFinding[], more: readonly VexFinding[]): VexFinding[] {
  const byVulnerability = new Map(held.map((f) => [f.vulnerability, f]));
  for (const finding of more) {
    const current = byVulnerability.get(finding.vulnerability);
    if (!current || rank(finding.status) < rank(current.status))
      byVulnerability.set(finding.vulnerability, finding);
  }
  return [...byVulnerability.values()].sort(
    (a, b) =>
      rank(a.status) - rank(b.status) || a.vulnerability.localeCompare(b.vulnerability, 'en'),
  );
}

/** A purl or a CPE: what a VEX statement can name a package by (file hashes aside). */
function isMatchable(pkg: DeliveryPackage): boolean {
  return (
    pkg.purl !== undefined ||
    pkg.occurrences.some((o) =>
      o.element.externalRefs?.some((ref) => ref.locator.toLowerCase().startsWith('cpe:')),
    )
  );
}

/**
 * BSI TR-03191 on a CSAF document, as counts: the requirements that apply
 * and how many hold, plus the labels of those that do not. A measurement,
 * never a conformance verdict; informational facts are left out.
 */
export function tr03191Summary(
  document: VexDocument,
): { passed: number; total: number; open: string[] } | undefined {
  if (!document.tr03191) return undefined;
  const gated = document.tr03191.filter((r) => r.applicable !== false && !r.informational);
  return {
    passed: gated.filter((r) => r.pass).length,
    total: gated.length,
    open: gated.filter((r) => !r.pass).map((r) => `${r.clause} ${r.label}`),
  };
}

/** Vulnerabilities whose id or an alias contains the text, case folded. */
export function findVulnerabilities(vex: DeliveryVex, text: string): VexVulnerability[] {
  const q = text.trim().toLowerCase();
  if (q === '') return vex.vulnerabilities;
  return vex.vulnerabilities.filter(
    (v) => v.id.toLowerCase().includes(q) || v.aliases.some((a) => a.toLowerCase().includes(q)),
  );
}

/** "affected", "under investigation", ... */
export const VEX_STATUS_LABEL: Record<VexStatus, string> = {
  affected: 'affected',
  under_investigation: 'under investigation',
  fixed: 'fixed',
  not_affected: 'not affected',
};
