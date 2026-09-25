import type { Diagnostic } from '../model/diagnostics';
import { diag } from '../model/diagnostics';
import type { SbomElement } from '../model/document';
import type { ElementId } from '../model/ids';
import type { WorkspaceState } from '../workspace/workspace';
import { cpeMatchKey } from './cpe';

/**
 * OpenVEX overlay: what the supplier COMMUNICATES about known
 * vulnerabilities in their product. This is not a scanner and performs no
 * CVE-database lookup — it matches supplier statements against the loaded
 * inventory by package URL and renders exactly what was said, with the
 * OpenVEX time rule deciding between conflicting statements.
 *
 * Findings live in an overlay map keyed by ElementId; the document model
 * stays untouched (overlays are views, not data).
 */

export type VexStatus = 'not_affected' | 'affected' | 'fixed' | 'under_investigation';

const VEX_STATUSES: ReadonlySet<string> = new Set([
  'not_affected',
  'affected',
  'fixed',
  'under_investigation',
]);

/** A file hash the advisory attaches to a product (CSAF product_identification_helper). */
export interface VexProductHash {
  algorithm: string;
  value: string;
}

export interface VexProductRef {
  /**
   * purl or CPE of the product itself ("pkg:..."/"cpe:..." @id or
   * identifiers); for a CSAF product identified only by file hashes, a
   * `hash:<algorithm>:<value>` pseudo-id, so the reference is never empty.
   */
  id: string;
  /** purls/CPEs of affected subcomponents inside that product. */
  subcomponents: string[];
  /** File hashes of the product; matched against element checksums (TR-03191 section 4.4). */
  hashes?: VexProductHash[];
}

/** A CSAF remediation, kept structured so the reader sees kind, link and date. */
export interface VexRemediation {
  /** vendor_fix, mitigation, workaround, none_available, no_fix_planned, ... */
  category: string;
  details?: string;
  url?: string;
  date?: string;
  /** CSAF restart_required.category, when stated. */
  restartRequired?: string;
}

export interface VexStatement {
  /** Vulnerability name, e.g. "CVE-2024-12345". */
  vulnerability: string;
  aliases?: string[];
  description?: string;
  products: VexProductRef[];
  status: VexStatus;
  /** Machine-readable reason, only meaningful for not_affected. */
  justification?: string;
  impactStatement?: string;
  actionStatement?: string;
  /** Structured remediations (CSAF); actionStatement stays the first details text. */
  remediations?: VexRemediation[];
  /** Statement timestamp; absent means "inherit the document's". */
  timestamp?: string;
}

/** One measured requirement of BSI TR-03191 against a CSAF document. Facts, never a conformance verdict. */
export interface CsafRequirementFinding {
  id: string;
  /** Section of TR-03191 the requirement comes from, e.g. "4.3". */
  clause: string;
  label: string;
  pass: boolean;
  /** What was observed, for the reader. */
  actual?: string;
  /** False when the document has nothing the clause applies to (no vulnerabilities, no referenced products); `pass` is then meaningless. */
  applicable?: boolean;
  /** A counted fact the TR conditions on circumstances a file cannot show; reported, never pass or fail. */
  informational?: boolean;
}

export interface VexDocument {
  /** The document's @id, or the file name when absent. */
  id: string;
  fileName: string;
  /** Source exchange format; drives a UI label, never the matching. */
  format?: 'openvex' | 'csaf';
  author?: string;
  timestamp?: string;
  version?: number;
  /** CSAF document.title. */
  title?: string;
  /** CSAF document.category: csaf_vex, csaf_security_advisory, csaf_base, ... */
  category?: string;
  /** CSAF document.distribution.tlp.label, e.g. TLP:CLEAR. */
  tlp?: string;
  /** CSAF tracking.status: draft, interim, final. */
  status?: string;
  /**
   * CSAF tracking.id as published. `id` is the globally unique form the
   * standard defines (publisher namespace plus tracking id), so two
   * publishers reusing one tracking id never displace each other.
   */
  trackingId?: string;
  /** CSAF only: the TR-03191 requirements measured on this document. */
  tr03191?: CsafRequirementFinding[];
  statements: VexStatement[];
  diagnostics: Diagnostic[];
}

/** One vulnerability statement resolved onto one inventory element. */
export interface VexFinding {
  vulnerability: string;
  status: VexStatus;
  justification?: string;
  impactStatement?: string;
  actionStatement?: string;
  description?: string;
  remediations?: VexRemediation[];
  /** @id (or file name) of the VEX document that said it. */
  source: string;
  /**
   * File name of that document. Together with `source` this is a unique
   * join key back to the VexDocument even when two loaded files share an
   * @id — a report must never cite the wrong document.
   */
  sourceFile: string;
  /** The element matched a subcomponent entry, not the product itself. */
  viaSubcomponent: boolean;
  /** Which identifier made the match: the purl, a CPE, or a file hash (CSAF). */
  matchedBy: 'purl' | 'cpe' | 'hash';
  /** Timestamp that won the time rule (statement's, else document's). */
  timestamp?: string;
  /** How many statements for this (element, vulnerability) the time rule discarded. */
  supersededCount?: number;
}

/** Display/sort order: the alarming states first. */
export const VEX_STATUS_ORDER: readonly VexStatus[] = [
  'affected',
  'under_investigation',
  'fixed',
  'not_affected',
];

/** VEX documents are small; anything bigger is not a VEX file. */
export const MAX_VEX_BYTES = 4 * 1024 * 1024;

/**
 * Cheap content sniff, same contract as sniffProfile: run BEFORE the SBOM
 * pipeline on the shared ingest funnel. OpenVEX is JSON with an
 * openvex.dev @context and a statements array.
 */
export function sniffVex(text: string): { isVex: true; raw: unknown } | { isVex: false } {
  if (text.length > MAX_VEX_BYTES) return { isVex: false };
  const head = text.trimStart();
  if (!head.startsWith('{') || !text.includes('openvex.dev')) return { isVex: false };
  try {
    const raw: unknown = JSON.parse(text);
    if (
      isRecord(raw) &&
      typeof raw['@context'] === 'string' &&
      raw['@context'].includes('openvex.dev') &&
      Array.isArray(raw.statements)
    ) {
      return { isVex: true, raw };
    }
  } catch {
    // Marker present but not valid JSON — let the SBOM pipeline report it.
  }
  return { isVex: false };
}

/**
 * Tolerant OpenVEX parser: malformed statements are skipped with a
 * diagnostic, never thrown. Accepts both the current shape (vulnerability
 * and products as objects) and the early spec's strings.
 */
export function parseOpenVex(fileName: string, raw: unknown): VexDocument {
  const diagnostics: Diagnostic[] = [];
  const root = isRecord(raw) ? raw : {};
  const statements: VexStatement[] = [];

  const rawStatements = Array.isArray(root.statements) ? root.statements : [];
  rawStatements.forEach((node, index) => {
    if (!isRecord(node)) {
      diagnostics.push(diag('warning', 'VEX_STATEMENT_SKIPPED', `Statement ${index + 1} is not an object.`));
      return;
    }
    const vulnerability = vulnName(node.vulnerability);
    if (!vulnerability) {
      diagnostics.push(
        diag('warning', 'VEX_STATEMENT_SKIPPED', `Statement ${index + 1} has no vulnerability name.`),
      );
      return;
    }
    const status = typeof node.status === 'string' ? node.status : '';
    if (!VEX_STATUSES.has(status)) {
      diagnostics.push(
        diag(
          'warning',
          'VEX_UNKNOWN_STATUS',
          `Statement ${index + 1} (${vulnerability}): unknown status "${status}" — skipped.`,
        ),
      );
      return;
    }
    const products = parseProducts(node.products);
    if (products.length === 0) {
      // Spec-legal for document-level tooling, but nothing we can match.
      diagnostics.push(
        diag(
          'info',
          'VEX_STATEMENT_UNMATCHABLE',
          `Statement ${index + 1} (${vulnerability}) names no products — nothing to match.`,
        ),
      );
      return;
    }
    const vulnNode = isRecord(node.vulnerability) ? node.vulnerability : undefined;
    statements.push({
      vulnerability,
      ...(strArray(vulnNode?.aliases) ? { aliases: strArray(vulnNode?.aliases) } : {}),
      ...(typeof vulnNode?.description === 'string' ? { description: vulnNode.description } : {}),
      products,
      status: status as VexStatus,
      ...(typeof node.justification === 'string' ? { justification: node.justification } : {}),
      ...(typeof node.impact_statement === 'string' ? { impactStatement: node.impact_statement } : {}),
      ...(typeof node.action_statement === 'string' ? { actionStatement: node.action_statement } : {}),
      ...(typeof node.timestamp === 'string' ? { timestamp: node.timestamp } : {}),
    });
  });

  return {
    id: typeof root['@id'] === 'string' && root['@id'] !== '' ? root['@id'] : fileName,
    fileName,
    format: 'openvex',
    ...(typeof root.author === 'string' ? { author: root.author } : {}),
    ...(typeof root.timestamp === 'string' ? { timestamp: root.timestamp } : {}),
    ...(typeof root.version === 'number' ? { version: root.version } : {}),
    statements,
    diagnostics,
  };
}

/** "CVE-..." (early spec) or { name, aliases, description }. */
function vulnName(node: unknown): string | undefined {
  if (typeof node === 'string' && node !== '') return node;
  if (isRecord(node) && typeof node.name === 'string' && node.name !== '') return node.name;
  return undefined;
}

/**
 * Products: strings (early spec) or { "@id", identifiers, subcomponents }.
 * identifiers may carry purl, cpe23, or cpe22 — purl preferred, CPE accepted.
 */
function parseProducts(node: unknown): VexProductRef[] {
  if (!Array.isArray(node)) return [];
  const products: VexProductRef[] = [];
  for (const entry of node) {
    if (typeof entry === 'string' && entry !== '') {
      products.push({ id: entry, subcomponents: [] });
      continue;
    }
    if (!isRecord(entry)) continue;
    const id = firstPurlish(entry['@id']) ?? identifierOf(entry.identifiers);
    if (!id) continue;
    const subcomponents: string[] = [];
    if (Array.isArray(entry.subcomponents)) {
      for (const sub of entry.subcomponents) {
        const subId =
          firstPurlish(sub) ??
          (isRecord(sub) ? (firstPurlish(sub['@id']) ?? identifierOf(sub.identifiers)) : undefined);
        if (subId) subcomponents.push(subId);
      }
    }
    products.push({ id, subcomponents });
  }
  return products;
}

function identifierOf(identifiers: unknown): string | undefined {
  if (!isRecord(identifiers)) return undefined;
  return firstPurlish(identifiers.purl) ?? firstPurlish(identifiers.cpe23) ?? firstPurlish(identifiers.cpe22);
}

function firstPurlish(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

function strArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const items = value.filter((v): v is string => typeof v === 'string');
  return items.length > 0 ? items : undefined;
}

/**
 * Conservative purl normalisation for matching, documented in docs/vex.md:
 * scheme/type/namespace are case-folded, the name and version compare
 * exactly (after percent-decoding), qualifiers and subpath are ignored.
 * Returns undefined for anything that is not a purl.
 */
export function purlMatchKey(purl: string): { pkg: string; version?: string } | undefined {
  if (!purl.startsWith('pkg:')) return undefined;
  let rest = purl.slice('pkg:'.length);
  // Strip subpath, then qualifiers.
  const hash = rest.indexOf('#');
  if (hash !== -1) rest = rest.slice(0, hash);
  const question = rest.indexOf('?');
  if (question !== -1) rest = rest.slice(0, question);
  const at = rest.lastIndexOf('@');
  let version: string | undefined;
  // A raw '/' after the '@' means the '@' belongs to an unencoded scope
  // (pkg:npm/@angular/core), not a version separator: a purl version part
  // never contains a raw slash. Without this guard the versionless scoped
  // form would split into garbage and silently never match.
  if (at > 0 && !rest.slice(at + 1).includes('/')) {
    version = decodeSegment(rest.slice(at + 1));
    rest = rest.slice(0, at);
  }
  const segments = rest.replace(/^\/+/, '').split('/').filter((s) => s !== '');
  if (segments.length === 0) return undefined;
  const type = segments[0]!.toLowerCase();
  const name = decodeSegment(segments[segments.length - 1]!);
  const namespace = segments
    .slice(1, -1)
    .map((s) => decodeSegment(s).toLowerCase())
    .join('/');
  const pkg = `${type}/${namespace}/${name}`;
  return version !== undefined && version !== '' ? { pkg, version } : { pkg };
}

function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

interface IndexedStatement {
  statement: VexStatement;
  source: string;
  sourceFile: string;
  /** Effective timestamp for the time rule (statement's, else document's). */
  timestamp?: string;
  /** Position for deterministic tie-breaks: later loaded wins. */
  order: number;
  viaSubcomponent: boolean;
}

/**
 * One index row: the candidate plus the version constraint of the key it was
 * filed under. The SAME candidate object is filed under every key its
 * product carries (purl, CPE, file hashes), so an element reachable through
 * several keys sees one candidate, not one per key.
 */
interface IndexEntry {
  candidate: IndexedStatement;
  version?: string;
}

/**
 * Match every loaded VEX statement against the workspace inventory.
 * Returns one finding per (element, vulnerability): when several statements
 * target the same pair, the one with the newest timestamp wins (the OpenVEX
 * time rule); a tie within one document falls to the more cautious status,
 * ties across documents fall to the later-loaded document; the ORDER of vexDocs
 * is part of the contract, so callers must hand documents over in a stable
 * order (the app loads in ingest order; a CLI should sort by path).
 * Findings are sorted alarming-first (affected before not_affected), and
 * the whole result is deterministic for identical inputs.
 */
export function matchVex(
  ws: WorkspaceState,
  vexDocs: readonly VexDocument[],
): Map<ElementId, VexFinding[]> {
  // match key -> index rows (both exact-version and versionless).
  const index = new Map<string, IndexEntry[]>();
  let order = 0;
  for (const doc of vexDocs) {
    for (const statement of doc.statements) {
      const timestamp = statement.timestamp ?? doc.timestamp;
      // ONE candidate per statement, filed under every key of every product
      // it names: a component installed on two hosts is two products of one
      // statement, and an element reachable through both must see one
      // candidate, not a phantom "superseded" duplicate.
      const candidate: IndexedStatement = {
        statement,
        source: doc.id,
        sourceFile: doc.fileName,
        ...(timestamp !== undefined ? { timestamp } : {}),
        order: order++,
        viaSubcomponent: false,
      };
      let viaSub: IndexedStatement | undefined;
      for (const product of statement.products) {
        // A product known only by its hashes carries a hash: pseudo-id; the
        // hashes list below files it, so the id must not file it again.
        if (!product.id.startsWith('hash:')) fileUnderRef(index, product.id, candidate);
        // A file hash names exact bytes: no version dimension, no wildcard.
        for (const hash of product.hashes ?? []) fileUnder(index, hashKey(hash.algorithm, hash.value), candidate);
        for (const sub of product.subcomponents) {
          viaSub ??= { ...candidate, order: order++, viaSubcomponent: true };
          fileUnderRef(index, sub, viaSub);
        }
      }
    }
  }
  if (index.size === 0) return new Map();

  const findings = new Map<ElementId, VexFinding[]>();
  for (const loaded of ws.documents.values()) {
    for (const element of loaded.document.elements) {
      const keys = elementMatchKeys(element);
      if (keys.length === 0) continue;

      // A versioned VEX identifier must match the element's version exactly;
      // a versionless one covers every version. An element reachable through
      // several keys sees each candidate once; the first key in purl, CPE,
      // hash order says how it matched.
      const applicable = new Map<IndexedStatement, VexFinding['matchedBy']>();
      for (const key of keys) {
        for (const entry of index.get(key.id) ?? []) {
          if (entry.version === undefined || (key.version !== undefined && entry.version === key.version)) {
            if (!applicable.has(entry.candidate)) applicable.set(entry.candidate, key.kind);
          }
        }
      }
      if (applicable.size === 0) continue;

      // A statement reachable both directly and through a subcomponent is
      // one statement: the direct path wins and nothing is superseded.
      const byStatement = new Map<VexStatement, IndexedStatement>();
      for (const candidate of applicable.keys()) {
        const seen = byStatement.get(candidate.statement);
        if (!seen || (seen.viaSubcomponent && !candidate.viaSubcomponent)) byStatement.set(candidate.statement, candidate);
      }
      const byVuln = new Map<string, { winner: IndexedStatement; superseded: number }>();
      for (const candidate of byStatement.values()) {
        const existing = byVuln.get(candidate.statement.vulnerability);
        if (!existing) {
          byVuln.set(candidate.statement.vulnerability, { winner: candidate, superseded: 0 });
        } else if (newerThan(candidate, existing.winner)) {
          byVuln.set(candidate.statement.vulnerability, { winner: candidate, superseded: existing.superseded + 1 });
        } else {
          existing.superseded++;
        }
      }
      const list = [...byVuln.values()]
        .map(({ winner: c, superseded }): VexFinding => ({
          vulnerability: c.statement.vulnerability,
          status: c.statement.status,
          ...(c.statement.justification !== undefined ? { justification: c.statement.justification } : {}),
          ...(c.statement.impactStatement !== undefined ? { impactStatement: c.statement.impactStatement } : {}),
          ...(c.statement.actionStatement !== undefined ? { actionStatement: c.statement.actionStatement } : {}),
          ...(c.statement.description !== undefined ? { description: c.statement.description } : {}),
          ...(c.statement.remediations !== undefined ? { remediations: c.statement.remediations } : {}),
          source: c.source,
          sourceFile: c.sourceFile,
          viaSubcomponent: c.viaSubcomponent,
          matchedBy: applicable.get(c) ?? 'purl',
          ...(c.timestamp !== undefined ? { timestamp: c.timestamp } : {}),
          ...(superseded > 0 ? { supersededCount: superseded } : {}),
        }))
        .sort(
          (a, b) =>
            VEX_STATUS_ORDER.indexOf(a.status) - VEX_STATUS_ORDER.indexOf(b.status) ||
            a.vulnerability.localeCompare(b.vulnerability),
        );
      findings.set(element.id, list);
    }
  }
  return findings;
}

/** Files a candidate under the match key of a purl, CPE or hash pseudo-id (ignored when it is none). */
function fileUnderRef(index: Map<string, IndexEntry[]>, ref: string, candidate: IndexedStatement): void {
  const key = refMatchKey(ref);
  if (!key) return;
  fileUnder(index, key.id, candidate, key.version);
}

function fileUnder(index: Map<string, IndexEntry[]>, id: string, candidate: IndexedStatement, version?: string): void {
  const list = index.get(id) ?? [];
  list.push(version !== undefined ? { candidate, version } : { candidate });
  index.set(id, list);
}

interface MatchKey {
  /** Index key: a purl package key, a CPE key behind `cpe|`, or a file hash behind `hash|`. */
  id: string;
  kind: 'purl' | 'cpe' | 'hash';
  version?: string;
}

/** `hash|SHA256:<lowercase hex>`: algorithm spellings differ between formats, the bytes do not. */
function hashKey(algorithm: string, value: string): string {
  return `hash|${algorithm.toUpperCase().replace(/[^A-Z0-9]/g, '')}:${value.toLowerCase()}`;
}

/**
 * One namespace for every identifier scheme. purl keys are
 * `type/namespace/name` (always contain a slash), CPE keys get a `cpe|`
 * prefix, hash keys a `hash|` prefix — none can collide.
 */
function refMatchKey(ref: string): MatchKey | undefined {
  const purl = purlMatchKey(ref);
  if (purl) return purl.version !== undefined ? { id: purl.pkg, kind: 'purl', version: purl.version } : { id: purl.pkg, kind: 'purl' };
  const cpe = cpeMatchKey(ref);
  if (cpe) {
    return cpe.version !== undefined
      ? { id: `cpe|${cpe.key}`, kind: 'cpe', version: cpe.version }
      : { id: `cpe|${cpe.key}`, kind: 'cpe' };
  }
  const hash = /^hash:([^:]+):([0-9a-fA-F]+)$/.exec(ref);
  if (hash) return { id: hashKey(hash[1]!, hash[2]!), kind: 'hash' };
  return undefined;
}

/**
 * Every key an inventory element can be matched by: its purl, its CPEs, and
 * (packages only) its checksums. Files carry checksums too, but a CSAF
 * product hash names a delivered artifact, which the inventory models as a
 * package; matching files would spread one statement over every file of
 * the same bytes.
 */
function elementMatchKeys(element: SbomElement): MatchKey[] {
  const keys = identifierMatchKeys(element);
  if (element.kind === 'package') {
    for (const checksum of element.checksums ?? []) {
      keys.push({ id: hashKey(checksum.algorithm, checksum.value), kind: 'hash' });
    }
  }
  return keys;
}

/** The purl and CPE keys only: what coverage classifies by (a checksum alone does not make a package "matchable"). */
function identifierMatchKeys(element: SbomElement): MatchKey[] {
  const keys: MatchKey[] = [];
  if (element.purl) {
    const purl = purlMatchKey(element.purl);
    if (purl) keys.push(purl.version !== undefined ? { id: purl.pkg, kind: 'purl', version: purl.version } : { id: purl.pkg, kind: 'purl' });
  }
  for (const ref of element.externalRefs ?? []) {
    if (!ref.locator.toLowerCase().startsWith('cpe:')) continue;
    const cpe = cpeMatchKey(ref.locator);
    if (cpe) {
      keys.push(
        cpe.version !== undefined
          ? { id: `cpe|${cpe.key}`, kind: 'cpe', version: cpe.version }
          : { id: `cpe|${cpe.key}`, kind: 'cpe' },
      );
    }
  }
  return keys;
}

/**
 * OpenVEX time rule; unparseable/missing timestamps lose to real ones. On a
 * tie WITHIN one document (a component installed on two hosts, affected on
 * one and fixed on the other, both dated with the document) the more
 * cautious status wins, so a reassuring statement never hides an alarming
 * one from the same source; the reader sees the conflict as supersededCount.
 * Ties across documents still fall to the later-loaded one.
 */
function newerThan(a: IndexedStatement, b: IndexedStatement): boolean {
  const ta = Date.parse(a.timestamp ?? '');
  const tb = Date.parse(b.timestamp ?? '');
  if (Number.isNaN(ta) !== Number.isNaN(tb)) return !Number.isNaN(ta);
  if (!Number.isNaN(ta) && ta !== tb) return ta > tb;
  if (a.source === b.source) {
    const sa = VEX_STATUS_ORDER.indexOf(a.statement.status);
    const sb = VEX_STATUS_ORDER.indexOf(b.statement.status);
    if (sa !== sb) return sa < sb;
  }
  return a.order > b.order;
}

/** The single worst status across findings — drives badges and facets. */
export function worstVexStatus(findings: readonly VexFinding[] | undefined): VexStatus | undefined {
  if (!findings || findings.length === 0) return undefined;
  for (const status of VEX_STATUS_ORDER) {
    if (findings.some((f) => f.status === status)) return status;
  }
  return undefined;
}

/** Coverage of the workspace's package inventory by VEX statements. */
export interface VexCoverage {
  /** Packages with at least one finding. */
  covered: number;
  /** Packages whose purl or CPE yields a match key but no statement matched. */
  uncovered: number;
  /**
   * Packages without a usable purl or CPE. A checksum does not make a package
   * matchable for this count (advisories rarely carry file hashes); a package
   * that did match by hash counts as covered through its findings.
   */
  unmatchable: number;
  /** All package elements considered (files never count). */
  total: number;
}

/**
 * Quantifies what the loaded VEX statements do NOT say: the counterpart to
 * matchVex for coverage reporting ("supplier communicated about N of M
 * packages"). One shared classification for the UI facet and any report
 * consumer, so the two can never drift.
 */
export function vexCoverage(
  ws: WorkspaceState,
  findings: ReadonlyMap<ElementId, VexFinding[]>,
): VexCoverage {
  const coverage: VexCoverage = { covered: 0, uncovered: 0, unmatchable: 0, total: 0 };
  for (const loaded of ws.documents.values()) {
    for (const element of loaded.document.elements) {
      if (element.kind !== 'package') continue;
      coverage.total++;
      if ((findings.get(element.id)?.length ?? 0) > 0) coverage.covered++;
      else if (identifierMatchKeys(element).length > 0) coverage.uncovered++;
      else coverage.unmatchable++;
    }
  }
  return coverage;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
