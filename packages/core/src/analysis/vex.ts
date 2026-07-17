import type { Diagnostic } from '../model/diagnostics';
import { diag } from '../model/diagnostics';
import type { ElementId } from '../model/ids';
import type { WorkspaceState } from '../workspace/workspace';

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

export interface VexProductRef {
  /** purl of the product itself ("pkg:..." @id or identifiers.purl). */
  id: string;
  /** purls of affected subcomponents inside that product. */
  subcomponents: string[];
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
  /** Statement timestamp; absent means "inherit the document's". */
  timestamp?: string;
}

export interface VexDocument {
  /** The document's @id, or the file name when absent. */
  id: string;
  fileName: string;
  author?: string;
  timestamp?: string;
  version?: number;
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
  /** @id (or file name) of the VEX document that said it. */
  source: string;
  /** The element matched a subcomponent entry, not the product itself. */
  viaSubcomponent: boolean;
  /** Timestamp that won the time rule (statement's, else document's). */
  timestamp?: string;
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

/** Products: strings (early spec) or { "@id", identifiers: { purl }, subcomponents }. */
function parseProducts(node: unknown): VexProductRef[] {
  if (!Array.isArray(node)) return [];
  const products: VexProductRef[] = [];
  for (const entry of node) {
    if (typeof entry === 'string' && entry !== '') {
      products.push({ id: entry, subcomponents: [] });
      continue;
    }
    if (!isRecord(entry)) continue;
    const id =
      firstPurlish(entry['@id']) ??
      (isRecord(entry.identifiers) ? firstPurlish(entry.identifiers.purl) : undefined);
    if (!id) continue;
    const subcomponents: string[] = [];
    if (Array.isArray(entry.subcomponents)) {
      for (const sub of entry.subcomponents) {
        const subId =
          firstPurlish(sub) ??
          (isRecord(sub)
            ? (firstPurlish(sub['@id']) ??
              (isRecord(sub.identifiers) ? firstPurlish(sub.identifiers.purl) : undefined))
            : undefined);
        if (subId) subcomponents.push(subId);
      }
    }
    products.push({ id, subcomponents });
  }
  return products;
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
  if (at > 0) {
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
  /** Effective timestamp for the time rule (statement's, else document's). */
  timestamp?: string;
  /** Position for deterministic tie-breaks: later loaded wins. */
  order: number;
  viaSubcomponent: boolean;
  /** Version constraint of the matching product/subcomponent purl, if any. */
  version?: string;
}

/**
 * Match every loaded VEX statement against the workspace inventory.
 * Returns one finding per (element, vulnerability): when several statements
 * target the same pair, the one with the newest timestamp wins (the OpenVEX
 * time rule); ties fall to the later-loaded document. Findings are sorted
 * alarming-first (affected before not_affected).
 */
export function matchVex(
  ws: WorkspaceState,
  vexDocs: readonly VexDocument[],
): Map<ElementId, VexFinding[]> {
  // purl package-key -> candidate statements (both exact-version and versionless).
  const index = new Map<string, IndexedStatement[]>();
  let order = 0;
  for (const doc of vexDocs) {
    for (const statement of doc.statements) {
      const timestamp = statement.timestamp ?? doc.timestamp;
      for (const product of statement.products) {
        addCandidate(index, product.id, {
          statement,
          source: doc.id,
          ...(timestamp !== undefined ? { timestamp } : {}),
          order: order++,
          viaSubcomponent: false,
        });
        for (const sub of product.subcomponents) {
          addCandidate(index, sub, {
            statement,
            source: doc.id,
            ...(timestamp !== undefined ? { timestamp } : {}),
            order: order++,
            viaSubcomponent: true,
          });
        }
      }
    }
  }
  if (index.size === 0) return new Map();

  const findings = new Map<ElementId, VexFinding[]>();
  for (const loaded of ws.documents.values()) {
    for (const element of loaded.document.elements) {
      if (!element.purl) continue;
      const key = purlMatchKey(element.purl);
      if (!key) continue;
      const candidates = index.get(key.pkg);
      if (!candidates) continue;

      // A versioned VEX purl must match the element's version exactly;
      // a versionless one covers every version of the package.
      const applicable = candidates.filter(
        (c) => c.version === undefined || (key.version !== undefined && c.version === key.version),
      );
      if (applicable.length === 0) continue;

      const byVuln = new Map<string, IndexedStatement>();
      for (const candidate of applicable) {
        const existing = byVuln.get(candidate.statement.vulnerability);
        if (!existing || newerThan(candidate, existing)) {
          byVuln.set(candidate.statement.vulnerability, candidate);
        }
      }
      const list = [...byVuln.values()]
        .map((c): VexFinding => ({
          vulnerability: c.statement.vulnerability,
          status: c.statement.status,
          ...(c.statement.justification !== undefined ? { justification: c.statement.justification } : {}),
          ...(c.statement.impactStatement !== undefined ? { impactStatement: c.statement.impactStatement } : {}),
          ...(c.statement.actionStatement !== undefined ? { actionStatement: c.statement.actionStatement } : {}),
          ...(c.statement.description !== undefined ? { description: c.statement.description } : {}),
          source: c.source,
          viaSubcomponent: c.viaSubcomponent,
          ...(c.timestamp !== undefined ? { timestamp: c.timestamp } : {}),
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

function addCandidate(
  index: Map<string, IndexedStatement[]>,
  purl: string,
  candidate: Omit<IndexedStatement, 'version'>,
): void {
  const key = purlMatchKey(purl);
  if (!key) return;
  const list = index.get(key.pkg) ?? [];
  list.push(key.version !== undefined ? { ...candidate, version: key.version } : candidate);
  index.set(key.pkg, list);
}

/** OpenVEX time rule; unparseable/missing timestamps lose to real ones. */
function newerThan(a: IndexedStatement, b: IndexedStatement): boolean {
  const ta = Date.parse(a.timestamp ?? '');
  const tb = Date.parse(b.timestamp ?? '');
  if (Number.isNaN(ta) && Number.isNaN(tb)) return a.order > b.order;
  if (Number.isNaN(ta)) return false;
  if (Number.isNaN(tb)) return true;
  return ta === tb ? a.order > b.order : ta > tb;
}

/** The single worst status across findings — drives badges and facets. */
export function worstVexStatus(findings: readonly VexFinding[] | undefined): VexStatus | undefined {
  if (!findings || findings.length === 0) return undefined;
  for (const status of VEX_STATUS_ORDER) {
    if (findings.some((f) => f.status === status)) return status;
  }
  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
