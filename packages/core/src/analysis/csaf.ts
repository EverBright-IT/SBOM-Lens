import type { Diagnostic } from '../model/diagnostics';
import { diag } from '../model/diagnostics';
import { createLint, createTally } from '../parse/spec-lint';
import { asRecordArray, asString, asStringArray, isRecord } from '../util/narrow';
import { lintCsafTr03191 } from './csaf-tr03191';
import type { VexDocument, VexProductHash, VexProductRef, VexRemediation, VexStatement, VexStatus } from './vex';

/**
 * CSAF 2.0 → the neutral VexDocument the rest of the app already consumes.
 * CSAF is the BSI exchange format and, unlike OpenVEX, separates identity
 * from assertion: a `product_tree` names products (branches, full product
 * names, relationships) and hangs an identifier on each, while the
 * `vulnerabilities[].product_status` buckets reference those products by id.
 * The work here is resolving that indirection to purls (or CPEs — BSI-CERT
 * advisories often carry only a CPE) and mapping the four status buckets
 * onto VexStatus; once a VexDocument comes out, matchVex, the time rule,
 * the overlay UI and coverage are all shared with OpenVEX.
 *
 * This handles the CSAF VEX profile and the security-advisory profile alike
 * (both carry product_status), and accepts the profiles without a
 * vulnerabilities list (csaf_base, informational advisory) as documents with
 * no statements, so an advisory folder loads whole. It is a viewer, not a
 * scanner: it renders what the document says, and stays tolerant — a
 * malformed vulnerability or an unresolvable product is skipped with a
 * diagnostic, never thrown.
 *
 * Product identification goes beyond purl and CPE: the file hashes a
 * product_identification_helper carries are kept, and matchVex compares
 * them with element checksums. That is the link TR-03191 section 4.4 asks
 * for ("hash values of the primary components ... in accordance with BSI
 * TR-03183-2"), and it works when no purl exists at all.
 */

/**
 * CSAF advisories with a large product tree run bigger than OpenVEX files;
 * this cap is separate from MAX_VEX_BYTES so the OpenVEX gate stays tight.
 */
export const MAX_CSAF_BYTES = 8 * 1024 * 1024;

/** product_status bucket → the VexStatus it means. Order is display-neutral. */
const STATUS_BUCKETS: ReadonlyArray<readonly [string, VexStatus]> = [
  ['known_affected', 'affected'],
  ['known_not_affected', 'not_affected'],
  ['fixed', 'fixed'],
  ['under_investigation', 'under_investigation'],
];

/** One product's resolved identifiers, gathered from the product tree. */
interface ProductIdent {
  purl?: string;
  /** CPE 2.2/2.3 string; matching against it is a separate concern. */
  cpe?: string;
  /** File hashes from product_identification_helper.hashes[].file_hashes. */
  hashes?: VexProductHash[];
}

/**
 * Cheap content sniff, same contract as sniffVex/sniffProfile: run on the
 * shared ingest funnel before the SBOM pipeline. A CSAF document is JSON with
 * a `document.csaf_version` and a `document.category`; `vulnerabilities` is
 * optional, because the base and informational profiles omit it.
 */
export function sniffCsaf(text: string): { isCsaf: true; raw: unknown } | { isCsaf: false } {
  if (text.length > MAX_CSAF_BYTES) return { isCsaf: false };
  const head = text.trimStart();
  if (!head.startsWith('{') || !text.includes('csaf_version')) return { isCsaf: false };
  try {
    const raw: unknown = JSON.parse(text);
    if (
      isRecord(raw) &&
      isRecord(raw.document) &&
      typeof raw.document.csaf_version === 'string' &&
      typeof raw.document.category === 'string' &&
      (raw.vulnerabilities === undefined || Array.isArray(raw.vulnerabilities))
    ) {
      return { isCsaf: true, raw };
    }
  } catch {
    // Marker present but not valid JSON — let the SBOM pipeline report it.
  }
  return { isCsaf: false };
}

/**
 * Tolerant CSAF parser. Resolves the product tree once, then walks every
 * vulnerability's status buckets, resolving product ids to purls and grouping
 * products that share the same justification/action/impact into one statement
 * (so a per-product annotation is never mis-attributed to a sibling).
 */
export function parseCsaf(fileName: string, raw: unknown): VexDocument {
  const diagnostics: Diagnostic[] = [];
  const root = isRecord(raw) ? raw : {};
  const docNode = isRecord(root.document) ? root.document : {};
  const tracking = isRecord(docNode.tracking) ? docNode.tracking : {};

  const products = resolveProductTree(root.product_tree);
  const groupMembers = resolveProductGroups(root.product_tree);
  const statements: VexStatement[] = [];

  asRecordArray(root.vulnerabilities).forEach((vuln, index) => {
    const vulnerability = vulnName(vuln);
    if (!vulnerability) {
      diagnostics.push(
        diag('warning', 'CSAF_VULN_SKIPPED', `Vulnerability ${index + 1} has no CVE or tracking id.`),
      );
      return;
    }
    const productStatus = isRecord(vuln.product_status) ? vuln.product_status : {};
    const aliases = vulnAliases(vuln, vulnerability);
    const description = notesText(vuln.notes);
    const timestamp = asString(vuln.release_date);
    // Flags and remediations name their products (CSAF 2.0 sections 3.2.3.5
    // and 3.2.3.12: product_ids or group_ids MUST be present), so an entry
    // without either applies to nobody and is reported as a schema finding
    // below. A threat may omit both, and then describes the vulnerability
    // for every product.
    const flags = annotationsByProduct(vuln.flags, 'label', groupMembers, false);
    const remediationTexts = annotationsByProduct(vuln.remediations, 'details', groupMembers, false);
    const remediationLists = remediationsByProduct(vuln.remediations, groupMembers);
    const impacts = annotationsByProduct(asRecordArray(vuln.threats).filter((t) => asString(t.category) === 'impact'), 'details', groupMembers, true);

    for (const [bucket, status] of STATUS_BUCKETS) {
      const productIds = asStringArray(productStatus[bucket]);
      if (productIds.length === 0) continue;

      // Group by the (justification, action, impact, remediations) tuple so
      // products that share annotations collapse into one statement,
      // matching OpenVEX shape, and a per-product annotation is never
      // attributed to a sibling.
      const groups = new Map<string, VexProductRef[]>();
      const meta = new Map<
        string,
        { justification?: string; actionStatement?: string; impactStatement?: string; remediations?: VexRemediation[] }
      >();
      for (const pid of productIds) {
        const ident = products.get(pid);
        // purl preferred, then CPE, then a file hash; each has its own match key.
        const firstHash = ident?.hashes?.[0];
        const idRef = ident?.purl ?? ident?.cpe ?? (firstHash ? `hash:${firstHash.algorithm}:${firstHash.value}` : undefined);
        if (!idRef) {
          diagnostics.push(
            diag(
              'info',
              'CSAF_PRODUCT_UNRESOLVED',
              `${vulnerability}: product "${pid}" has no resolvable identifier; skipped.`,
            ),
          );
          continue;
        }
        // A justification is only meaningful for not_affected (VEX contract).
        const justification = status === 'not_affected' ? flags.get(pid) : undefined;
        const actionStatement = remediationTexts.get(pid);
        const impactStatement = impacts.get(pid);
        const remediations = remediationLists.get(pid);
        const key = `${justification ?? ''} ${actionStatement ?? ''} ${impactStatement ?? ''} ${JSON.stringify(remediations ?? [])}`;
        const list = groups.get(key) ?? [];
        list.push({ id: idRef, subcomponents: [], ...(ident?.hashes ? { hashes: ident.hashes } : {}) });
        groups.set(key, list);
        if (!meta.has(key)) {
          meta.set(key, {
            ...(justification !== undefined ? { justification } : {}),
            ...(actionStatement !== undefined ? { actionStatement } : {}),
            ...(impactStatement !== undefined ? { impactStatement } : {}),
            ...(remediations !== undefined && remediations.length > 0 ? { remediations } : {}),
          });
        }
      }

      for (const [key, refs] of groups) {
        const m = meta.get(key) ?? {};
        statements.push({
          vulnerability,
          ...(aliases.length > 0 ? { aliases } : {}),
          ...(description !== undefined ? { description } : {}),
          products: refs,
          status,
          ...(m.justification !== undefined ? { justification: m.justification } : {}),
          ...(m.impactStatement !== undefined ? { impactStatement: m.impactStatement } : {}),
          ...(m.actionStatement !== undefined ? { actionStatement: m.actionStatement } : {}),
          ...(m.remediations !== undefined ? { remediations: m.remediations } : {}),
          ...(timestamp !== undefined ? { timestamp } : {}),
        });
      }
    }
  });

  diagnostics.push(...csafSchemaFindings(root, definedProductIds(root.product_tree)));

  const publisher = isRecord(docNode.publisher) ? docNode.publisher : undefined;
  const trackingVersion = asString(tracking.version);
  const versionNumber = trackingVersion !== undefined ? Number.parseInt(trackingVersion, 10) : Number.NaN;
  const distribution = isRecord(docNode.distribution) ? docNode.distribution : undefined;
  const tlp = distribution && isRecord(distribution.tlp) ? asString(distribution.tlp.label) : undefined;

  // CSAF 2.0 section 3.2.1.12.4: the tracking id is unique per publisher,
  // and namespace plus id identify a document globally. Keyed that way, two
  // publishers reusing one id never displace each other; the tracking id
  // stays available for display.
  const trackingId = asString(tracking.id);
  const publisherNamespace = publisher ? asString(publisher.namespace) : undefined;
  const id = trackingId !== undefined ? (publisherNamespace ? `${publisherNamespace}#${trackingId}` : trackingId) : fileName;

  return {
    id,
    fileName,
    format: 'csaf',
    ...(trackingId !== undefined ? { trackingId } : {}),
    ...(publisher && asString(publisher.name) !== undefined ? { author: asString(publisher.name)! } : {}),
    ...(asString(tracking.current_release_date) !== undefined
      ? { timestamp: asString(tracking.current_release_date)! }
      : asString(tracking.initial_release_date) !== undefined
        ? { timestamp: asString(tracking.initial_release_date)! }
        : {}),
    ...(Number.isInteger(versionNumber) ? { version: versionNumber } : {}),
    ...(asString(docNode.title) !== undefined ? { title: asString(docNode.title)! } : {}),
    ...(asString(docNode.category) !== undefined ? { category: asString(docNode.category)! } : {}),
    ...(tlp !== undefined ? { tlp } : {}),
    ...(asString(tracking.status) !== undefined ? { status: asString(tracking.status)! } : {}),
    tr03191: lintCsafTr03191(root, products),
    statements,
    diagnostics,
  };
}

/**
 * The few CSAF schema facts this reader depends on, as spec findings
 * (`CSAF_SCHEMA_*`, so isSpecFinding tells them from parser notes). Not a
 * schema validator: the OASIS csaf-validator owns that; these are the
 * mandatory pieces whose absence breaks consumption, most importantly a
 * product id used in a vulnerability that the product tree never defines
 * (CSAF 2.0 mandatory test 6.1.1).
 */
function csafSchemaFindings(root: Record<string, unknown>, defined: ReadonlySet<string>): Diagnostic[] {
  const lint = createLint();
  const docNode = isRecord(root.document) ? root.document : {};
  const tracking = isRecord(docNode.tracking) ? docNode.tracking : {};

  const version = asString(docNode.csaf_version);
  if (version !== undefined && !/^2\.\d+$/.test(version)) {
    lint.warn('CSAF_SCHEMA_BAD_VERSION', `document.csaf_version "${version}" is not a CSAF 2.x version.`);
  }

  const missingTracking = ['id', 'version', 'status', 'initial_release_date', 'current_release_date'].filter(
    (field) => asString(tracking[field]) === undefined,
  );
  if (missingTracking.length > 0) {
    lint.warn('CSAF_SCHEMA_MISSING_TRACKING', `document.tracking lacks the mandatory ${missingTracking.join(', ')}.`);
  }

  const publisher = isRecord(docNode.publisher) ? docNode.publisher : {};
  const missingPublisher = ['category', 'name', 'namespace'].filter((field) => asString(publisher[field]) === undefined);
  if (missingPublisher.length > 0) {
    lint.warn('CSAF_SCHEMA_MISSING_PUBLISHER', `document.publisher lacks the mandatory ${missingPublisher.join(', ')}.`);
  }

  const badCve = createTally({ unique: true });
  const undefinedProduct = createTally({ unique: true });
  const untargetedRemediation = createTally();
  const untargetedFlag = createTally();
  const untargeted = (entry: Record<string, unknown>) =>
    asStringArray(entry.product_ids).length === 0 && asStringArray(entry.group_ids).length === 0;
  const tree = isRecord(root.product_tree) ? root.product_tree : {};
  // 6.1.1 names every place a product id may be referenced from.
  for (const group of asRecordArray(tree.product_groups)) {
    for (const pid of asStringArray(group.product_ids)) if (!defined.has(pid)) undefinedProduct.add(pid);
  }
  for (const rel of asRecordArray(tree.relationships)) {
    for (const field of ['product_reference', 'relates_to_product_reference']) {
      const pid = asString(rel[field]);
      if (pid !== undefined && !defined.has(pid)) undefinedProduct.add(pid);
    }
  }
  asRecordArray(root.vulnerabilities).forEach((vuln, index) => {
    const name = asString(vuln.cve) ?? `vulnerability ${index + 1}`;
    const cve = asString(vuln.cve);
    if (cve !== undefined && !/^CVE-\d{4}-\d{4,}$/.test(cve)) badCve.add(cve);
    const status = isRecord(vuln.product_status) ? vuln.product_status : {};
    for (const ids of Object.values(status)) {
      for (const pid of asStringArray(ids)) if (!defined.has(pid)) undefinedProduct.add(pid);
    }
    for (const list of [vuln.remediations, vuln.flags, vuln.threats, vuln.scores]) {
      for (const entry of asRecordArray(list)) {
        for (const pid of [...asStringArray(entry.product_ids), ...asStringArray(entry.products)]) {
          if (!defined.has(pid)) undefinedProduct.add(pid);
        }
      }
    }
    for (const entry of asRecordArray(vuln.remediations)) if (untargeted(entry)) untargetedRemediation.add(name);
    for (const entry of asRecordArray(vuln.flags)) if (untargeted(entry)) untargetedFlag.add(name);
  });
  lint.warnTally('CSAF_SCHEMA_BAD_CVE_ID', badCve, (count, list) => `${count} cve value(s) do not follow CVE-YYYY-NNNN: ${list}.`);
  lint.warnTally(
    'CSAF_SCHEMA_UNDEFINED_PRODUCT_ID',
    undefinedProduct,
    (count, list) => `${count} product id(s) referenced but not defined in the product tree (mandatory test 6.1.1): ${list}.`,
  );
  lint.warnTally(
    'CSAF_SCHEMA_UNTARGETED_REMEDIATION',
    untargetedRemediation,
    (count, list) => `${count} remediation(s) name neither product_ids nor group_ids and apply to nobody (mandatory test 6.1.29): ${list}.`,
  );
  lint.warnTally(
    'CSAF_SCHEMA_UNTARGETED_FLAG',
    untargetedFlag,
    (count, list) => `${count} flag(s) name neither product_ids nor group_ids and apply to nobody (mandatory test 6.1.32): ${list}.`,
  );
  return lint.diagnostics;
}

/**
 * Every product id the tree DEFINES (full_product_names, branch products,
 * relationship products), whether or not it resolves to an identifier. This
 * is the definition set 6.1.1 talks about; resolvability is a separate
 * question that CSAF_PRODUCT_UNRESOLVED answers.
 */
function definedProductIds(tree: unknown): Set<string> {
  const defined = new Set<string>();
  forEachProductNode(tree, (node) => {
    const pid = asString(node.product_id);
    if (pid) defined.add(pid);
  });
  return defined;
}

/** Bounded, iterative visit of every full_product_name node in a product tree. */
function forEachProductNode(tree: unknown, visit: (node: Record<string, unknown>) => void): void {
  if (!isRecord(tree)) return;
  for (const fpn of asRecordArray(tree.full_product_names)) visit(fpn);
  const stack = asRecordArray(tree.branches).map((branch) => ({ branch, depth: 0 }));
  while (stack.length > 0) {
    const { branch, depth } = stack.pop()!;
    if (isRecord(branch.product)) visit(branch.product);
    if (depth >= MAX_BRANCH_DEPTH) continue;
    for (const child of asRecordArray(branch.branches)) stack.push({ branch: child, depth: depth + 1 });
  }
  for (const rel of asRecordArray(tree.relationships)) {
    if (isRecord(rel.full_product_name)) visit(rel.full_product_name);
  }
}

/** product_groups: group_id -> member product ids (CSAF 2.0 section 3.2.2.6). */
function resolveProductGroups(tree: unknown): Map<string, string[]> {
  const groups = new Map<string, string[]>();
  if (!isRecord(tree)) return groups;
  for (const group of asRecordArray(tree.product_groups)) {
    const id = asString(group.group_id);
    if (id) groups.set(id, asStringArray(group.product_ids));
  }
  return groups;
}

/** product_ids plus every member of the referenced product_groups. */
function targetProducts(entry: Record<string, unknown>, groups: Map<string, string[]>): string[] {
  const ids = [...asStringArray(entry.product_ids)];
  for (const groupId of asStringArray(entry.group_ids)) ids.push(...(groups.get(groupId) ?? []));
  return ids;
}

/** Every remediation per product, structured, in document order; an untargeted remediation reaches nobody. */
function remediationsByProduct(node: unknown, groups: Map<string, string[]>): Map<string, VexRemediation[]> {
  const byProduct = new Map<string, VexRemediation[]>();
  for (const entry of asRecordArray(node)) {
    const category = asString(entry.category);
    if (category === undefined) continue;
    const restart = isRecord(entry.restart_required) ? asString(entry.restart_required.category) : undefined;
    const remediation: VexRemediation = {
      category,
      ...(asString(entry.details) !== undefined ? { details: asString(entry.details)! } : {}),
      ...(asString(entry.url) !== undefined ? { url: asString(entry.url)! } : {}),
      ...(asString(entry.date) !== undefined ? { date: asString(entry.date)! } : {}),
      ...(restart !== undefined ? { restartRequired: restart } : {}),
    };
    for (const pid of targetProducts(entry, groups)) {
      const list = byProduct.get(pid) ?? [];
      list.push(remediation);
      byProduct.set(pid, list);
    }
  }
  return byProduct;
}

/**
 * product_id → resolved identifiers. Walks full_product_names, the recursive
 * branch tree, and relationships. A relationship's synthetic product resolves
 * to the COMPONENT it installs (product_reference) — that is the package that
 * appears in an SBOM inventory — unless the relationship carries its own
 * identifier.
 */
function resolveProductTree(tree: unknown): Map<string, ProductIdent> {
  const ids = new Map<string, ProductIdent>();
  if (!isRecord(tree)) return ids;

  for (const fpn of asRecordArray(tree.full_product_names)) register(ids, fpn);
  walkBranches(asRecordArray(tree.branches), ids);

  // Relationships reference products registered above, so resolve them last.
  for (const rel of asRecordArray(tree.relationships)) {
    const fpn = isRecord(rel.full_product_name) ? rel.full_product_name : undefined;
    const pid = fpn ? asString(fpn.product_id) : undefined;
    if (!pid) continue;
    const own = fpn ? identFrom(fpn) : {};
    if (own.purl || own.cpe || own.hashes) {
      ids.set(pid, own);
      continue;
    }
    const componentRef = asString(rel.product_reference);
    const resolved = componentRef ? ids.get(componentRef) : undefined;
    if (resolved) ids.set(pid, resolved);
  }
  return ids;
}

/** Branch trees are walked iteratively with a depth cap: a hostile document must not exhaust the stack. */
const MAX_BRANCH_DEPTH = 64;

function walkBranches(branches: readonly Record<string, unknown>[], ids: Map<string, ProductIdent>): void {
  const stack = branches.map((branch) => ({ branch, depth: 0 }));
  while (stack.length > 0) {
    const { branch, depth } = stack.pop()!;
    if (isRecord(branch.product)) register(ids, branch.product);
    if (depth >= MAX_BRANCH_DEPTH) continue;
    for (const child of asRecordArray(branch.branches)) stack.push({ branch: child, depth: depth + 1 });
  }
}

function register(ids: Map<string, ProductIdent>, node: Record<string, unknown>): void {
  const pid = asString(node.product_id);
  if (!pid) return;
  const ident = identFrom(node);
  // A later, richer registration wins; a bare id is kept only if unseen.
  if (ident.purl || ident.cpe || ident.hashes || !ids.has(pid)) ids.set(pid, ident);
}

function identFrom(node: Record<string, unknown>): ProductIdent {
  const helper = isRecord(node.product_identification_helper) ? node.product_identification_helper : undefined;
  if (!helper) return {};
  const purl = asString(helper.purl);
  const cpe = asString(helper.cpe);
  const hashes: VexProductHash[] = [];
  for (const entry of asRecordArray(helper.hashes)) {
    for (const hash of asRecordArray(entry.file_hashes)) {
      const algorithm = asString(hash.algorithm);
      const value = asString(hash.value);
      if (algorithm && value) hashes.push({ algorithm, value });
    }
  }
  return { ...(purl ? { purl } : {}), ...(cpe ? { cpe } : {}), ...(hashes.length > 0 ? { hashes } : {}) };
}

/** CVE preferred, else the first tracking id's text. */
function vulnName(vuln: Record<string, unknown>): string | undefined {
  const cve = asString(vuln.cve);
  if (cve) return cve;
  for (const id of asRecordArray(vuln.ids)) {
    const text = asString(id.text);
    if (text) return text;
  }
  return undefined;
}

/** Every OTHER tracking id becomes an alias (the chosen name excluded). */
function vulnAliases(vuln: Record<string, unknown>, chosen: string): string[] {
  const aliases: string[] = [];
  const cve = asString(vuln.cve);
  if (cve && cve !== chosen) aliases.push(cve);
  for (const id of asRecordArray(vuln.ids)) {
    const text = asString(id.text);
    if (text && text !== chosen && !aliases.includes(text)) aliases.push(text);
  }
  return aliases;
}

/**
 * Collapses a CSAF annotation array (flags, remediations, threats) into
 * product_id -> value. Targets are product_ids plus the members of
 * group_ids. An entry that names neither is a schema violation for flags
 * and remediations (6.1.29, 6.1.32) and reaches nobody; for threats, which
 * may omit both, it describes the vulnerability for every product when
 * `documentWide` is set. An entry naming only an unknown group applies to
 * nobody, never to everybody. First writer wins so the earliest/most
 * specific entry sticks.
 */
function annotationsByProduct(
  node: unknown,
  field: 'label' | 'details',
  groups: Map<string, string[]>,
  documentWide: boolean,
): Map<string, string> {
  const byProduct = new Map<string, string>();
  let fallback: string | undefined;
  for (const entry of asRecordArray(node)) {
    const value = asString(entry[field]);
    if (value === undefined) continue;
    const targets = targetProducts(entry, groups);
    if (targets.length === 0) {
      if (documentWide && asStringArray(entry.group_ids).length === 0 && fallback === undefined) fallback = value;
      continue;
    }
    for (const pid of targets) if (!byProduct.has(pid)) byProduct.set(pid, value);
  }
  return new ProductMap(byProduct, fallback);
}

/** A Map whose miss falls back to a document-wide default when one was set. */
class ProductMap extends Map<string, string> {
  constructor(
    entries: Map<string, string>,
    private readonly fallback: string | undefined,
  ) {
    super(entries);
  }
  override get(key: string): string | undefined {
    return super.get(key) ?? this.fallback;
  }
}

/** First description/summary note, else the first note with any text. */
function notesText(node: unknown): string | undefined {
  const notes = asRecordArray(node);
  for (const note of notes) {
    const category = asString(note.category);
    if ((category === 'description' || category === 'summary') && asString(note.text)) {
      return asString(note.text);
    }
  }
  for (const note of notes) {
    const text = asString(note.text);
    if (text) return text;
  }
  return undefined;
}
