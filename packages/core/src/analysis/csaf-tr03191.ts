import { asRecordArray, asString, asStringArray, isRecord } from '../util/narrow';
import type { CsafRequirementFinding } from './vex';

/**
 * BSI TR-03191 (Common Security Advisory Framework, v1.0.1, 27 May 2024)
 * measured on one CSAF document. The TR is short: section 4.2 wants a CVE
 * and a CVSS for every vulnerability, the Security Advisory or VEX profile,
 * and the fixing versions next to the affected ones; 4.3 the TLP label;
 * 4.4 a vendor/product_name/product_version tree, enumerated versions, and
 * the hashes of the primary components in the product_identification_helper
 * "if an SBOM is mandatory"; 4.6 that content never changes without a new
 * current_release_date and revision_history entry.
 *
 * Everything here is a fact about the document with the clause it comes
 * from, never a conformance verdict: the TR also demands distribution as a
 * trusted provider, signature validity windows and a 48-hour reaction to
 * BSI warnings, none of which a file can show. These are not CSAF spec
 * findings either, so the codes carry no `_SCHEMA_` infix (that infix is
 * reserved for "the document violates its own specification").
 */

const ADVISORY_PROFILES = new Set(['csaf_security_advisory', 'csaf_vex']);
const OTHER_PROFILES = new Set(['csaf_informational_advisory', 'csaf_security_incident_response']);
const NO_FIX_CATEGORIES = new Set(['no_fix_planned', 'none_available']);
const AFFECTED_BUCKETS = ['known_affected', 'first_affected', 'last_affected'];
const FIXED_BUCKETS = ['fixed', 'first_fixed'];
const STATUS_BUCKETS = [
  'known_affected',
  'first_affected',
  'last_affected',
  'known_not_affected',
  'fixed',
  'first_fixed',
  'under_investigation',
  'recommended',
];

export function lintCsafTr03191(raw: unknown): CsafRequirementFinding[] {
  const root = isRecord(raw) ? raw : {};
  const docNode = isRecord(root.document) ? root.document : {};
  const tracking = isRecord(docNode.tracking) ? docNode.tracking : {};
  const vulnerabilities = asRecordArray(root.vulnerabilities);
  const tree = isRecord(root.product_tree) ? root.product_tree : {};
  const findings: CsafRequirementFinding[] = [];

  // --- 4.2 General ----------------------------------------------------------
  const withCve = vulnerabilities.filter((v) => asString(v.cve) !== undefined).length;
  findings.push({
    id: 'tr03191-cve',
    clause: '4.2',
    label: 'CVE number for every vulnerability',
    pass: withCve === vulnerabilities.length,
    actual: `${withCve} of ${vulnerabilities.length}`,
  });

  const withCvss = vulnerabilities.filter(hasCvss).length;
  findings.push({
    id: 'tr03191-cvss',
    clause: '4.2',
    label: 'CVSS presented for every vulnerability',
    pass: withCvss === vulnerabilities.length,
    actual: `${withCvss} of ${vulnerabilities.length}`,
  });

  const category = asString(docNode.category);
  const profileOk =
    category !== undefined &&
    (ADVISORY_PROFILES.has(category) || (vulnerabilities.length === 0 && OTHER_PROFILES.has(category)));
  findings.push({
    id: 'tr03191-profile',
    clause: '4.2',
    label: 'Security Advisory or VEX profile for vulnerability information',
    pass: profileOk,
    actual: category ?? 'no document.category',
  });

  const withAffected = vulnerabilities.filter((v) => bucketIds(v, AFFECTED_BUCKETS).length > 0);
  const withFix = withAffected.filter(
    (v) =>
      bucketIds(v, FIXED_BUCKETS).length > 0 ||
      asRecordArray(v.remediations).some((r) => NO_FIX_CATEGORIES.has(asString(r.category) ?? '')),
  ).length;
  findings.push({
    id: 'tr03191-fixed-versions',
    clause: '4.2',
    label: 'Fixing versions stated next to the affected ones (or no fix declared)',
    pass: withFix === withAffected.length,
    actual: `${withFix} of ${withAffected.length} vulnerabilities with affected products`,
  });

  // --- 4.3 Document -----------------------------------------------------------
  const distribution = isRecord(docNode.distribution) ? docNode.distribution : {};
  const tlp = isRecord(distribution.tlp) ? asString(distribution.tlp.label) : undefined;
  findings.push({
    id: 'tr03191-tlp',
    clause: '4.3',
    label: 'TLP classification in distribution.tlp.label',
    pass: tlp !== undefined,
    actual: tlp ?? 'missing',
  });

  // --- 4.4 Product tree -------------------------------------------------------
  const chains = countChains(asRecordArray(tree.branches));
  findings.push({
    id: 'tr03191-hierarchy',
    clause: '4.4',
    label: 'Product tree structured vendor / product_name / product_version',
    pass: chains > 0,
    actual: `${chains} complete chain${chains === 1 ? '' : 's'}`,
  });

  const ranges = countRanges(asRecordArray(tree.branches));
  findings.push({
    id: 'tr03191-versions-enumerated',
    clause: '4.4',
    label: 'Versions enumerated individually (ranges only where enumeration is impossible)',
    pass: ranges === 0,
    actual: `${ranges} product_version_range branch${ranges === 1 ? '' : 'es'}`,
  });

  const hashed = productsWithHashes(tree);
  const referenced = new Set<string>();
  for (const v of vulnerabilities) for (const pid of bucketIds(v, STATUS_BUCKETS)) referenced.add(pid);
  const referencedWithHash = [...referenced].filter((pid) => hashed.has(pid)).length;
  findings.push({
    id: 'tr03191-product-hashes',
    clause: '4.4',
    label: 'Hashes of the primary components in product_identification_helper (where an SBOM is mandatory)',
    pass: referenced.size > 0 && referencedWithHash === referenced.size,
    actual: `${referencedWithHash} of ${referenced.size} referenced products`,
  });

  // --- 4.6 Distribution -------------------------------------------------------
  const revisions = asRecordArray(tracking.revision_history).length;
  const currentRelease = asString(tracking.current_release_date);
  findings.push({
    id: 'tr03191-revision-history',
    clause: '4.6',
    label: 'current_release_date and revision_history carried',
    pass: revisions > 0 && currentRelease !== undefined,
    actual: `${revisions} revision${revisions === 1 ? '' : 's'}${currentRelease ? `, current ${currentRelease.slice(0, 10)}` : ', no current_release_date'}`,
  });

  return findings;
}

/** CSAF 2.0 scores[].cvss_v2/cvss_v3, CSAF 2.1 metrics[].content.cvss_v2/v3/v4. */
function hasCvss(vuln: Record<string, unknown>): boolean {
  const carries = (node: Record<string, unknown>) =>
    isRecord(node.cvss_v4) || isRecord(node.cvss_v3) || isRecord(node.cvss_v2);
  if (asRecordArray(vuln.scores).some(carries)) return true;
  return asRecordArray(vuln.metrics).some((m) => isRecord(m.content) && carries(m.content));
}

function bucketIds(vuln: Record<string, unknown>, buckets: readonly string[]): string[] {
  const status = isRecord(vuln.product_status) ? vuln.product_status : {};
  return buckets.flatMap((bucket) => asStringArray(status[bucket]));
}

/** Complete vendor -> product_name -> product_version chains in the branch tree. */
function countChains(branches: readonly Record<string, unknown>[], depth: string[] = []): number {
  let count = 0;
  for (const branch of branches) {
    const category = asString(branch.category);
    const path = category ? [...depth, category] : depth;
    if (category === 'product_version' && path.includes('vendor') && path.includes('product_name')) count++;
    count += countChains(asRecordArray(branch.branches), path);
  }
  return count;
}

function countRanges(branches: readonly Record<string, unknown>[]): number {
  let count = 0;
  for (const branch of branches) {
    if (asString(branch.category) === 'product_version_range') count++;
    count += countRanges(asRecordArray(branch.branches));
  }
  return count;
}

/** product_ids whose product_identification_helper carries at least one file hash. */
function productsWithHashes(tree: Record<string, unknown>): Set<string> {
  const out = new Set<string>();
  const visit = (node: Record<string, unknown>) => {
    const pid = asString(node.product_id);
    const helper = isRecord(node.product_identification_helper) ? node.product_identification_helper : undefined;
    if (pid && helper && asRecordArray(helper.hashes).some((h) => asRecordArray(h.file_hashes).length > 0)) {
      out.add(pid);
    }
  };
  for (const fpn of asRecordArray(tree.full_product_names)) visit(fpn);
  const walk = (branches: readonly Record<string, unknown>[]) => {
    for (const branch of branches) {
      if (isRecord(branch.product)) visit(branch.product);
      walk(asRecordArray(branch.branches));
    }
  };
  walk(asRecordArray(tree.branches));
  for (const rel of asRecordArray(tree.relationships)) {
    if (isRecord(rel.full_product_name)) visit(rel.full_product_name);
  }
  return out;
}
