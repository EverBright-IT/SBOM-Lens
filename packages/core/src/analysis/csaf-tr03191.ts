import { asRecordArray, asString, asStringArray, isRecord } from '../util/narrow';
import type { CsafRequirementFinding } from './vex';

/**
 * BSI TR-03191 (Common Security Advisory Framework, v1.0.1, 27 May 2024)
 * measured on one CSAF document. The TR is short: section 4.2 wants a CVE
 * and a CVSS for every vulnerability, the Security Advisory or VEX profile
 * for vulnerability information, and the fixing versions next to the
 * affected ones; 4.3 the TLP label; 4.4 a vendor/product_name/
 * product_version tree, enumerated versions where enumeration is possible,
 * and the hashes of the primary components in the product_identification_
 * helper "if an SBOM is mandatory"; 4.5 the incident-response and
 * informational profiles for their cases; 4.6 that content never changes
 * without a new current_release_date and revision_history entry.
 *
 * Everything here is a fact about the document with the clause it comes
 * from, never a conformance verdict. A clause that has nothing to apply to
 * (no vulnerabilities, no referenced products) reads as not applicable
 * rather than as passed or failed, and a count the TR conditions on
 * circumstances a file cannot show (version ranges are allowed where
 * enumeration is impossible) is reported as a fact without a verdict. The
 * TR also demands distribution as a trusted provider, signature validity
 * windows and a 48-hour reaction to BSI warnings, none of which a file can
 * show. These are not CSAF spec findings either, so the codes carry no
 * `_SCHEMA_` infix.
 */

const ADVISORY_PROFILES = new Set(['csaf_security_advisory', 'csaf_vex', 'csaf_security_incident_response']);
const NO_VULNERABILITY_PROFILES = new Set(['csaf_informational_advisory', 'csaf_security_incident_response']);
const NO_FIX_CATEGORIES = new Set(['no_fix_planned', 'none_available']);
const AFFECTED_BUCKETS = ['known_affected', 'first_affected', 'last_affected'];
const FIXED_BUCKETS = ['fixed', 'first_fixed', 'recommended'];
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
/** Product trees deeper than this are not walked further; a hostile document must not exhaust the stack. */
const MAX_BRANCH_DEPTH = 64;

/** What the measurement needs to know about a resolved product: whether the tree gave it file hashes. */
export interface CsafProductFacts {
  hashes?: readonly unknown[];
}

/**
 * @param resolved product_id -> facts as the CSAF parser resolved them
 * (relationship products inherit their component's hashes). Optional: a
 * direct caller without a parser walks the tree itself.
 */
export function lintCsafTr03191(raw: unknown, resolved?: ReadonlyMap<string, CsafProductFacts>): CsafRequirementFinding[] {
  const root = isRecord(raw) ? raw : {};
  const docNode = isRecord(root.document) ? root.document : {};
  const tracking = isRecord(docNode.tracking) ? docNode.tracking : {};
  const vulnerabilities = asRecordArray(root.vulnerabilities);
  const tree = isRecord(root.product_tree) ? root.product_tree : {};
  const findings: CsafRequirementFinding[] = [];
  const noVulnerabilities = vulnerabilities.length === 0;

  // --- 4.2 General ----------------------------------------------------------
  const withCve = vulnerabilities.filter((v) => asString(v.cve) !== undefined).length;
  findings.push({
    id: 'tr03191-cve',
    clause: '4.2',
    label: 'CVE number for every vulnerability',
    pass: withCve === vulnerabilities.length,
    actual: noVulnerabilities ? 'no vulnerabilities listed' : `${withCve} of ${vulnerabilities.length}`,
    ...(noVulnerabilities ? { applicable: false } : {}),
  });

  const withCvss = vulnerabilities.filter(hasCvss).length;
  findings.push({
    id: 'tr03191-cvss',
    clause: '4.2',
    label: 'CVSS presented for every vulnerability',
    pass: withCvss === vulnerabilities.length,
    actual: noVulnerabilities ? 'no vulnerabilities listed' : `${withCvss} of ${vulnerabilities.length}`,
    ...(noVulnerabilities ? { applicable: false } : {}),
  });

  // The Security Advisory or VEX profile for vulnerability information (4.2);
  // the incident-response profile is mandatory for incidents (4.5) and may
  // list vulnerabilities; the informational profile carries none by
  // definition. A base document with nothing to report has no profile
  // obligation to measure.
  const category = asString(docNode.category);
  const profileApplicable = !noVulnerabilities || (category !== undefined && NO_VULNERABILITY_PROFILES.has(category));
  const profileOk =
    category !== undefined && (ADVISORY_PROFILES.has(category) || (noVulnerabilities && NO_VULNERABILITY_PROFILES.has(category)));
  findings.push({
    id: 'tr03191-profile',
    clause: '4.2',
    label: 'Security Advisory, VEX or Security Incident Response profile for vulnerability information',
    pass: profileOk,
    actual: category ?? 'no document.category',
    ...(profileApplicable ? {} : { applicable: false }),
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
    label: 'Fixing versions as fixed, first_fixed or recommended product status for every vulnerability with affected products (or a no-fix remediation)',
    pass: withFix === withAffected.length,
    actual:
      withAffected.length === 0
        ? 'no vulnerability lists affected products'
        : `${withFix} of ${withAffected.length} vulnerabilities with affected products`,
    ...(withAffected.length === 0 ? { applicable: false } : {}),
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
  const { chains, ranges } = branchFacts(asRecordArray(tree.branches));
  findings.push({
    id: 'tr03191-hierarchy',
    clause: '4.4',
    label: 'Product tree structured vendor / product_name / product_version',
    pass: chains > 0,
    actual: `${chains} complete chain${chains === 1 ? '' : 's'}`,
  });

  findings.push({
    id: 'tr03191-version-ranges',
    clause: '4.4',
    label: 'Version ranges used (allowed only where enumeration is impossible or unreasonable, which a file cannot show)',
    pass: ranges === 0,
    actual: `${ranges} product_version_range branch${ranges === 1 ? '' : 'es'}`,
    informational: true,
  });

  const hashed = resolved ? hashedFrom(resolved) : productsWithHashes(tree);
  const referenced = new Set<string>();
  for (const v of vulnerabilities) for (const pid of bucketIds(v, STATUS_BUCKETS)) referenced.add(pid);
  const referencedWithHash = [...referenced].filter((pid) => hashed.has(pid)).length;
  findings.push({
    id: 'tr03191-product-hashes',
    clause: '4.4',
    label: 'Hashes of the primary components in product_identification_helper (where an SBOM is mandatory)',
    pass: referencedWithHash === referenced.size,
    actual: referenced.size === 0 ? 'no products referenced by vulnerabilities' : `${referencedWithHash} of ${referenced.size} referenced products`,
    ...(referenced.size === 0 ? { applicable: false } : {}),
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

/**
 * Complete vendor -> product_name -> product_version chains and
 * product_version_range branches, in one bounded, iterative walk.
 */
function branchFacts(branches: readonly Record<string, unknown>[]): { chains: number; ranges: number } {
  let chains = 0;
  let ranges = 0;
  const stack: { branch: Record<string, unknown>; path: readonly string[]; depth: number }[] = branches.map((branch) => ({
    branch,
    path: [],
    depth: 0,
  }));
  while (stack.length > 0) {
    const { branch, path, depth } = stack.pop()!;
    const category = asString(branch.category);
    const here = category ? [...path, category] : path;
    if (category === 'product_version' && here.includes('vendor') && here.includes('product_name')) chains++;
    if (category === 'product_version_range') ranges++;
    if (depth >= MAX_BRANCH_DEPTH) continue;
    for (const child of asRecordArray(branch.branches)) stack.push({ branch: child, path: here, depth: depth + 1 });
  }
  return { chains, ranges };
}

function hashedFrom(resolved: ReadonlyMap<string, CsafProductFacts>): Set<string> {
  const out = new Set<string>();
  for (const [pid, facts] of resolved) if (facts.hashes && facts.hashes.length > 0) out.add(pid);
  return out;
}

/** product_ids whose own product_identification_helper carries at least one file hash (no relationship resolution). */
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
  return out;
}
