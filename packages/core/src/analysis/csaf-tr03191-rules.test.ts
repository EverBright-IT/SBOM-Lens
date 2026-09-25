import { describe, expect, it } from 'vitest';
import { parseCsaf } from './csaf';

/**
 * TR-03191 rows measure facts with their clause; the rules pinned here are
 * the ones a reviewer found too lenient or inconsistent: a no-fix remediation
 * counts only for the affected products it addresses, a document without any
 * product tree cannot fail the hierarchy row, the profile row cites both
 * clauses it draws on, and a tree cut off at the depth cap says so instead
 * of reporting unread products as undefined.
 */

function doc(vulns: unknown[], tree: unknown, category = 'csaf_vex') {
  return {
    document: {
      csaf_version: '2.0',
      category,
      title: 'x',
      publisher: { category: 'vendor', name: 'V', namespace: 'https://v.example' },
      tracking: { id: 'V-1', version: '1', status: 'final', initial_release_date: '2026-01-01T00:00:00Z', current_release_date: '2026-01-01T00:00:00Z' },
    },
    ...(tree === undefined ? {} : { product_tree: tree }),
    vulnerabilities: vulns,
  };
}
const TREE = {
  full_product_names: [
    { product_id: 'A', name: 'a', product_identification_helper: { purl: 'pkg:generic/a@1' } },
    { product_id: 'B', name: 'b', product_identification_helper: { purl: 'pkg:generic/b@1' } },
  ],
  product_groups: [{ group_id: 'G', product_ids: ['A'] }],
};
const row = (raw: unknown, id: string) => parseCsaf('t.json', raw).tr03191!.find((f) => f.id === id)!;

describe('TR-03191 rows', () => {
  it('counts a no-fix remediation only when it addresses an affected product', () => {
    const vuln = (remediation: Record<string, unknown>) => ({
      cve: 'CVE-2026-0001',
      product_status: { known_affected: ['A'], known_not_affected: ['B'] },
      remediations: [{ category: 'none_available', details: 'no fix', ...remediation }],
    });
    expect(row(doc([vuln({ product_ids: ['B'] })], TREE), 'tr03191-fixed-versions').pass).toBe(false);
    expect(row(doc([vuln({ product_ids: ['A'] })], TREE), 'tr03191-fixed-versions').pass).toBe(true);
    expect(row(doc([vuln({ group_ids: ['G'] })], TREE), 'tr03191-fixed-versions').pass).toBe(true);
  });

  it('reads the hierarchy row as not applicable without any product tree', () => {
    const r = row(doc([], undefined, 'csaf_base'), 'tr03191-hierarchy');
    expect(r.applicable).toBe(false);
    expect(r.actual).toBe('no product tree');
    // A tree without the vendor/product/version branches is still a fact.
    expect(row(doc([], TREE, 'csaf_base'), 'tr03191-hierarchy')).toMatchObject({ pass: false, actual: '0 complete chains' });
  });

  it('cites 4.2 and 4.5 on the profile row', () => {
    expect(row(doc([{ cve: 'CVE-2026-0001', product_status: { known_affected: ['A'] } }], TREE), 'tr03191-profile').clause).toBe('4.2, 4.5');
  });

  it('reports a tree beyond the depth cap as capped and leaves 6.1.1 unmeasured', () => {
    let leaf: Record<string, unknown> = { category: 'product_version', name: '1.0', product: { product_id: 'DEEP', name: 'deep' } };
    for (let i = 0; i < 70; i++) leaf = { category: 'product_name', name: `n${i}`, branches: [leaf] };
    const parsed = parseCsaf('deep.json', doc([{ cve: 'CVE-2026-0001', product_status: { known_affected: ['DEEP'] } }], { branches: [leaf] }));
    const codes = parsed.diagnostics.map((d) => d.code);
    expect(codes).toContain('CSAF_TREE_CAPPED');
    expect(codes).not.toContain('CSAF_SCHEMA_UNDEFINED_PRODUCT_ID');
  });
});
