import { describe, expect, it } from 'vitest';
import { lintCsafTr03191 } from './csaf-tr03191';

/**
 * TR-03191 measured on CSAF documents: each finding is a fact with its
 * clause, pass when the document carries what the clause asks for, fail
 * otherwise, never a verdict about the publisher.
 */

const SHA = 'aabb00112233445566778899aabbccddeeff00112233445566778899aabbccdd';

function advisory(overrides: Record<string, unknown> = {}, docOverrides: Record<string, unknown> = {}) {
  return {
    document: {
      csaf_version: '2.0',
      category: 'csaf_security_advisory',
      title: 'ACME-2026-0007',
      distribution: { tlp: { label: 'TLP:CLEAR' } },
      publisher: { category: 'vendor', name: 'ACME PSIRT', namespace: 'https://acme.example' },
      tracking: {
        id: 'ACME-SA-2026-0007',
        status: 'final',
        version: '2',
        initial_release_date: '2026-05-01T00:00:00Z',
        current_release_date: '2026-06-01T00:00:00Z',
        revision_history: [
          { number: '1', date: '2026-05-01T00:00:00Z', summary: 'Initial' },
          { number: '2', date: '2026-06-01T00:00:00Z', summary: 'Fix available' },
        ],
      },
      ...docOverrides,
    },
    product_tree: {
      branches: [
        {
          category: 'vendor',
          name: 'ACME',
          branches: [
            {
              category: 'product_name',
              name: 'Gateway',
              branches: [
                {
                  category: 'product_version',
                  name: '2.1.0',
                  product: {
                    product_id: 'GW-2.1.0',
                    name: 'ACME Gateway 2.1.0',
                    product_identification_helper: {
                      purl: 'pkg:generic/acme/gateway@2.1.0',
                      hashes: [{ file_name: 'gateway-2.1.0.bin', file_hashes: [{ algorithm: 'sha256', value: SHA }] }],
                    },
                  },
                },
                {
                  category: 'product_version',
                  name: '2.1.1',
                  product: {
                    product_id: 'GW-2.1.1',
                    name: 'ACME Gateway 2.1.1',
                    product_identification_helper: {
                      purl: 'pkg:generic/acme/gateway@2.1.1',
                      hashes: [{ file_name: 'gateway-2.1.1.bin', file_hashes: [{ algorithm: 'sha256', value: SHA.replace(/a/g, 'b') }] }],
                    },
                  },
                },
              ],
            },
          ],
        },
      ],
    },
    vulnerabilities: [
      {
        cve: 'CVE-2026-4444',
        scores: [{ cvss_v3: { version: '3.1', baseScore: 7.5, baseSeverity: 'HIGH', vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' }, products: ['GW-2.1.0'] }],
        product_status: { known_affected: ['GW-2.1.0'], fixed: ['GW-2.1.1'] },
        remediations: [{ category: 'vendor_fix', details: 'Update to 2.1.1.', product_ids: ['GW-2.1.0'], url: 'https://acme.example/advisories/7' }],
      },
    ],
    ...overrides,
  };
}

const byId = (raw: unknown) => Object.fromEntries(lintCsafTr03191(raw).map((f) => [f.id, f]));

describe('lintCsafTr03191', () => {
  it('passes every measured requirement on a complete advisory', () => {
    const findings = lintCsafTr03191(advisory());
    expect(findings).toHaveLength(9);
    expect(findings.every((f) => f.pass)).toBe(true);
    expect(findings.map((f) => f.clause)).toEqual(['4.2', '4.2', '4.2', '4.2', '4.3', '4.4', '4.4', '4.4', '4.6']);
  });

  it('reports a vulnerability without CVE or CVSS (4.2)', () => {
    const r = byId(advisory({ vulnerabilities: [{ ids: [{ system_name: 'ACME', text: 'ACME-1' }], product_status: { known_affected: ['GW-2.1.0'], fixed: ['GW-2.1.1'] } }] }));
    expect(r['tr03191-cve']).toMatchObject({ pass: false, actual: '0 of 1' });
    expect(r['tr03191-cvss']).toMatchObject({ pass: false, actual: '0 of 1' });
  });

  it('accepts CSAF 2.1 metrics as a CVSS presentation', () => {
    const vuln = { cve: 'CVE-2026-4444', metrics: [{ content: { cvss_v4: { version: '4.0', baseScore: 8.7 } }, products: ['GW-2.1.0'] }], product_status: { known_affected: ['GW-2.1.0'], fixed: ['GW-2.1.1'] } };
    expect(byId(advisory({ vulnerabilities: [vuln] }))['tr03191-cvss']!.pass).toBe(true);
  });

  it('wants the Security Advisory or VEX profile when vulnerabilities are listed (4.2)', () => {
    expect(byId(advisory({}, { category: 'csaf_base' }))['tr03191-profile']).toMatchObject({ pass: false, actual: 'csaf_base' });
    expect(byId(advisory({}, { category: 'csaf_vex' }))['tr03191-profile']!.pass).toBe(true);
    // An informational advisory carries no vulnerabilities; the profile is the right one for it.
    expect(byId(advisory({ vulnerabilities: [] }, { category: 'csaf_informational_advisory' }))['tr03191-profile']!.pass).toBe(true);
  });

  it('wants fixing versions next to affected ones, or an explicit no-fix remediation (4.2)', () => {
    const noFix = { cve: 'CVE-2026-5555', scores: [{ cvss_v3: { baseScore: 5 }, products: ['GW-2.1.0'] }], product_status: { known_affected: ['GW-2.1.0'] } };
    expect(byId(advisory({ vulnerabilities: [noFix] }))['tr03191-fixed-versions']).toMatchObject({ pass: false, actual: '0 of 1 vulnerabilities with affected products' });
    const declared = { ...noFix, remediations: [{ category: 'no_fix_planned', details: 'End of life.', product_ids: ['GW-2.1.0'] }] };
    expect(byId(advisory({ vulnerabilities: [declared] }))['tr03191-fixed-versions']!.pass).toBe(true);
  });

  it('wants the TLP label (4.3)', () => {
    expect(byId(advisory({}, { distribution: {} }))['tr03191-tlp']).toMatchObject({ pass: false, actual: 'missing' });
    expect(byId(advisory())['tr03191-tlp']!.actual).toBe('TLP:CLEAR');
  });

  it('wants the vendor / product_name / product_version tree and enumerated versions (4.4)', () => {
    const flat = advisory({
      product_tree: {
        full_product_names: [{ product_id: 'GW-2.1.0', name: 'gateway', product_identification_helper: { purl: 'pkg:generic/acme/gateway@2.1.0' } }],
      },
    });
    expect(byId(flat)['tr03191-hierarchy']).toMatchObject({ pass: false, actual: '0 complete chains' });
    const ranged = advisory();
    (ranged.product_tree.branches[0]!.branches[0]!.branches as Record<string, unknown>[]).push({ category: 'product_version_range', name: 'vers:generic/<2.0' });
    expect(byId(ranged)['tr03191-versions-enumerated']).toMatchObject({ pass: false, actual: '1 product_version_range branch' });
  });

  it('counts referenced products carrying file hashes (4.4)', () => {
    expect(byId(advisory())['tr03191-product-hashes']).toMatchObject({ pass: true, actual: '2 of 2 referenced products' });
    const noHash = advisory();
    delete (noHash.product_tree.branches[0]!.branches[0]!.branches[0]!.product.product_identification_helper as Record<string, unknown>).hashes;
    expect(byId(noHash)['tr03191-product-hashes']).toMatchObject({ pass: false, actual: '1 of 2 referenced products' });
  });

  it('wants current_release_date and a revision history (4.6)', () => {
    const r = byId(advisory({}, { tracking: { id: 'X', status: 'final', version: '1', initial_release_date: '2026-05-01T00:00:00Z' } }));
    expect(r['tr03191-revision-history']).toMatchObject({ pass: false, actual: '0 revisions, no current_release_date' });
  });
});
