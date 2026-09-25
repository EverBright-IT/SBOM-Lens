import { describe, expect, it } from 'vitest';
import type { WorkspaceState } from '../workspace/workspace';
import { addDocument, emptyWorkspace } from '../workspace/workspace';
import { loadedFromText } from '../test-fixtures';
import { MAX_CSAF_BYTES, parseCsaf, sniffCsaf } from './csaf';
import { matchVex } from './vex';

/**
 * CSAF 2.0 → VexDocument: the sniff, product-tree resolution (full product
 * names, recursive branches, relationships), status-bucket mapping, and the
 * proof that a parsed CSAF document matches the inventory through the shared
 * matchVex — the same engine OpenVEX uses.
 */

const OPENSSL = 'pkg:apk/alpine/openssl@3.0.9';
const API_SERVER = 'pkg:npm/%40acme/api-server@2.1.0';

/** A CSAF VEX advisory exercising every product-tree shape and status bucket. */
function csafDoc(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    document: {
      csaf_version: '2.0',
      category: 'csaf_vex',
      title: 'ACME advisory',
      publisher: { category: 'vendor', name: 'ACME Security Team' },
      tracking: {
        id: 'ACME-VEX-2026-0001',
        version: '3',
        current_release_date: '2026-06-01T00:00:00Z',
        initial_release_date: '2026-05-01T00:00:00Z',
      },
    },
    product_tree: {
      full_product_names: [
        {
          product_id: 'CSAFPID-openssl',
          name: 'openssl 3.0.9',
          product_identification_helper: { purl: OPENSSL },
        },
        {
          product_id: 'CSAFPID-cpeonly',
          name: 'acme thing 1.0',
          product_identification_helper: { cpe: 'cpe:2.3:a:acme:thing:1.0:*:*:*:*:*:*:*' },
        },
      ],
      branches: [
        {
          category: 'vendor',
          name: 'ACME',
          branches: [
            {
              category: 'product_name',
              name: 'api-server',
              product: {
                product_id: 'CSAFPID-apiserver',
                name: 'api-server 2.1.0',
                product_identification_helper: { purl: API_SERVER },
              },
            },
          ],
        },
      ],
      relationships: [
        {
          category: 'default_component_of',
          product_reference: 'CSAFPID-openssl',
          relates_to_product_reference: 'CSAFPID-apiserver',
          full_product_name: { product_id: 'CSAFPID-openssl-on-apiserver', name: 'openssl on api-server' },
        },
      ],
    },
    vulnerabilities: [
      {
        cve: 'CVE-2026-1111',
        ids: [{ system_name: 'GitHub', text: 'GHSA-aaaa-bbbb-cccc' }],
        notes: [{ category: 'description', text: 'Heap overflow in the TLS parser.' }],
        product_status: { known_affected: ['CSAFPID-openssl'] },
        remediations: [{ category: 'vendor_fix', details: 'Upgrade to 3.0.10.', product_ids: ['CSAFPID-openssl'] }],
        threats: [{ category: 'impact', details: 'Remote code execution.', product_ids: ['CSAFPID-openssl'] }],
      },
      {
        cve: 'CVE-2026-2222',
        product_status: { known_not_affected: ['CSAFPID-apiserver'] },
        flags: [{ label: 'vulnerable_code_not_present', product_ids: ['CSAFPID-apiserver'] }],
      },
      {
        cve: 'CVE-2026-3333',
        product_status: {
          fixed: ['CSAFPID-openssl-on-apiserver'],
          under_investigation: ['CSAFPID-cpeonly'],
        },
      },
    ],
    ...extra,
  };
}

function wsWith(...packages: [name: string, version: string, purl?: string][]): WorkspaceState {
  const lines = [
    'SPDXVersion: SPDX-2.3',
    'SPDXID: SPDXRef-DOCUMENT',
    'DocumentName: csaf-target',
    'DocumentNamespace: https://example.org/spdxdocs/csaf-target',
  ];
  packages.forEach(([name, version, purl], i) => {
    lines.push(
      `PackageName: ${name}`,
      `SPDXID: SPDXRef-P${i}`,
      `PackageVersion: ${version}`,
      'PackageDownloadLocation: NOASSERTION',
    );
    if (purl) lines.push(`ExternalRef: PACKAGE-MANAGER purl ${purl}`);
  });
  const loaded = loadedFromText('csaf-target.spdx', lines.join('\n') + '\n');
  return addDocument(emptyWorkspace, loaded).workspace;
}

function findingsFor(ws: WorkspaceState, name: string, map: ReturnType<typeof matchVex>) {
  const doc = [...ws.documents.values()][0]!;
  const element = doc.document.elements.find((e) => e.name === name)!;
  return map.get(element.id);
}

describe('sniffCsaf', () => {
  it('accepts the base and informational profiles, which carry no vulnerabilities list', () => {
    const base = JSON.stringify({ document: { csaf_version: '2.0', category: 'csaf_base', title: 'Note' } });
    expect(sniffCsaf(base).isCsaf).toBe(true);
    expect(parseCsaf('note.json', JSON.parse(base)).statements).toEqual([]);
  });

  it('recognizes CSAF and rejects everything else', () => {
    expect(sniffCsaf(JSON.stringify(csafDoc())).isCsaf).toBe(true);
    expect(sniffCsaf('{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}').isCsaf).toBe(false);
    expect(sniffCsaf('{"schema":"sbomlens-profile/v3"}').isCsaf).toBe(false);
    expect(sniffCsaf('SPDXVersion: SPDX-2.3').isCsaf).toBe(false);
    // marker present but not a CSAF document shape
    expect(sniffCsaf('{"comment":"mentions csaf_version only in prose"}').isCsaf).toBe(false);
  });

  it('rejects oversized input without parsing', () => {
    const huge = '{"csaf_version":"2.0",' + ' '.repeat(MAX_CSAF_BYTES) + '}';
    expect(sniffCsaf(huge).isCsaf).toBe(false);
  });
});

describe('parseCsaf', () => {
  it('resolves the product tree and maps every status bucket', () => {
    const doc = parseCsaf('acme.csaf.json', csafDoc());
    expect(doc.format).toBe('csaf');
    expect(doc.id).toBe('ACME-VEX-2026-0001');
    expect(doc.author).toBe('ACME Security Team');
    expect(doc.timestamp).toBe('2026-06-01T00:00:00Z');
    expect(doc.version).toBe(3);

    const affected = doc.statements.find((s) => s.vulnerability === 'CVE-2026-1111')!;
    expect(affected.status).toBe('affected');
    expect(affected.products).toEqual([{ id: OPENSSL, subcomponents: [] }]);
    expect(affected.description).toBe('Heap overflow in the TLS parser.');
    expect(affected.actionStatement).toBe('Upgrade to 3.0.10.');
    expect(affected.impactStatement).toBe('Remote code execution.');
    expect(affected.aliases).toEqual(['GHSA-aaaa-bbbb-cccc']);
    // A justification is only attached to not_affected.
    expect(affected.justification).toBeUndefined();

    const notAffected = doc.statements.find((s) => s.vulnerability === 'CVE-2026-2222')!;
    expect(notAffected.status).toBe('not_affected');
    expect(notAffected.products).toEqual([{ id: API_SERVER, subcomponents: [] }]);
    expect(notAffected.justification).toBe('vulnerable_code_not_present');
  });

  it('resolves a relationship product to its component identifier', () => {
    const doc = parseCsaf('acme.csaf.json', csafDoc());
    const fixed = doc.statements.find((s) => s.vulnerability === 'CVE-2026-3333' && s.status === 'fixed')!;
    // CSAFPID-openssl-on-apiserver has no own helper → resolves to the
    // component (product_reference = CSAFPID-openssl).
    expect(fixed.products).toEqual([{ id: OPENSSL, subcomponents: [] }]);
  });

  it('emits a CPE-only product as a matchable statement', () => {
    const doc = parseCsaf('acme.csaf.json', csafDoc());
    const underInvestigation = doc.statements.find((s) => s.status === 'under_investigation')!;
    expect(underInvestigation.products).toEqual([
      { id: 'cpe:2.3:a:acme:thing:1.0:*:*:*:*:*:*:*', subcomponents: [] },
    ]);
    expect(doc.diagnostics.some((d) => d.code === 'CSAF_PRODUCT_CPE_ONLY')).toBe(false);
  });

  it('matches a CPE-only product against an element carrying that CPE', () => {
    const lines = [
      'SPDXVersion: SPDX-2.3',
      'SPDXID: SPDXRef-DOCUMENT',
      'DocumentName: cpe-inv',
      'DocumentNamespace: https://example.org/spdxdocs/cpe-inv',
      'PackageName: thing',
      'SPDXID: SPDXRef-P0',
      'PackageVersion: 1.0',
      'PackageDownloadLocation: NOASSERTION',
      'ExternalRef: SECURITY cpe23Type cpe:2.3:a:acme:thing:1.0:*:*:*:*:*:*:*',
    ];
    const loaded = loadedFromText('cpe-inv.spdx', lines.join('\n') + '\n');
    const ws = addDocument(emptyWorkspace, loaded).workspace;
    const map = matchVex(ws, [parseCsaf('acme.csaf.json', csafDoc())]);
    const findings = [...map.values()].flat();
    expect(findings.map((f) => `${f.vulnerability}:${f.status}`)).toEqual([
      'CVE-2026-3333:under_investigation',
    ]);
  });

  it('skips a vulnerability with no CVE or tracking id', () => {
    const doc = parseCsaf(
      'x.csaf.json',
      csafDoc({ vulnerabilities: [{ product_status: { known_affected: ['CSAFPID-openssl'] } }] }),
    );
    expect(doc.statements).toHaveLength(0);
    expect(doc.diagnostics.some((d) => d.code === 'CSAF_VULN_SKIPPED')).toBe(true);
  });

  it('falls back to the file name and initial_release_date when tracking is thin', () => {
    const doc = parseCsaf('fallback.csaf.json', {
      document: { csaf_version: '2.0', tracking: { initial_release_date: '2026-01-01T00:00:00Z' } },
      vulnerabilities: [],
    });
    expect(doc.id).toBe('fallback.csaf.json');
    expect(doc.timestamp).toBe('2026-01-01T00:00:00Z');
    expect(doc.version).toBeUndefined();
  });
});

describe('CSAF through the shared matcher', () => {
  it('matches resolved products against the inventory by purl', () => {
    const ws = wsWith(['openssl', '3.0.9', OPENSSL], ['@acme/api-server', '2.1.0', API_SERVER]);
    const doc = parseCsaf('acme.csaf.json', csafDoc());
    const map = matchVex(ws, [doc]);

    const openssl = findingsFor(ws, 'openssl', map)!;
    expect(openssl.map((f) => `${f.vulnerability}:${f.status}`).sort()).toEqual([
      'CVE-2026-1111:affected',
      'CVE-2026-3333:fixed',
    ]);
    expect(openssl.find((f) => f.vulnerability === 'CVE-2026-1111')!.source).toBe('ACME-VEX-2026-0001');

    const apiServer = findingsFor(ws, '@acme/api-server', map)!;
    expect(apiServer).toHaveLength(1);
    expect(apiServer[0]!.status).toBe('not_affected');
  });

  it('lets the OpenVEX time rule arbitrate a CSAF/OpenVEX conflict', () => {
    const ws = wsWith(['openssl', '3.0.9', OPENSSL]);
    const csaf = parseCsaf('acme.csaf.json', csafDoc()); // CVE-2026-1111 affected @ 2026-06-01
    const olderOpenVex = {
      id: 'https://acme.example/vex-old',
      fileName: 'old.openvex.json',
      format: 'openvex' as const,
      timestamp: '2026-01-01T00:00:00Z',
      statements: [
        {
          vulnerability: 'CVE-2026-1111',
          products: [{ id: OPENSSL, subcomponents: [] }],
          status: 'under_investigation' as const,
          timestamp: '2026-01-01T00:00:00Z',
        },
      ],
      diagnostics: [],
    };
    const map = matchVex(ws, [olderOpenVex, csaf]);
    const openssl = findingsFor(ws, 'openssl', map)!;
    const finding = openssl.find((f) => f.vulnerability === 'CVE-2026-1111')!;
    // Newer CSAF statement wins; the older OpenVEX one is superseded.
    expect(finding.status).toBe('affected');
    expect(finding.supersededCount).toBe(1);
  });
});

describe('CSAF product groups, hashes, remediations and schema findings', () => {
  const SHA = 'aabb00112233445566778899aabbccddeeff00112233445566778899aabbccdd';

  it('applies a group-scoped remediation to the group members only, never to everybody', () => {
    const doc = parseCsaf(
      'groups.json',
      csafDoc({
        product_tree: {
          ...(csafDoc().product_tree as Record<string, unknown>),
          product_groups: [{ group_id: 'CSAFGID-servers', product_ids: ['CSAFPID-apiserver'] }],
        },
        vulnerabilities: [
          {
            cve: 'CVE-2026-7777',
            product_status: { known_affected: ['CSAFPID-openssl', 'CSAFPID-apiserver'] },
            remediations: [{ category: 'workaround', details: 'Disable TLS 1.0 on servers.', group_ids: ['CSAFGID-servers'] }],
            threats: [{ category: 'impact', details: 'Downgrade attack.', group_ids: ['CSAFGID-unknown'] }],
          },
        ],
      }),
    );
    const affected = doc.statements.filter((s) => s.vulnerability === 'CVE-2026-7777');
    const forApi = affected.find((s) => s.products.some((p) => p.id === API_SERVER))!;
    const forOpenssl = affected.find((s) => s.products.some((p) => p.id === OPENSSL))!;
    expect(forApi.actionStatement).toBe('Disable TLS 1.0 on servers.');
    expect(forApi.remediations).toEqual([{ category: 'workaround', details: 'Disable TLS 1.0 on servers.' }]);
    expect(forOpenssl.actionStatement).toBeUndefined();
    // A threat aimed at an unknown group applies to nobody.
    expect(forApi.impactStatement).toBeUndefined();
    expect(forOpenssl.impactStatement).toBeUndefined();
  });

  it('keeps remediations structured with url, date and restart requirement', () => {
    const doc = parseCsaf(
      'rem.json',
      csafDoc({
        vulnerabilities: [
          {
            cve: 'CVE-2026-8888',
            product_status: { known_affected: ['CSAFPID-openssl'] },
            remediations: [
              {
                category: 'vendor_fix',
                details: 'Upgrade to 3.0.10.',
                url: 'https://acme.example/fix',
                date: '2026-06-02T00:00:00Z',
                restart_required: { category: 'system' },
                product_ids: ['CSAFPID-openssl'],
              },
            ],
          },
        ],
      }),
    );
    expect(doc.statements[0]!.remediations).toEqual([
      { category: 'vendor_fix', details: 'Upgrade to 3.0.10.', url: 'https://acme.example/fix', date: '2026-06-02T00:00:00Z', restartRequired: 'system' },
    ]);
  });

  it('matches a product identified only by file hashes against an element checksum', () => {
    const doc = parseCsaf(
      'hash.json',
      csafDoc({
        product_tree: {
          full_product_names: [
            {
              product_id: 'CSAFPID-blob',
              name: 'firmware blob',
              product_identification_helper: { hashes: [{ filename: 'fw.bin', file_hashes: [{ algorithm: 'sha-256', value: SHA.toUpperCase() }] }] },
            },
          ],
        },
        vulnerabilities: [{ cve: 'CVE-2026-9999', product_status: { known_affected: ['CSAFPID-blob'] } }],
      }),
    );
    expect(doc.statements[0]!.products[0]).toEqual({
      id: `hash:sha-256:${SHA.toUpperCase()}`,
      subcomponents: [],
      hashes: [{ algorithm: 'sha-256', value: SHA.toUpperCase() }],
    });
    expect(doc.diagnostics.map((d) => d.code)).not.toContain('CSAF_PRODUCT_UNRESOLVED');

    const lines = [
      'SPDXVersion: SPDX-2.3',
      'SPDXID: SPDXRef-DOCUMENT',
      'DocumentName: fw',
      'DocumentNamespace: https://example.org/spdxdocs/fw',
      'PackageName: firmware',
      'SPDXID: SPDXRef-fw',
      'PackageVersion: 9',
      'PackageDownloadLocation: NOASSERTION',
      `PackageChecksum: SHA256: ${SHA}`,
      '',
    ];
    const ws = addDocument(emptyWorkspace, loadedFromText('fw.spdx', lines.join('\n'))).workspace;
    const findings = findingsFor(ws, 'firmware', matchVex(ws, [doc]));
    expect(findings).toHaveLength(1);
    expect(findings![0]).toMatchObject({ vulnerability: 'CVE-2026-9999', status: 'affected', matchedBy: 'hash' });
    // One statement, one hash: the pseudo-id and the hashes list must not index it twice.
    expect(findings![0]!.supersededCount).toBeUndefined();
  });

  it('reads title, category, TLP and tracking status, and measures TR-03191', () => {
    const doc = parseCsaf(
      'meta.json',
      csafDoc({
        document: {
          ...(csafDoc().document as Record<string, unknown>),
          distribution: { tlp: { label: 'AMBER' } },
          tracking: { ...((csafDoc().document as Record<string, unknown>).tracking as Record<string, unknown>), status: 'final' },
        },
      }),
    );
    expect(doc).toMatchObject({ title: 'ACME advisory', category: 'csaf_vex', tlp: 'AMBER', status: 'final', trackingId: 'ACME-VEX-2026-0001' });
    expect(doc.tr03191).toHaveLength(9);
    expect(doc.tr03191!.find((f) => f.id === 'tr03191-tlp')).toMatchObject({ pass: true, actual: 'AMBER' });
  });

  it('emits schema findings for the mandatory pieces this reader relies on', () => {
    const doc = parseCsaf(
      'broken.json',
      csafDoc({
        document: { csaf_version: '3.0', category: 'csaf_vex', publisher: { name: 'ACME' }, tracking: { id: 'X' } },
        vulnerabilities: [
          { cve: 'CVE-26-1', product_status: { known_affected: ['CSAFPID-ghost'] }, remediations: [{ category: 'vendor_fix', details: 'x', product_ids: ['CSAFPID-ghost2'] }] },
        ],
      }),
    );
    const codes = doc.diagnostics.map((d) => d.code);
    expect(codes).toEqual(
      expect.arrayContaining([
        'CSAF_SCHEMA_BAD_VERSION',
        'CSAF_SCHEMA_MISSING_TRACKING',
        'CSAF_SCHEMA_MISSING_PUBLISHER',
        'CSAF_SCHEMA_BAD_CVE_ID',
        'CSAF_SCHEMA_UNDEFINED_PRODUCT_ID',
      ]),
    );
    const undefinedIds = doc.diagnostics.find((d) => d.code === 'CSAF_SCHEMA_UNDEFINED_PRODUCT_ID')!;
    expect(undefinedIds.message).toContain('2 product id(s)');
    // A document with the mandatory pieces stays silent (the shared fixture
    // leaves out publisher.namespace and tracking.status, which are exactly
    // the kind of omission the findings exist for).
    const complete = csafDoc();
    const document = complete.document as Record<string, Record<string, unknown>>;
    document.publisher = { ...document.publisher, namespace: 'https://acme.example' };
    document.tracking = { ...document.tracking, status: 'final' };
    expect(parseCsaf('clean.json', complete).diagnostics.filter((d) => d.code.includes('_SCHEMA_'))).toEqual([]);
  });
});

describe('CSAF targeting, identity and hostile shapes', () => {
  const SHA = 'aabb00112233445566778899aabbccddeeff00112233445566778899aabbccdd';

  it('lets an untargeted remediation or flag reach nobody and reports it (6.1.29, 6.1.32)', () => {
    const doc = parseCsaf(
      'untargeted.json',
      csafDoc({
        vulnerabilities: [
          {
            cve: 'CVE-2026-1010',
            product_status: { known_affected: ['CSAFPID-openssl'], known_not_affected: ['CSAFPID-apiserver'] },
            remediations: [{ category: 'vendor_fix', details: 'Upgrade a to 2.' }],
            flags: [{ label: 'vulnerable_code_not_present' }],
            threats: [{ category: 'impact', details: 'Applies to the whole vulnerability.' }],
          },
        ],
      }),
    );
    const affected = doc.statements.find((s) => s.status === 'affected')!;
    const notAffected = doc.statements.find((s) => s.status === 'not_affected')!;
    expect(affected.actionStatement).toBeUndefined();
    expect(affected.remediations).toBeUndefined();
    expect(notAffected.actionStatement).toBeUndefined();
    expect(notAffected.justification).toBeUndefined();
    // A threat without targets is a statement about the vulnerability.
    expect(affected.impactStatement).toBe('Applies to the whole vulnerability.');
    const codes = doc.diagnostics.map((d) => d.code);
    expect(codes).toContain('CSAF_SCHEMA_UNTARGETED_REMEDIATION');
    expect(codes).toContain('CSAF_SCHEMA_UNTARGETED_FLAG');
  });

  it('keys the document by publisher namespace and tracking id', () => {
    const base = csafDoc();
    (base.document as Record<string, Record<string, unknown>>).publisher = { category: 'vendor', name: 'ACME', namespace: 'https://acme.example' };
    const doc = parseCsaf('ns.json', base);
    expect(doc.id).toBe('https://acme.example#ACME-VEX-2026-0001');
    expect(doc.trackingId).toBe('ACME-VEX-2026-0001');
  });

  it('defines product ids from every tree node, not only the resolvable ones (6.1.1)', () => {
    const doc = parseCsaf(
      'rel.json',
      csafDoc({
        product_tree: {
          full_product_names: [{ product_id: 'P-bare', name: 'bare product' }],
          relationships: [
            {
              category: 'installed_on',
              product_reference: 'P-bare',
              relates_to_product_reference: 'P-ghost',
              full_product_name: { product_id: 'R1', name: 'bare on ghost' },
            },
          ],
          product_groups: [{ group_id: 'G', product_ids: ['R1', 'P-missing'] }],
        },
        vulnerabilities: [{ cve: 'CVE-2026-2020', product_status: { known_affected: ['R1'] } }],
      }),
    );
    const finding = doc.diagnostics.find((d) => d.code === 'CSAF_SCHEMA_UNDEFINED_PRODUCT_ID')!;
    expect(finding.message).toContain('2 product id(s)');
    expect(finding.message).toContain('P-ghost');
    expect(finding.message).toContain('P-missing');
    expect(finding.message).not.toContain('R1');
  });

  it('files a purl-and-hash product once: no phantom superseded statements, purl wins the attribution', () => {
    const doc = parseCsaf(
      'both.json',
      csafDoc({
        product_tree: {
          full_product_names: [
            {
              product_id: 'P',
              name: 'openssl',
              product_identification_helper: { purl: OPENSSL, hashes: [{ filename: 'openssl.tar', file_hashes: [{ algorithm: 'sha256', value: SHA }] }] },
            },
          ],
        },
        vulnerabilities: [{ cve: 'CVE-2026-3030', product_status: { known_affected: ['P'] } }],
      }),
    );
    const lines = [
      'SPDXVersion: SPDX-2.3',
      'SPDXID: SPDXRef-DOCUMENT',
      'DocumentName: both',
      'DocumentNamespace: https://example.org/spdxdocs/both',
      'PackageName: openssl',
      'SPDXID: SPDXRef-openssl',
      'PackageVersion: 3.0.9',
      'PackageDownloadLocation: NOASSERTION',
      `ExternalRef: PACKAGE-MANAGER purl ${OPENSSL}`,
      `PackageChecksum: SHA256: ${SHA}`,
      '',
    ];
    const ws = addDocument(emptyWorkspace, loadedFromText('both.spdx', lines.join('\n'))).workspace;
    const findings = findingsFor(ws, 'openssl', matchVex(ws, [doc]))!;
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ vulnerability: 'CVE-2026-3030', matchedBy: 'purl' });
    expect(findings[0]!.supersededCount).toBeUndefined();
  });

  it('does not match a file element by hash; a product hash names a delivered package', () => {
    const doc = parseCsaf(
      'file.json',
      csafDoc({
        product_tree: {
          full_product_names: [{ product_id: 'P', name: 'blob', product_identification_helper: { hashes: [{ filename: 'b', file_hashes: [{ algorithm: 'sha256', value: SHA }] }] } }],
        },
        vulnerabilities: [{ cve: 'CVE-2026-4040', product_status: { known_affected: ['P'] } }],
      }),
    );
    const lines = [
      'SPDXVersion: SPDX-2.3',
      'SPDXID: SPDXRef-DOCUMENT',
      'DocumentName: f',
      'DocumentNamespace: https://example.org/spdxdocs/f',
      'FileName: ./blob.bin',
      'SPDXID: SPDXRef-blob',
      `FileChecksum: SHA256: ${SHA}`,
      '',
    ];
    const ws = addDocument(emptyWorkspace, loadedFromText('f.spdx', lines.join('\n'))).workspace;
    expect(matchVex(ws, [doc]).size).toBe(0);
  });

  it('survives a product tree nested thousands of levels deep', () => {
    let branch: Record<string, unknown> = { category: 'product_version', name: '1', product: { product_id: 'deep', name: 'deep' } };
    for (let i = 0; i < 5000; i++) branch = { category: 'product_name', name: `n${i}`, branches: [branch] };
    const doc = parseCsaf('deep.json', csafDoc({ product_tree: { branches: [branch] }, vulnerabilities: [] }));
    expect(doc.statements).toEqual([]);
    expect(doc.tr03191).toHaveLength(9);
  });
});
