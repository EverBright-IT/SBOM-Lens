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

  it('reports a CPE-only product as informational, never a false match', () => {
    const doc = parseCsaf('acme.csaf.json', csafDoc());
    // The under_investigation product is CPE-only → no statement, one info.
    expect(doc.statements.some((s) => s.status === 'under_investigation')).toBe(false);
    expect(doc.diagnostics.some((d) => d.code === 'CSAF_PRODUCT_CPE_ONLY')).toBe(true);
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
