import { describe, expect, it } from 'vitest';
import { loadedFromText } from '../test-fixtures';
import type { WorkspaceState } from '../workspace/workspace';
import { addDocument, emptyWorkspace } from '../workspace/workspace';
import { matchVex, parseOpenVex, purlMatchKey, sniffVex, vexCoverage, worstVexStatus } from './vex';

/**
 * The VEX overlay end to end: sniff, tolerant parse (current and early
 * spec shapes), the conservative purl matching, and the OpenVEX time rule.
 */

function vexJson(statements: unknown[], extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': 'https://acme.example/vex-2026-001',
    author: 'ACME Security Team',
    timestamp: '2026-03-01T00:00:00Z',
    version: 1,
    statements,
    ...extra,
  });
}

function wsWith(...packages: [name: string, version: string, purl?: string][]): WorkspaceState {
  const lines = [
    'SPDXVersion: SPDX-2.3',
    'SPDXID: SPDXRef-DOCUMENT',
    'DocumentName: vex-target',
    'DocumentNamespace: https://example.org/spdxdocs/vex-target',
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
  const loaded = loadedFromText('vex-target.spdx', lines.join('\n') + '\n');
  return addDocument(emptyWorkspace, loaded).workspace;
}

function findingsFor(ws: WorkspaceState, name: string, map: ReturnType<typeof matchVex>) {
  const doc = [...ws.documents.values()][0]!;
  const element = doc.document.elements.find((e) => e.name === name)!;
  return map.get(element.id);
}

describe('sniffVex', () => {
  it('recognizes OpenVEX and rejects everything else', () => {
    expect(sniffVex(vexJson([])).isVex).toBe(true);
    expect(sniffVex('{"schema": "sbomlens-profile/v3"}').isVex).toBe(false);
    expect(sniffVex('SPDXVersion: SPDX-2.3').isVex).toBe(false);
    // openvex.dev mentioned but not as @context
    expect(sniffVex('{"comment": "see openvex.dev"}').isVex).toBe(false);
  });
});

describe('parseOpenVex', () => {
  it('parses the current shape including subcomponents', () => {
    const raw = JSON.parse(
      vexJson([
        {
          vulnerability: { name: 'CVE-2026-1111', description: 'A bug.', aliases: ['GHSA-xxxx'] },
          products: [
            {
              '@id': 'pkg:npm/acme-app@2.0.0',
              subcomponents: [{ '@id': 'pkg:npm/lodash@4.17.21' }],
            },
          ],
          status: 'not_affected',
          justification: 'vulnerable_code_not_in_execute_path',
          impact_statement: 'The vulnerable function is never called.',
        },
      ]),
    ) as unknown;
    const doc = parseOpenVex('a.openvex.json', raw);
    expect(doc.id).toBe('https://acme.example/vex-2026-001');
    expect(doc.statements).toHaveLength(1);
    const s = doc.statements[0]!;
    expect(s.vulnerability).toBe('CVE-2026-1111');
    expect(s.products[0]!.subcomponents).toEqual(['pkg:npm/lodash@4.17.21']);
    expect(s.justification).toBe('vulnerable_code_not_in_execute_path');
    expect(doc.diagnostics).toEqual([]);
  });

  it('parses the early spec shape (string vulnerability, string products)', () => {
    const raw = JSON.parse(
      vexJson([
        { vulnerability: 'CVE-2026-2222', products: ['pkg:golang/acme.org/tool@1.0.0'], status: 'fixed' },
      ]),
    ) as unknown;
    const doc = parseOpenVex('b.openvex.json', raw);
    expect(doc.statements[0]!.vulnerability).toBe('CVE-2026-2222');
    expect(doc.statements[0]!.products[0]!.id).toBe('pkg:golang/acme.org/tool@1.0.0');
  });

  it('skips malformed statements with diagnostics instead of throwing', () => {
    const raw = JSON.parse(
      vexJson([
        { products: ['pkg:npm/a@1'], status: 'fixed' }, // no vulnerability
        { vulnerability: 'CVE-1', products: ['pkg:npm/a@1'], status: 'wontfix' }, // unknown status
        { vulnerability: 'CVE-2', products: [], status: 'affected' }, // nothing to match
        'not an object',
      ]),
    ) as unknown;
    const doc = parseOpenVex('c.openvex.json', raw);
    expect(doc.statements).toHaveLength(0);
    expect(doc.diagnostics.map((d) => d.code)).toEqual([
      'VEX_STATEMENT_SKIPPED',
      'VEX_UNKNOWN_STATUS',
      'VEX_STATEMENT_UNMATCHABLE',
      'VEX_STATEMENT_SKIPPED',
    ]);
  });
});

describe('purlMatchKey', () => {
  it('case-folds type and namespace, keeps name and version exact', () => {
    expect(purlMatchKey('pkg:NPM/%40Angular/core@1.0.0')).toEqual({
      pkg: 'npm/@angular/core',
      version: '1.0.0',
    });
    // name case is preserved -> different keys
    expect(purlMatchKey('pkg:generic/ACME')!.pkg).not.toBe(purlMatchKey('pkg:generic/acme')!.pkg);
  });

  it('ignores qualifiers and subpath, handles versionless purls', () => {
    expect(purlMatchKey('pkg:oci/webstack@sha256%3Aabc?repository_url=ghcr.io#sub/path')).toEqual({
      pkg: 'oci//webstack',
      version: 'sha256:abc',
    });
    expect(purlMatchKey('pkg:npm/left-pad')).toEqual({ pkg: 'npm//left-pad' });
    expect(purlMatchKey('not-a-purl')).toBeUndefined();
  });
});

describe('matchVex', () => {
  const ws = wsWith(
    ['web-frontend', '2.0.0', 'pkg:npm/acme-web@2.0.0'],
    ['lodash', '4.17.21', 'pkg:npm/lodash@4.17.21'],
    ['other', '9.9.9', 'pkg:npm/unrelated@9.9.9'],
    ['no-purl', '1.0.0'],
  );

  it('matches by exact version and leaves other versions alone', () => {
    const vex = parseOpenVex('v.openvex.json', JSON.parse(vexJson([
      { vulnerability: 'CVE-2026-1111', products: ['pkg:npm/acme-web@2.0.0'], status: 'affected', action_statement: 'Upgrade to 2.0.1.' },
      { vulnerability: 'CVE-2026-3333', products: ['pkg:npm/acme-web@1.0.0'], status: 'affected' },
    ])) as unknown);
    const map = matchVex(ws, [vex]);
    const findings = findingsFor(ws, 'web-frontend', map)!;
    expect(findings.map((f) => f.vulnerability)).toEqual(['CVE-2026-1111']);
    expect(findings[0]!.actionStatement).toBe('Upgrade to 2.0.1.');
    expect(findingsFor(ws, 'other', map)).toBeUndefined();
  });

  it('a versionless VEX purl covers every version; subcomponents mark the inner package', () => {
    const vex = parseOpenVex('v.openvex.json', JSON.parse(vexJson([
      { vulnerability: 'CVE-2026-4444', products: ['pkg:npm/acme-web'], status: 'under_investigation' },
      {
        vulnerability: 'CVE-2026-5555',
        products: [{ '@id': 'pkg:npm/acme-web@2.0.0', subcomponents: [{ '@id': 'pkg:npm/lodash@4.17.21' }] }],
        status: 'not_affected',
        justification: 'component_not_present',
      },
    ])) as unknown);
    const map = matchVex(ws, [vex]);
    expect(findingsFor(ws, 'web-frontend', map)!.map((f) => f.vulnerability)).toEqual([
      'CVE-2026-4444',
      'CVE-2026-5555',
    ]);
    const inner = findingsFor(ws, 'lodash', map)!;
    expect(inner).toHaveLength(1);
    expect(inner[0]!.viaSubcomponent).toBe(true);
    expect(inner[0]!.status).toBe('not_affected');
  });

  it('applies the OpenVEX time rule across documents: the newest statement wins', () => {
    const older = parseOpenVex('old.openvex.json', JSON.parse(vexJson(
      [{ vulnerability: 'CVE-2026-1111', products: ['pkg:npm/acme-web@2.0.0'], status: 'under_investigation' }],
      { '@id': 'vex-old', timestamp: '2026-01-01T00:00:00Z' },
    )) as unknown);
    const newer = parseOpenVex('new.openvex.json', JSON.parse(vexJson(
      [{ vulnerability: 'CVE-2026-1111', products: ['pkg:npm/acme-web@2.0.0'], status: 'fixed', timestamp: '2026-06-01T00:00:00Z' }],
      { '@id': 'vex-new', timestamp: '2026-02-01T00:00:00Z' },
    )) as unknown);
    // Loaded in both orders: the statement timestamp decides, not load order.
    for (const docs of [[older, newer], [newer, older]]) {
      const map = matchVex(ws, docs);
      const findings = findingsFor(ws, 'web-frontend', map)!;
      expect(findings).toHaveLength(1);
      expect(findings[0]!.status).toBe('fixed');
      expect(findings[0]!.source).toBe('vex-new');
    }
  });

  it('sorts findings alarming-first and reports the worst status', () => {
    const vex = parseOpenVex('v.openvex.json', JSON.parse(vexJson([
      { vulnerability: 'CVE-2026-6666', products: ['pkg:npm/acme-web@2.0.0'], status: 'not_affected', justification: 'component_not_present' },
      { vulnerability: 'CVE-2026-7777', products: ['pkg:npm/acme-web@2.0.0'], status: 'affected' },
    ])) as unknown);
    const findings = findingsFor(ws, 'web-frontend', matchVex(ws, [vex]))!;
    expect(findings.map((f) => f.status)).toEqual(['affected', 'not_affected']);
    expect(worstVexStatus(findings)).toBe('affected');
    expect(worstVexStatus([])).toBeUndefined();
  });
});

describe('verify-facing contract (Etappe K handover)', () => {
  const ws = wsWith(
    ['covered-pkg', '1.0.0', 'pkg:npm/covered@1.0.0'],
    ['uncovered-pkg', '2.0.0', 'pkg:npm/uncovered@2.0.0'],
    ['no-purl-pkg', '3.0.0'],
  );
  const docs = [
    parseOpenVex('a.openvex.json', JSON.parse(vexJson(
      [{ vulnerability: 'CVE-2026-0001', products: ['pkg:npm/covered@1.0.0'], status: 'under_investigation' }],
      { '@id': 'vex-a', timestamp: '2026-01-01T00:00:00Z' },
    )) as unknown),
    parseOpenVex('b.openvex.json', JSON.parse(vexJson(
      [
        { vulnerability: 'CVE-2026-0001', products: ['pkg:npm/covered@1.0.0'], status: 'fixed', timestamp: '2026-06-01T00:00:00Z' },
        { vulnerability: 'CVE-2026-0002', products: ['pkg:npm/covered@1.0.0'], status: 'affected' },
      ],
      { '@id': 'vex-b', timestamp: '2026-02-01T00:00:00Z' },
    )) as unknown),
  ];

  it('is deterministic across runs: identical inputs, identical output', () => {
    const first = matchVex(ws, docs);
    const second = matchVex(ws, docs);
    expect([...second.entries()]).toEqual([...first.entries()]);
  });

  it('carries the join key and the superseded count on findings', () => {
    const findings = findingsFor(ws, 'covered-pkg', matchVex(ws, docs))!;
    const winner = findings.find((f) => f.vulnerability === 'CVE-2026-0001')!;
    expect(winner.status).toBe('fixed');
    expect(winner.source).toBe('vex-b');
    expect(winner.sourceFile).toBe('b.openvex.json');
    expect(winner.supersededCount).toBe(1);
    const single = findings.find((f) => f.vulnerability === 'CVE-2026-0002')!;
    expect(single.supersededCount).toBeUndefined();
  });

  it('classifies coverage: covered / uncovered / unmatchable with exact counts', () => {
    const findings = matchVex(ws, docs);
    expect(vexCoverage(ws, findings)).toEqual({
      covered: 1,
      uncovered: 1,
      unmatchable: 1,
      total: 3,
    });
    // Without any VEX loaded, nothing is covered but the classification holds.
    expect(vexCoverage(ws, new Map())).toEqual({
      covered: 0,
      uncovered: 2,
      unmatchable: 1,
      total: 3,
    });
  });
});
