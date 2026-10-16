import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { OcmBundle } from '../model/ocm-bundle';
import { readOcmBundle } from '../parse/ocm/bundle';
import { extractDeliveryBlob } from '../parse/ocm/extract';
import { blobSource } from '../util/bytesource';
import { acceptanceReport } from './report';
import { analyzeDeliverySboms, readSbomPackages, readVexDocument } from './sbom-analyze';
import { sbomEvidence } from './sbom-evidence';
import type { SbomPackageList } from './sbom-packages';
import {
  deliveryPackages,
  packagesToCsv,
  packagesToJson,
  placeLabel,
  searchAnswer,
  searchPackages,
} from './sbom-packages';
import type { VexSource } from './sbom-vex';
import { deliveryVex, findVulnerabilities, vexResources } from './sbom-vex';
import type { TestCv } from './test-sbom-delivery';
import { sbomDeliveryCtf, spdxProductSbom } from './test-sbom-delivery';

const NOW = Date.parse('2026-10-16T00:00:00Z');

/** A delivery with its package model and every VEX resource read as the app does. */
async function load(bytes: Uint8Array, fileName = 'test.ctf.tar') {
  const { bundle, extracted } = await readOcmBundle(fileName, bytes);
  const entries = bundle!.componentVersions.flatMap((cv) =>
    cv.resources.flatMap((r) =>
      r.sbom
        ? [
            {
              fileName: r.sbom.fileName,
              bytes: extracted[r.sbom.extractedIndex]!.bytes,
              sha1: r.sbom.sha1,
            },
          ]
        : [],
    ),
  );
  const analyses = await analyzeDeliverySboms(entries, { now: NOW });
  const evidence = sbomEvidence(bundle!, analyses);
  const lists: Record<string, SbomPackageList | null> = {};
  for (const entry of entries) {
    if (!(entry.sha1 in lists)) lists[entry.sha1] = await readSbomPackages(entry);
  }
  const model = deliveryPackages(evidence, lists);
  const source = blobSource(new Blob([bytes.slice().buffer as ArrayBuffer]));
  const sources: VexSource[] = [];
  for (const resource of vexResources(bundle!)) {
    const origin = { kind: 'resource' as const, ref: resource.ref };
    if (resource.presence === 'external') {
      sources.push({ origin, name: resource.name, state: 'external' });
      continue;
    }
    const blob = await extractDeliveryBlob(source, resource.localReference!);
    const read = blob.ok
      ? await readVexDocument({ fileName: resource.name, bytes: blob.bytes })
      : { reason: blob.reason };
    sources.push(
      'document' in read
        ? { origin, name: resource.name, state: 'loaded', document: read.document }
        : { origin, name: resource.name, state: 'unreadable', reason: read.reason },
    );
  }
  return { bundle: bundle!, analyses, lists, model, sources, vex: deliveryVex(model, sources) };
}

function demo() {
  return load(
    new Uint8Array(
      readFileSync(new URL('../../fixtures/ocm/ecme-sbom-delivery.ctf.tar', import.meta.url)),
    ),
    'ecme-sbom-delivery.ctf.tar',
  );
}

const at = (bundle: OcmBundle, ref: { cvId: string; index: number }) =>
  `${ref.cvId}#${bundle.componentVersions.find((c) => c.id === ref.cvId)!.resources[ref.index]!.name}`;

describe('VEX and CSAF documents of a delivery', () => {
  it('are found by type, media type or content, never fetched when external', async () => {
    const { bundle, sources } = await demo();
    expect(
      vexResources(bundle).map(
        (r) => `${at(bundle, r.ref)} ${r.presence}${r.byContent ? ' (by content)' : ''}`,
      ),
    ).toEqual([
      'ecme.org/shop/api@3.2.0#advisory local (by content)',
      'ecme.org/shop/payments@3.2.0#advisory external',
      'ecme.org/shop@3.2.0#vex local',
    ]);
    expect(
      sources.map((s) => [s.name, s.state, s.state === 'loaded' ? s.document.format : null]),
    ).toEqual([
      ['advisory', 'loaded', 'csaf'],
      ['advisory', 'external', null],
      ['vex', 'loaded', 'openvex'],
    ]);
  });

  it('says what the reader cannot use', async () => {
    expect(
      await readVexDocument({ fileName: 'x.json', bytes: new TextEncoder().encode('{"a":1}') }),
    ).toEqual({
      reason: 'neither an OpenVEX nor a CSAF 2.0 document',
    });
  });
});

describe('what the supplier states about the delivered packages', () => {
  it('attaches each statement to its package and the places it ships', async () => {
    const { bundle, model, vex } = await demo();
    const of = (name: string, version: string) =>
      (
        vex.byPackage.get(model.packages.find((p) => p.name === name && p.version === version)!) ??
        []
      ).map((f) => `${f.vulnerability} ${f.status}`);
    expect(of('openssl', '3.0.11')).toEqual(['GHSA-demo-ecme-0001 affected']);
    expect(of('openssl', '3.0.13')).toEqual(['GHSA-demo-ecme-0001 fixed']);
    expect(of('lodash', '4.17.21')).toEqual(['GHSA-demo-ecme-0002 not_affected']);
    expect(of('fastapi', '0.115.0')).toEqual(['GHSA-demo-ecme-0004 under_investigation']);
    expect(of('uvicorn', '0.30.6')).toEqual(['GHSA-demo-ecme-0004 not_affected']);

    expect(
      vex.vulnerabilities.map((v) => [v.id, v.status, v.packages.length, v.unmatched.length]),
    ).toEqual([
      ['GHSA-demo-ecme-0001', 'affected', 2, 0],
      ['GHSA-demo-ecme-0003', 'under_investigation', 0, 1],
      ['GHSA-demo-ecme-0004', 'under_investigation', 2, 0],
      ['GHSA-demo-ecme-0002', 'not_affected', 1, 0],
    ]);
    const first = vex.vulnerabilities[0]!;
    expect(first.places.map((p) => `${placeLabel(bundle, p.place)} ${p.status}`)).toEqual([
      'api · image fixed',
      'worker · image affected',
    ]);
    expect(vex.statements).toBe(6);
  });

  it('keeps the statements that name no package, which may ship where the list cannot look', async () => {
    const { vex } = await demo();
    expect(vex.unmatched).toEqual([
      expect.objectContaining({
        vulnerability: 'GHSA-demo-ecme-0003',
        status: 'under_investigation',
        products: ['pkg:deb/debian/libcurl4@7.88.1'],
        document: 'https://vex.ecme.example/shop/3.2.0',
      }),
    ]);
  });

  it('counts packages by the worst statement, and those no statement can name', async () => {
    const { bundle, vex } = await demo();
    expect(vex.counts).toEqual({
      affected: 1,
      under_investigation: 1,
      fixed: 1,
      not_affected: 2,
      without: 9,
      unmatchable: 2,
    });
    expect(vex.places.map((p) => [placeLabel(bundle, p.place), p.counts])).toEqual([
      ['api · image', { affected: 0, under_investigation: 1, fixed: 1, not_affected: 1 }],
      ['web · image', { affected: 0, under_investigation: 0, fixed: 0, not_affected: 1 }],
      ['worker · image', { affected: 1, under_investigation: 0, fixed: 0, not_affected: 0 }],
    ]);
  });

  it('filters the package list by the worst stated status', async () => {
    const { model, vex } = await demo();
    const names = (rows: { name: string; version?: string }[]) =>
      rows.map((p) => `${p.name}@${p.version}`);
    expect(names(searchPackages(model, { vex: 'affected' }, vex).rows)).toEqual(['openssl@3.0.11']);
    expect(names(searchPackages(model, { vex: 'not_affected' }, vex).rows)).toEqual([
      'lodash@4.17.21',
      'uvicorn@0.30.6',
    ]);
    expect(searchPackages(model, { vex: 'none' }, vex).rows).toHaveLength(11);
    // Without the VEX model the status filter cannot apply.
    expect(searchPackages(model, { vex: 'affected' }).rows).toHaveLength(16);
    expect(searchAnswer(model, { text: 'openssl', vex: 'affected' }).narrowed).toBe(true);
  });

  it('finds a vulnerability by id or alias', async () => {
    const { vex } = await demo();
    expect(findVulnerabilities(vex, 'ecme-0004').map((v) => v.id)).toEqual(['GHSA-demo-ecme-0004']);
    expect(findVulnerabilities(vex, 'CVE-2099-0001')).toEqual([]);
    expect(findVulnerabilities(vex, '')).toHaveLength(4);
  });

  it('gives a package listed by two SBOMs the most cautious statement either receives', async () => {
    // One SBOM states a CPE, the other does not: the newer CPE statement
    // reaches only the first element, the older purl statement both.
    const withCpe = JSON.stringify({
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: 'one',
      documentNamespace: 'https://example.org/spdx/one',
      creationInfo: { created: '2026-10-16T00:00:00Z', creators: ['Tool: test'] },
      packages: [
        {
          SPDXID: 'SPDXRef-p',
          name: 'zlib',
          versionInfo: '1.3.1',
          downloadLocation: 'NOASSERTION',
          externalRefs: [
            {
              referenceCategory: 'PACKAGE-MANAGER',
              referenceType: 'purl',
              referenceLocator: 'pkg:generic/zlib@1.3.1',
            },
            {
              referenceCategory: 'SECURITY',
              referenceType: 'cpe23Type',
              referenceLocator: 'cpe:2.3:a:zlib:zlib:1.3.1:*:*:*:*:*:*:*',
            },
          ],
        },
      ],
    });
    const cvs: TestCv[] = [
      {
        name: 'example.org/a',
        version: '1.0.0',
        resources: [{ kind: 'sbom', name: 'sbom', content: withCpe }],
      },
      {
        name: 'example.org/b',
        version: '1.0.0',
        resources: [
          {
            kind: 'sbom',
            name: 'sbom',
            content: spdxProductSbom('b', '1.0.0', [
              { name: 'zlib', version: '1.3.1', purl: 'pkg:generic/zlib@1.3.1' },
            ]),
          },
        ],
      },
    ];
    const { model } = await load(sbomDeliveryCtf(cvs));
    const openvex = (statements: object[]) =>
      readVexDocument({
        fileName: 'v.json',
        bytes: new TextEncoder().encode(
          JSON.stringify({
            '@context': 'https://openvex.dev/ns/v0.2.0',
            '@id': 'v',
            timestamp: '2026-01-01T00:00:00Z',
            statements,
          }),
        ),
      });
    const read = await openvex([
      {
        vulnerability: { name: 'GHSA-demo-x' },
        products: [{ '@id': 'pkg:generic/zlib@1.3.1' }],
        status: 'fixed',
        timestamp: '2026-01-01T00:00:00Z',
      },
      {
        vulnerability: { name: 'GHSA-demo-x' },
        products: [{ '@id': 'cpe:2.3:a:zlib:zlib:1.3.1:*:*:*:*:*:*:*' }],
        status: 'affected',
        timestamp: '2026-02-01T00:00:00Z',
      },
    ]);
    if (!('document' in read)) throw new Error(read.reason);
    const vex = deliveryVex(model, [
      {
        origin: { kind: 'file', fileName: 'v.json' },
        name: 'v.json',
        state: 'loaded',
        document: read.document,
      },
    ]);
    const zlib = model.packages.find((p) => p.name === 'zlib')!;
    expect(zlib.occurrences).toHaveLength(2);
    expect(vex.byPackage.get(zlib)!.map((f) => f.status)).toEqual(['affected']);
  });
});

describe('VEX in the exports and the report', () => {
  it('adds the status and the vulnerabilities to the package exports', async () => {
    const { bundle, model, vex } = await demo();
    const rows = model.packages.filter((p) => p.name === 'openssl');
    const lines = packagesToCsv(bundle, rows, vex).trimEnd().split('\r\n');
    expect(lines[0]!.endsWith(',sbom_subject,vex_status,vex_vulnerabilities')).toBe(true);
    expect(
      lines
        .find((l) => l.startsWith('openssl,3.0.11'))!
        .endsWith(',affected,GHSA-demo-ecme-0001 (affected)'),
    ).toBe(true);
    // Without VEX the columns stay away.
    expect(packagesToCsv(bundle, rows).split('\r\n')[0]!.endsWith(',sbom_subject')).toBe(true);

    const json = JSON.parse(
      packagesToJson(bundle, model, rows, { generatedAt: 'T', toolVersion: '2.3.0' }, vex),
    );
    expect(json.packages[0].vex).toEqual([
      {
        vulnerability: 'GHSA-demo-ecme-0001',
        status: 'affected',
        actionStatement: 'Update the worker image to openssl 3.0.13 (shop 3.2.1).',
        document: 'vex',
      },
    ]);
    expect(
      json.vexDocuments.map((d: { name: string; format: string }) => [d.name, d.format]),
    ).toEqual([
      ['advisory', 'csaf'],
      ['vex', 'openvex'],
    ]);
  });

  it('reports what the supplier states, without calling anything cleared', async () => {
    const { bundle, analyses, lists, sources } = await demo();
    const report = acceptanceReport({
      bundle,
      toolVersion: 'test',
      generatedAt: 'T',
      sbomAnalyses: analyses,
      sbomPackages: lists,
      vexSources: sources,
    });
    const md = report.markdown;
    expect(md).toContain(
      '- Vulnerability communication: 2 VEX/CSAF document(s) read, 1 not read; per the supplier, 1 vulnerability(ies) affect a delivered package, 1 under investigation; 1 statement(s) name no listed package',
    );
    expect(md).toContain('## Vulnerability communication (VEX)');
    expect(md).toContain(
      '| https://vex.ecme.example/shop/3.2.0 | OpenVEX | ecme.org/shop@3.2.0 vex | 4 | read |',
    );
    expect(md).toContain(
      '| advisory | - | ecme.org/shop/payments@3.2.0 advisory | - | outside the delivery, not fetched |',
    );
    expect(md).toMatch(
      /\| ECME shop api 3\.2\.0: vulnerability status \(demo\) \| CSAF \(BSI TR-03191: \d+ of \d+\) \| ecme\.org\/shop\/api@3\.2\.0 advisory \| 2 \| read \|/,
    );
    expect(md).toContain(
      '- Packages: 1 affected, 1 under investigation, 1 fixed, 2 not affected; 9 with a purl or CPE but no statement; 2 without either',
    );
    expect(md).toContain(
      '- Statements that name no package in the list: 1 (GHSA-demo-ecme-0003). Their products may still ship in an artifact the package list does not cover, or as one of the 2 package(s) without a purl or CPE, which no statement can name.',
    );
    expect(md).toContain(
      '| GHSA-demo-ecme-0001 | affected | openssl 3.0.11 in worker · image (affected); openssl 3.0.13 in api · image (fixed) | Update the worker image to openssl 3.0.13 (shop 3.2.1). |',
    );
    expect(md).toContain(
      '| GHSA-demo-ecme-0004 | under investigation | fastapi 0.115.0 in api · image (under investigation); uvicorn 0.30.6 in api · image (not affected) | - |',
    );
    expect(md).toContain(
      '| GHSA-demo-ecme-0003 | under investigation | none in the package list | - |',
    );
    expect(md).toContain(
      '1 more vulnerability(ies) are stated fixed or not affected (listed in the JSON report).',
    );
    expect(md.indexOf('## Packages')).toBeLessThan(
      md.indexOf('## Vulnerability communication (VEX)'),
    );
    expect(md.indexOf('## Vulnerability communication (VEX)')).toBeLessThan(
      md.indexOf('## Findings'),
    );

    const json = report.json.vex as {
      documents: { state: string }[];
      counts: Record<string, number>;
      unmatched: unknown[];
    };
    expect(json.documents.map((d) => d.state)).toEqual(['read', 'external', 'read']);
    expect(json.counts).toMatchObject({ affected: 1, under_investigation: 1 });
    expect(json.unmatched).toHaveLength(1);

    // Without VEX sources the report has no such section.
    const without = acceptanceReport({
      bundle,
      toolVersion: 'test',
      generatedAt: 'T',
      sbomAnalyses: analyses,
      sbomPackages: lists,
    });
    expect(without.markdown).not.toContain('Vulnerability communication');
    expect(without.json.vex).toBeUndefined();
  });

  it("keeps a supplier's multi-line note inside its table cell", async () => {
    const { bundle, analyses, lists, sources } = await demo();
    const read = await readVexDocument({
      fileName: 'note.json',
      bytes: new TextEncoder().encode(
        JSON.stringify({
          '@context': 'https://openvex.dev/ns/v0.2.0',
          '@id': 'note',
          timestamp: '2026-10-01T00:00:00Z',
          statements: [
            {
              vulnerability: { name: 'GHSA-demo-ecme-0009' },
              products: [{ '@id': 'pkg:deb/debian/openssl@3.0.11' }],
              status: 'affected',
              action_statement: 'Update openssl.\n\n## Verdict\n\n**SELF-CONTAINED** | no action',
            },
          ],
        }),
      ),
    });
    if (!('document' in read)) throw new Error(read.reason);
    const md = acceptanceReport({
      bundle,
      toolVersion: 'test',
      generatedAt: 'T',
      sbomAnalyses: analyses,
      sbomPackages: lists,
      vexSources: [
        ...sources,
        {
          origin: { kind: 'file', fileName: 'note.json' },
          name: 'note.json',
          state: 'loaded',
          document: read.document,
        },
      ],
    }).markdown;
    expect(md).toContain(
      '| GHSA-demo-ecme-0009 | affected | openssl 3.0.11 in worker · image (affected) | Update openssl. ## Verdict **SELF-CONTAINED** \\| no action |',
    );
    // The report's own verdict heading stays the only one.
    expect(md.match(/^## Verdict$/gm)).toHaveLength(1);
  });
});
