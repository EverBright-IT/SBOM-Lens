import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { OcmBundle } from '../model/ocm-bundle';
import { readOcmBundle } from '../parse/ocm/bundle';
import { acceptanceReport } from './report';
import { analyzeDeliverySboms, readSbomPackages } from './sbom-analyze';
import { sbomEvidence } from './sbom-evidence';
import type { DeliveryPackage, PackagePlace, SbomPackageList } from './sbom-packages';
import {
  coveragePlaceKey,
  deliveryConflicts,
  deliveryLicenses,
  deliveryPackages,
  isIdentifier,
  packagesToCsv,
  packagesToJson,
  placeLabel,
  searchAnswer,
  searchPackages,
} from './sbom-packages';
import type { TestCv } from './test-sbom-delivery';
import {
  sbomDeliveryCtf,
  spdxImageSbom,
  spdxProductSbom,
  spdxWithoutDescribes,
  storedImage,
} from './test-sbom-delivery';

const NOW = Date.parse('2026-10-15T00:00:00Z');

async function load(
  bytes: Uint8Array,
  fileName = 'test.ctf.tar',
  opts: { skipLists?: string[] } = {},
) {
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
    if (opts.skipLists?.includes(entry.sha1) || entry.sha1 in lists) continue;
    lists[entry.sha1] = await readSbomPackages(entry);
  }
  return { bundle: bundle!, analyses, evidence, lists, model: deliveryPackages(evidence, lists) };
}

function demo() {
  return load(
    new Uint8Array(
      readFileSync(new URL('../../fixtures/ocm/ecme-sbom-delivery.ctf.tar', import.meta.url)),
    ),
    'ecme-sbom-delivery.ctf.tar',
  );
}

const ids = (rows: readonly DeliveryPackage[]) => rows.map((p) => `${p.name}@${p.version ?? ''}`);
const labels = (bundle: OcmBundle, places: readonly PackagePlace[]) =>
  places.map((p) => placeLabel(bundle, p));

describe('package lists from the worker', () => {
  it('keep every package, the subject marked, without files, raw JSON and references other than CPEs', async () => {
    const sbom = JSON.stringify({
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: 'registry.example.org/team/app',
      documentNamespace: 'https://example.org/spdx/app',
      creationInfo: { created: '2026-10-15T00:00:00Z', creators: ['Tool: syft-1.46.0'] },
      documentDescribes: ['SPDXRef-DocumentRoot-Image'],
      packages: [
        {
          SPDXID: 'SPDXRef-DocumentRoot-Image',
          name: 'registry.example.org/team/app',
          versionInfo: '1.0.0',
          downloadLocation: 'NOASSERTION',
        },
        {
          SPDXID: 'SPDXRef-Package-openssl',
          name: 'openssl',
          versionInfo: '3.0.13',
          downloadLocation: 'NOASSERTION',
          supplier: 'Organization: Debian',
          licenseConcluded: 'NOASSERTION',
          licenseDeclared: 'Apache-2.0',
          copyrightText: 'Copyright (c) the OpenSSL authors, a long text the views never show',
          externalRefs: [
            {
              referenceCategory: 'SECURITY',
              referenceType: 'cpe23Type',
              referenceLocator: 'cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*',
            },
            {
              referenceCategory: 'PACKAGE-MANAGER',
              referenceType: 'purl',
              referenceLocator: 'pkg:deb/debian/openssl@3.0.13?arch=amd64',
            },
          ],
        },
      ],
      files: [
        {
          SPDXID: 'SPDXRef-File-1',
          fileName: '/usr/lib/libssl.so.3',
          checksums: [{ algorithm: 'SHA1', checksumValue: 'a'.repeat(40) }],
        },
        {
          SPDXID: 'SPDXRef-File-2',
          fileName: '/usr/lib/libcrypto.so.3',
          checksums: [{ algorithm: 'SHA1', checksumValue: 'b'.repeat(40) }],
        },
      ],
      relationships: [
        {
          spdxElementId: 'SPDXRef-DocumentRoot-Image',
          relationshipType: 'CONTAINS',
          relatedSpdxElement: 'SPDXRef-Package-openssl',
        },
        {
          spdxElementId: 'SPDXRef-Package-openssl',
          relationshipType: 'CONTAINS',
          relatedSpdxElement: 'SPDXRef-File-1',
        },
      ],
    });
    const list = await readSbomPackages({
      fileName: 'app.spdx.json',
      bytes: new TextEncoder().encode(sbom),
      sha1: 'f'.repeat(40),
    });
    expect(list).not.toBeNull();
    expect(list!.sha1).toBe('f'.repeat(40));
    expect(list!.omitted).toEqual({ files: 2 });
    expect(list!.subjects).toEqual(['SPDXRef-DocumentRoot-Image']);
    expect(list!.document.relationships).toEqual([]);
    expect(list!.document.elements.map((el) => el.name)).toEqual([
      'registry.example.org/team/app',
      'openssl',
    ]);
    const openssl = list!.document.elements.find((el) => el.name === 'openssl')!;
    expect(openssl).toMatchObject({
      name: 'openssl',
      version: '3.0.13',
      purl: 'pkg:deb/debian/openssl@3.0.13?arch=amd64',
      supplier: 'Organization: Debian',
      licenseDeclared: 'Apache-2.0',
      raw: { kind: 'json', value: {} },
    });
    expect(openssl.copyright).toBeUndefined();
    expect(openssl.externalRefs?.map((r) => r.locator)).toEqual([
      'cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*',
    ]);
  });

  it('keep every package of an SBOM that names all of them as described, and mark none', async () => {
    const packages = ['a', 'b', 'c', 'd'].map((name) => ({
      SPDXID: `SPDXRef-${name}`,
      name,
      versionInfo: '1.0.0',
      downloadLocation: 'NOASSERTION',
    }));
    const sbom = JSON.stringify({
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: 'all-described',
      documentNamespace: 'https://example.org/spdx/all-described',
      creationInfo: { created: '2026-10-16T00:00:00Z', creators: ['Tool: test'] },
      documentDescribes: packages.map((p) => p.SPDXID),
      packages,
    });
    const list = await readSbomPackages({
      fileName: 'all.spdx.json',
      bytes: new TextEncoder().encode(sbom),
      sha1: 'e'.repeat(40),
    });
    expect(list!.document.elements.map((el) => el.name)).toEqual(['a', 'b', 'c', 'd']);
    expect(list!.subjects).toEqual([]);
  });

  it('is null for bytes no parser accepts', async () => {
    expect(
      await readSbomPackages({
        fileName: 'x.json',
        bytes: new TextEncoder().encode('{"not":"an sbom"}'),
      }),
    ).toBeNull();
  });
});

describe('the packages of the SBOM demo delivery', () => {
  it('lists every package once with where it ships and how strongly', async () => {
    const { bundle, model } = await demo();
    expect(ids(model.packages.filter((p) => !p.subject))).toEqual([
      'celery@5.4.0',
      'cobra@v1.8.1',
      'fastapi@0.115.0',
      'lodash@4.17.21',
      'nginx@1.27.1',
      'openssl@3.0.11',
      'openssl@3.0.13',
      'react@18.3.1',
      'redis@5.0.8',
      'uvicorn@0.30.6',
      'yaml@v3.0.1',
      'zlib@1.3.1',
    ]);
    // Each SBOM's subject (three images and a product) ships too: listed and
    // marked, so a search finds it, and per SBOM the count matches the fact
    // sheet's.
    expect(model.packages.filter((p) => p.subject).map((p) => p.name)).toEqual([
      'localhost:5000/shop/web',
      'registry.ecme.example/shop/api',
      'shop-cli',
      'shop/worker',
    ]);
    expect(model.subjects).toBe(4);
    const where = Object.fromEntries(
      model.packages.map((p) => [
        `${p.name}@${p.version}`,
        p.places.map(
          (place) =>
            `${placeLabel(bundle, place)} [${place.strength}${place.notes.length ? ` ${place.notes.join(',')}` : ''}]`,
        ),
      ]),
    );
    expect(where['fastapi@0.115.0']).toEqual(['api · image [digest]']);
    expect(where['nginx@1.27.1']).toEqual(['web · image [reference digest-differs]']);
    expect(where['celery@5.4.0']).toEqual(['worker · image [digest]']);
    expect(where['cobra@v1.8.1']).toEqual(['shop-cli (component version) [component]']);
    expect(where['openssl@3.0.13']).toEqual(['api · image [digest]']);
    expect(where['openssl@3.0.11']).toEqual(['worker · image [digest]']);
    expect(model.ecosystems).toEqual([
      { ecosystem: 'deb', packages: 4 },
      { ecosystem: 'pypi', packages: 4 },
      { ecosystem: 'golang', packages: 2 },
      { ecosystem: 'npm', packages: 2 },
      { ecosystem: 'oci', packages: 2 },
      { ecosystem: undefined, packages: 2 },
    ]);
    expect(model.places.map((p) => [placeLabel(bundle, p.place), p.packages])).toEqual([
      ['api · image', 5],
      ['web · image', 4],
      ['worker · image', 4],
      ['shop-cli (component version)', 3],
    ]);
    expect(model.omitted).toEqual({ files: 0 });
  });

  it('names the artifacts the list does not speak for', async () => {
    const { bundle, model } = await demo();
    const name = (cvId: string, index: number) =>
      `${cvId}#${bundle.componentVersions.find((c) => c.id === cvId)!.resources[index]!.name}`;
    expect(model.scope.listed.map((r) => name(r.artifact.cvId, r.artifact.index))).toEqual([
      'ecme.org/shop/api@3.2.0#image',
      'ecme.org/shop/web@3.2.0#image',
      'ecme.org/shop/worker@3.2.0#image',
      'ecme.org/shop/shop-cli@3.2.0#binary',
    ]);
    expect(
      model.scope.notListed.map(
        ({ row, reason }) => `${name(row.artifact.cvId, row.artifact.index)} ${reason}`,
      ),
    ).toEqual([
      'ecme.org/shop/payments@3.2.0#image external',
      'ecme.org/shop/gateway@3.2.0#image no-sbom',
    ]);
    expect(model.scope.unverified).toEqual([]);
    // Bound by repository and tag, but its SBOM states another digest.
    expect(model.scope.digestDiffers.map((r) => name(r.artifact.cvId, r.artifact.index))).toEqual([
      'ecme.org/shop/web@3.2.0#image',
    ]);
    // Each listed artifact filters to its own place.
    const keys = new Set(model.places.map((p) => p.place.key));
    expect(model.scope.listed.every((row) => keys.has(coveragePlaceKey(row)!))).toBe(true);
    expect(coveragePlaceKey(model.scope.notListed[0]!.row)).toBeUndefined();
  });

  it('finds a package by purl or CPE, with or without version, and says where', async () => {
    const { bundle, model } = await demo();
    const any = searchPackages(model, { text: 'pkg:deb/debian/openssl' });
    expect(any.identity).toBe(true);
    expect(ids(any.rows)).toEqual(['openssl@3.0.11', 'openssl@3.0.13']);
    expect(
      any.places.map((g) => `${placeLabel(bundle, g.place)}: ${ids(g.packages).join(', ')}`),
    ).toEqual(['api · image: openssl@3.0.13', 'worker · image: openssl@3.0.11']);

    const exact = searchPackages(model, { text: 'pkg:deb/debian/openssl@3.0.11' });
    expect(ids(exact.rows)).toEqual(['openssl@3.0.11']);
    expect(
      labels(
        bundle,
        exact.places.map((g) => g.place),
      ),
    ).toEqual(['worker · image']);

    const cpe = searchPackages(model, { text: 'cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*' });
    expect(ids(cpe.rows)).toEqual(['openssl@3.0.13']);
    expect(
      ids(searchPackages(model, { text: 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*' }).rows),
    ).toEqual(['openssl@3.0.11', 'openssl@3.0.13']);
    expect(
      labels(
        bundle,
        searchPackages(model, { text: 'cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*' }).places.map(
          (g) => g.place,
        ),
      ),
    ).toEqual(['web · image']);

    // An identifier finds nothing that merely spells alike.
    expect(searchPackages(model, { text: 'pkg:npm/lodash-es' }).rows).toEqual([]);
    const text = searchPackages(model, { text: 'lodash' });
    expect(text.identity).toBe(false);
    expect(ids(text.rows)).toEqual(['lodash@4.17.21']);
  });

  it('filters by ecosystem, place and license', async () => {
    const { model } = await demo();
    expect(ids(searchPackages(model, { ecosystem: 'npm' }).rows)).toEqual([
      'lodash@4.17.21',
      'react@18.3.1',
    ]);
    const worker = model.places.find((p) => p.place.key.includes('worker'))!.place.key;
    expect(ids(searchPackages(model, { place: worker }).rows)).toEqual([
      'celery@5.4.0',
      'openssl@3.0.11',
      'redis@5.0.8',
      `shop/worker@sha256:${model.packages.find((p) => p.name === 'shop/worker')!.version!.slice('sha256:'.length)}`,
    ]);
    expect(ids(searchPackages(model, { licenseId: 'MIT' }).rows)).toEqual([
      'fastapi@0.115.0',
      'lodash@4.17.21',
      'react@18.3.1',
      'redis@5.0.8',
      'yaml@v3.0.1',
    ]);
    // Only the subjects state no license: an image rarely has one of its own.
    const unlicensed = searchPackages(model, { licenseId: '' }).rows;
    expect(unlicensed).toHaveLength(4);
    expect(unlicensed.every((p) => p.subject)).toBe(true);
    expect(
      ids(searchPackages(model, { text: 'pkg:deb/debian/openssl', place: worker }).rows),
    ).toEqual(['openssl@3.0.11']);
    const cliSbom = model.sources.find((s) => s.places.some((p) => p.kind === 'component'))!.sha1;
    const listed = searchPackages(model, { sbom: cliSbom });
    expect(ids(listed.rows)).toEqual(['cobra@v1.8.1', 'shop-cli@v3.2.0', 'yaml@v3.0.1']);
    expect(listed.places).toHaveLength(1);
    expect(searchPackages(model, { sbom: 'no-such-sbom' }).rows).toEqual([]);
  });

  it('counts license identifiers per package, without judging them', async () => {
    const { bundle, model } = await demo();
    const licenses = deliveryLicenses(model);
    expect(licenses.rows.map((r) => [r.id, r.kind, r.packages])).toEqual([
      ['MIT', 'listed', 5],
      ['Apache-2.0', 'listed', 3],
      ['BSD-3-Clause', 'listed', 2],
      ['BSD-2-Clause', 'listed', 1],
      ['Zlib', 'listed', 1],
    ]);
    expect(labels(bundle, licenses.rows[1]!.places)).toEqual([
      'api · image',
      'worker · image',
      'shop-cli (component version)',
    ]);
    expect(licenses).toMatchObject({
      packages: 16,
      withoutLicense: 4,
      subjectsWithoutLicense: 4,
      unparsed: [],
      kinds: { listed: 5, deprecated: 0, ref: 0, unknown: 0 },
    });
  });

  it('flags the openssl versions that differ between the api and worker images', async () => {
    const { bundle, model } = await demo();
    const conflicts = deliveryConflicts(model);
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0]).toMatchObject({
      key: 'purl:pkg:deb/debian/openssl',
      name: 'openssl',
      acrossPlaces: true,
    });
    expect(conflicts[0]!.versions.map((v) => v.version)).toEqual(['3.0.11', '3.0.13']);
    expect(labels(bundle, conflicts[0]!.places)).toEqual(['api · image', 'worker · image']);
  });

  it('exports one CSV line per package and place, and JSON with what was not searched', async () => {
    const { bundle, model } = await demo();
    const rows = searchPackages(model, { text: 'pkg:deb/debian' }).rows;
    const csv = packagesToCsv(bundle, rows);
    const lines = csv.trimEnd().split('\r\n');
    expect(lines[0]).toBe(
      'name,version,ecosystem,purl,license,supplier,component_version,artifact,artifact_type,binding,sbom,sbom_subject',
    );
    expect(lines).toContain(
      'nginx,1.27.1,deb,pkg:deb/debian/nginx@1.27.1,BSD-2-Clause,Organization: ECME Corp,ecme.org/shop/web@3.2.0,image,ociImage,reference (digest differs),sbom (ecme.org/shop/web@3.2.0),',
    );
    expect(lines).toContain(
      'openssl,3.0.13,deb,pkg:deb/debian/openssl@3.0.13,Apache-2.0,Organization: ECME Corp,ecme.org/shop/api@3.2.0,image,ociImage,digest,sbom (ecme.org/shop/api@3.2.0),',
    );
    expect(lines).toHaveLength(1 + 4);

    const json = JSON.parse(
      packagesToJson(bundle, model, rows, {
        generatedAt: '2026-10-16T00:00:00Z',
        toolVersion: '2.2.0',
        filter: { text: 'pkg:deb/debian' },
      }),
    );
    expect(json).toMatchObject({
      schema: 'ocm-lens-packages/v1',
      delivery: 'ecme-sbom-delivery.ctf.tar',
      filter: { text: 'pkg:deb/debian' },
      notListed: [
        {
          componentVersion: 'ecme.org/shop/payments@3.2.0',
          resource: 'image',
          type: 'ociImage',
          reason: 'external',
        },
        {
          componentVersion: 'ecme.org/shop/gateway@3.2.0',
          resource: 'image',
          type: 'ociImage',
          reason: 'no-sbom',
        },
      ],
      digestDiffers: [{ componentVersion: 'ecme.org/shop/web@3.2.0', resource: 'image' }],
      omitted: { files: 0 },
    });
    expect(json.packages.find((p: { name: string }) => p.name === 'zlib')).toEqual({
      name: 'zlib',
      version: '1.3.1',
      ecosystem: 'deb',
      purl: 'pkg:deb/debian/zlib@1.3.1',
      licenses: ['Zlib'],
      supplier: 'Organization: ECME Corp',
      sbomSubject: false,
      foundIn: [
        {
          componentVersion: 'ecme.org/shop/api@3.2.0',
          artifact: 'image',
          type: 'ociImage',
          binding: 'digest',
          notes: [],
          sboms: [{ componentVersion: 'ecme.org/shop/api@3.2.0', resource: 'sbom' }],
        },
      ],
    });
  });
});

describe('the acceptance report with packages', () => {
  it('adds key figures, the version differences and what the list does not cover', async () => {
    const { bundle, analyses, lists } = await demo();
    const base = { bundle, toolVersion: 'test', generatedAt: 'T', sbomAnalyses: analyses };
    const report = acceptanceReport({ ...base, sbomPackages: lists });
    const md = report.markdown;
    expect(md).toContain(
      '- Packages: 16 listed by 4 analysed SBOM(s); 1 package(s) differ in version between artifacts',
    );
    expect(md).toContain('## Packages');
    expect(md).toContain(
      "16 package(s) listed by 4 analysed SBOM(s), each identity and version counted once, 4 of them an SBOM's subject (the image or product it describes).",
    );
    expect(md).toContain(
      '- Ecosystems (purl type): deb 4, pypi 4, golang 2, npm 2, oci 2, without purl 2',
    );
    expect(md).toContain(
      '- License identifiers: 5 distinct (5 on the SPDX License List); 4 package(s) without a license (4 of them SBOM subjects); 0 with a value that is not an SPDX expression',
    );
    expect(md).toContain(
      '- Most named: MIT (5), Apache-2.0 (3), BSD-3-Clause (2), BSD-2-Clause (1), Zlib (1)',
    );
    expect(md).toContain(
      '- Not covered by this list: ecme.org/shop/payments@3.2.0 image (SBOM outside the delivery); ecme.org/shop/gateway@3.2.0 image (no SBOM)',
    );
    expect(md).toContain(
      '- Covered by an SBOM that states a different digest (it may describe a local build, not the delivered bytes): ecme.org/shop/web@3.2.0 image',
    );
    expect(md).toContain(
      '| openssl (pkg:deb/debian/openssl) | 3.0.11 in worker · image; 3.0.13 in api · image |',
    );
    // The packages section follows the SBOM evidence, before the findings.
    expect(md.indexOf('## SBOM evidence')).toBeLessThan(md.indexOf('## Packages'));
    expect(md.indexOf('## Packages')).toBeLessThan(md.indexOf('## Findings'));

    const json = report.json.packages as Record<string, unknown>;
    expect(json).toMatchObject({
      total: 16,
      sboms: 4,
      subjects: 4,
      omitted: { files: 0 },
      licenses: { withoutLicense: 4, subjectsWithoutLicense: 4, notSpdxExpressions: 0 },
      digestDiffers: [{ cvId: 'ecme.org/shop/web@3.2.0', artifact: 'image' }],
      notListed: [
        { cvId: 'ecme.org/shop/payments@3.2.0', artifact: 'image', reason: 'external' },
        { cvId: 'ecme.org/shop/gateway@3.2.0', artifact: 'image', reason: 'no-sbom' },
      ],
    });
    expect(json.conflicts).toEqual([
      {
        name: 'openssl',
        identity: 'purl:pkg:deb/debian/openssl',
        acrossArtifacts: true,
        versions: [
          {
            version: '3.0.11',
            foundIn: [{ cvId: 'ecme.org/shop/worker@3.2.0', artifact: 'image', binding: 'digest' }],
          },
          {
            version: '3.0.13',
            foundIn: [{ cvId: 'ecme.org/shop/api@3.2.0', artifact: 'image', binding: 'digest' }],
          },
        ],
      },
    ]);

    // Without package lists the report stays as it was.
    const without = acceptanceReport(base);
    expect(without.markdown).not.toContain('## Packages');
    expect(without.json.packages).toBeUndefined();
    expect(without.markdown).toBe(
      md
        .replace(/\n- Packages: [^\n]*/, '')
        .replace(/\n\n## Packages[\s\S]*?(?=\n\n## Findings)/, ''),
    );
  });
});

describe('packages in harder deliveries', () => {
  const image = storedImage('app');
  const packages = [
    { name: '=HYPERLINK("http://x")', version: '1', license: 'Apache License 2.0' },
    {
      name: '@types/node',
      version: '22.0.0',
      purl: 'pkg:npm/%40types/node@22.0.0',
      license: 'MIT',
    },
    { name: 'left-pad', version: '1.3.0', purl: 'pkg:npm/left-pad@1.3.0' },
    { name: 'left-pad', version: '1.1.0', purl: 'pkg:npm/left-pad@1.1.0', license: 'WTFPL' },
  ];

  it('keeps a formula out of the CSV, but not an npm scope', async () => {
    const cvs: TestCv[] = [
      {
        name: 'example.org/app',
        version: '1.0.0',
        resources: [
          { kind: 'stored-image', name: 'image', referenceName: 'team/app:1.0.0', image },
          {
            kind: 'sbom',
            name: 'sbom',
            content: spdxImageSbom({
              repository: 'registry.example.org/team/app',
              tag: '1.0.0',
              digest: image.manifest.digest,
              packages,
            }),
          },
        ],
      },
    ];
    const { bundle, model } = await load(sbomDeliveryCtf(cvs));
    const csv = packagesToCsv(bundle, model.packages);
    expect(csv).toContain(`"'=HYPERLINK(""http://x"")",1,`);
    expect(csv).toContain('\r\n@types/node,22.0.0,npm,');
    const licenses = deliveryLicenses(model);
    expect(licenses.unparsed).toEqual([{ value: 'Apache License 2.0', packages: 1 }]);
    // left-pad 1.3.0 states none, and neither does the image (the subject).
    expect(licenses.withoutLicense).toBe(2);
    expect(licenses.subjectsWithoutLicense).toBe(1);
    expect(licenses.rows.map((r) => [r.id, r.kind])).toEqual([
      ['MIT', 'listed'],
      ['WTFPL', 'listed'],
    ]);
    // Two versions inside one image: a conflict, but not one between artifacts.
    expect(deliveryConflicts(model).map((c) => [c.name, c.acrossPlaces])).toEqual([
      ['left-pad', false],
    ]);
  });

  it('keeps a full-width formula out of the CSV, by the same rule as SBOM Lens', async () => {
    const cvs: TestCv[] = [
      {
        name: 'example.org/app',
        version: '1.0.0',
        resources: [
          { kind: 'stored-image', name: 'image', referenceName: 'team/app:1.0.0', image },
          {
            kind: 'sbom',
            name: 'sbom',
            content: spdxImageSbom({
              repository: 'registry.example.org/team/app',
              tag: '1.0.0',
              digest: image.manifest.digest,
              packages: [{ name: '＝HYPERLINK("http://x")', version: '1' }],
            }),
          },
        ],
      },
    ];
    const { bundle, model } = await load(sbomDeliveryCtf(cvs));
    const csv = packagesToCsv(bundle, model.packages);
    expect(csv).toContain(`\r\n"'＝HYPERLINK(""http://x"")",1,`);
  });

  it('lists the packages of an SBOM that identifies nothing under that SBOM, and calls its artifact unverified', async () => {
    const cvs: TestCv[] = [
      {
        name: 'example.org/obs',
        version: '1.0.0',
        resources: [
          {
            kind: 'external-image',
            name: 'image',
            imageReference: 'registry.example.org/obs/collector:1.0.0',
          },
          {
            kind: 'sbom',
            name: 'sbom',
            content: spdxProductSbom('something-else', '9.9.9', [
              { name: 'otel', version: '1.0.0', purl: 'pkg:golang/go.opentelemetry.io/otel@1.0.0' },
            ]),
          },
        ],
      },
    ];
    const { bundle, model } = await load(sbomDeliveryCtf(cvs));
    expect(labels(bundle, model.packages[0]!.places)).toEqual(['obs · sbom (bound to nothing)']);
    expect(model.packages[0]!.places[0]).toMatchObject({ kind: 'unbound', strength: 'none' });
    expect(model.scope.unverified.map((r) => r.artifact)).toEqual([
      { cvId: 'example.org/obs@1.0.0', index: 0 },
    ]);
    expect(model.scope.notListed).toEqual([]);
  });

  it('places an SBOM shipped under two component versions in both, and keeps the stronger binding', async () => {
    const sbom = spdxProductSbom('tool', '2.0.0', [
      { name: 'zstd', version: '1.5.6', purl: 'pkg:generic/zstd@1.5.6', license: 'BSD-3-Clause' },
    ]);
    const cvs: TestCv[] = [
      {
        name: 'example.org/tool',
        version: '2.0.0',
        resources: [
          { kind: 'blob', name: 'binary', type: 'executable', content: 'tool' },
          { kind: 'sbom', name: 'sbom', content: sbom },
        ],
      },
      {
        name: 'example.org/bundle',
        version: '1.0.0',
        resources: [{ kind: 'sbom', name: 'tool-sbom', content: sbom }],
      },
    ];
    const { bundle, model } = await load(sbomDeliveryCtf(cvs));
    expect(model.sources).toHaveLength(1);
    const pkg = model.packages.find((p) => p.name === 'zstd');
    expect(labels(bundle, pkg!.places)).toEqual(['tool (component version)']);
    expect(pkg!.places[0]!.sboms).toEqual([
      { cvId: 'example.org/tool@2.0.0', index: 1 },
      { cvId: 'example.org/bundle@1.0.0', index: 0 },
    ]);
  });

  it('says when a bound SBOM has no package list yet, or could not give one', async () => {
    const product = spdxProductSbom('cli', '1.0.0', [{ name: 'cobra', version: '1.8.1' }]);
    const cvs: TestCv[] = [
      {
        name: 'example.org/cli',
        version: '1.0.0',
        resources: [
          { kind: 'blob', name: 'binary', type: 'executable', content: 'cli' },
          { kind: 'sbom', name: 'sbom', content: product },
        ],
      },
    ];
    const sha1 = (await readOcmBundle('t.ctf.tar', sbomDeliveryCtf(cvs))).bundle!
      .componentVersions[0]!.resources[1]!.sbom!.sha1;
    const pending = await load(sbomDeliveryCtf(cvs), 'test.ctf.tar', { skipLists: [sha1] });
    expect(pending.model.packages).toEqual([]);
    expect(pending.model.scope.notListed.map((n) => n.reason)).toEqual(['not-loaded']);
    const failed = deliveryPackages(pending.evidence, { [sha1]: null });
    expect(failed.scope.notListed.map((n) => n.reason)).toEqual(['unreadable']);
  });

  it('reports every place of a package one SBOM gives a CPE and another does not', async () => {
    const api = storedImage('api');
    const worker = storedImage('worker');
    const withCpe = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      version: 1,
      metadata: {
        component: {
          'bom-ref': 'root',
          type: 'container',
          name: 'team/api',
          version: api.config.digest,
        },
      },
      components: [
        {
          'bom-ref': 'p',
          type: 'library',
          name: 'openssl',
          version: '3.0.13',
          purl: 'pkg:deb/debian/openssl@3.0.13',
          cpe: 'cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*',
        },
      ],
    });
    const cvs: TestCv[] = [
      {
        name: 'example.org/api',
        version: '1.0.0',
        resources: [
          { kind: 'stored-image', name: 'image', referenceName: 'team/api:1.0.0', image: api },
          {
            kind: 'sbom',
            name: 'sbom',
            content: withCpe,
            mediaType: 'application/vnd.cyclonedx+json',
          },
        ],
      },
      {
        name: 'example.org/worker',
        version: '1.0.0',
        resources: [
          {
            kind: 'stored-image',
            name: 'image',
            referenceName: 'team/worker:1.0.0',
            image: worker,
          },
          {
            kind: 'sbom',
            name: 'sbom',
            content: spdxImageSbom({
              repository: 'registry.example.org/team/worker',
              tag: '1.0.0',
              digest: worker.manifest.digest,
              packages: [
                { name: 'openssl', version: '3.0.13', purl: 'pkg:deb/debian/openssl@3.0.13' },
              ],
            }),
          },
        ],
      },
    ];
    const { bundle, model } = await load(sbomDeliveryCtf(cvs));
    const found = searchPackages(model, { text: 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*' });
    expect(ids(found.rows)).toEqual(['openssl@3.0.13']);
    expect(
      labels(
        bundle,
        found.places.map((g) => g.place),
      ),
    ).toEqual(['api · image', 'worker · image']);
  });

  it('exports a package even when no place is known for it', async () => {
    const { bundle, lists } = await demo();
    const placeless = deliveryPackages(
      { sboms: [], coverage: [], counts: {} as never, findings: [] },
      lists,
    );
    const csv = packagesToCsv(bundle, placeless.packages).trimEnd().split('\r\n');
    expect(csv).toHaveLength(1 + 16);
    expect(csv).toContain(
      'zlib,1.3.1,deb,pkg:deb/debian/zlib@1.3.1,Zlib,Organization: ECME Corp,,,,,,',
    );
  });

  it('lets inferred subjects stay packages', async () => {
    const cvs: TestCv[] = [
      {
        name: 'example.org/lib',
        version: '1.0.0',
        resources: [
          { kind: 'blob', name: 'jar', type: 'mavenArtifact', content: 'jar' },
          {
            kind: 'sbom',
            name: 'sbom',
            content: spdxWithoutDescribes([
              { name: 'guava', version: '33.0.0', purl: 'pkg:maven/com.google.guava/guava@33.0.0' },
            ]),
          },
        ],
      },
    ];
    const { model } = await load(sbomDeliveryCtf(cvs));
    expect(ids(model.packages)).toEqual(['guava@33.0.0']);
    expect(model.subjects).toBe(0);
  });
});

describe('the answer to "is it in this delivery?"', () => {
  it('names what was not searched, what an SBOM with another digest covers, and what an identifier cannot find', async () => {
    const { bundle, model } = await demo();
    const answer = searchAnswer(model, { text: 'pkg:pypi/celery' });
    expect(answer).toMatchObject({
      identifier: 'purl',
      found: 1,
      withoutIdentifier: 2,
      narrowed: false,
      everyArtifactSearched: false,
    });
    expect(
      labels(
        bundle,
        answer.places.map((g) => g.place),
      ),
    ).toEqual(['worker · image']);
    expect(answer.notSearched.map((n) => n.reason)).toEqual(['external', 'no-sbom']);
    expect(answer.digestDiffers.map((r) => r.artifact)).toEqual([
      { cvId: 'ecme.org/shop/web@3.2.0', index: 0 },
    ]);
    // A CPE query counts the packages that state no CPE.
    expect(searchAnswer(model, { text: 'cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*' })).toMatchObject({
      identifier: 'cpe',
      found: 1,
      withoutIdentifier: 13,
    });
    // A name has no identifier to miss; any filter narrows the answer.
    const narrowed = searchAnswer(model, { text: 'celery', ecosystem: 'pypi' });
    expect(narrowed).toMatchObject({ found: 1, withoutIdentifier: 0, narrowed: true });
    expect(narrowed.identifier).toBeUndefined();
  });

  it('finds an image by its own purl: the subject ships too', async () => {
    const { bundle, model } = await demo();
    const answer = searchAnswer(model, { text: 'pkg:oci/api' });
    expect(answer.found).toBe(1);
    expect(
      labels(
        bundle,
        answer.places.map((g) => g.place),
      ),
    ).toEqual(['api · image']);
  });

  it('finds the packages of an SBOM that names every package as described', async () => {
    const names = ['tool', 'zstd', 'lz4', 'xz', 'bzip2'];
    const packages = names.map((name, i) => ({
      SPDXID: `SPDXRef-${name}`,
      name,
      versionInfo: i === 0 ? '2.0.0' : '1.0.0',
      downloadLocation: 'NOASSERTION',
      externalRefs: [
        {
          referenceCategory: 'PACKAGE-MANAGER',
          referenceType: 'purl',
          referenceLocator: `pkg:generic/${name}@${i === 0 ? '2.0.0' : '1.0.0'}`,
        },
      ],
    }));
    const sbom = JSON.stringify({
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: 'tool',
      documentNamespace: 'https://example.org/spdx/tool-all-described',
      creationInfo: { created: '2026-10-16T00:00:00Z', creators: ['Tool: test'] },
      documentDescribes: packages.map((p) => p.SPDXID),
      packages,
    });
    const cvs: TestCv[] = [
      {
        name: 'example.org/tool',
        version: '2.0.0',
        resources: [
          { kind: 'blob', name: 'binary', type: 'executable', content: 'tool' },
          { kind: 'sbom', name: 'sbom', content: sbom },
        ],
      },
    ];
    const { bundle, model } = await load(sbomDeliveryCtf(cvs));
    expect(model.packages).toHaveLength(5);
    expect(model.subjects).toBe(0);
    const answer = searchAnswer(model, { text: 'pkg:generic/zstd' });
    expect(answer.found).toBe(1);
    expect(
      labels(
        bundle,
        answer.places.map((g) => g.place),
      ),
    ).toEqual(['tool (component version)']);
    expect(answer.everyArtifactSearched).toBe(true);
  });

  it('says every artifact was searched only when nothing qualifies the answer', async () => {
    const image = storedImage('solo');
    const cvs: TestCv[] = [
      {
        name: 'example.org/solo',
        version: '1.0.0',
        resources: [
          { kind: 'stored-image', name: 'image', referenceName: 'team/solo:1.0.0', image },
          {
            kind: 'sbom',
            name: 'sbom',
            content: spdxImageSbom({
              repository: 'registry.example.org/team/solo',
              tag: '1.0.0',
              digest: image.manifest.digest,
              packages: [{ name: 'musl', version: '1.2.5', purl: 'pkg:apk/alpine/musl@1.2.5' }],
            }),
          },
        ],
      },
    ];
    const { model } = await load(sbomDeliveryCtf(cvs));
    const miss = searchAnswer(model, { text: 'pkg:apk/alpine/openssl' });
    expect(miss).toMatchObject({ found: 0, everyArtifactSearched: true, notSearched: [] });
    expect(searchAnswer(model, { text: 'pkg:apk/alpine/openssl', ecosystem: 'apk' })).toMatchObject(
      {
        narrowed: true,
        everyArtifactSearched: false,
      },
    );
  });
});

describe('isIdentifier', () => {
  it('knows purls and CPEs from names', () => {
    expect(isIdentifier('pkg:npm/lodash')).toBe(true);
    expect(isIdentifier('cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*')).toBe(true);
    expect(isIdentifier('cpe:/a:openssl:openssl')).toBe(true);
    expect(isIdentifier('openssl')).toBe(false);
    expect(isIdentifier('pkg:')).toBe(false);
  });
});
