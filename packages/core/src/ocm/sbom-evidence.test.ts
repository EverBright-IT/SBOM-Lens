import { describe, expect, it } from 'vitest';
import type { OcmBundle } from '../model/ocm-bundle';
import { readOcmBundle } from '../parse/ocm/bundle';
import { acceptanceReport } from './report';
import { analyzeDeliverySboms, analyzeSbom } from './sbom-analyze';
import type { SbomEvidence } from './sbom-evidence';
import { ntiaLabel, ntiaSummary, parseImageReference, sameRepository, sbomEvidence } from './sbom-evidence';
import type { TestCv } from './test-sbom-delivery';
import {
  blob,
  cdxImageSbom,
  sbomDeliveryCtf,
  spdxImageSbom,
  spdxProductSbom,
  spdxWithoutDescribes,
  storedImage,
} from './test-sbom-delivery';

const NOW = Date.parse('2026-10-15T00:00:00Z');

async function open(cvs: TestCv[], budget?: number) {
  const { bundle, extracted, diagnostics } = await readOcmBundle('test.ctf.tar', sbomDeliveryCtf(cvs));
  const entries = bundle!.componentVersions.flatMap((cv) =>
    cv.resources.flatMap((r) =>
      r.sbom ? [{ fileName: r.sbom.fileName, bytes: extracted[r.sbom.extractedIndex]!.bytes, sha1: r.sbom.sha1 }] : [],
    ),
  );
  const analyses = await analyzeDeliverySboms(entries, budget === undefined ? { now: NOW } : { budget, now: NOW });
  return { bundle: bundle!, extracted, diagnostics, analyses, evidence: sbomEvidence(bundle!, analyses) };
}

function name(bundle: OcmBundle, ref: { cvId: string; index: number } | undefined): string | undefined {
  if (!ref) return undefined;
  return bundle.componentVersions.find((c) => c.id === ref.cvId)?.resources[ref.index]?.name;
}

function sbom(evidence: SbomEvidence, bundle: OcmBundle, cvId: string, resource: string) {
  return evidence.sboms.find((s) => s.at.cvId === cvId && name(bundle, s.at) === resource)!;
}

function row(evidence: SbomEvidence, bundle: OcmBundle, cvId: string, resource: string) {
  return evidence.coverage.find((r) => r.artifact.cvId === cvId && name(bundle, r.artifact) === resource)!;
}

describe('image references', () => {
  it('splits scheme, registry path, tag and digest', () => {
    expect(parseImageReference('http://localhost:5001/team/app:1.0@sha256:' + 'a'.repeat(64))).toEqual({
      repository: 'localhost:5001/team/app',
      tag: '1.0',
      digest: 'sha256:' + 'a'.repeat(64),
    });
    expect(parseImageReference('team/app')).toEqual({ repository: 'team/app' });
    expect(parseImageReference('docker.io/library/nginx:1.27')).toEqual({ repository: 'nginx', tag: '1.27' });
  });

  it('matches a repository with and without its registry host, by whole segments', () => {
    expect(sameRepository('localhost:5001/team/app', 'team/app')).toBe(true);
    expect(sameRepository('registry.example.org/team/app', 'team/app')).toBe(true);
    expect(sameRepository('registry.example.org/team/app', 'app')).toBe(false);
    expect(sameRepository('registry.example.org/team/app', 'eam/app')).toBe(false);
    // Scanned on one registry, shipped from another: same repository path.
    expect(sameRepository('localhost:5000/shop/web', 'registry.example.org/shop/web')).toBe(true);
    expect(sameRepository('localhost:5000/shop/web', 'registry.example.org/shop/api')).toBe(false);
  });
});

describe('SBOM evidence', () => {
  it('binds by digest when the SBOM states the delivered manifest digest', async () => {
    const image = storedImage('api');
    const { bundle, evidence } = await open([
      {
        name: 'example.org/api',
        version: '1.0.0',
        resources: [
          { kind: 'stored-image', name: 'image', referenceName: 'team/api:1.0.0', image },
          { kind: 'sbom', name: 'sbom', content: spdxImageSbom({ repository: 'registry.example.org/team/api', digest: image.manifest.digest }) },
        ],
      },
    ]);
    const s = sbom(evidence, bundle, 'example.org/api@1.0.0', 'sbom');
    expect(s.binding).toMatchObject({ strength: 'digest', notes: [] });
    expect(name(bundle, s.binding!.target)).toBe('image');
    expect(row(evidence, bundle, 'example.org/api@1.0.0', 'image')).toMatchObject({ status: 'bound', strength: 'digest' });
    expect(evidence.counts).toMatchObject({ expected: 1, covered: 1, byDigest: 1 });
    expect(evidence.findings).toEqual([]);
  });

  it('binds a CycloneDX SBOM by the image config digest (the image ID)', async () => {
    const image = storedImage('worker');
    const { bundle, evidence } = await open([
      {
        name: 'example.org/worker',
        version: '2.0.0',
        resources: [
          { kind: 'stored-image', name: 'image', referenceName: 'team/worker:2.0.0', image },
          {
            kind: 'sbom',
            name: 'sbom',
            mediaType: 'application/json',
            content: cdxImageSbom({ repository: 'team/worker', version: image.config.digest }),
          },
        ],
      },
    ]);
    const s = sbom(evidence, bundle, 'example.org/worker@2.0.0', 'sbom');
    expect(s.binding?.strength).toBe('digest');
    // The declared media type said JSON; the content says CycloneDX.
    const resource = bundle.componentVersions[0]!.resources.find((r) => r.name === 'sbom')!;
    expect(resource.sbom).toMatchObject({ format: 'cyclonedx', contentType: 'application/vnd.cyclonedx+json' });
    expect(resource.sbom!.fileName).toMatch(/\.cdx\.json$/);
  });

  it('binds by reference and says so when the SBOM carries a different digest (scanned before the push)', async () => {
    const { bundle, evidence } = await open([
      {
        name: 'example.org/web',
        version: '1.0.0',
        resources: [
          {
            kind: 'external-image',
            name: 'image',
            imageReference: `http://localhost:5001/team/web:1.0.0@sha256:${'5'.repeat(64)}`,
          },
          {
            kind: 'sbom',
            name: 'sbom',
            content: spdxImageSbom({ repository: 'localhost:5001/team/web', tag: '1.0.0', digest: `sha256:${'a'.repeat(64)}` }),
          },
        ],
      },
    ]);
    const s = sbom(evidence, bundle, 'example.org/web@1.0.0', 'sbom');
    expect(s.binding).toMatchObject({ strength: 'reference', notes: ['digest-differs'] });
    expect(row(evidence, bundle, 'example.org/web@1.0.0', 'image')).toMatchObject({ status: 'bound', strength: 'reference' });
  });

  it('matches across a registry host change: the SBOM names localhost, the air-gap copy names the path', async () => {
    const image = storedImage('ui');
    const { bundle, evidence } = await open([
      {
        name: 'example.org/ui',
        version: '0.3.0',
        resources: [
          { kind: 'stored-image', name: 'image', referenceName: 'team/ui:0.3.0', image },
          { kind: 'sbom', name: 'sbom', content: spdxImageSbom({ repository: 'localhost:5001/team/ui', tag: '0.3.0' }) },
        ],
      },
    ]);
    expect(sbom(evidence, bundle, 'example.org/ui@0.3.0', 'sbom').binding).toMatchObject({ strength: 'reference', notes: [] });
  });

  it('binds a product SBOM to its component version, with name and version normalized', async () => {
    const { bundle, evidence } = await open([
      {
        name: 'example.org/tools/sbom-lens',
        version: '0.29.8',
        resources: [
          { kind: 'blob', name: 'vscode-extension', type: 'vscodeExtension', content: 'pretend vsix' },
          { kind: 'blob', name: 'docs', type: 'plainText', content: 'readme' },
          { kind: 'sbom', name: 'release-sbom', content: spdxProductSbom('sbomlens', 'v0.29.8') },
        ],
      },
    ]);
    const s = sbom(evidence, bundle, 'example.org/tools/sbom-lens@0.29.8', 'release-sbom');
    expect(s.binding).toMatchObject({ strength: 'component', targetCv: 'example.org/tools/sbom-lens@0.29.8' });
    expect(row(evidence, bundle, 'example.org/tools/sbom-lens@0.29.8', 'vscode-extension')).toMatchObject({
      expected: true,
      status: 'bound',
      strength: 'component',
    });
    // Product SBOMs speak for the software, not for documentation.
    expect(row(evidence, bundle, 'example.org/tools/sbom-lens@0.29.8', 'docs')).toMatchObject({
      expected: false,
      status: 'missing',
    });
  });

  it('infers the subject from the top-level packages when the SBOM declares none', async () => {
    const { bundle, evidence } = await open([
      {
        name: 'example.org/webstack',
        version: '2.1.0',
        resources: [
          { kind: 'blob', name: 'bin', type: 'executable', content: 'pretend binary' },
          { kind: 'sbom', name: 'sbom', content: spdxWithoutDescribes([{ name: 'webstack', version: '2.1.0' }]) },
        ],
      },
    ]);
    const s = sbom(evidence, bundle, 'example.org/webstack@2.1.0', 'sbom');
    expect(s.binding).toMatchObject({ strength: 'component', notes: ['inferred-subject'] });
  });

  it('calls an SBOM that describes something else unbound, and its neighbours unverified', async () => {
    const { bundle, evidence } = await open([
      {
        name: 'example.org/obs',
        version: '1.4.0',
        resources: [
          { kind: 'external-image', name: 'image', imageReference: 'registry.example.org/obs/collector:1.4.0' },
          { kind: 'sbom', name: 'sbom', content: spdxProductSbom('grafana', '11.0.0') },
        ],
      },
    ]);
    expect(sbom(evidence, bundle, 'example.org/obs@1.4.0', 'sbom').binding?.strength).toBe('none');
    expect(row(evidence, bundle, 'example.org/obs@1.4.0', 'image')).toMatchObject({ status: 'unverified' });
    expect(evidence.counts).toMatchObject({ expected: 1, covered: 0, unverified: 1, unbound: 1 });
    expect(evidence.findings.map((f) => f.code)).toEqual(['OCM_SBOM_UNBOUND']);
  });

  it('flags ambiguity when one SBOM fits two images equally well', async () => {
    const { bundle, evidence } = await open([
      {
        name: 'example.org/pair',
        version: '1.0.0',
        resources: [
          { kind: 'external-image', name: 'blue', imageReference: 'registry.example.org/team/app:blue' },
          { kind: 'external-image', name: 'green', imageReference: 'registry.example.org/team/app:green' },
          { kind: 'sbom', name: 'sbom', content: spdxImageSbom({ repository: 'team/app' }) },
        ],
      },
    ]);
    expect(sbom(evidence, bundle, 'example.org/pair@1.0.0', 'sbom').binding).toMatchObject({
      strength: 'reference',
      notes: ['ambiguous'],
    });
    expect(evidence.findings.map((f) => f.code)).toContain('OCM_SBOM_AMBIGUOUS');
  });

  it('reports an external SBOM as declared, and an image without any SBOM as missing', async () => {
    const { bundle, evidence } = await open([
      {
        name: 'example.org/cli',
        version: '3.0.0',
        resources: [
          { kind: 'blob', name: 'binary', type: 'executable', content: 'pretend binary' },
          { kind: 'external-sbom', name: 'sbom', url: 'https://example.org/cli-3.0.0.spdx.json' },
        ],
      },
      {
        name: 'example.org/gateway',
        version: '2.0.0',
        resources: [
          { kind: 'external-image', name: 'image', imageReference: 'registry.example.org/gateway:2.0.0' },
          { kind: 'blob', name: 'chart', type: 'helmChart', content: 'pretend chart' },
        ],
      },
    ]);
    expect(sbom(evidence, bundle, 'example.org/cli@3.0.0', 'sbom').presence).toBe('external');
    expect(row(evidence, bundle, 'example.org/cli@3.0.0', 'binary')).toMatchObject({ status: 'declared', reason: 'external' });
    expect(row(evidence, bundle, 'example.org/gateway@2.0.0', 'image')).toMatchObject({ status: 'missing' });
    expect(row(evidence, bundle, 'example.org/gateway@2.0.0', 'chart')).toMatchObject({ expected: false });
    expect(evidence.counts).toMatchObject({ expected: 2, covered: 0, declared: 1, missing: 1 });
    expect(evidence.findings.map((f) => [f.code, f.severity])).toEqual([
      ['OCM_SBOM_MISSING', 'warning'],
      ['OCM_SBOM_EXTERNAL', 'info'],
    ]);
  });

  it('defers SBOMs past the load-time budget and counts them as declared', async () => {
    const { bundle, analyses, evidence } = await open(
      [
        {
          name: 'example.org/api',
          version: '1.0.0',
          resources: [
            { kind: 'external-image', name: 'image', imageReference: 'registry.example.org/team/api:1.0.0' },
            { kind: 'sbom', name: 'sbom', content: spdxImageSbom({ repository: 'team/api', tag: '1.0.0' }) },
          ],
        },
      ],
      0,
    );
    expect(Object.values(analyses).map((a) => a.state)).toEqual(['deferred']);
    expect(row(evidence, bundle, 'example.org/api@1.0.0', 'image')).toMatchObject({ status: 'declared', reason: 'deferred' });
    expect(evidence.counts.deferred).toBe(1);
  });

  it('extracts one SBOM shipped under two component versions once, under a unique name', async () => {
    const shared = spdxProductSbom('shared', '1.0.0');
    const { bundle, extracted } = await open([
      { name: 'example.org/a', version: '1.0.0', resources: [{ kind: 'sbom', name: 'sbom', content: shared }] },
      { name: 'example.org/b', version: '1.0.0', resources: [{ kind: 'sbom', name: 'sbom', content: shared }] },
      {
        name: 'example.org/c',
        version: '1.0.0',
        resources: [{ kind: 'sbom', name: 'sbom', content: spdxProductSbom('other', '1.0.0') }],
      },
    ]);
    expect(extracted).toHaveLength(2);
    const [a, b, c] = bundle.componentVersions.map((cv) => cv.resources[0]!.sbom!);
    expect(a!.sha1).toBe(b!.sha1);
    expect(a!.extractedIndex).toBe(b!.extractedIndex);
    expect(new Set(extracted.map((e) => e.fileName)).size).toBe(2);
    expect(c!.fileName).toBe('test.ctf.tar!c-1.0.0-sbom.spdx.json');
  });
});

describe('findings', () => {
  it('notes a delivery without any SBOM as info, not as a warning', async () => {
    const { evidence } = await open([
      {
        name: 'example.org/gateway',
        version: '2.0.0',
        resources: [{ kind: 'external-image', name: 'image', imageReference: 'registry.example.org/gateway:2.0.0' }],
      },
    ]);
    expect(evidence.findings.map((f) => [f.code, f.severity])).toEqual([['OCM_SBOM_MISSING', 'info']]);
    expect(evidence.findings[0]!.message).toContain('This delivery carries no SBOMs');
  });

  it('counts an extracted SBOM without an analysis as not analysed yet, never unreadable', async () => {
    const { bundle } = await open([
      {
        name: 'example.org/api',
        version: '1.0.0',
        resources: [
          { kind: 'external-image', name: 'image', imageReference: 'registry.example.org/team/api:1.0.0' },
          { kind: 'sbom', name: 'sbom', content: spdxImageSbom({ repository: 'team/api', tag: '1.0.0' }) },
        ],
      },
    ]);
    const evidence = sbomEvidence(bundle, {});
    expect(evidence.sboms[0]!.presence).toBe('deferred');
    expect(row(evidence, bundle, 'example.org/api@1.0.0', 'image')).toMatchObject({ status: 'declared', reason: 'deferred' });
  });
});

describe('NTIA reading', () => {
  it('names the weakest package-level element instead of a bare gated count', async () => {
    const text = spdxImageSbom({
      repository: 'team/api',
      tag: '1.0.0',
      packages: [
        { name: 'openssl', version: '3.0.13', purl: 'pkg:deb/debian/openssl@3.0.13' },
        { name: 'zlib', version: '1.3.1', purl: 'pkg:deb/debian/zlib@1.3.1' },
        { name: 'musl', version: '1.2.5', purl: 'pkg:apk/alpine/musl@1.2.5' },
      ],
    });
    const analysis = await analyzeSbom({ fileName: 'a.spdx.json', bytes: new TextEncoder().encode(text) }, { now: NOW });
    if (analysis.state !== 'analyzed') throw new Error('not analysed');
    const ntia = ntiaSummary(analysis.summary.profiles.ntia);
    // The engine gates the document checks only; the root package has no
    // supplier, so three of four packages carry one.
    expect(analysis.summary.profiles.ntia.gatedFailed).toBe(0);
    expect(ntia).toMatchObject({ documentPassed: 4, documentTotal: 4, complete: false });
    expect(ntia.weakestField).toMatchObject({ label: 'Supplier', satisfied: 3, total: 4, percent: 75 });
    expect(ntiaLabel(ntia)).toBe('document 4 of 4, supplier 75 %');
    expect(ntiaLabel({ documentPassed: 4, documentTotal: 4, complete: true })).toBe('complete');
  });
});

describe('SBOM analysis', () => {
  it('summarizes an SPDX 2.3 SBOM: spec, generator, fields, NTIA, and the BSI format gate', async () => {
    const text = spdxImageSbom({
      repository: 'team/api',
      tag: '1.0.0',
      packages: [
        { name: 'openssl', version: '3.0.13', purl: 'pkg:deb/debian/openssl@3.0.13', license: 'Apache-2.0' },
        { name: 'zlib', version: '1.3.1' },
      ],
    });
    const analysis = await analyzeSbom({ fileName: 'api.spdx.json', bytes: new TextEncoder().encode(text) }, { now: NOW });
    expect(analysis.state).toBe('analyzed');
    if (analysis.state !== 'analyzed') return;
    const { summary } = analysis;
    expect(summary.spec).toBe('SPDX 2.3');
    expect(summary.creators).toContain('Tool: test-1.0');
    expect(summary.packages).toBe(3);
    expect(summary.fields.license).toBe(1);
    expect(summary.subject).toMatchObject({ source: 'describes', references: [{ repository: 'team/api', tag: '1.0.0' }] });
    // The TR accepts SPDX 3.0.1+ or CycloneDX 1.6+ only: the gate fails visibly.
    expect(summary.profiles.bsi.results[0]!.pass).toBe(false);
    expect(summary.profiles.ntia.gatedPassed + summary.profiles.ntia.gatedFailed).toBeGreaterThan(0);
  });

  it('labels CycloneDX by its spec version', async () => {
    const text = cdxImageSbom({ repository: 'team/worker', version: '2.0.0' });
    const analysis = await analyzeSbom({ fileName: 'w.cdx.json', bytes: new TextEncoder().encode(text) }, { now: NOW });
    expect(analysis.state === 'analyzed' && analysis.summary.spec).toBe('CycloneDX 1.6');
  });

  it('reports bytes no parser accepts as unreadable instead of throwing', async () => {
    const analysis = await analyzeSbom({ fileName: 'x.json', bytes: new TextEncoder().encode('{"not":"an sbom"}') });
    expect(analysis.state).toBe('unreadable');
  });

  it('keeps blob() digests real so the walker accepts the fixture', () => {
    expect(blob('x').hex).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('acceptance report with SBOM evidence', () => {
  it('grades the evidence in Markdown and JSON without touching the transport verdict', async () => {
    const image = storedImage('api');
    const { bundle, analyses } = await open([
      {
        name: 'example.org/api',
        version: '1.0.0',
        resources: [
          { kind: 'stored-image', name: 'image', referenceName: 'team/api:1.0.0', image },
          { kind: 'blob', name: 'chart', type: 'helmChart', content: 'pretend chart' },
          {
            kind: 'sbom',
            name: 'sbom',
            content: spdxImageSbom({
              repository: 'registry.example.org/team/api',
              digest: image.manifest.digest,
              packages: [{ name: 'openssl', version: '3.0.13', purl: 'pkg:deb/debian/openssl@3.0.13', license: 'Apache-2.0' }],
            }),
          },
        ],
      },
      {
        name: 'example.org/gateway',
        version: '2.0.0',
        resources: [{ kind: 'stored-image', name: 'image', referenceName: 'team/gateway:2.0.0', image: storedImage('gw') }],
      },
    ]);
    const withEvidence = acceptanceReport({ bundle, toolVersion: 'test', generatedAt: 'T', sbomAnalyses: analyses });
    const without = acceptanceReport({ bundle, toolVersion: 'test', generatedAt: 'T' });
    const verdict = (md: string) => md.split('\n').find((l) => l.startsWith('**'));
    expect(verdict(withEvidence.markdown)).toBe(verdict(without.markdown));

    const md = withEvidence.markdown;
    expect(md).toContain(
      '- SBOM evidence: 1 of 2 artifact(s) that ship software have a bound SBOM (1 by digest); 1 without an SBOM',
    );
    expect(md).toContain('## SBOM evidence');
    expect(md).toContain('| example.org/api@1.0.0 | image | ociImage | sbom | digest |');
    expect(md).toContain('| example.org/gateway@2.0.0 | image | ociImage | - | none |');
    expect(md).not.toContain('| chart |');
    expect(md).toContain(
      `| example.org/api@1.0.0 | sbom | SPDX 2.3 | test-1.0 | 2 | registry.example.org/team/api sha256:${image.manifest.hex.slice(0, 12)} | digest | document 4 of 4, supplier 50 % | format not accepted |`,
    );
    expect(md).toContain('- warning: 1 artifact(s) that ship software carry no SBOM: example.org/gateway@2.0.0: image.');
    expect(without.markdown).toContain('## Embedded SBOMs');

    const json = withEvidence.json.sbomEvidence as {
      counts: Record<string, number>;
      artifacts: { cvId: string; artifact: string; status: string; strength?: string }[];
      sboms: { artifact: string; spec: string; binding: { strength: string; target: { artifact: string } } }[];
    };
    expect(json.counts).toMatchObject({ expected: 2, covered: 1, byDigest: 1, missing: 1 });
    expect(json.artifacts).toContainEqual(
      expect.objectContaining({ cvId: 'example.org/api@1.0.0', artifact: 'image', status: 'bound', strength: 'digest' }),
    );
    expect(json.sboms[0]).toMatchObject({ artifact: 'sbom', spec: 'SPDX 2.3', binding: { strength: 'digest', target: { artifact: 'image' } } });
    expect(without.json.sbomEvidence).toBeUndefined();
  });
});
