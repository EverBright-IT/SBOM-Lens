import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
// @ts-expect-error - plain-JS test/fixture helper without type declarations
import { writeTar } from '../../../scripts/tar-writer.mjs';
import { acceptanceReport } from '../../ocm/report';
import { readOcmBundle } from './bundle';

/**
 * The CTF layout the ocm CLI (0.13.0) writes when it stores images and
 * charts by value (`ocm transfer --copy-resources`, `input: helm`): the tag
 * points at an OCI index around the descriptor manifest and the stored
 * artifacts' manifests, the same manifests appear untagged in the artifact
 * index, the image/chart resources are LocalBlobs whose localReference is
 * their manifest digest, and a descriptor superseded by signing stays in
 * the CTF untagged. Synthetic bytes, real SHA-256 digests.
 */

const MANIFEST = 'application/vnd.oci.image.manifest.v1+json';
const INDEX = 'application/vnd.oci.image.index.v1+json';
const CD_CONFIG = 'application/vnd.ocm.software.component.config.v1+json';
const CD_LAYER = 'application/vnd.ocm.software.component-descriptor.v2+json';

interface Stored {
  digest: string;
  hex: string;
  size: number;
  bytes: string;
}

function blob(bytes: string): Stored {
  const hex = createHash('sha256').update(bytes).digest('hex');
  return { digest: `sha256:${hex}`, hex, size: Buffer.byteLength(bytes), bytes };
}

const ref = (b: Stored, mediaType: string) => ({ mediaType, digest: b.digest, size: b.size });

function manifest(config: Stored, configType: string, layers: [Stored, string][]): Stored {
  return blob(
    JSON.stringify({
      schemaVersion: 2,
      mediaType: MANIFEST,
      config: ref(config, configType),
      layers: layers.map(([b, t]) => ref(b, t)),
    }),
  );
}

function descriptor(name: string, resources: Record<string, unknown>[]): Stored {
  return blob(
    JSON.stringify({
      meta: { schemaVersion: 'v2' },
      component: {
        name,
        version: '1.0.0',
        provider: { name: 'Example' },
        repositoryContexts: [],
        componentReferences: [],
        sources: [],
        resources,
      },
    }),
  );
}

const localBlob = (name: string, type: string, target: Stored, mediaType: string) => ({
  name,
  version: '1.0.0',
  type,
  relation: 'local',
  access: { type: 'LocalBlob/v1', localReference: target.digest, mediaType },
  digest: {
    hashAlgorithm: 'SHA-256',
    normalisationAlgorithm: 'genericBlobDigest/v1',
    value: target.hex,
  },
});

const SBOM = blob(
  JSON.stringify({
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: 'app',
    documentNamespace: 'https://example.com/spdx/app-1.0.0',
    creationInfo: { created: '2026-10-15T00:00:00Z', creators: ['Tool: test'] },
    packages: [
      { SPDXID: 'SPDXRef-pkg', name: 'pkg', versionInfo: '1.0.0', downloadLocation: 'NOASSERTION' },
    ],
  }),
);
const IMAGE_CONFIG = blob('{"architecture":"amd64","os":"linux"}');
const IMAGE_LAYER_1 = blob('layer one: pretend this is a gzipped filesystem');
const IMAGE_LAYER_2 = blob('layer two');
const IMAGE = manifest(IMAGE_CONFIG, 'application/vnd.oci.image.config.v1+json', [
  [IMAGE_LAYER_1, 'application/vnd.oci.image.layer.v1.tar+gzip'],
  [IMAGE_LAYER_2, 'application/vnd.oci.image.layer.v1.tar+gzip'],
]);
const CHART_CONFIG = blob('{"name":"app","version":"1.0.0"}');
const CHART_LAYER = blob('pretend this is a chart tgz');
const CHART = manifest(CHART_CONFIG, 'application/vnd.cncf.helm.config.v1+json', [
  [CHART_LAYER, 'application/vnd.cncf.helm.chart.content.v1.tar+gzip'],
]);

function deliveryCtf(
  options: { layer?: 'missing' | 'truncated'; untaggedOnly?: boolean } = {},
): Uint8Array {
  const cd = descriptor('example.com/app', [
    localBlob('image', 'ociImage', IMAGE, MANIFEST),
    localBlob('helm-chart', 'helmChart', CHART, MANIFEST),
    localBlob('sbom', 'sbom', SBOM, 'application/spdx+json'),
  ]);
  const cdConfig = blob(JSON.stringify({ componentDescriptorLayer: ref(cd, CD_LAYER) }));
  const cdManifest = manifest(cdConfig, CD_CONFIG, [
    [cd, CD_LAYER],
    [SBOM, 'application/spdx+json'],
  ]);
  // What signing leaves behind: the same CV, an older descriptor, untagged.
  const oldCd = descriptor('example.com/app', [
    localBlob('sbom', 'sbom', SBOM, 'application/spdx+json'),
  ]);
  const oldConfig = blob(JSON.stringify({ componentDescriptorLayer: ref(oldCd, CD_LAYER) }));
  const oldManifest = manifest(oldConfig, CD_CONFIG, [[oldCd, CD_LAYER]]);
  const index = blob(
    JSON.stringify({
      schemaVersion: 2,
      mediaType: INDEX,
      manifests: [
        {
          ...ref(cdManifest, MANIFEST),
          artifactType: 'application/vnd.ocm.software.component-descriptor.v2',
        },
        ref(IMAGE, MANIFEST),
        ref(CHART, MANIFEST),
      ],
    }),
  );
  const repository = 'component-descriptors/example.com/app';
  const artifacts = options.untaggedOnly
    ? [{ repository, digest: cdManifest.digest, mediaType: MANIFEST }]
    : [
        { repository, digest: IMAGE.digest, mediaType: MANIFEST },
        { repository, digest: CHART.digest, mediaType: MANIFEST },
        { repository, digest: oldManifest.digest, mediaType: MANIFEST },
        { repository, digest: cdManifest.digest, mediaType: MANIFEST },
        { repository, tag: '1.0.0', digest: index.digest, mediaType: INDEX },
      ];
  const blobs = [
    cd,
    cdConfig,
    cdManifest,
    oldCd,
    oldConfig,
    oldManifest,
    index,
    SBOM,
    IMAGE,
    IMAGE_CONFIG,
    IMAGE_LAYER_1,
    ...(options.layer === 'missing' ? [] : [IMAGE_LAYER_2]),
    CHART,
    CHART_CONFIG,
    CHART_LAYER,
  ];
  return new Uint8Array(
    writeTar([
      { name: 'artifact-index.json', bytes: JSON.stringify({ schemaVersion: 1, artifacts }) },
      ...blobs.map((b) => ({
        name: `blobs/${b.digest.replace(':', '.')}`,
        // A copy cut short: the right name, fewer bytes.
        bytes: options.layer === 'truncated' && b === IMAGE_LAYER_2 ? b.bytes.slice(0, 5) : b.bytes,
      })),
    ]),
  );
}

describe('CTFs with images and charts stored by value (ocm CLI layout)', () => {
  it('reads the tagged index once, ignores the superseded descriptor, and finds the stored artifacts', async () => {
    const { bundle, diagnostics } = await readOcmBundle('app.ctf.tar', deliveryCtf());
    expect(bundle!.componentVersions.map((cv) => cv.id)).toEqual(['example.com/app@1.0.0']);
    expect(bundle!.issues).toEqual([]);
    expect(diagnostics.filter((d) => d.severity !== 'info')).toEqual([]);

    const byName = Object.fromEntries(
      bundle!.componentVersions[0]!.resources.map((r) => [r.name, r]),
    );
    expect(byName.image!.transport).toBe('transported');
    expect(byName['helm-chart']!.transport).toBe('transported');
    expect(byName.sbom!.transport).toBe('transported');
    expect(byName.sbom!.sbom).toBeDefined();

    const image = byName.image!.blob!;
    expect(image.kind).toBe('oci-artifact');
    expect(image.digestCheck).toBe('match');
    expect(image.size).toBe(
      IMAGE.size + IMAGE_CONFIG.size + IMAGE_LAYER_1.size + IMAGE_LAYER_2.size,
    );
    expect(image.oci!.layers.map((l) => l.digest)).toEqual([
      IMAGE_LAYER_1.digest,
      IMAGE_LAYER_2.digest,
    ]);

    expect(bundle!.completeness.airGapReady).toBe(true);
    expect(bundle!.completeness.broken).toBe(0);
    const report = acceptanceReport({ bundle: bundle!, toolVersion: 'test', generatedAt: 'T' });
    expect(report.markdown).toContain('**SELF-CONTAINED.**');
  });

  it.each([
    ['missing', '1 of 3 blob(s) missing from the delivery'],
    ['truncated', '1 of 3 blob(s) not at the declared size'],
  ] as const)('calls a stored image with a %s layer broken and says why', async (layer, why) => {
    const { bundle, diagnostics } = await readOcmBundle('app.ctf.tar', deliveryCtf({ layer }));
    const byName = Object.fromEntries(
      bundle!.componentVersions[0]!.resources.map((r) => [r.name, r]),
    );
    expect(byName.image!.transport).toBe('broken');
    expect(byName['helm-chart']!.transport).toBe('transported');
    expect(bundle!.completeness.airGapReady).toBe(false);
    const incomplete = diagnostics.filter((d) => d.code === 'OCM_ARTIFACT_INCOMPLETE');
    expect(incomplete).toHaveLength(1);
    expect(incomplete[0]!.message).toContain('"image"');
    expect(incomplete[0]!.message).toContain(why);

    // No network brings the blob back: the report says incomplete, not
    // "needs network", and the JSON keeps its shape.
    const report = acceptanceReport({ bundle: bundle!, toolVersion: 'test', generatedAt: 'T' });
    expect(report.markdown).toContain(
      '**INCOMPLETE DELIVERY.** 1 localBlob resource(s) are missing from the archive or incomplete.',
    );
    expect(report.json.verdict).toEqual({
      airGapReady: false,
      reasons: ['1 localBlob resource(s) are missing from the archive or incomplete'],
    });
  });

  it('still reads a descriptor that is only listed untagged', async () => {
    const { bundle } = await readOcmBundle('app.ctf.tar', deliveryCtf({ untaggedOnly: true }));
    expect(bundle!.componentVersions.map((cv) => cv.id)).toEqual(['example.com/app@1.0.0']);
    expect(
      bundle!.componentVersions[0]!.resources.every((r) => r.transport === 'transported'),
    ).toBe(true);
  });
});
