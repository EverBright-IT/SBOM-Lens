import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
// @ts-expect-error - plain-JS test/fixture helper without type declarations
import { writeTar } from '../../../scripts/tar-writer.mjs';
import { acceptanceReport } from '../../ocm/report';
import { bufferSource } from '../../util/bytesource';
import { readOcmBundle } from './bundle';
import { digestDeliveryBlob } from './extract';

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

type Normalisation = 'genericBlobDigest/v1' | 'ociArtifactDigest/v1';

const localBlob = (
  name: string,
  type: string,
  target: Stored,
  mediaType: string,
  normalisation: Normalisation = 'genericBlobDigest/v1',
) => ({
  name,
  version: '1.0.0',
  type,
  relation: 'local',
  access: { type: 'LocalBlob/v1', localReference: target.digest, mediaType },
  digest: {
    hashAlgorithm: 'SHA-256',
    normalisationAlgorithm: normalisation,
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
/** The second platform of the image when it is stored as an index. */
const ARM_CONFIG = blob('{"architecture":"arm64","os":"linux"}');
const ARM_LAYER = blob('arm layer: another gzipped filesystem');
const ARM_IMAGE = manifest(ARM_CONFIG, 'application/vnd.oci.image.config.v1+json', [
  [ARM_LAYER, 'application/vnd.oci.image.layer.v1.tar+gzip'],
]);
/** JSON an index may name that is no manifest the check can read. */
const NOT_A_MANIFEST = blob('{"note":"not a manifest"}');
/** The OCI empty descriptor's content: its digest is OCI_EMPTY_DIGEST. */
const EMPTY = blob('{}');
const EMPTY_CONFIG_LAYER = blob('an artifact with the empty config');
const EMPTY_CONFIG_ARTIFACT = manifest(EMPTY, 'application/vnd.oci.empty.v1+json', [
  [EMPTY_CONFIG_LAYER, 'application/octet-stream'],
]);
/** A JSON resource shaped a little like a manifest, which it is not. */
const SETTINGS = blob(JSON.stringify({ config: { mode: 'strict' }, layers: ['base', 'app'] }));

function imageIndex(second: Stored): Stored {
  return blob(
    JSON.stringify({
      schemaVersion: 2,
      mediaType: INDEX,
      manifests: [
        { ...ref(IMAGE, MANIFEST), platform: { architecture: 'amd64', os: 'linux' } },
        { ...ref(second, MANIFEST), platform: { architecture: 'arm64', os: 'linux' } },
      ],
    }),
  );
}

function deliveryCtf(
  options: {
    layer?: 'missing' | 'truncated' | 'altered';
    untaggedOnly?: boolean;
    /** ocm 0.13 declares genericBlobDigest/v1 on stored images and charts, 0.21 ociArtifactDigest/v1. */
    stored?: Normalisation;
    /** The media type the image's access declares (not signed); null leaves it out. */
    accessMediaType?: string | null;
    /** Store the image as an index over two platforms. */
    index?: boolean;
    /** The index's second platform: left out of the archive, or JSON that is no manifest. */
    indexChild?: 'missing' | 'opaque';
    /** Add a JSON resource shaped like a manifest and an artifact with the empty config. */
    extras?: boolean;
  } = {},
): Uint8Array {
  const second = options.indexChild === 'opaque' ? NOT_A_MANIFEST : ARM_IMAGE;
  const image = options.index ? imageIndex(second) : IMAGE;
  const imageType = options.index ? INDEX : MANIFEST;
  const imageResource = localBlob('image', 'ociImage', image, imageType, options.stored);
  if (options.accessMediaType === null) delete (imageResource.access as { mediaType?: string }).mediaType;
  else if (options.accessMediaType !== undefined) imageResource.access.mediaType = options.accessMediaType;
  const cd = descriptor('example.com/app', [
    imageResource,
    localBlob('helm-chart', 'helmChart', CHART, MANIFEST, options.stored),
    localBlob('sbom', 'sbom', SBOM, 'application/spdx+json'),
    ...(options.extras
      ? [
          localBlob('settings', 'json', SETTINGS, 'application/json'),
          localBlob('artifact', 'ociArtifact', EMPTY_CONFIG_ARTIFACT, MANIFEST, options.stored),
        ]
      : []),
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
        ref(image, imageType),
        ref(CHART, MANIFEST),
      ],
    }),
  );
  const repository = 'component-descriptors/example.com/app';
  const artifacts = options.untaggedOnly
    ? [{ repository, digest: cdManifest.digest, mediaType: MANIFEST }]
    : [
        { repository, digest: image.digest, mediaType: imageType },
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
    ...(options.index
      ? [image, ...(options.indexChild === 'missing' ? [] : [second]), ARM_CONFIG, ARM_LAYER]
      : []),
    CHART,
    CHART_CONFIG,
    CHART_LAYER,
    // The empty config stays out, as layouts may leave it.
    ...(options.extras ? [SETTINGS, EMPTY_CONFIG_ARTIFACT, EMPTY_CONFIG_LAYER] : []),
  ];
  return new Uint8Array(
    writeTar([
      { name: 'artifact-index.json', bytes: JSON.stringify({ schemaVersion: 1, artifacts }) },
      ...blobs.map((b) => ({
        name: `blobs/${b.digest.replace(':', '.')}`,
        // A copy cut short: the right name, fewer bytes. Or swapped: the right
        // name and size, other bytes.
        bytes:
          options.layer === 'truncated' && b === IMAGE_LAYER_2
            ? b.bytes.slice(0, 5)
            : options.layer === 'altered' && b === IMAGE_LAYER_2
              ? b.bytes.toUpperCase()
              : b.bytes,
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

describe('stored images: the manifest and every blob it names', () => {
  const imageOf = (bundle: Awaited<ReturnType<typeof readOcmBundle>>['bundle']) =>
    bundle!.componentVersions[0]!.resources.find((r) => r.name === 'image')!;

  it.each(['genericBlobDigest/v1', 'ociArtifactDigest/v1'] as const)(
    'calls a stored image with a swapped layer a mismatch, though its manifest matches (%s)',
    async (stored) => {
      expect(IMAGE_LAYER_2.bytes.toUpperCase()).not.toBe(IMAGE_LAYER_2.bytes);
      const intact = await readOcmBundle('app.ctf.tar', deliveryCtf({ stored }));
      expect(imageOf(intact.bundle).blob!.digestCheck).toBe('match');
      const { bundle } = await readOcmBundle(
        'app.ctf.tar',
        deliveryCtf({ stored, layer: 'altered' }),
      );
      expect(imageOf(bundle).blob!.digestCheck).toBe('mismatch');
      const report = acceptanceReport({ bundle: bundle!, toolVersion: 'test', generatedAt: 'T' });
      expect(report.markdown).not.toContain('declared digest(s) match the delivered bytes');
    },
  );

  it('puts a digest mismatch into the verdict, ahead of the transport answer', async () => {
    const verdictOf = (markdown: string) => markdown.split('## Verdict')[1]!.split('\n## ')[0]!;
    const { bundle } = await readOcmBundle('app.ctf.tar', deliveryCtf({ layer: 'altered' }));
    const report = acceptanceReport({ bundle: bundle!, toolVersion: 'test', generatedAt: 'T' });
    const verdict = verdictOf(report.markdown);
    expect(verdict).toContain('**1 DIGEST MISMATCH.**');
    expect(verdict.indexOf('DIGEST MISMATCH')).toBeLessThan(verdict.indexOf('**SELF-CONTAINED.**'));
    // The JSON keeps its shape: the transport verdict, the mismatches under digests.
    expect(report.json.verdict).toEqual({ airGapReady: true, reasons: [] });
    expect((report.json.digests as { mismatch: unknown[] }).mismatch).toEqual([
      { cvId: 'example.com/app@1.0.0', artifact: 'image' },
    ]);
    // An intact delivery has no such line.
    const intact = await readOcmBundle('app.ctf.tar', deliveryCtf());
    expect(verdictOf(acceptanceReport({ bundle: intact.bundle!, toolVersion: 'test', generatedAt: 'T' }).markdown)).not.toContain(
      'MISMATCH',
    );
  });

  it.each(['genericBlobDigest/v1', 'ociArtifactDigest/v1'] as const)(
    'defers the layers past the hash budget and judges them all on demand (%s)',
    async (stored) => {
      for (const [layer, expected] of [
        [undefined, 'match'],
        ['altered', 'mismatch'],
      ] as const) {
        const bytes = deliveryCtf(layer ? { layer, stored } : { stored });
        const { bundle } = await readOcmBundle('app.ctf.tar', bytes, { eagerHashBudget: 0 });
        const image = imageOf(bundle);
        expect(image.blob!.digestCheck).toBe('pending');
        const verdict = await digestDeliveryBlob(
          bufferSource(bytes),
          IMAGE.digest,
          image.raw.digest as Record<string, unknown>,
        );
        expect(verdict).toBe(expected);
      }
    },
  );
});

describe('stored images are recognised by their bytes, not by the media type the access declares', () => {
  const resource = (bundle: Awaited<ReturnType<typeof readOcmBundle>>['bundle'], name: string) =>
    bundle!.componentVersions[0]!.resources.find((r) => r.name === name)!;
  const variants = [
    ['application/octet-stream', 'genericBlobDigest/v1'],
    ['application/octet-stream', 'ociArtifactDigest/v1'],
    ['application/json', 'genericBlobDigest/v1'],
    ['application/json', 'ociArtifactDigest/v1'],
    [null, 'genericBlobDigest/v1'],
  ] as const;

  it.each(variants)('checks every layer of an image whose access says %s (%s)', async (accessMediaType, stored) => {
    const intact = await readOcmBundle('app.ctf.tar', deliveryCtf({ accessMediaType, stored }));
    expect(resource(intact.bundle, 'image').blob).toMatchObject({ kind: 'oci-artifact', digestCheck: 'match' });

    const altered = await readOcmBundle('app.ctf.tar', deliveryCtf({ accessMediaType, stored, layer: 'altered' }));
    expect(resource(altered.bundle, 'image').blob!.digestCheck).toBe('mismatch');
    const report = acceptanceReport({ bundle: altered.bundle!, toolVersion: 'test', generatedAt: 'T' });
    expect(report.markdown).not.toContain('declared digest(s) match the delivered bytes');

    const missing = await readOcmBundle('app.ctf.tar', deliveryCtf({ accessMediaType, stored, layer: 'missing' }));
    expect(resource(missing.bundle, 'image').transport).toBe('broken');
    expect(missing.bundle!.completeness.airGapReady).toBe(false);
    expect(missing.diagnostics.some((d) => d.code === 'OCM_ARTIFACT_INCOMPLETE')).toBe(true);

    // Deferred, the on-demand check goes by the bytes too.
    const bytes = deliveryCtf({ accessMediaType, stored, layer: 'altered' });
    const deferred = await readOcmBundle('app.ctf.tar', bytes, { eagerHashBudget: 0 });
    const image = resource(deferred.bundle, 'image');
    expect(image.blob!.digestCheck).toBe('pending');
    expect(await digestDeliveryBlob(bufferSource(bytes), IMAGE.digest, image.raw.digest as Record<string, unknown>)).toBe(
      'mismatch',
    );
  });
});

describe('a delivery past the materialization budget keeps its structure', () => {
  // Nothing is loaded by the tar reader: index, descriptor manifests,
  // descriptors and stored manifests are all read on demand.
  const NOTHING = { materializeTotalMax: 0 };
  const resource = (bundle: Awaited<ReturnType<typeof readOcmBundle>>['bundle'], name: string) =>
    bundle!.componentVersions[0]!.resources.find((r) => r.name === name)!;

  it('reads every component version and judges a stored image with everything below it', async () => {
    const loaded = await readOcmBundle('app.ctf.tar', deliveryCtf());
    const { bundle, diagnostics } = await readOcmBundle('app.ctf.tar', deliveryCtf(), NOTHING);
    expect(bundle!.componentVersions.map((cv) => cv.id)).toEqual(['example.com/app@1.0.0']);
    expect(diagnostics.filter((d) => d.severity !== 'info')).toEqual([]);
    for (const name of ['image', 'helm-chart', 'sbom']) {
      expect(resource(bundle, name).transport, name).toBe(resource(loaded.bundle, name).transport);
      expect(resource(bundle, name).blob!.digestCheck, name).toBe(resource(loaded.bundle, name).blob!.digestCheck);
    }
    expect(resource(bundle, 'image').blob).toMatchObject({ kind: 'oci-artifact', digestCheck: 'match' });
    expect(resource(bundle, 'sbom').sbom).toBeDefined();
    expect(bundle!.completeness.airGapReady).toBe(true);
  });

  it('calls a swapped layer a mismatch and a missing one incomplete', async () => {
    const altered = await readOcmBundle('app.ctf.tar', deliveryCtf({ layer: 'altered' }), NOTHING);
    expect(resource(altered.bundle, 'image').blob!.digestCheck).toBe('mismatch');
    const missing = await readOcmBundle('app.ctf.tar', deliveryCtf({ layer: 'missing' }), NOTHING);
    expect(resource(missing.bundle, 'image').transport).toBe('broken');
    expect(missing.bundle!.completeness.airGapReady).toBe(false);
  });
});

describe('an image stored as an index (several platforms, attestations)', () => {
  const resource = (bundle: Awaited<ReturnType<typeof readOcmBundle>>['bundle'], name: string) =>
    bundle!.componentVersions[0]!.resources.find((r) => r.name === name)!;

  it.each(['genericBlobDigest/v1', 'ociArtifactDigest/v1'] as const)(
    'is complete and matching only with every manifest and every blob they name (%s)',
    async (stored) => {
      const { bundle, diagnostics } = await readOcmBundle('app.ctf.tar', deliveryCtf({ index: true, stored }));
      expect(diagnostics.filter((d) => d.severity !== 'info')).toEqual([]);
      const image = resource(bundle, 'image');
      expect(image.transport).toBe('transported');
      expect(image.blob).toMatchObject({ kind: 'oci-artifact', digestCheck: 'match' });
      expect(image.blob!.oci!.layers.map((l) => l.digest)).toEqual([
        IMAGE_LAYER_1.digest,
        IMAGE_LAYER_2.digest,
        ARM_LAYER.digest,
      ]);
      const index = imageIndex(ARM_IMAGE);
      expect(image.blob!.size).toBe(
        index.size + IMAGE.size + IMAGE_CONFIG.size + IMAGE_LAYER_1.size + IMAGE_LAYER_2.size + ARM_IMAGE.size + ARM_CONFIG.size + ARM_LAYER.size,
      );
      expect(bundle!.completeness.airGapReady).toBe(true);

      const altered = await readOcmBundle('app.ctf.tar', deliveryCtf({ index: true, stored, layer: 'altered' }));
      expect(resource(altered.bundle, 'image').blob!.digestCheck).toBe('mismatch');

      const missing = await readOcmBundle('app.ctf.tar', deliveryCtf({ index: true, stored, indexChild: 'missing' }));
      expect(resource(missing.bundle, 'image').transport).toBe('broken');
      expect(missing.bundle!.completeness.airGapReady).toBe(false);
      const incomplete = missing.diagnostics.filter((d) => d.code === 'OCM_ARTIFACT_INCOMPLETE');
      expect(incomplete.map((d) => d.message)).toEqual([expect.stringContaining('"image"')]);
    },
  );

  it.each(['genericBlobDigest/v1', 'ociArtifactDigest/v1'] as const)(
    'is judged the same way past the hash budget and past the materialization budget (%s)',
    async (stored) => {
      for (const [layer, expected] of [
        [undefined, 'match'],
        ['altered', 'mismatch'],
      ] as const) {
        const bytes = deliveryCtf(layer ? { index: true, stored, layer } : { index: true, stored });
        const deferred = await readOcmBundle('app.ctf.tar', bytes, { eagerHashBudget: 0 });
        const image = resource(deferred.bundle, 'image');
        expect(image.blob!.digestCheck).toBe('pending');
        const localReference = (image.raw.access as Record<string, unknown>).localReference as string;
        expect(await digestDeliveryBlob(bufferSource(bytes), localReference, image.raw.digest as Record<string, unknown>)).toBe(
          expected,
        );
        const unloaded = await readOcmBundle('app.ctf.tar', bytes, { materializeTotalMax: 0 });
        expect(resource(unloaded.bundle, 'image').blob!.digestCheck).toBe(expected);
      }
    },
  );

  it('leaves the verdict unchecked when a manifest it names cannot be read as one', async () => {
    const bytes = deliveryCtf({ index: true, indexChild: 'opaque' });
    const { bundle } = await readOcmBundle('app.ctf.tar', bytes);
    const image = resource(bundle, 'image');
    expect(image.transport).toBe('transported');
    expect(image.blob!.digestCheck).toBe('unchecked');
    const deferred = await readOcmBundle('app.ctf.tar', bytes, { eagerHashBudget: 0 });
    const localReference = (image.raw.access as Record<string, unknown>).localReference as string;
    expect(resource(deferred.bundle, 'image').blob!.digestCheck).toBe('pending');
    expect(await digestDeliveryBlob(bufferSource(bytes), localReference, image.raw.digest as Record<string, unknown>)).toBe(
      'unchecked',
    );
  });
});

describe('what is not a stored image', () => {
  const resource = (bundle: Awaited<ReturnType<typeof readOcmBundle>>['bundle'], name: string) =>
    bundle!.componentVersions[0]!.resources.find((r) => r.name === name)!;

  it('reads a JSON resource shaped like a manifest as the file it is, in the walk and on demand', async () => {
    const bytes = deliveryCtf({ extras: true });
    const { bundle } = await readOcmBundle('app.ctf.tar', bytes);
    const settings = resource(bundle, 'settings');
    expect(settings.transport).toBe('transported');
    expect(settings.blob).toMatchObject({ kind: 'json', digestCheck: 'match' });
    expect(await digestDeliveryBlob(bufferSource(bytes), SETTINGS.digest, settings.raw.digest as Record<string, unknown>)).toBe(
      'match',
    );
  });

  it.each(['genericBlobDigest/v1', 'ociArtifactDigest/v1'] as const)(
    'does not miss the empty config, whose bytes follow from its digest (%s)',
    async (stored) => {
      const bytes = deliveryCtf({ extras: true, stored });
      const { bundle, diagnostics } = await readOcmBundle('app.ctf.tar', bytes);
      expect(diagnostics.filter((d) => d.code === 'OCM_ARTIFACT_INCOMPLETE')).toEqual([]);
      const artifact = resource(bundle, 'artifact');
      expect(artifact.transport).toBe('transported');
      expect(artifact.blob).toMatchObject({ kind: 'oci-artifact', digestCheck: 'match' });
      expect(
        await digestDeliveryBlob(bufferSource(bytes), EMPTY_CONFIG_ARTIFACT.digest, artifact.raw.digest as Record<string, unknown>),
      ).toBe('match');
    },
  );
});
