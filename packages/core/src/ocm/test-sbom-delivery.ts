import { createHash } from 'node:crypto';
// @ts-expect-error - plain-JS test/fixture helper without type declarations
import { writeTar } from '../../scripts/tar-writer.mjs';

/**
 * Test support: flat-layout CTFs whose component versions carry SBOMs and
 * images the way real deliveries do (SBOMs as local blobs; images external
 * by reference or stored by value as OCI manifests). Real SHA-256 digests,
 * synthetic content. Imported by tests only.
 */

const MANIFEST = 'application/vnd.oci.image.manifest.v1+json';
const CD_LAYER = 'application/vnd.ocm.software.component-descriptor.v2+json';
const CD_CONFIG = 'application/vnd.ocm.software.component.config.v1+json';

export interface TestBlob {
  digest: string;
  hex: string;
  size: number;
  bytes: string;
}

export function blob(bytes: string): TestBlob {
  const hex = createHash('sha256').update(bytes).digest('hex');
  return { digest: `sha256:${hex}`, hex, size: Buffer.byteLength(bytes), bytes };
}

export type TestResource =
  | { kind: 'sbom'; name: string; content: string; mediaType?: string }
  | { kind: 'external-sbom'; name: string; url: string }
  | { kind: 'external-image'; name: string; type?: string; imageReference: string }
  | { kind: 'stored-image'; name: string; type?: string; referenceName: string; image: StoredImage }
  | { kind: 'blob'; name: string; type: string; content: string };

export interface StoredImage {
  config: TestBlob;
  configMediaType: string;
  layers: TestBlob[];
  manifest: TestBlob;
}

/** An image stored by value: config, layers, and the manifest naming them. */
export function storedImage(
  seed: string,
  configMediaType = 'application/vnd.oci.image.config.v1+json',
): StoredImage {
  const config = blob(`{"architecture":"amd64","os":"linux","seed":"${seed}"}`);
  const layers = [blob(`layer of ${seed}`)];
  const manifest = blob(
    JSON.stringify({
      schemaVersion: 2,
      mediaType: MANIFEST,
      config: { mediaType: configMediaType, digest: config.digest, size: config.size },
      layers: layers.map((l) => ({ mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip', digest: l.digest, size: l.size })),
    }),
  );
  return { config, configMediaType, layers, manifest };
}

export interface TestCv {
  name: string;
  version: string;
  resources: TestResource[];
}

export function sbomDeliveryCtf(cvs: TestCv[]): Uint8Array {
  const blobs = new Map<string, TestBlob>();
  const keep = (b: TestBlob) => blobs.set(b.digest, b);
  const artifacts = cvs.map((cv) => {
    const layers: TestBlob[] = [];
    const resources = cv.resources.map((r) => {
      const base = { name: r.name, version: cv.version, relation: 'local' };
      switch (r.kind) {
        case 'sbom': {
          const b = blob(r.content);
          layers.push(b);
          const mediaType = r.mediaType ?? 'application/spdx+json';
          return {
            ...base,
            type: 'sbom',
            access: { type: 'LocalBlob/v1', localReference: b.digest, mediaType },
            digest: { hashAlgorithm: 'SHA-256', normalisationAlgorithm: 'genericBlobDigest/v1', value: b.hex },
          };
        }
        case 'external-sbom':
          return { ...base, type: 'sbom', relation: 'external', access: { type: 'wget', url: r.url, mediaType: 'application/spdx+json' } };
        case 'external-image':
          return {
            ...base,
            type: r.type ?? 'ociImage',
            relation: 'external',
            access: { type: 'ociArtifact', imageReference: r.imageReference },
          };
        case 'stored-image': {
          const { manifest, config, layers: imageLayers } = r.image;
          [manifest, config, ...imageLayers].forEach(keep);
          return {
            ...base,
            type: r.type ?? 'ociImage',
            access: { type: 'LocalBlob/v1', localReference: manifest.digest, mediaType: MANIFEST, referenceName: r.referenceName },
            digest: { hashAlgorithm: 'SHA-256', normalisationAlgorithm: 'genericBlobDigest/v1', value: manifest.hex },
          };
        }
        case 'blob': {
          const b = blob(r.content);
          layers.push(b);
          return {
            ...base,
            type: r.type,
            access: { type: 'LocalBlob/v1', localReference: b.digest, mediaType: 'application/octet-stream' },
            digest: { hashAlgorithm: 'SHA-256', normalisationAlgorithm: 'genericBlobDigest/v1', value: b.hex },
          };
        }
      }
    });
    const cd = blob(
      JSON.stringify({
        meta: { schemaVersion: 'v2' },
        component: {
          name: cv.name,
          version: cv.version,
          provider: { name: 'Example' },
          repositoryContexts: [],
          componentReferences: [],
          sources: [],
          resources,
        },
      }),
    );
    const config = blob(JSON.stringify({ componentDescriptorLayer: { mediaType: CD_LAYER, digest: cd.digest, size: cd.size } }));
    const manifest = blob(
      JSON.stringify({
        schemaVersion: 2,
        mediaType: MANIFEST,
        config: { mediaType: CD_CONFIG, digest: config.digest, size: config.size },
        layers: [cd, ...layers].map((b, i) => ({
          mediaType: i === 0 ? CD_LAYER : 'application/octet-stream',
          digest: b.digest,
          size: b.size,
        })),
      }),
    );
    [cd, config, manifest, ...layers].forEach(keep);
    return { repository: `component-descriptors/${cv.name}`, tag: cv.version, digest: manifest.digest, mediaType: MANIFEST };
  });
  return new Uint8Array(
    writeTar([
      { name: 'artifact-index.json', bytes: JSON.stringify({ schemaVersion: 1, artifacts }) },
      ...[...blobs.values()].map((b) => ({ name: `blobs/${b.digest.replace(':', '.')}`, bytes: b.bytes })),
    ]),
  );
}

interface TestPackage {
  name: string;
  version: string;
  purl?: string;
  license?: string;
}

/** An SPDX 2.3 image SBOM shaped like syft's: the root names the image. */
export function spdxImageSbom(opts: {
  repository: string;
  tag?: string;
  digest?: string;
  packages?: TestPackage[];
}): string {
  const encoded = encodeURIComponent(opts.repository);
  const qualifiers = ['arch=amd64', ...(opts.tag ? [`tag=${opts.tag}`] : [])].join('&');
  const root = {
    SPDXID: 'SPDXRef-DocumentRoot-Image',
    name: opts.repository,
    versionInfo: opts.tag ?? opts.digest ?? '',
    downloadLocation: 'NOASSERTION',
    ...(opts.digest ? { checksums: [{ algorithm: 'SHA256', checksumValue: opts.digest.replace('sha256:', '') }] } : {}),
    externalRefs: opts.digest
      ? [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: `pkg:oci/${encoded}@${encodeURIComponent(opts.digest)}?${qualifiers}` }]
      : [],
  };
  return spdx(opts.repository, root, opts.packages ?? []);
}

/** A product-level SPDX SBOM (a source or release scan). */
export function spdxProductSbom(name: string, version: string, packages: TestPackage[] = []): string {
  return spdx(name, { SPDXID: 'SPDXRef-DocumentRoot-Directory', name, versionInfo: version, downloadLocation: 'NOASSERTION' }, packages);
}

/** An SPDX SBOM without DESCRIBES: the top-level packages stand in. */
export function spdxWithoutDescribes(packages: TestPackage[]): string {
  return JSON.stringify({
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: 'no-describes',
    documentNamespace: 'https://example.org/spdx/no-describes',
    creationInfo: { created: '2026-10-15T00:00:00Z', creators: ['Tool: test'] },
    packages: packages.map((p, i) => spdxPackage(p, i)),
  });
}

function spdx(name: string, root: Record<string, unknown>, packages: TestPackage[]): string {
  return JSON.stringify({
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name,
    documentNamespace: `https://example.org/spdx/${encodeURIComponent(name)}`,
    creationInfo: { created: '2026-10-15T00:00:00Z', creators: ['Organization: Example', 'Tool: test-1.0'] },
    documentDescribes: [root.SPDXID],
    packages: [root, ...packages.map((p, i) => spdxPackage(p, i))],
    relationships: packages.map((_, i) => ({
      spdxElementId: root.SPDXID,
      relationshipType: 'CONTAINS',
      relatedSpdxElement: `SPDXRef-Package-${i}`,
    })),
  });
}

function spdxPackage(p: TestPackage, i: number): Record<string, unknown> {
  return {
    SPDXID: `SPDXRef-Package-${i}`,
    name: p.name,
    versionInfo: p.version,
    downloadLocation: 'NOASSERTION',
    supplier: 'Organization: Example',
    licenseConcluded: p.license ?? 'NOASSERTION',
    ...(p.purl ? { externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: p.purl }] } : {}),
  };
}

/** A CycloneDX 1.6 image SBOM: metadata.component is the container. */
export function cdxImageSbom(opts: { repository: string; version: string; hashes?: string[]; packages?: TestPackage[] }): string {
  return JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: 'urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79',
    version: 1,
    metadata: {
      timestamp: '2026-10-15T00:00:00Z',
      tools: { components: [{ type: 'application', name: 'test', version: '1.0' }] },
      component: {
        'bom-ref': 'image-root',
        type: 'container',
        name: opts.repository,
        version: opts.version,
        ...(opts.hashes ? { hashes: opts.hashes.map((h) => ({ alg: 'SHA-256', content: h.replace('sha256:', '') })) } : {}),
      },
    },
    components: (opts.packages ?? []).map((p, i) => ({
      'bom-ref': `pkg-${i}`,
      type: 'library',
      name: p.name,
      version: p.version,
      ...(p.purl ? { purl: p.purl } : {}),
      ...(p.license ? { licenses: [{ license: { id: p.license } }] } : {}),
    })),
  });
}
