/**
 * Regenerates the binary OCM fixtures (deterministic bytes — the archive
 * tests compare against the committed files, so any drift fails CI):
 *
 *   node scripts/generate-ocm-fixtures.mjs
 *
 * delivery.ctf.tar pins BOTH artifact layouts seen in the wild: one
 * component as a flat OCI manifest, one as a nested artifact-set archive.
 * Digest strings are deterministic placeholders — SBOM Lens displays OCM
 * digests but never verifies them; only index/manifest/blob-name consistency
 * matters here.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { writeTar } from './tar-writer.mjs';

const outDir = new URL('../fixtures/ocm/', import.meta.url);

const HEX = (ch) => ch.repeat(64);
const SBOM_DIGEST = HEX('2');
const WEBSTACK_CD_DIGEST = HEX('3');
const WEBSTACK_SET_DIGEST = HEX('4');
const PLATFORM_CD_DIGEST = HEX('5');
const PLATFORM_MANIFEST_DIGEST = HEX('6');

const sbomJson =
  JSON.stringify(
    {
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: 'acme-webstack-delivery-sbom',
      documentNamespace: 'https://example.org/spdxdocs/acme-webstack-delivery-sbom',
      creationInfo: { created: '2026-06-01T10:00:00Z', creators: ['Organization: ACME Corp'] },
      documentDescribes: ['SPDXRef-Package-webstack'],
      packages: [
        {
          name: 'webstack',
          SPDXID: 'SPDXRef-Package-webstack',
          versionInfo: '2.1.0',
          downloadLocation: 'NOASSERTION',
          supplier: 'Organization: ACME Corp',
          externalRefs: [
            {
              referenceCategory: 'PACKAGE-MANAGER',
              referenceType: 'purl',
              referenceLocator: 'pkg:npm/%40acme/webstack@2.1.0',
            },
          ],
        },
        {
          name: 'nginx-gateway',
          SPDXID: 'SPDXRef-Package-nginx',
          versionInfo: '1.27.1',
          downloadLocation: 'NOASSERTION',
          supplier: 'Organization: ACME Corp',
        },
      ],
      relationships: [
        { spdxElementId: 'SPDXRef-Package-webstack', relationshipType: 'CONTAINS', relatedSpdxElement: 'SPDXRef-Package-nginx' },
      ],
    },
    null,
    2,
  ) + '\n';

const webstackCd = `meta:
  schemaVersion: v2
component:
  name: acme.org/webstack
  version: 2.1.0
  provider: ACME Corp
  componentReferences: []
  sources: []
  resources:
    - name: webstack-sbom
      version: 2.1.0
      type: sbom
      relation: local
      access:
        type: localBlob
        localReference: sha256.${SBOM_DIGEST}
        mediaType: application/spdx+json
    - name: gateway-image
      version: 2.1.0
      type: ociImage
      relation: local
      access:
        type: ociArtifact
        imageReference: registry.example.org/acme/gateway:2.1.0
`;

const platformCd = `meta:
  schemaVersion: v2
component:
  name: acme.org/platform
  version: 1.0.0
  provider: ACME Corp
  sources: []
  resources: []
  componentReferences:
    - name: webstack
      componentName: acme.org/webstack
      version: 2.1.0
`;

/** Nested artifact set for webstack: its own tar with descriptor + blobs. */
export function buildWebstackArtifactSet() {
  const manifest = JSON.stringify({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: { mediaType: 'application/vnd.ocm.software.component.config.v1+json', digest: 'sha256:' + HEX('0'), size: 2 },
    layers: [
      {
        mediaType: 'application/vnd.ocm.software.component-descriptor.v2+yaml',
        digest: `sha256:${WEBSTACK_CD_DIGEST}`,
        size: webstackCd.length,
      },
      {
        mediaType: 'application/spdx+json',
        digest: `sha256:${SBOM_DIGEST}`,
        size: sbomJson.length,
      },
    ],
  });
  return writeTar([
    { name: 'artifact-set-descriptor.json', bytes: manifest },
    { name: `blobs/sha256.${WEBSTACK_CD_DIGEST}`, bytes: webstackCd },
    { name: `blobs/sha256.${SBOM_DIGEST}`, bytes: sbomJson },
  ]);
}

/** The CTF: index + one nested artifact set + one flat manifest artifact. */
export function buildDeliveryCtf() {
  const platformManifest = JSON.stringify({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    layers: [
      {
        mediaType: 'application/vnd.ocm.software.component-descriptor.v2+yaml',
        digest: `sha256:${PLATFORM_CD_DIGEST}`,
        size: platformCd.length,
      },
    ],
  });
  const index = JSON.stringify({
    schemaVersion: 1,
    artifacts: [
      { repository: 'component-descriptors/acme.org/platform', tag: '1.0.0', digest: `sha256:${PLATFORM_MANIFEST_DIGEST}` },
      { repository: 'component-descriptors/acme.org/webstack', tag: '2.1.0', digest: `sha256:${WEBSTACK_SET_DIGEST}` },
    ],
  });
  return writeTar([
    { name: 'artifact-index.json', bytes: index },
    { name: `blobs/sha256.${PLATFORM_MANIFEST_DIGEST}`, bytes: platformManifest },
    { name: `blobs/sha256.${PLATFORM_CD_DIGEST}`, bytes: platformCd },
    { name: `blobs/sha256.${WEBSTACK_SET_DIGEST}`, bytes: buildWebstackArtifactSet() },
  ]);
}

/** Component archive: descriptor + blobs at the tar root. */
export function buildComponentArchive() {
  return writeTar([
    { name: 'component-descriptor.yaml', bytes: webstackCd },
    { name: `blobs/sha256.${SBOM_DIGEST}`, bytes: sbomJson },
  ]);
}

const isMain = import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  mkdirSync(outDir, { recursive: true });
  const files = [
    ['delivery.ctf.tar', buildDeliveryCtf()],
    ['component-archive.tar', buildComponentArchive()],
  ];
  for (const [name, bytes] of files) {
    writeFileSync(new URL(name, outDir), bytes);
    console.log(`${name}  (${bytes.length} bytes)`);
  }
}
