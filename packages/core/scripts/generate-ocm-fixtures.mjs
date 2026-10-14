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
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { writeTar } from './tar-writer.mjs';

const outDir = new URL('../fixtures/ocm/', import.meta.url);

const HEX = (ch) => ch.repeat(64);
const SBOM_DIGEST = HEX('2');
const WEBSTACK_CD_DIGEST = HEX('3');
const WEBSTACK_SET_DIGEST = HEX('4');
const PLATFORM_CD_DIGEST = HEX('5');
const PLATFORM_MANIFEST_DIGEST = HEX('6');
/** Deliberately wrong declared digest — the demo's visible mismatch case. */
const CONFIG_DECLARED_DIGEST = HEX('9');

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

// --- Real artifact blobs the delivery physically transports (B2). --------
// Content is fixed, so every hash below is deterministic. The helm chart and
// the OCI artifact set carry CORRECT digests (match case); runtime-config
// declares a wrong one (mismatch case, visible in the demo).

const chartYaml = `apiVersion: v2
name: webstack
description: ACME webstack deployment chart
version: 2.1.0
appVersion: "2.1.0"
`;
const chartValues = `replicaCount: 2
image:
  repository: registry.example.org/acme/webstack
  tag: 2.1.0
service:
  port: 8080
`;
const chartDeployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: webstack
`;
const chartTar = writeTar([
  { name: 'webstack/Chart.yaml', bytes: chartYaml },
  { name: 'webstack/values.yaml', bytes: chartValues },
  { name: 'webstack/templates/deployment.yaml', bytes: chartDeployment },
]);
const CHART_DIGEST = sha256(chartTar);

const configYaml = `logLevel: info
features:
  dashboards: true
  tracing: false
`;
const CONFIG_STORED_DIGEST = sha256(configYaml);

// Mini OCI artifact set: a manifest plus two tiny layers. Its declared
// digest uses ociArtifactDigest/v1, i.e. the sha256 of the manifest bytes.
const dashLayerOne = 'dashboards layer one\n';
const dashLayerTwo = 'dashboards layer two\n';
const dashManifest = JSON.stringify({
  schemaVersion: 2,
  mediaType: 'application/vnd.oci.image.manifest.v1+json',
  layers: [
    { mediaType: 'application/vnd.oci.image.layer.v1.tar', digest: `sha256:${sha256(dashLayerOne)}`, size: dashLayerOne.length },
    { mediaType: 'application/vnd.oci.image.layer.v1.tar', digest: `sha256:${sha256(dashLayerTwo)}`, size: dashLayerTwo.length },
  ],
});
const DASH_MANIFEST_DIGEST = sha256(dashManifest);
const dashArtifactSet = writeTar([
  { name: 'artifact-set-descriptor.json', bytes: dashManifest },
  { name: `blobs/sha256.${sha256(dashLayerOne)}`, bytes: dashLayerOne },
  { name: `blobs/sha256.${sha256(dashLayerTwo)}`, bytes: dashLayerTwo },
]);
const DASH_SET_STORED_DIGEST = sha256(dashArtifactSet);

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
    - name: webstack-chart
      version: 2.1.0
      type: helmChart
      relation: local
      access:
        type: localBlob
        localReference: sha256.${CHART_DIGEST}
        mediaType: application/vnd.cncf.helm.chart.content.v1.tar
      digest:
        hashAlgorithm: SHA-256
        normalisationAlgorithm: genericBlobDigest/v1
        value: "${CHART_DIGEST}"
    - name: runtime-config
      version: 2.1.0
      type: plainText
      relation: local
      access:
        type: localBlob
        localReference: sha256.${CONFIG_STORED_DIGEST}
        mediaType: application/yaml
      digest:
        hashAlgorithm: SHA-256
        normalisationAlgorithm: genericBlobDigest/v1
        value: "${CONFIG_DECLARED_DIGEST}"
    - name: dashboards-image
      version: 2.1.0
      type: ociImage
      relation: local
      access:
        type: localBlob
        localReference: sha256.${DASH_SET_STORED_DIGEST}
        mediaType: application/vnd.oci.image.manifest.v1+tar
      digest:
        hashAlgorithm: SHA-256
        normalisationAlgorithm: ociArtifactDigest/v1
        value: "${DASH_MANIFEST_DIGEST}"
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
      {
        mediaType: 'application/vnd.cncf.helm.chart.content.v1.tar',
        digest: `sha256:${CHART_DIGEST}`,
        size: chartTar.length,
      },
      {
        mediaType: 'application/yaml',
        digest: `sha256:${CONFIG_STORED_DIGEST}`,
        size: configYaml.length,
      },
      {
        mediaType: 'application/vnd.oci.image.manifest.v1+tar',
        digest: `sha256:${DASH_SET_STORED_DIGEST}`,
        size: dashArtifactSet.length,
      },
    ],
  });
  return writeTar([
    { name: 'artifact-set-descriptor.json', bytes: manifest },
    { name: `blobs/sha256.${WEBSTACK_CD_DIGEST}`, bytes: webstackCd },
    { name: `blobs/sha256.${SBOM_DIGEST}`, bytes: sbomJson },
    { name: `blobs/sha256.${CHART_DIGEST}`, bytes: chartTar },
    { name: `blobs/sha256.${CONFIG_STORED_DIGEST}`, bytes: configYaml },
    { name: `blobs/sha256.${DASH_SET_STORED_DIGEST}`, bytes: dashArtifactSet },
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
    { name: `blobs/sha256.${CHART_DIGEST}`, bytes: chartTar },
    { name: `blobs/sha256.${CONFIG_STORED_DIGEST}`, bytes: configYaml },
    { name: `blobs/sha256.${DASH_SET_STORED_DIGEST}`, bytes: dashArtifactSet },
  ]);
}

// --- OCM Lens 2.0 demo delivery -------------------------------------------
// One bundle that shows every verdict the product can give: three levels of
// aggregation (platform -> observability -> base), a diamond (base referenced
// twice), the CLI-SIGNED webstack descriptor verbatim (signed with ocm CLI
// v0.13.0 / RSASSA-PSS / jsonNormalisation-v4alpha1 against the committed
// test keypair; verifiable in-app with keys/test-rsa.pub.pem), a deliberate
// digest mismatch, one external ociArtifact, and two embedded SBOMs.
// Narrative vendor is ECME Corp; content is entirely synthetic.

const signedEcmeCd = readFileSync(new URL('../fixtures/ocm/signed-ecme-descriptor.json', import.meta.url));

// The signed descriptor's localBlob references are content-addressed sha256
// values of EXACTLY these strings (they were the input files of the signing
// run). Guard against drift: change a byte here and the signed demo breaks.
const ecmeSbomJson =
  JSON.stringify(
    {
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: 'ecme-webstack-delivery-sbom',
      documentNamespace: 'https://sbom.ecme.example/webstack/2.1.0',
      creationInfo: { created: '2026-03-01T00:00:00Z', creators: ['Tool: ecme-sbom-gen'] },
      packages: [
        { SPDXID: 'SPDXRef-Package-webstack', name: 'webstack', versionInfo: '2.1.0', downloadLocation: 'NOASSERTION' },
        { SPDXID: 'SPDXRef-Package-nginx', name: 'nginx-gateway', versionInfo: '1.27.0', downloadLocation: 'NOASSERTION' },
      ],
      relationships: [
        { spdxElementId: 'SPDXRef-Package-webstack', relationshipType: 'CONTAINS', relatedSpdxElement: 'SPDXRef-Package-nginx' },
      ],
    },
    null,
    2,
  ) + '\n';
const ecmeRuntimeConfig = 'logLevel: info\nregion: eu-central-1\nfeatureFlags:\n  newCheckout: true\n';

const ECME_SBOM_REF = sha256(ecmeSbomJson);
const ECME_CONFIG_REF = sha256(ecmeRuntimeConfig);
if (ECME_SBOM_REF !== 'f16ad138ab42cef1c9df2aaed44f687fa9836d100aa95ff5fecdb02877d38508')
  throw new Error('ecmeSbomJson drifted: the signed demo descriptor no longer matches its blobs');
if (ECME_CONFIG_REF !== 'e9b7fe4a8a2c2d6ddce52ef6b5f012040dd9cae8726866a08606b0a5760e51c8')
  throw new Error('ecmeRuntimeConfig drifted: the signed demo descriptor no longer matches its blobs');

const obsChartTar = writeTar([
  {
    name: 'observability/Chart.yaml',
    bytes: 'apiVersion: v2\nname: observability\ndescription: ECME metrics and dashboards\nversion: 1.4.0\n',
  },
  { name: 'observability/values.yaml', bytes: 'retentionDays: 30\nscrapeInterval: 15s\n' },
]);
const OBS_CHART_DIGEST = sha256(obsChartTar);
const obsConfig = 'alerting: enabled\nreceivers:\n  - oncall@ecme.example\n';
const OBS_CONFIG_STORED = sha256(obsConfig);
/** Deliberately wrong declared digest - the demo's visible mismatch case. */
const OBS_CONFIG_DECLARED = HEX('7');
const obsSbom =
  JSON.stringify(
    {
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: 'ecme-observability-sbom',
      documentNamespace: 'https://sbom.ecme.example/observability/1.4.0',
      creationInfo: { created: '2026-02-01T00:00:00Z', creators: ['Tool: ecme-sbom-gen'] },
      packages: [
        {
          SPDXID: 'SPDXRef-Package-grafana',
          name: 'grafana',
          versionInfo: '11.0.0',
          downloadLocation: 'NOASSERTION',
        },
      ],
    },
    null,
    2,
  ) + '\n';
const OBS_SBOM_DIGEST = sha256(obsSbom);
const baseInfo = 'distro: wolfi\npackages: none\npurpose: minimal base image metadata\n';
const BASE_INFO_DIGEST = sha256(baseInfo);

const platform2Cd = `meta:
  schemaVersion: v2
component:
  name: ecme.org/platform
  version: 2.0.0
  provider: ECME Corp
  creationTime: "2026-03-01T08:00:00Z"
  sources: []
  resources:
    - name: gateway-image
      version: 2.0.0
      type: ociImage
      relation: external
      access:
        type: ociArtifact
        imageReference: registry.ecme.example/ecme/gateway:2.0.0
  componentReferences:
    - name: webstack
      componentName: ecme.org/webstack
      version: 2.1.0
    - name: observability
      componentName: ecme.org/observability
      version: 1.4.0
    - name: base
      componentName: ecme.org/base
      version: 0.9.0
`;

const obsCd = `meta:
  schemaVersion: v2
component:
  name: ecme.org/observability
  version: 1.4.0
  provider: ECME Corp
  sources: []
  resources:
    - name: obs-chart
      version: 1.4.0
      type: helmChart
      relation: local
      access:
        type: localBlob
        localReference: sha256.${OBS_CHART_DIGEST}
        mediaType: application/vnd.cncf.helm.chart.content.v1.tar
      digest:
        hashAlgorithm: SHA-256
        normalisationAlgorithm: genericBlobDigest/v1
        value: "${OBS_CHART_DIGEST}"
    - name: obs-config
      version: 1.4.0
      type: plainText
      relation: local
      access:
        type: localBlob
        localReference: sha256.${OBS_CONFIG_STORED}
        mediaType: application/yaml
      digest:
        hashAlgorithm: SHA-256
        normalisationAlgorithm: genericBlobDigest/v1
        value: "${OBS_CONFIG_DECLARED}"
    - name: obs-sbom
      version: 1.4.0
      type: sbom
      relation: local
      access:
        type: localBlob
        localReference: sha256.${OBS_SBOM_DIGEST}
        mediaType: application/spdx+json
  componentReferences:
    - name: base
      componentName: ecme.org/base
      version: 0.9.0
`;

const baseCd = `meta:
  schemaVersion: v2
component:
  name: ecme.org/base
  version: 0.9.0
  provider: ECME Corp
  sources: []
  resources:
    - name: base-info
      version: 0.9.0
      type: plainText
      relation: local
      access:
        type: localBlob
        localReference: sha256.${BASE_INFO_DIGEST}
        mediaType: application/yaml
      digest:
        hashAlgorithm: SHA-256
        normalisationAlgorithm: genericBlobDigest/v1
        value: "${BASE_INFO_DIGEST}"
  componentReferences: []
`;

const HEX2 = (pair) => pair.repeat(32);
const P2_CD_DIGEST = HEX('b');
const P2_MANIFEST_DIGEST = HEX('c');
const OBS_CD_DIGEST = HEX('d');
const OBS_MANIFEST_DIGEST = HEX('e');
const BASE_CD_DIGEST = HEX('f');
const BASE_MANIFEST_DIGEST = HEX2('a1');
const WEB_CD_DIGEST = HEX2('b2');
const WEB_MANIFEST_DIGEST = HEX2('c3');

const flatManifest = (cdDigest, cdMediaType, extraLayers = []) =>
  JSON.stringify({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    layers: [
      { mediaType: cdMediaType, digest: `sha256:${cdDigest}`, size: 0 },
      ...extraLayers,
    ],
  });

export function buildDemoDeliveryCtf() {
  const yamlCd = 'application/vnd.ocm.software.component-descriptor.v2+yaml';
  const jsonCd = 'application/vnd.ocm.software.component-descriptor.v2+json';
  const index = JSON.stringify({
    schemaVersion: 1,
    artifacts: [
      { repository: 'component-descriptors/ecme.org/platform', tag: '2.0.0', digest: `sha256:${P2_MANIFEST_DIGEST}` },
      { repository: 'component-descriptors/ecme.org/webstack', tag: '2.1.0', digest: `sha256:${WEB_MANIFEST_DIGEST}` },
      { repository: 'component-descriptors/ecme.org/observability', tag: '1.4.0', digest: `sha256:${OBS_MANIFEST_DIGEST}` },
      { repository: 'component-descriptors/ecme.org/base', tag: '0.9.0', digest: `sha256:${BASE_MANIFEST_DIGEST}` },
    ],
  });
  return writeTar([
    { name: 'artifact-index.json', bytes: index },
    { name: `blobs/sha256.${P2_MANIFEST_DIGEST}`, bytes: flatManifest(P2_CD_DIGEST, yamlCd) },
    { name: `blobs/sha256.${P2_CD_DIGEST}`, bytes: platform2Cd },
    {
      name: `blobs/sha256.${WEB_MANIFEST_DIGEST}`,
      bytes: flatManifest(WEB_CD_DIGEST, jsonCd, [
        { mediaType: 'application/spdx+json', digest: `sha256:${ECME_SBOM_REF}`, size: ecmeSbomJson.length },
        { mediaType: 'application/yaml', digest: `sha256:${ECME_CONFIG_REF}`, size: ecmeRuntimeConfig.length },
      ]),
    },
    { name: `blobs/sha256.${WEB_CD_DIGEST}`, bytes: signedEcmeCd },
    { name: `blobs/sha256.${ECME_SBOM_REF}`, bytes: ecmeSbomJson },
    { name: `blobs/sha256.${ECME_CONFIG_REF}`, bytes: ecmeRuntimeConfig },
    {
      name: `blobs/sha256.${OBS_MANIFEST_DIGEST}`,
      bytes: flatManifest(OBS_CD_DIGEST, yamlCd, [
        { mediaType: 'application/vnd.cncf.helm.chart.content.v1.tar', digest: `sha256:${OBS_CHART_DIGEST}`, size: obsChartTar.length },
        { mediaType: 'application/yaml', digest: `sha256:${OBS_CONFIG_STORED}`, size: obsConfig.length },
        { mediaType: 'application/spdx+json', digest: `sha256:${OBS_SBOM_DIGEST}`, size: obsSbom.length },
      ]),
    },
    { name: `blobs/sha256.${OBS_CD_DIGEST}`, bytes: obsCd },
    { name: `blobs/sha256.${OBS_CHART_DIGEST}`, bytes: obsChartTar },
    { name: `blobs/sha256.${OBS_CONFIG_STORED}`, bytes: obsConfig },
    { name: `blobs/sha256.${OBS_SBOM_DIGEST}`, bytes: obsSbom },
    {
      name: `blobs/sha256.${BASE_MANIFEST_DIGEST}`,
      bytes: flatManifest(BASE_CD_DIGEST, yamlCd, [
        { mediaType: 'application/yaml', digest: `sha256:${BASE_INFO_DIGEST}`, size: baseInfo.length },
      ]),
    },
    { name: `blobs/sha256.${BASE_CD_DIGEST}`, bytes: baseCd },
    { name: `blobs/sha256.${BASE_INFO_DIGEST}`, bytes: baseInfo },
  ]);
}

const isMain = import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  mkdirSync(outDir, { recursive: true });
  const files = [
    ['delivery.ctf.tar', buildDeliveryCtf()],
    ['component-archive.tar', buildComponentArchive()],
    ['ecme-delivery.ctf.tar', buildDemoDeliveryCtf()],
  ];
  for (const [name, bytes] of files) {
    writeFileSync(new URL(name, outDir), bytes);
    console.log(`${name}  (${bytes.length} bytes)`);
  }
}
