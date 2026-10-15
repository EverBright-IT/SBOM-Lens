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

// --- SBOM evidence demo (OCM Lens 2.1) -------------------------------------
// One delivery, every SBOM binding level the product grades: by digest (the
// stored manifest, and an image config digest), by reference (scanned on
// another registry before the push), by component (a release SBOM), an SBOM
// that lives outside the delivery, and an image without any. Real SHA-256
// digests throughout; the packages (one shared, one in two versions) are
// there for the package views to come.

const SBOM_DEMO_CREATED = '2026-10-01T00:00:00Z';
const OCI_MANIFEST = 'application/vnd.oci.image.manifest.v1+json';

const blobOf = (bytes) => ({ bytes, hex: sha256(bytes), size: Buffer.byteLength(bytes) });

function storedDemoImage(name, cmd) {
  const layer = blobOf(`ecme ${name} image layer`);
  const config = blobOf(
    JSON.stringify({
      architecture: 'amd64',
      os: 'linux',
      config: { Cmd: cmd },
      rootfs: { type: 'layers', diff_ids: [`sha256:${layer.hex}`] },
    }),
  );
  const manifest = blobOf(
    JSON.stringify({
      schemaVersion: 2,
      mediaType: OCI_MANIFEST,
      config: { mediaType: 'application/vnd.oci.image.config.v1+json', digest: `sha256:${config.hex}`, size: config.size },
      layers: [{ mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip', digest: `sha256:${layer.hex}`, size: layer.size }],
    }),
  );
  return { layer, config, manifest };
}

function demoPackage(index, [name, version, purl, license, cpe]) {
  return {
    SPDXID: `SPDXRef-Package-${index}`,
    name,
    versionInfo: version,
    supplier: 'Organization: ECME Corp',
    downloadLocation: 'NOASSERTION',
    licenseConcluded: license,
    externalRefs: [
      { referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: purl },
      ...(cpe ? [{ referenceCategory: 'SECURITY', referenceType: 'cpe23Type', referenceLocator: cpe }] : []),
    ],
  };
}

function demoSpdx(name, namespace, root, packages) {
  const pkgs = packages.map((p, i) => demoPackage(i, p));
  return JSON.stringify({
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name,
    documentNamespace: `https://sbom.ecme.example/${namespace}`,
    creationInfo: { created: SBOM_DEMO_CREATED, creators: ['Organization: ECME Corp (security@ecme.example)', 'Tool: ecme-sbom-gen-2.0'] },
    documentDescribes: [root.SPDXID],
    packages: [{ downloadLocation: 'NOASSERTION', supplier: 'Organization: ECME Corp', ...root }, ...pkgs],
    relationships: pkgs.map((p) => ({ spdxElementId: root.SPDXID, relationshipType: 'CONTAINS', relatedSpdxElement: p.SPDXID })),
  });
}

const OPENSSL = (version) => [
  'openssl',
  version,
  `pkg:deb/debian/openssl@${version}`,
  'Apache-2.0',
  `cpe:2.3:a:openssl:openssl:${version}:*:*:*:*:*:*:*`,
];

function demoCd(name, resources, references = []) {
  return JSON.stringify({
    meta: { schemaVersion: 'v2' },
    component: {
      name,
      version: '3.2.0',
      provider: { name: 'ECME Corp' },
      repositoryContexts: [],
      sources: [],
      componentReferences: references.map((ref) => ({ name: ref.split('/').pop(), componentName: ref, version: '3.2.0' })),
      resources,
    },
  });
}

const localResource = (name, type, blob, mediaType, extra = {}) => ({
  name,
  version: '3.2.0',
  type,
  relation: 'local',
  access: { type: 'LocalBlob/v1', localReference: `sha256:${blob.hex}`, mediaType, ...extra },
  digest: { hashAlgorithm: 'SHA-256', normalisationAlgorithm: 'genericBlobDigest/v1', value: blob.hex },
});

const externalImage = (name, imageReference) => ({
  name,
  version: '3.2.0',
  type: 'ociImage',
  relation: 'external',
  access: { type: 'ociArtifact', imageReference },
});

export function buildSbomDemoCtf() {
  const jsonCd = 'application/vnd.ocm.software.component-descriptor.v2+json';
  const api = storedDemoImage('api', ['uvicorn', 'app:main']);
  const worker = storedDemoImage('worker', ['celery', 'worker']);
  const webPushed = sha256('ecme web image, as pushed');
  const webLocal = sha256('ecme web image, as built locally');

  const apiSbom = blobOf(
    demoSpdx(
      'registry.ecme.example/shop/api',
      'shop/api/3.2.0',
      {
        SPDXID: 'SPDXRef-DocumentRoot-Image',
        name: 'registry.ecme.example/shop/api',
        versionInfo: `sha256:${api.manifest.hex}`,
        checksums: [{ algorithm: 'SHA256', checksumValue: api.manifest.hex }],
        externalRefs: [
          {
            referenceCategory: 'PACKAGE-MANAGER',
            referenceType: 'purl',
            referenceLocator: `pkg:oci/api@sha256%3A${api.manifest.hex}?repository_url=registry.ecme.example%2Fshop%2Fapi&tag=3.2.0`,
          },
        ],
      },
      [
        ['fastapi', '0.115.0', 'pkg:pypi/fastapi@0.115.0', 'MIT'],
        ['uvicorn', '0.30.6', 'pkg:pypi/uvicorn@0.30.6', 'BSD-3-Clause'],
        OPENSSL('3.0.13'),
        ['zlib', '1.3.1', 'pkg:deb/debian/zlib@1.3.1', 'Zlib'],
      ],
    ),
  );
  const webSbom = blobOf(
    demoSpdx(
      'localhost:5000/shop/web',
      'shop/web/3.2.0',
      {
        SPDXID: 'SPDXRef-DocumentRoot-Image',
        name: 'localhost:5000/shop/web',
        versionInfo: '3.2.0',
        checksums: [{ algorithm: 'SHA256', checksumValue: webLocal }],
        externalRefs: [
          {
            referenceCategory: 'PACKAGE-MANAGER',
            referenceType: 'purl',
            referenceLocator: `pkg:oci/localhost%3A5000%2Fshop%2Fweb@sha256%3A${webLocal}?arch=amd64&tag=3.2.0`,
          },
        ],
      },
      [
        ['nginx', '1.27.1', 'pkg:deb/debian/nginx@1.27.1', 'BSD-2-Clause', 'cpe:2.3:a:f5:nginx:1.27.1:*:*:*:*:*:*:*'],
        ['react', '18.3.1', 'pkg:npm/react@18.3.1', 'MIT'],
        ['lodash', '4.17.21', 'pkg:npm/lodash@4.17.21', 'MIT'],
      ],
    ),
  );
  const workerSbom = blobOf(
    JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      serialNumber: 'urn:uuid:7d4c3a1e-5b8f-4c2a-9e61-2f0d8b3c4a51',
      version: 1,
      metadata: {
        timestamp: SBOM_DEMO_CREATED,
        authors: [{ name: 'ECME Corp', email: 'security@ecme.example' }],
        tools: { components: [{ type: 'application', name: 'ecme-sbom-gen', version: '2.0' }] },
        component: { 'bom-ref': 'image', type: 'container', name: 'shop/worker', version: `sha256:${worker.config.hex}` },
      },
      components: [
        ['celery', '5.4.0', 'pkg:pypi/celery@5.4.0', 'BSD-3-Clause'],
        ['redis', '5.0.8', 'pkg:pypi/redis@5.0.8', 'MIT'],
        OPENSSL('3.0.11'),
      ].map(([name, version, purl, license, cpe], i) => ({
        'bom-ref': `pkg-${i}`,
        type: 'library',
        supplier: { name: 'ECME Corp' },
        name,
        version,
        purl,
        ...(cpe ? { cpe } : {}),
        licenses: [{ license: { id: license } }],
      })),
      dependencies: [{ ref: 'image', dependsOn: ['pkg-0', 'pkg-1', 'pkg-2'] }],
    }),
  );
  const cli = blobOf('ecme shop-cli 3.2.0 linux-amd64 (demo bytes)');
  const cliSbom = blobOf(
    demoSpdx(
      'shop-cli',
      'shop/shop-cli/3.2.0',
      { SPDXID: 'SPDXRef-DocumentRoot-Directory', name: 'shop-cli', versionInfo: 'v3.2.0' },
      [
        ['cobra', 'v1.8.1', 'pkg:golang/github.com/spf13/cobra@v1.8.1', 'Apache-2.0'],
        ['yaml', 'v3.0.1', 'pkg:golang/gopkg.in/yaml.v3@v3.0.1', 'MIT'],
      ],
    ),
  );
  const chart = blobOf('ecme gateway helm chart 3.2.0 (demo bytes)');

  const components = [
    ['ecme.org/shop/api', [
      localResource('image', 'ociImage', api.manifest, OCI_MANIFEST, { referenceName: 'shop/api:3.2.0' }),
      localResource('sbom', 'sbom', apiSbom, 'application/spdx+json'),
    ], [apiSbom]],
    ['ecme.org/shop/web', [
      externalImage('image', `registry.ecme.example/shop/web:3.2.0@sha256:${webPushed}`),
      localResource('sbom', 'sbom', webSbom, 'application/spdx+json'),
    ], [webSbom]],
    ['ecme.org/shop/worker', [
      localResource('image', 'ociImage', worker.manifest, OCI_MANIFEST, { referenceName: 'shop/worker:3.2.0' }),
      // Declared as plain JSON: OCM Lens reads the content, which is CycloneDX.
      localResource('sbom', 'sbom', workerSbom, 'application/json'),
    ], [workerSbom]],
    ['ecme.org/shop/shop-cli', [
      localResource('binary', 'executable', cli, 'application/octet-stream'),
      localResource('release-sbom', 'sbom', cliSbom, 'application/spdx+json'),
    ], [cli, cliSbom]],
    ['ecme.org/shop/payments', [
      externalImage('image', 'registry.ecme.example/shop/payments:3.2.0'),
      {
        name: 'sbom',
        version: '3.2.0',
        type: 'sbom',
        relation: 'external',
        access: { type: 'wget', url: 'https://downloads.ecme.example/shop/3.2.0/payments.spdx.json', mediaType: 'application/spdx+json' },
      },
    ], []],
    ['ecme.org/shop/gateway', [
      externalImage('image', 'registry.ecme.example/shop/gateway:3.2.0'),
      localResource('chart', 'helmChart', chart, 'application/vnd.cncf.helm.chart.content.v1.tar+gzip'),
    ], [chart]],
  ];
  const root = ['ecme.org/shop', [], [], components.map(([name]) => name)];

  const entries = [];
  const artifacts = [];
  for (const [name, resources, layers, references = []] of [...components, root]) {
    const cd = blobOf(demoCd(name, resources, references));
    const manifest = blobOf(
      flatManifest(cd.hex, jsonCd, layers.map((b) => ({ mediaType: 'application/octet-stream', digest: `sha256:${b.hex}`, size: b.size }))),
    );
    entries.push({ name: `blobs/sha256.${cd.hex}`, bytes: cd.bytes }, { name: `blobs/sha256.${manifest.hex}`, bytes: manifest.bytes });
    for (const b of layers) entries.push({ name: `blobs/sha256.${b.hex}`, bytes: b.bytes });
    artifacts.push({ repository: `component-descriptors/${name}`, tag: '3.2.0', digest: `sha256:${manifest.hex}` });
  }
  for (const image of [api, worker]) {
    for (const b of [image.manifest, image.config, image.layer]) entries.push({ name: `blobs/sha256.${b.hex}`, bytes: b.bytes });
  }
  return writeTar([{ name: 'artifact-index.json', bytes: JSON.stringify({ schemaVersion: 1, artifacts }) }, ...entries]);
}

const isMain = import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  mkdirSync(outDir, { recursive: true });
  const files = [
    ['delivery.ctf.tar', buildDeliveryCtf()],
    ['component-archive.tar', buildComponentArchive()],
    ['ecme-delivery.ctf.tar', buildDemoDeliveryCtf()],
    ['ecme-sbom-delivery.ctf.tar', buildSbomDemoCtf()],
  ];
  for (const [name, bytes] of files) {
    writeFileSync(new URL(name, outDir), bytes);
    console.log(`${name}  (${bytes.length} bytes)`);
  }
}
