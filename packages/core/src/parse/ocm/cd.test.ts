import { describe, expect, it } from 'vitest';
import { loadFixture } from '../../test-fixtures';
import { fakeSha1 } from '../../test-fixtures';
import { detect } from '../detect';
import { parseDocument, registerOcmParser } from '../parser';
import type { SourceInput } from '../parser';
import { parseOcmComponentDescriptor } from './cd';

// parseDocument only knows about descriptors once a product wires them in —
// see ocm-seam.test.ts for what an SPDX-only build does instead.
registerOcmParser(parseOcmComponentDescriptor);

function inputFor(name: string, text: string): SourceInput {
  return { fileName: name, text, sha1: fakeSha1(name), byteSize: text.length };
}

function parseFixture(name: string) {
  const text = loadFixture(name);
  const result = parseDocument(inputFor(name, text));
  expect(result.document, `${name} should produce a document`).not.toBeNull();
  return result.document!;
}

describe('OCM detection', () => {
  it('detects v2 YAML, v3alpha1 YAML, and JSON descriptors', () => {
    expect(detect(loadFixture('ocm/cd-v2.yaml'))).toMatchObject({ format: 'ocm-cd', serialization: 'yaml' });
    expect(detect(loadFixture('ocm/cd-v3alpha1.yaml'))).toMatchObject({ format: 'ocm-cd', serialization: 'yaml' });
    const json = JSON.stringify({ meta: { schemaVersion: 'v2' }, component: { name: 'a', version: '1' } });
    expect(detect(json)).toMatchObject({ format: 'ocm-cd', serialization: 'json' });
  });

  it('rejects descriptors without name/version and keeps Trivy/CDX detection intact', () => {
    const broken = parseDocument(inputFor('broken.yaml', loadFixture('negative/ocm-broken.yaml')));
    expect(broken.document).toBeNull();
    expect(broken.diagnostics[0]!.code).toBe('OCM_CD_MALFORMED');
    expect(detect(loadFixture('negative/trivy-native.json'))).toMatchObject({
      format: 'unsupported',
      code: 'TRIVY_NATIVE_NOT_SUPPORTED',
    });
    expect(detect(loadFixture('negative/cyclonedx.json'))).toMatchObject({
      format: 'unsupported',
      code: 'CYCLONEDX_NOT_SUPPORTED',
    });
  });
});

describe('OCM CD mapping (v2)', () => {
  const doc = parseFixture('ocm/cd-v2.yaml');

  it('maps component identity to document + root pseudo-package', () => {
    expect(doc.spec).toEqual({ model: 'ocm', version: 'OCM-CD/v2', serialization: 'yaml' });
    expect(doc.name).toBe('acme.org/webstack');
    expect(doc.namespace).toBe('ocm://acme.org/webstack/2.1.0');
    expect(doc.describes).toEqual(['SPDXRef-component']);
    expect(doc.creators).toEqual(['Organization: ACME Corp']);
    expect(doc.created).toBe('2026-06-01T10:00:00Z');
    const root = doc.elements.find((e) => e.spdxId === 'SPDXRef-component')!;
    expect(root).toMatchObject({ name: 'acme.org/webstack', version: '2.1.0', purpose: 'APPLICATION' });
  });

  it('maps resources and sources to CONTAINS-ed package elements', () => {
    const names = doc.elements.map((e) => e.name);
    expect(names).toEqual(
      expect.arrayContaining(['gateway-image', 'deploy-chart', 'webstack-sbom', 'telemetry-bundle', 'webstack-src']),
    );
    const gateway = doc.elements.find((e) => e.name === 'gateway-image')!;
    expect(gateway.purpose).toBe('ociImage');
    expect(gateway.downloadLocation).toContain('registry.example.org/acme/gateway');
    expect(gateway.checksums).toEqual([
      { algorithm: 'SHA256', value: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' },
    ]);
    expect(gateway.purl).toBe(
      'pkg:oci/gateway@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef?repository_url=registry.example.org/acme',
    );
    const src = doc.elements.find((e) => e.name === 'webstack-src')!;
    expect(src.purpose).toBe('SOURCE');
    const contains = doc.relationships.filter(
      (r) => r.type === 'CONTAINS' && r.from.kind === 'local' && r.from.spdxId === 'SPDXRef-component',
    );
    expect(contains.length).toBeGreaterThanOrEqual(5); // 4 resources + 1 source (+ 2 external refs)
  });

  it('maps componentReferences to ocm:// refs without checksums', () => {
    expect(doc.externalDocumentRefs).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ docRef: 'DocumentRef-ref-identity', uri: 'ocm://acme.org/identity/1.4.2' }),
        expect.objectContaining({ docRef: 'DocumentRef-ref-runtime', uri: 'ocm://acme.org/runtime/3.0.0' }),
      ]),
    );
    // The OCM reference extras ride along for the detail view.
    expect(doc.externalDocumentRefs[0]!.ocm?.componentName).toBeDefined();
    const external = doc.relationships.filter((r) => r.to.kind === 'external');
    expect(external).toHaveLength(2);
    expect(external.every((r) => r.to.kind === 'external' && r.to.spdxId === null)).toBe(true);
  });

  it('reports archive-only SBOM resources and unsupported access types', () => {
    const codes = doc.diagnostics.map((d) => d.code);
    expect(codes).toContain('OCM_SBOM_IN_ARCHIVE'); // standalone CD: blob not at hand
    expect(codes).toContain('OCM_ACCESS_UNSUPPORTED'); // the s3 resource
    expect(codes).toContain('OCM_DIGESTS_NOT_VERIFIED');
  });

  it('wires SBOM refs by byte checksum when a blob context resolves them', () => {
    const text = loadFixture('ocm/cd-v2.yaml');
    const detection = detect(text);
    expect(detection.format).toBe('ocm-cd');
    if (detection.format !== 'ocm-cd') return;
    const result = parseOcmComponentDescriptor(inputFor('cd-v2.yaml', text), detection.parsed, 'yaml', {
      sbomChecksumFor: (ref) =>
        ref === 'sha256.2222222222222222222222222222222222222222222222222222222222222222'
          ? 'aaaa000000000000000000000000000000000000'
          : undefined,
    });
    const sbomRef = result.document!.externalDocumentRefs.find((r) => r.docRef.startsWith('DocumentRef-sbom-'));
    expect(sbomRef).toMatchObject({
      docRef: 'DocumentRef-sbom-webstack-sbom',
      uri: 'ocm-blob://acme.org/webstack/2.1.0/webstack-sbom',
      checksum: { algorithm: 'SHA1', value: 'aaaa000000000000000000000000000000000000' },
    });
    const describedBy = result.document!.relationships.find((r) => r.type === 'DESCRIBED_BY');
    expect(describedBy?.from).toEqual({ kind: 'local', spdxId: 'SPDXRef-resource-webstack-sbom' });
    expect(describedBy?.to).toEqual({ kind: 'external', docRef: 'DocumentRef-sbom-webstack-sbom', spdxId: null });
  });

  it('attaches no blob info to a standalone CD (contents live in the delivery)', () => {
    expect(doc.elements.every((e) => e.ocm?.blob === undefined)).toBe(true);
  });

  it('attaches blob info and a mismatch diagnostic through the blob context', () => {
    const text = loadFixture('ocm/cd-v2.yaml');
    const detection = detect(text);
    if (detection.format !== 'ocm-cd') return;
    const result = parseOcmComponentDescriptor(inputFor('cd-v2.yaml', text), detection.parsed, 'yaml', {
      sbomChecksumFor: () => undefined,
      blobInfoFor: (ref) =>
        ref === 'sha256.2222222222222222222222222222222222222222222222222222222222222222'
          ? { size: 7, kind: 'json', digestCheck: 'mismatch' }
          : undefined,
    });
    const sbom = result.document!.elements.find((e) => e.name === 'webstack-sbom')!;
    expect(sbom.ocm!.blob).toEqual({ size: 7, kind: 'json', digestCheck: 'mismatch' });
    const mismatch = result.diagnostics.find((d) => d.code === 'OCM_DIGEST_MISMATCH');
    expect(mismatch?.message).toContain('webstack-sbom');
    const tally = result.diagnostics.find((d) => d.code === 'OCM_DIGESTS_NOT_VERIFIED');
    expect(tally?.message).toContain('1 artifact(s)');
  });
});

describe('ociPurl edge cases', () => {
  it('treats a registry port as part of the host, not as a tag', () => {
    const cd = {
      meta: { schemaVersion: 'v2' },
      component: {
        name: 'acme.org/ported',
        version: '1.0.0',
        resources: [
          {
            name: 'img-port-no-tag',
            version: '1.0.0',
            type: 'ociImage',
            access: { type: 'ociArtifact', imageReference: 'registry.example.org:5000/acme/gateway' },
          },
          {
            name: 'img-port-and-tag',
            version: '1.0.0',
            type: 'ociImage',
            access: { type: 'ociArtifact', imageReference: 'registry.example.org:5000/acme/gateway:2.1.0' },
          },
        ],
      },
    };
    const result = parseOcmComponentDescriptor(
      inputFor('ported.json', JSON.stringify(cd)),
      cd as never,
      'json',
    );
    const [noTag, withTag] = result.document!.elements.filter((e) => e.name.startsWith('img-'));
    // No tag: falls back to the resource version — the port must never leak in.
    expect(noTag!.purl).toBe('pkg:oci/gateway@1.0.0?repository_url=registry.example.org:5000/acme');
    expect(withTag!.purl).toBe('pkg:oci/gateway@2.1.0?repository_url=registry.example.org:5000/acme');
  });
});

describe('OCM CD mapping (v3alpha1)', () => {
  const doc = parseFixture('ocm/cd-v3alpha1.yaml');

  it('maps metadata/spec shape with a best-effort diagnostic', () => {
    expect(doc.spec.version).toBe('OCM-CD/v3alpha1');
    expect(doc.namespace).toBe('ocm://acme.org/webstack/2.1.0');
    expect(doc.creators).toEqual(['Organization: ACME Corp']);
    expect(doc.externalDocumentRefs).toEqual([
      expect.objectContaining({ docRef: 'DocumentRef-ref-identity', uri: 'ocm://acme.org/identity/1.4.2' }),
    ]);
    expect(doc.diagnostics.some((d) => d.code === 'OCM_V3ALPHA1')).toBe(true);
    expect(doc.elements.some((e) => e.name === 'gateway-image')).toBe(true);
  });
});

describe('OCM-native extension data (ocm attachments)', () => {
  const doc = parseFixture('ocm/cd-v2.yaml');

  it('preserves component labels, provider, contexts, and signatures on the document', () => {
    expect(doc.ocm?.schemaVersion).toBe('v2');
    expect(doc.ocm?.provider?.name).toBe('ACME Corp');
    expect(doc.ocm?.labels).toEqual([
      { name: 'acme.org/release-train', value: 'spring-2026', signing: true, version: undefined },
      {
        name: 'acme.org/build',
        value: { pipeline: 'web-ci', run: 4711 },
        signing: undefined,
        version: undefined,
      },
    ]);
    expect(doc.ocm?.repositoryContexts).toEqual([
      {
        type: 'OCIRegistry',
        baseUrl: 'registry.example.org/acme',
        subPath: undefined,
        componentNameMapping: undefined,
      },
    ]);
    expect(doc.ocm?.signatures).toHaveLength(1);
    expect(doc.ocm?.signatures?.[0]).toMatchObject({
      name: 'acme-release-signature',
      algorithm: 'RSASSA-PKCS1-V1_5',
      mediaType: 'application/vnd.ocm.signature.rsa',
      issuer: 'CN=acme-release',
      digest: { hashAlgorithm: 'SHA-256', normalisationAlgorithm: 'jsonNormalisation/v3' },
    });
    // The context flattening is gone — the comment only names the schema.
    expect(doc.comment).toBe('OCM component descriptor (schema v2)');
    expect(doc.diagnostics.some((d) => d.code === 'OCM_EXPERIMENTAL')).toBe(false);
  });

  it('preserves artifact type/relation/extraIdentity/labels/digest on elements', () => {
    const gateway = doc.elements.find((e) => e.name === 'gateway-image')!;
    expect(gateway.ocm).toMatchObject({
      role: 'resource',
      type: 'ociImage',
      relation: 'local',
      extraIdentity: { architecture: 'amd64' },
      access: { type: 'ociArtifact' },
      digest: {
        hashAlgorithm: 'SHA-256',
        normalisationAlgorithm: 'ociArtifactDigest/v1',
      },
    });
    expect(gateway.ocm?.labels?.[0]).toMatchObject({ name: 'acme.org/scan-status', value: 'passed' });
    const source = doc.elements.find((e) => e.name === 'webstack-src')!;
    expect(source.ocm?.role).toBe('source');
    expect(source.ocm?.access?.raw.repoUrl).toBe('https://example.org/acme/webstack');
  });

  it('keeps the reference digest on the external ref and the full component node in root raw', () => {
    const identity = doc.externalDocumentRefs.find((r) => r.docRef === 'DocumentRef-ref-identity')!;
    expect(identity.ocm?.componentName).toBe('acme.org/identity');
    expect(identity.ocm?.digest?.normalisationAlgorithm).toBe('jsonNormalisation/v3');
    expect(identity.checksum).toBeUndefined();

    const root = doc.elements.find((e) => e.spdxId === 'SPDXRef-component')!;
    expect(root.ocm?.role).toBe('component');
    expect(root.raw.kind).toBe('json');
    const rawValue = root.raw.kind === 'json' ? root.raw.value : {};
    expect(rawValue.resources).toBeDefined();
    expect(rawValue.labels).toBeDefined();
  });
});
