import { describe, expect, it } from 'vitest';
import { emitSpdx23Json } from '../emit/spdx23';
import { parseDocument } from '../parse/parser';
import { sha1Hex } from '../util/sha1';
import { validateComposeConfig, type ComposeConfig } from './config';
import { ComposeError, composeDocument, type ComposeChild } from './compose';

/**
 * End-to-end over the real seams: validate config → compose → emit →
 * re-parse through our own spdx2 parser. If the composer and the viewer
 * ever disagree about what an ExternalDocumentRef looks like, these fail.
 */

const CHILD_JSON = JSON.stringify(
  {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: 'webstack-sbom',
    documentNamespace: 'https://acme.example/spdx/webstack-1.4.2',
    creationInfo: { created: '2026-01-01T00:00:00Z', creators: ['Tool: syft-1.46.0'] },
    packages: [
      { name: 'webstack', SPDXID: 'SPDXRef-Package-webstack', versionInfo: '1.4.2', downloadLocation: 'NOASSERTION' },
    ],
    documentDescribes: ['SPDXRef-Package-webstack'],
  },
  null,
  2,
);

function config(): ComposeConfig {
  const result = validateComposeConfig({
    schema: 'sbomloom-compose/v1',
    product: {
      name: 'acme-suite',
      version: '2.0.0',
      namespace: 'https://acme.example/spdx/acme-suite-2.0.0',
      supplier: 'Organization: ACME Corp',
      purl: { type: 'generic', qualifiers: { 'x-release-channel': 'stable' } },
    },
    creators: ['Organization: ACME Corp'],
    artifacts: [
      {
        name: 'webstack',
        version: '1.4.2',
        type: 'container',
        purl: { type: 'oci', version: 'sha256:aabbcc', qualifiers: { repository_url: 'ghcr.io/acme/webstack' } },
        sbom: 'webstack.spdx.json',
      },
      { name: 'installer', type: 'archive', relationship: 'DEPENDS_ON' },
    ],
  });
  if (!result.ok) throw new Error(result.errors.join('; '));
  return result.config;
}

function children(): ComposeChild[] {
  return [{ artifact: 'webstack', fileName: 'webstack.spdx.json', bytes: new TextEncoder().encode(CHILD_JSON) }];
}

const OPTS = { created: '2026-07-17T12:00:00Z', toolVersion: '0.0.0-dev' };

describe('composeDocument', () => {
  it('wires root, artifacts, and the external ref with the real child SHA-1', async () => {
    const { document, diagnostics } = await composeDocument(config(), children(), OPTS);
    expect(diagnostics).toEqual([]);
    expect(document.namespace).toBe('https://acme.example/spdx/acme-suite-2.0.0');
    expect(document.describes).toEqual(['SPDXRef-Package-acme-suite']);
    expect(document.creators).toEqual(['Tool: sbomloom-0.0.0-dev', 'Organization: ACME Corp']);

    const bytes = new TextEncoder().encode(CHILD_JSON);
    const expectedSha1 = await sha1Hex(bytes.buffer as ArrayBuffer);
    expect(document.externalDocumentRefs).toEqual([
      {
        docRef: 'DocumentRef-webstack',
        uri: 'https://acme.example/spdx/webstack-1.4.2',
        checksum: { algorithm: 'SHA1', value: expectedSha1 },
      },
    ]);

    const types = document.relationships.map((r) => r.type);
    expect(types).toEqual(['DESCRIBES', 'CONTAINS', 'DESCRIBED_BY', 'DEPENDS_ON']);
    const describedBy = document.relationships[2];
    expect(describedBy.from).toEqual({ kind: 'local', spdxId: 'SPDXRef-Package-webstack' });
    expect(describedBy.to).toEqual({ kind: 'external', docRef: 'DocumentRef-webstack', spdxId: 'SPDXRef-DOCUMENT' });

    const webstack = document.elements.find((e) => e.name === 'webstack');
    expect(webstack?.purpose).toBe('CONTAINER');
    expect(webstack?.purl).toBe('pkg:oci/webstack@sha256%3Aaabbcc?repository_url=ghcr.io/acme/webstack');
  });

  it('is deterministic: same inputs, byte-identical emission', async () => {
    const one = emitSpdx23Json((await composeDocument(config(), children(), OPTS)).document);
    const two = emitSpdx23Json((await composeDocument(config(), children(), OPTS)).document);
    expect(one).toBe(two);
    expect(one.endsWith('\n')).toBe(true);
  });

  it('round-trips through our own SPDX 2.3 parser', async () => {
    const { document } = await composeDocument(config(), children(), OPTS);
    const text = emitSpdx23Json(document);
    const parsed = parseDocument({ fileName: 'acme-suite.spdx.json', text, sha1: 'f'.repeat(40), byteSize: text.length });
    expect(parsed.document).not.toBeNull();
    expect(parsed.diagnostics.filter((d) => d.severity === 'error')).toEqual([]);
    const doc = parsed.document!;
    expect(doc.spec).toEqual({ model: 'spdx-2', version: 'SPDX-2.3', serialization: 'json' });
    expect(doc.namespace).toBe(document.namespace);
    expect(doc.created).toBe('2026-07-17T12:00:00Z');
    expect(doc.creators).toEqual(document.creators);
    expect(doc.describes).toEqual(document.describes);
    expect(doc.externalDocumentRefs).toEqual(document.externalDocumentRefs);
    expect(doc.elements.map((e) => [e.spdxId, e.purl])).toEqual(
      document.elements.map((e) => [e.spdxId, e.purl]),
    );
    const external = doc.relationships.find((r) => r.to.kind === 'external');
    expect(external?.type).toBe('DESCRIBED_BY');
  });

  it('keeps colliding sanitized SPDX ids unique', async () => {
    const result = validateComposeConfig({
      schema: 'sbomloom-compose/v1',
      product: { name: 'p', version: '1', namespace: 'urn:acme:p' },
      artifacts: [{ name: 'app one' }, { name: 'app-one' }],
    });
    if (!result.ok) throw new Error(result.errors.join());
    const { document } = await composeDocument(result.config, [], OPTS);
    const ids = document.elements.map((e) => e.spdxId);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toContain('SPDXRef-Package-app-one');
    expect(ids).toContain('SPDXRef-Package-app-one-2');
  });

  it('fails closed on child problems', async () => {
    const cfg = config();
    await expect(composeDocument(cfg, [], OPTS)).rejects.toThrow(/no child bytes were supplied/);
    await expect(
      composeDocument(cfg, [{ artifact: 'webstack', fileName: 'x.txt', bytes: new TextEncoder().encode('hello') }], OPTS),
    ).rejects.toThrow(/did not parse/);
    const noNamespace = CHILD_JSON.replace(/"documentNamespace": "[^"]+",\n\s*/, '');
    await expect(
      composeDocument(cfg, [{ artifact: 'webstack', fileName: 'x.spdx.json', bytes: new TextEncoder().encode(noNamespace) }], OPTS),
    ).rejects.toThrow(/no documentNamespace/);
    await expect(
      composeDocument(cfg, [...children(), { artifact: 'ghost', fileName: 'g.json', bytes: new Uint8Array(1) }], OPTS),
    ).rejects.toThrow(/unknown artifacts: ghost/);
    await expect(composeDocument(cfg, [...children(), ...children()], OPTS)).rejects.toThrow(
      /more than one child SBOM/,
    );
    await expect(composeDocument(cfg, children(), { created: '17.07.2026' })).rejects.toThrow(ComposeError);
  });

  it('emit refuses documents missing SPDX mandatory metadata', async () => {
    const { document } = await composeDocument(config(), children(), OPTS);
    expect(() => emitSpdx23Json({ ...document, namespace: null })).toThrow(/documentNamespace/);
    expect(() => emitSpdx23Json({ ...document, created: undefined })).toThrow(/creationInfo/);
    expect(() => emitSpdx23Json({ ...document, creators: [] })).toThrow(/creationInfo/);
  });

  it('emits packages with mandatory 2.3 fields and the purl as external ref', async () => {
    const { document } = await composeDocument(config(), children(), OPTS);
    const out = JSON.parse(emitSpdx23Json(document)) as {
      packages: Record<string, unknown>[];
      externalDocumentRefs: Record<string, unknown>[];
    };
    for (const pkg of out.packages) {
      expect(pkg.downloadLocation).toBe('NOASSERTION');
      expect(pkg.filesAnalyzed).toBe(false);
    }
    const webstack = out.packages.find((p) => p.name === 'webstack')!;
    expect(webstack.primaryPackagePurpose).toBe('CONTAINER');
    expect(webstack.externalRefs).toEqual([
      {
        referenceCategory: 'PACKAGE-MANAGER',
        referenceType: 'purl',
        referenceLocator: 'pkg:oci/webstack@sha256%3Aaabbcc?repository_url=ghcr.io/acme/webstack',
      },
    ]);
    expect(out.externalDocumentRefs[0].externalDocumentId).toBe('DocumentRef-webstack');
    expect((out.externalDocumentRefs[0].checksum as Record<string, unknown>).algorithm).toBe('SHA1');
  });
});
