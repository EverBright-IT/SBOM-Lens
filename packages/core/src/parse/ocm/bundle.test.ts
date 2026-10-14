import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
// @ts-expect-error — plain-JS test/fixture helper without type declarations
import { writeTar } from '../../../scripts/tar-writer.mjs';
import { readOcmBundle } from './bundle';
import { cd, ctfOf } from './test-ctf';

function fixtureBytes(name: string): Uint8Array {
  return new Uint8Array(readFileSync(new URL(`../../../fixtures/${name}`, import.meta.url)));
}

describe('readOcmBundle — committed CTF fixture', () => {
  it('builds the OCM-native model: CVs, graph, completeness, blobs, SBOM link', async () => {
    const result = await readOcmBundle('delivery.ctf.tar', fixtureBytes('ocm/delivery.ctf.tar'));
    const bundle = result.bundle!;
    expect(bundle).not.toBeNull();
    expect(bundle.layout).toBe('ctf');
    expect(bundle.compressed).toBe(false);

    // Two component versions, platform referencing webstack.
    expect(bundle.componentVersions.map((cv) => cv.id).sort()).toEqual([
      'acme.org/platform@1.0.0',
      'acme.org/webstack@2.1.0',
    ]);
    expect(bundle.roots).toEqual(['acme.org/platform@1.0.0']);
    expect(bundle.shared).toEqual([]);

    const platform = bundle.componentVersions.find((cv) => cv.name === 'acme.org/platform')!;
    expect(platform.references).toHaveLength(1);
    expect(platform.references[0]!.target).toBe('acme.org/webstack@2.1.0');
    expect(platform.schemaVersion).toBe('v2');
    expect(platform.provider?.name).toBe('ACME Corp');

    // Transport classification: 4 localBlobs in the archive, 1 ociArtifact.
    const webstack = bundle.componentVersions.find((cv) => cv.name === 'acme.org/webstack')!;
    const byName = new Map(webstack.resources.map((r) => [r.name, r]));
    expect(byName.get('gateway-image')!.transport).toBe('external');
    expect(byName.get('gateway-image')!.location).toBe('registry.example.org/acme/gateway:2.1.0');
    expect(byName.get('webstack-chart')!.transport).toBe('transported');
    expect(byName.get('webstack-chart')!.blob?.digestCheck).toBe('match');
    expect(byName.get('runtime-config')!.blob?.digestCheck).toBe('mismatch');
    expect(webstack.diagnostics.some((d) => d.code === 'OCM_DIGEST_MISMATCH')).toBe(true);

    expect(bundle.completeness).toMatchObject({
      transported: 4,
      external: 1,
      broken: 0,
      unknown: 0,
      none: 0,
      unresolvedRefs: 0,
      airGapReady: false,
    });

    // The embedded SBOM is extracted and linked to its resource.
    const sbomResource = byName.get('webstack-sbom')!;
    expect(sbomResource.sbom?.format).toBe('spdx');
    expect(result.extracted[sbomResource.sbom!.extractedIndex]!.fileName).toBe(sbomResource.sbom!.fileName);

    // Blob statistics: webstack's four non-CD layers, no dedup in this bundle.
    expect(bundle.blobs).toHaveLength(4);
    expect(bundle.blobs.every((b) => b.referencedBy.includes('acme.org/webstack@2.1.0'))).toBe(true);
    expect(bundle.dedupSavedBytes).toBe(0);
    expect(bundle.blobs[0]!.size).toBeGreaterThanOrEqual(bundle.blobs.at(-1)!.size);
  });

  it('reads a component archive as a single-CV bundle', async () => {
    const result = await readOcmBundle('component-archive.tar', fixtureBytes('ocm/component-archive.tar'));
    const bundle = result.bundle!;
    expect(bundle.layout).toBe('component-archive');
    expect(bundle.componentVersions).toHaveLength(1);
    expect(bundle.roots).toEqual(['acme.org/webstack@2.1.0']);
  });
});

describe('readOcmBundle — graph topology', () => {
  it('resolves a diamond: two paths into one shared CV', async () => {
    const bytes = ctfOf([
      cd('acme.org/root', '1.0.0', [
        ['acme.org/left', '1.0.0'],
        ['acme.org/right', '1.0.0'],
      ]),
      cd('acme.org/left', '1.0.0', [['acme.org/base', '1.0.0']]),
      cd('acme.org/right', '1.0.0', [['acme.org/base', '1.0.0']]),
      cd('acme.org/base', '1.0.0', []),
    ]);
    const { bundle } = await readOcmBundle('diamond.ctf.tar', bytes);
    expect(bundle!.roots).toEqual(['acme.org/root@1.0.0']);
    expect(bundle!.shared).toEqual(['acme.org/base@1.0.0']);
    expect(bundle!.completeness.unresolvedRefs).toBe(0);
  });

  it('marks cycle-closing edges and still exposes an entry point', async () => {
    const bytes = ctfOf([
      cd('acme.org/a', '1.0.0', [['acme.org/b', '1.0.0']]),
      cd('acme.org/b', '1.0.0', [['acme.org/a', '1.0.0']]),
    ]);
    const { bundle } = await readOcmBundle('cycle.ctf.tar', bytes);
    const cyclicEdges = bundle!.componentVersions.flatMap((cv) => cv.references).filter((r) => r.cyclic);
    expect(cyclicEdges).toHaveLength(1);
    // The closing edge does not count as incoming, so the cycle surfaces a
    // natural entry point instead of vanishing from the root list.
    expect(bundle!.roots).toEqual(['acme.org/a@1.0.0']);
    expect(bundle!.issues.some((d) => d.code === 'BUNDLE_REFERENCE_CYCLE')).toBe(true);
  });

  it('counts references that point outside the bundle against completeness', async () => {
    const bytes = ctfOf([cd('acme.org/app', '1.0.0', [['acme.org/elsewhere', '9.9.9']])]);
    const { bundle } = await readOcmBundle('open.ctf.tar', bytes);
    expect(bundle!.completeness.unresolvedRefs).toBe(1);
    expect(bundle!.completeness.airGapReady).toBe(false);
    expect(bundle!.issues.some((d) => d.code === 'BUNDLE_REFS_UNRESOLVED')).toBe(true);
    expect(bundle!.componentVersions[0]!.references[0]!.target).toBeUndefined();
  });

  it('keeps one copy of a CV delivered twice with identical content', async () => {
    const same = cd('acme.org/twice', '1.0.0', []);
    const { bundle } = await readOcmBundle('dup.ctf.tar', ctfOf([same, same]));
    expect(bundle!.componentVersions).toHaveLength(1);
    expect(bundle!.issues.some((d) => d.code === 'BUNDLE_DUPLICATE_CV')).toBe(true);
  });
});

describe('readOcmBundle — transport classification', () => {
  it('flags a localBlob whose bytes are missing from the archive as broken', async () => {
    const broken = cd(
      'acme.org/hollow',
      '1.0.0',
      [],
    ).replace(
      '  resources: []\n',
      `  resources:\n    - name: ghost\n      version: 1.0.0\n      type: blob\n      relation: local\n      access:\n        type: localBlob\n        localReference: sha256.${'f'.repeat(64)}\n`,
    );
    const { bundle } = await readOcmBundle('broken.ctf.tar', ctfOf([broken]));
    const ghost = bundle!.componentVersions[0]!.resources[0]!;
    expect(ghost.transport).toBe('broken');
    expect(bundle!.completeness.broken).toBe(1);
    expect(bundle!.completeness.airGapReady).toBe(false);
  });

  it('treats versioned access types (LocalBlob/v1, real CLI output) like their base type', async () => {
    const versioned = cd('acme.org/cli-style', '1.0.0', []).replace(
      '  resources: []\n',
      `  resources:\n    - name: cfg\n      version: 1.0.0\n      type: blob\n      relation: local\n      access:\n        type: LocalBlob/v1\n        localReference: sha256.${'e'.repeat(64)}\n`,
    );
    const { bundle } = await readOcmBundle('cli.ctf.tar', ctfOf([versioned]));
    // The blob is absent, so the honest class is broken — NOT unknown.
    expect(bundle!.componentVersions[0]!.resources[0]!.transport).toBe('broken');
  });

  it('classifies an access type it does not know as unknown, not external', async () => {
    const exotic = cd('acme.org/exotic', '1.0.0', []).replace(
      '  resources: []\n',
      '  resources:\n    - name: odd\n      version: 1.0.0\n      type: blob\n      relation: local\n      access:\n        type: fancyNewProtocol\n        locator: somewhere\n',
    );
    const { bundle } = await readOcmBundle('exotic.ctf.tar', ctfOf([exotic]));
    expect(bundle!.componentVersions[0]!.resources[0]!.transport).toBe('unknown');
    expect(bundle!.completeness.airGapReady).toBe(false);
  });
});

describe('bundleFromDescriptor — bare descriptor files', () => {
  it('builds a single-CV descriptor bundle; localBlobs are honestly broken', async () => {
    const text = cd('acme.org/solo', '3.0.0', [['acme.org/dep', '1.0.0']]).replace(
      '  resources: []\n',
      `  resources:\n    - name: cfg\n      version: 3.0.0\n      type: blob\n      relation: local\n      access:\n        type: localBlob\n        localReference: sha256.${'d'.repeat(64)}\n`,
    );
    const result = await (await import('./bundle')).bundleFromDescriptor('solo.yaml', text);
    const bundle = result.bundle!;
    expect(bundle.layout).toBe('descriptor');
    expect(bundle.componentVersions[0]!.fileName).toBe('solo.yaml');
    expect(bundle.componentVersions[0]!.resources[0]!.transport).toBe('broken');
    expect(bundle.completeness.unresolvedRefs).toBe(1);
  });

  it('rejects non-descriptor text with one honest diagnostic', async () => {
    const result = await (await import('./bundle')).bundleFromDescriptor('note.txt', 'hello world');
    expect(result.bundle).toBeNull();
    expect(result.diagnostics[0]!.code).toBe('OCM_NOT_A_DESCRIPTOR');
  });
});

describe('readOcmBundle — non-bundle inputs', () => {
  it('returns bundle null for a plain SPDX tar (file sweep territory)', async () => {
    const spdx = JSON.stringify({
      spdxVersion: 'SPDX-2.3',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: 'plain',
      documentNamespace: 'https://example.org/plain',
      creationInfo: { created: '2024-01-01T00:00:00Z', creators: ['Tool: test'] },
      packages: [],
    });
    const bytes = new Uint8Array(writeTar([{ name: 'plain.spdx.json', bytes: spdx }]));
    const result = await readOcmBundle('plain.tar', bytes);
    expect(result.bundle).toBeNull();
    expect(result.extracted).toHaveLength(1);
  });
});
