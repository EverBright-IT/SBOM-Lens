import { describe, expect, it } from 'vitest';
import type { PartRead } from './oci';
import { OCI_MANIFEST_MAX, carriesComponentDescriptor, mayBeOciContent, ociContent, storedArtifactParts } from './oci';

const bytesOf = (value: unknown) => new TextEncoder().encode(typeof value === 'string' ? value : JSON.stringify(value));
const d = (n: number) => `sha256:${n.toString(16).padStart(64, '0')}`;
const manifestOf = (config: number, layers: number[], extra: Record<string, unknown> = {}) => ({
  schemaVersion: 2,
  mediaType: 'application/vnd.oci.image.manifest.v1+json',
  config: { mediaType: 'application/vnd.oci.image.config.v1+json', digest: d(config), size: 10 },
  layers: layers.map((n) => ({ mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip', digest: d(n), size: 20 })),
  ...extra,
});
const indexOf = (manifests: number[], extra: Record<string, unknown> = {}) => ({
  schemaVersion: 2,
  mediaType: 'application/vnd.oci.image.index.v1+json',
  manifests: manifests.map((n) => ({ mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: d(n), size: 30 })),
  ...extra,
});

describe('ociContent', () => {
  it('reads an image manifest and an index, OCI and Docker spellings, with or without a media type', () => {
    expect(ociContent(bytesOf(manifestOf(1, [2, 3])))).toMatchObject({
      kind: 'manifest',
      config: { digest: d(1), size: 10, role: 'config' },
      layers: [
        { digest: d(2), role: 'layer' },
        { digest: d(3), role: 'layer' },
      ],
    });
    expect(ociContent(bytesOf(indexOf([4, 5])))).toMatchObject({
      kind: 'index',
      manifests: [
        { digest: d(4), size: 30, role: 'manifest' },
        { digest: d(5), role: 'manifest' },
      ],
    });
    const docker = { ...indexOf([4]), mediaType: 'application/vnd.docker.distribution.manifest.list.v2+json' };
    expect(ociContent(bytesOf(docker))?.kind).toBe('index');
    const untyped: Record<string, unknown> = manifestOf(1, []);
    delete untyped.mediaType;
    expect(ociContent(bytesOf(untyped))?.kind).toBe('manifest');
    expect(ociContent(bytesOf(`\n  ${JSON.stringify(manifestOf(1, [2]))}`))?.kind).toBe('manifest');
  });

  it('takes nothing else for a manifest', () => {
    const cases: unknown[] = [
      { config: { digest: d(1) }, layers: [] }, // no schema version
      { ...manifestOf(1, []), schemaVersion: 1 },
      { ...manifestOf(1, [2]), layers: [{ mediaType: 'x' }] }, // a layer without a digest
      { ...manifestOf(1, []), config: { digest: 'not a digest' } },
      { ...manifestOf(1, []), mediaType: 'application/vnd.oci.image.index.v1+json' }, // says index, is no index
      { ...indexOf([1]), mediaType: 'application/vnd.oci.image.manifest.v1+json' }, // says manifest, is no manifest
      { ...indexOf([1]), layers: [] },
      { schemaVersion: 2, config: { digest: d(1) } }, // no layers
      [manifestOf(1, [])],
      'null',
    ];
    for (const value of cases) expect(ociContent(bytesOf(value)), JSON.stringify(value)).toBeUndefined();
    expect(ociContent(new Uint8Array(0))).toBeUndefined();
    expect(ociContent(bytesOf('{"schemaVersion":2,'))).toBeUndefined();
    const padded = bytesOf(JSON.stringify(manifestOf(1, [2])) + ' '.repeat(OCI_MANIFEST_MAX));
    expect(ociContent(padded)).toBeUndefined();
  });

  it('keeps a declared size only when it is one', () => {
    const odd = { ...manifestOf(1, []), config: { digest: d(1), size: -5 } };
    expect(ociContent(bytesOf(odd))).toMatchObject({ config: { size: 0 } });
  });
});

describe('mayBeOciContent and carriesComponentDescriptor', () => {
  it('lets only a JSON object through the head check', () => {
    expect(mayBeOciContent(bytesOf('{"a":1}'))).toBe(true);
    expect(mayBeOciContent(bytesOf('  \n{'))).toBe(true);
    expect(mayBeOciContent(bytesOf('   '))).toBe(true);
    expect(mayBeOciContent(new Uint8Array([0x1f, 0x8b, 0x08]))).toBe(false);
    expect(mayBeOciContent(bytesOf('[1]'))).toBe(false);
  });

  it('tells a descriptor manifest from an artifact', () => {
    expect(carriesComponentDescriptor(manifestOf(1, [2]))).toBe(false);
    expect(
      carriesComponentDescriptor({ config: { mediaType: 'application/vnd.ocm.software.component.config.v1+json' } }),
    ).toBe(true);
    expect(
      carriesComponentDescriptor({
        layers: [{ mediaType: 'application/vnd.gardener.cloud.cnudie.component-descriptor.v2+yaml+tar' }],
      }),
    ).toBe(true);
  });
});

describe('storedArtifactParts', () => {
  const reader = (blobs: Record<string, unknown>) => async (digest: string): Promise<PartRead> => {
    const value = blobs[digest];
    if (value === undefined) return 'absent';
    if (value === 'unreadable') return 'unreadable';
    return bytesOf(value);
  };

  it('lists config and layers of a manifest without reading anything', async () => {
    const content = ociContent(bytesOf(manifestOf(1, [2, 3, 2])))!;
    const { parts, opaque } = await storedArtifactParts(content, async () => {
      throw new Error('a manifest needs no reads');
    });
    expect(parts.map((p) => [p.digest, p.role])).toEqual([
      [d(1), 'config'],
      [d(2), 'layer'],
      [d(3), 'layer'],
    ]);
    expect(opaque).toBe(0);
  });

  it('follows an index down to every layer, each blob once', async () => {
    const content = ociContent(bytesOf(indexOf([10, 20])))!;
    const { parts, opaque } = await storedArtifactParts(
      content,
      reader({ [d(10)]: manifestOf(11, [12, 13]), [d(20)]: manifestOf(21, [13, 22]) }),
    );
    expect(parts.map((p) => [p.digest, p.role])).toEqual([
      [d(10), 'manifest'],
      [d(11), 'config'],
      [d(12), 'layer'],
      [d(13), 'layer'],
      [d(20), 'manifest'],
      [d(21), 'config'],
      [d(22), 'layer'],
    ]);
    expect(opaque).toBe(0);
  });

  it('counts what it cannot read below, and stops at a nesting limit and at cycles', async () => {
    const content = ociContent(bytesOf(indexOf([10, 20, 30])))!;
    const result = await storedArtifactParts(
      content,
      reader({ [d(10)]: { note: 'no manifest' }, [d(20)]: 'unreadable' /* 30 absent */ }),
    );
    expect(result.parts.map((p) => p.digest)).toEqual([d(10), d(20), d(30)]);
    expect(result.opaque).toBe(2); // the absent one is the part itself missing

    // An index naming itself (only possible with swapped bytes) ends.
    const looping = await storedArtifactParts(ociContent(bytesOf(indexOf([40])))!, reader({ [d(40)]: indexOf([40]) }));
    expect(looping.parts.map((p) => p.digest)).toEqual([d(40)]);

    // Indexes of indexes: legal, but not without end.
    const chain: Record<string, unknown> = {};
    for (let n = 50; n < 60; n++) chain[d(n)] = indexOf([n + 1]);
    const deep = await storedArtifactParts(ociContent(bytesOf(indexOf([50])))!, reader(chain));
    expect(deep.opaque).toBe(1);
    expect(deep.parts.length).toBeLessThan(10);
  });
});
