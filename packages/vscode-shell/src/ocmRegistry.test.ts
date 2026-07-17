import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { readOcmDelivery } from '@sbomlens/core/ocm';
import { createOcmBridgeHandler, createOcmRegistryClient, repoFor, tagFromVersion, versionFromTag } from './ocmRegistry';
import { writeTar } from './tar';

/**
 * The registry client against a scripted fetch: the OCI auth dance, the
 * tag/version mapping, layer selection with caps — and the proof that the
 * CTF it packs runs through the real delivery walker unchanged.
 */

const CD_MEDIA = 'application/vnd.ocm.software.component-descriptor.v2+yaml';

function sha256(bytes: Uint8Array | string): string {
  return createHash('sha256').update(bytes).digest('hex');
}

const CD_TEXT = [
  'meta:',
  '  schemaVersion: v2',
  'component:',
  '  name: acme.org/fetched',
  '  version: 1.2.3',
  '  provider: ACME',
  '  componentReferences: []',
  '  sources: []',
  '  resources:',
  '    - name: runtime-config',
  '      version: 1.2.3',
  '      type: plainText',
  '      relation: local',
  '      access:',
  '        type: localBlob',
  '        localReference: sha256:CONFIGDIGEST',
  '        mediaType: text/plain',
  '      digest:',
  '        hashAlgorithm: SHA-256',
  '        normalisationAlgorithm: genericBlobDigest/v1',
  '        value: "CONFIGVALUE"',
].join('\n');

/** A tiny fake registry: token endpoint + tags + manifest + blobs. */
function fakeRegistry(opts?: { requireAuth?: boolean; hugeLayer?: boolean }) {
  const configBytes = new TextEncoder().encode('replicas: 3\n');
  const configDigest = sha256(configBytes);
  const cdText = CD_TEXT.replace('CONFIGDIGEST', configDigest).replace('CONFIGVALUE', configDigest);
  const cdBytes = new TextEncoder().encode(cdText);
  const cdDigest = sha256(cdBytes);
  const hugeSize = 999 * 1024 * 1024;

  const manifest = {
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    layers: [
      { mediaType: CD_MEDIA, digest: `sha256:${cdDigest}`, size: cdBytes.byteLength },
      { mediaType: 'text/plain', digest: `sha256:${configDigest}`, size: configBytes.byteLength },
      ...(opts?.hugeLayer
        ? [{ mediaType: 'application/octet-stream', digest: `sha256:${'9'.repeat(64)}`, size: hugeSize }]
        : []),
    ],
  };

  const calls: string[] = [];
  let tokenGranted = false;
  const authHeaderSeenAtToken: string[] = [];

  const fetchFn = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const url = String(input);
    calls.push(url);
    const headers = new Headers(init?.headers);

    if (url.startsWith('https://auth.example/token')) {
      authHeaderSeenAtToken.push(headers.get('authorization') ?? '');
      tokenGranted = true;
      return Response.json({ token: 'TESTTOKEN' });
    }
    if (opts?.requireAuth && headers.get('authorization') !== 'Bearer TESTTOKEN') {
      return new Response('unauthorized', {
        status: 401,
        headers: {
          'www-authenticate':
            'Bearer realm="https://auth.example/token",service="registry.example",scope="repository:acme/component-descriptors/acme.org/fetched:pull"',
        },
      });
    }
    if (url.endsWith('/tags/list')) {
      return Response.json({ name: 'x', tags: ['1.2.3', '2.0.0.build-7'] });
    }
    if (url.includes('/manifests/')) {
      return Response.json(manifest);
    }
    if (url.endsWith(`/blobs/sha256:${cdDigest}`)) {
      return new Response(new Uint8Array(cdBytes));
    }
    if (url.endsWith(`/blobs/sha256:${configDigest}`)) {
      return new Response(new Uint8Array(configBytes));
    }
    return new Response('not found', { status: 404 });
  }) as typeof fetch;

  return { fetchFn, calls, authHeaderSeenAtToken, configDigest, wasTokenGranted: () => tokenGranted };
}

describe('repo mapping', () => {
  it('maps registry base paths and the tag/version build metadata', () => {
    expect(repoFor('ghcr.io/acme/ocm', 'acme.org/webstack')).toEqual({
      host: 'ghcr.io',
      repo: 'acme/ocm/component-descriptors/acme.org/webstack',
    });
    expect(repoFor('oci://registry.example/', 'a/b')).toEqual({
      host: 'registry.example',
      repo: 'component-descriptors/a/b',
    });
    expect(tagFromVersion('2.0.0+7')).toBe('2.0.0.build-7');
    expect(versionFromTag('2.0.0.build-7')).toBe('2.0.0+7');
  });
});

describe('listVersions', () => {
  it('lists tags anonymously and maps build metadata back', async () => {
    const registry = fakeRegistry();
    const client = createOcmRegistryClient({ fetchFn: registry.fetchFn });
    const result = await client.listVersions('registry.example/acme', 'acme.org/fetched');
    expect(result).toEqual({ ok: true, versions: ['1.2.3', '2.0.0+7'] });
  });

  it('runs the bearer dance on 401 and retries with the token', async () => {
    const registry = fakeRegistry({ requireAuth: true });
    const client = createOcmRegistryClient({ fetchFn: registry.fetchFn });
    const result = await client.listVersions('registry.example/acme', 'acme.org/fetched');
    expect(result.ok).toBe(true);
    expect(registry.wasTokenGranted()).toBe(true);
    expect(registry.authHeaderSeenAtToken[0]).toBe(''); // anonymous token request
  });

  it('sends a stored credential as Basic to the token endpoint', async () => {
    const registry = fakeRegistry({ requireAuth: true });
    const client = createOcmRegistryClient({
      fetchFn: registry.fetchFn,
      credentialFor: () => Promise.resolve({ username: 'me', password: 'PAT' }),
    });
    await client.listVersions('registry.example/acme', 'acme.org/fetched');
    expect(registry.authHeaderSeenAtToken[0]).toBe(`Basic ${Buffer.from('me:PAT').toString('base64')}`);
  });
});

describe('fetchComponentVersion', () => {
  it('packs a CTF that the real delivery walker reads: descriptor, blob, digest match', async () => {
    const registry = fakeRegistry({ requireAuth: true });
    const client = createOcmRegistryClient({ fetchFn: registry.fetchFn });
    const result = await client.fetchComponentVersion('registry.example/acme', 'acme.org/fetched', '1.2.3');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.fileName).toBe('registry.example/acme.org/fetched@1.2.3.ctf');
    expect(result.skippedLayers).toBe(0);

    const delivery = await readOcmDelivery(result.fileName, result.ctf);
    expect(delivery.documents).toHaveLength(1);
    const doc = delivery.documents[0]!.document;
    expect(doc.name).toBe('acme.org/fetched');
    const config = doc.elements.find((e) => e.name === 'runtime-config')!;
    expect(config.ocm!.blob!.kind).toBe('text');
    expect(config.ocm!.blob!.digestCheck).toBe('match');
  });

  it('skips layers above the cap but still delivers the descriptor', async () => {
    const registry = fakeRegistry({ hugeLayer: true });
    const client = createOcmRegistryClient({ fetchFn: registry.fetchFn });
    const result = await client.fetchComponentVersion('registry.example/acme', 'acme.org/fetched', '1.2.3');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.skippedLayers).toBe(1);
    const delivery = await readOcmDelivery(result.fileName, result.ctf);
    expect(delivery.documents[0]!.document.name).toBe('acme.org/fetched');
  });

  it('fails honestly when the manifest has no component-descriptor layer', async () => {
    const fetchFn = (async () =>
      Response.json({ schemaVersion: 2, layers: [{ mediaType: 'text/plain', digest: 'sha256:aa', size: 2 }] })) as typeof fetch;
    const client = createOcmRegistryClient({ fetchFn });
    const result = await client.fetchComponentVersion('r.example', 'a/b', '1.0.0');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain('no component-descriptor layer');
  });

  it('follows an image index to the referenced manifest', async () => {
    const registry = fakeRegistry();
    const inner = registry.fetchFn;
    let indexServed = false;
    const fetchFn = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      const url = String(input);
      if (url.includes('/manifests/1.2.3') && !indexServed) {
        indexServed = true;
        return Response.json({
          schemaVersion: 2,
          mediaType: 'application/vnd.oci.image.index.v1+json',
          manifests: [{ digest: 'sha256:deadbeef', mediaType: 'application/vnd.oci.image.manifest.v1+json' }],
        });
      }
      if (url.includes('/manifests/sha256:deadbeef')) {
        return inner(url.replace('sha256:deadbeef', '1.2.3'), init);
      }
      return inner(input, init);
    }) as typeof fetch;
    const client = createOcmRegistryClient({ fetchFn });
    const result = await client.fetchComponentVersion('registry.example/acme', 'acme.org/fetched', '1.2.3');
    expect(result.ok).toBe(true);
  });
});

/**
 * Live smoke against the real public OCM registry (the ocm CLI publishes
 * itself as a component). Opt-in via GHCR_SMOKE=1 — network tests never run
 * in CI, but the auth dance, tag mapping, and layer handling get a real
 * counterpart on demand: GHCR_SMOKE=1 npx vitest run packages/vscode-shell
 */
describe.runIf(process.env.GHCR_SMOKE === '1')('live: ghcr.io/open-component-model', () => {
  it('lists and fetches ocm.software/ocmcli, and the walker reads it', async () => {
    const client = createOcmRegistryClient();
    const registry = 'ghcr.io/open-component-model/ocm';
    const component = 'ocm.software/ocmcli';

    const versions = await client.listVersions(registry, component);
    expect(versions.ok, JSON.stringify(versions)).toBe(true);
    if (!versions.ok) return;
    const releases = versions.versions.filter((v) => !v.includes('-'));
    expect(releases.length).toBeGreaterThan(0);

    const version = releases[releases.length - 1]!;
    const resolved = await client.fetchComponentVersion(registry, component, version);
    expect(resolved.ok, JSON.stringify(resolved)).toBe(true);
    if (!resolved.ok) return;

    const delivery = await readOcmDelivery(resolved.fileName, resolved.ctf);
    expect(delivery.documents, JSON.stringify(delivery.diagnostics)).toHaveLength(1);
    expect(delivery.documents[0]!.document.name).toBe(component);
     
    console.log(
      `live smoke: ${component}@${version}, ctf ${Math.round(resolved.ctf.byteLength / 1024)} KB, ` +
        `${resolved.skippedLayers} layers skipped, ${delivery.documents[0]!.document.elements.length} elements`,
    );
  }, 120_000);
});

describe('tar writer parity', () => {
  it('produces bytes the fixture writer would (sorted, deterministic)', () => {
    const a = writeTar([
      { name: 'b.txt', bytes: 'B' },
      { name: 'a.txt', bytes: 'A' },
    ]);
    const b = writeTar([
      { name: 'a.txt', bytes: 'A' },
      { name: 'b.txt', bytes: 'B' },
    ]);
    expect(a).toEqual(b);
    expect(sha256(a)).toBe(sha256(b));
  });
});

describe('createOcmBridgeHandler', () => {
  it('answers ocmListVersions and claims the message', async () => {
    const posted: unknown[] = [];
    const handler = createOcmBridgeHandler(
      {
        listVersions: async () => ({ ok: true, versions: ['1.0.0'] }),
        fetchComponentVersion: async () => ({ ok: false, error: 'unused' }),
      },
      (m) => posted.push(m),
    );
    const claimed = await handler({ type: 'ocmListVersions', id: 7, registry: 'r', component: 'c' });
    expect(claimed).toBe(true);
    expect(posted).toEqual([{ type: 'ocmVersions', id: 7, ok: true, versions: ['1.0.0'] }]);
  });

  it('pushes the resolved CTF as an ingest, then reports ocmResolved', async () => {
    const posted: { type: string }[] = [];
    const ctf = new Uint8Array([1, 2, 3]);
    const handler = createOcmBridgeHandler(
      {
        listVersions: async () => ({ ok: false, error: 'unused' }),
        fetchComponentVersion: async () => ({ ok: true, fileName: 'r/c@1.ctf', ctf, skippedLayers: 2 }),
      },
      (m) => posted.push(m),
    );
    await handler({ type: 'ocmResolve', id: 9, registry: 'r', component: 'c', version: '1' });
    expect(posted.map((m) => m.type)).toEqual(['ingestFiles', 'ocmResolved']);
    expect(posted[1]).toMatchObject({ id: 9, ok: true, skippedLayers: 2 });
  });

  it('reports failures without an ingest push and ignores foreign messages', async () => {
    const posted: { type: string }[] = [];
    const handler = createOcmBridgeHandler(
      {
        listVersions: async () => ({ ok: false, error: 'unused' }),
        fetchComponentVersion: async () => ({ ok: false, error: 'HTTP 404' }),
      },
      (m) => posted.push(m),
    );
    await handler({ type: 'ocmResolve', id: 1, registry: 'r', component: 'c', version: '1' });
    expect(posted.map((m) => m.type)).toEqual(['ocmResolved']);
    expect(posted[0]).toMatchObject({ ok: false, error: 'HTTP 404' });
    expect(await handler({ type: 'ready' })).toBe(false);
  });
});
