import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import type { RequestListener, Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
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

    if (url.startsWith('https://registry.example/token')) {
      authHeaderSeenAtToken.push(headers.get('authorization') ?? '');
      tokenGranted = true;
      return Response.json({ token: 'TESTTOKEN' });
    }
    if (opts?.requireAuth && headers.get('authorization') !== 'Bearer TESTTOKEN') {
      return new Response('unauthorized', {
        status: 401,
        headers: {
          'www-authenticate':
            'Bearer realm="https://registry.example/token",service="registry.example",scope="repository:acme/component-descriptors/acme.org/fetched:pull"',
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

/** A registry that answers 401 with the given realm until the realm's token arrives. */
function challengingRegistry(realm: string) {
  const calls: string[] = [];
  const tokenRedirect: (string | undefined)[] = [];
  const fetchFn = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const url = String(input);
    calls.push(url);
    if (!url.endsWith('/tags/list')) {
      tokenRedirect.push(init?.redirect);
      return Response.json({ access_token: 'GRANTED' });
    }
    if (new Headers(init?.headers).get('authorization') === 'Bearer GRANTED') {
      return Response.json({ tags: ['1.0.0'] });
    }
    return new Response('unauthorized', {
      status: 401,
      headers: { 'www-authenticate': `Bearer realm="${realm}",service="registry"` },
    });
  }) as typeof fetch;
  return { fetchFn, calls, tokenRedirect };
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

  // The realm is the registry's word: a registry must not be able to send the
  // extension host (or a stored credential) to a URL of its choosing.
  it.each([
    'http://intern.test:8080/geheim#',
    'https://intern.test/token',
    'http://registry.example/token',
    'https://registry.example.intern.test/token',
    'https://registry.example@intern.test/token',
    'https://auth.docker.io/token',
    '//intern.test/token',
  ])('does not request the bearer realm %s', async (realm) => {
    const registry = challengingRegistry(realm);
    const client = createOcmRegistryClient({
      fetchFn: registry.fetchFn,
      credentialFor: () => Promise.resolve({ username: 'me', password: 'PAT' }),
    });
    const result = await client.listVersions('registry.example', 'acme/x');
    expect(registry.calls).toEqual(['https://registry.example/v2/component-descriptors/acme/x/tags/list']);
    expect(result).toEqual({
      ok: false,
      error: 'registry.example: HTTP 401 for component-descriptors/acme/x tags',
    });
  });

  it.each([
    ['registry.example', 'https://registry.example/token'],
    ['registry.example:5050', 'https://registry.example/jwt/auth'],
    ['registry-1.docker.io', 'https://auth.docker.io/token'],
    ['registry.gitlab.com', 'https://gitlab.com/jwt/auth'],
  ])('requests the token for %s from %s, without following redirects', async (host, realm) => {
    const registry = challengingRegistry(realm);
    const client = createOcmRegistryClient({ fetchFn: registry.fetchFn });
    const result = await client.listVersions(host, 'acme/x');
    expect(result).toEqual({ ok: true, versions: ['1.0.0'] });
    expect(registry.calls[1]).toBe(
      `${realm}?service=registry&scope=repository%3Acomponent-descriptors%2Facme%2Fx%3Apull`,
    );
    expect(registry.tokenRedirect).toEqual(['manual']);
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
 * A redirect is the registry's word: it must not be able to send the
 * extension host to a host the caller did not name. The scripted fetch here
 * behaves like the real one: it follows a Location on its own unless told
 * `manual`, and drops Authorization when the origin changes. So every address
 * the extension host would have requested shows up in `calls`.
 */
function followingFetch(respond: (url: URL, headers: Headers) => Response | Promise<Response>) {
  const calls: { url: string; authorization: string | null }[] = [];
  const fetchFn = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    let url = new URL(String(input));
    for (let hop = 0; hop <= 20; hop++) {
      calls.push({ url: url.href, authorization: headers.get('authorization') });
      const response = await respond(url, headers);
      const location = response.headers.get('location');
      if (init?.redirect === 'manual' || !location) return response;
      const next = new URL(location, url);
      if (next.origin !== url.origin) headers.delete('authorization');
      url = next;
    }
    throw new TypeError('redirect count exceeded');
  }) as typeof fetch;
  return { fetchFn, calls, hosts: () => calls.map((call) => new URL(call.url).host) };
}

function redirectTo(location: string, status = 307): Response {
  return new Response(null, { status, headers: { location } });
}

function challenge(realm: string): Response {
  return new Response('unauthorized', {
    status: 401,
    headers: { 'www-authenticate': `Bearer realm="${realm}",service="registry"` },
  });
}

describe('redirects', () => {
  const TAGS_URL = 'https://registry.example/v2/component-descriptors/acme/x/tags/list';
  const servers: Server[] = [];

  function listen(handler: RequestListener): Promise<string> {
    return new Promise((resolve) => {
      const server = createServer(handler);
      servers.push(server);
      server.listen(0, '127.0.0.1', () => {
        resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`);
      });
    });
  }

  afterEach(() => {
    for (const server of servers.splice(0)) {
      server.closeAllConnections();
      server.close();
    }
  });

  it.each([301, 302, 303, 307, 308])(
    'does not follow a %i of the registry to an http address (real fetch)',
    async (status) => {
      const foreign: (string | undefined)[] = [];
      const foreignHost = await listen((req, res) => {
        foreign.push(req.url);
        res.end('{}');
      });
      const registryHost = await listen((_req, res) => {
        res.writeHead(status, { location: `${foreignHost}/x` }).end();
      });
      // The client only speaks https: map the registry onto the local server.
      const fetchFn = ((input: Parameters<typeof fetch>[0], init?: RequestInit) =>
        fetch(String(input).replace('https://registry.example', registryHost), init)) as typeof fetch;
      const client = createOcmRegistryClient({ fetchFn });

      const versions = await client.listVersions('registry.example', 'acme/x');
      const resolved = await client.fetchComponentVersion('registry.example', 'acme/x', '1.0.0');

      expect(foreign).toEqual([]);
      expect(versions).toEqual({
        ok: false,
        error: `registry.example: HTTP ${status} for component-descriptors/acme/x tags`,
      });
      expect(resolved).toEqual({
        ok: false,
        error: `registry.example/component-descriptors/acme/x: manifest 1.0.0: HTTP ${status}`,
      });
    },
  );

  it.each([
    'https://intern.test/x',
    'https://registry.example:8443/x',
    'https://registry.example.intern.test/x',
    'https://registry.example@intern.test/x',
    'https://pkg-containers.githubusercontent.com/x',
    '//intern.test/x',
  ])('follows a redirect to %s, and the token stays with the registry', async (location) => {
    const { fetchFn, calls } = followingFetch((url, headers) => {
      if (url.pathname === '/token') return Response.json({ token: 'TESTTOKEN' });
      if (url.href !== TAGS_URL) return Response.json({ tags: ['1.0.0'] });
      return headers.get('authorization') === 'Bearer TESTTOKEN'
        ? redirectTo(location)
        : challenge('https://registry.example/token');
    });
    const client = createOcmRegistryClient({ fetchFn });
    const result = await client.listVersions('registry.example', 'acme/x');
    expect(result).toEqual({ ok: true, versions: ['1.0.0'] });
    const followed = calls.at(-1)!;
    expect(new URL(followed.url).origin).not.toBe('https://registry.example');
    expect(followed.authorization).toBeNull();
  });

  it.each(['http://intern.test:8080/x', 'http://registry.example/x', 'file:///etc/passwd'])(
    'does not follow a redirect to %s',
    async (location) => {
      const { fetchFn, calls } = followingFetch((url) =>
        url.href === TAGS_URL ? redirectTo(location) : Response.json({ tags: ['1.0.0'] }),
      );
      const client = createOcmRegistryClient({ fetchFn });
      const result = await client.listVersions('registry.example', 'acme/x');
      expect(calls.map((call) => call.url)).toEqual([TAGS_URL]);
      expect(result).toEqual({
        ok: false,
        error: 'registry.example: HTTP 307 for component-descriptors/acme/x tags',
      });
    },
  );

  it('does not follow a blob redirect to an http address', async () => {
    const registry = fakeRegistry();
    const { fetchFn, hosts } = followingFetch((url) =>
      url.pathname.includes('/blobs/') ? redirectTo('http://intern.test/blob') : registry.fetchFn(url),
    );
    const client = createOcmRegistryClient({ fetchFn });
    const result = await client.fetchComponentVersion('registry.example/acme', 'acme.org/fetched', '1.2.3');
    expect(hosts()).toEqual(['registry.example', 'registry.example']);
    expect(result).toEqual({
      ok: false,
      error: 'acme/component-descriptors/acme.org/fetched:1.2.3: descriptor layer HTTP 307',
    });
  });

  it('follows a redirect within the registry and keeps the token there', async () => {
    const registry = fakeRegistry({ requireAuth: true });
    const { fetchFn, calls } = followingFetch((url, headers) =>
      url.pathname.startsWith('/v2/old/')
        ? redirectTo(url.pathname.replace('/v2/old/', '/v2/acme/'), 308)
        : registry.fetchFn(url, { headers }),
    );
    const client = createOcmRegistryClient({ fetchFn });
    const result = await client.listVersions('registry.example/old', 'acme.org/fetched');
    expect(result).toEqual({ ok: true, versions: ['1.2.3', '2.0.0+7'] });
    expect(calls.at(-1)).toEqual({
      url: 'https://registry.example/v2/acme/component-descriptors/acme.org/fetched/tags/list',
      authorization: 'Bearer TESTTOKEN',
    });
  });

  it('follows a registry to its blob store on another host, without the token', async () => {
    const registry = fakeRegistry({ requireAuth: true });
    const { fetchFn, calls } = followingFetch(async (url, headers) => {
      if (url.host === 'pkg-containers.githubusercontent.com') {
        return registry.fetchFn(`https://ghcr.io${url.pathname}`, {
          headers: { authorization: 'Bearer TESTTOKEN' },
        });
      }
      // The realm only counts on the registry's own host, so ghcr.io names itself.
      if (url.pathname === '/token') {
        return registry.fetchFn(`https://registry.example/token${url.search}`, { headers });
      }
      if (url.pathname.includes('/blobs/') && headers.has('authorization')) {
        return redirectTo(`https://pkg-containers.githubusercontent.com${url.pathname}`);
      }
      const response = await registry.fetchFn(url, { headers });
      return response.status === 401 ? challenge('https://ghcr.io/token') : response;
    });
    const client = createOcmRegistryClient({ fetchFn });
    const result = await client.fetchComponentVersion('ghcr.io/acme', 'acme.org/fetched', '1.2.3');
    expect(result.ok).toBe(true);
    const store = calls.filter((call) => call.url.startsWith('https://pkg-containers.githubusercontent.com/'));
    expect(store.map((call) => call.authorization)).toEqual([null, null]);
  });

  it('does not take a 401 of the blob store for a challenge of the registry', async () => {
    const credentialHosts: string[] = [];
    const { fetchFn, hosts } = followingFetch((url) =>
      url.host === 'ghcr.io'
        ? redirectTo('https://pkg-containers.githubusercontent.com/x')
        : challenge('https://intern.test/token'),
    );
    const client = createOcmRegistryClient({
      fetchFn,
      credentialFor: (host) => {
        credentialHosts.push(host);
        return Promise.resolve({ username: 'me', password: 'PAT' });
      },
    });
    const result = await client.listVersions('ghcr.io', 'acme/x');
    expect(hosts()).toEqual(['ghcr.io', 'pkg-containers.githubusercontent.com']);
    expect(credentialHosts).toEqual([]);
    expect(result).toEqual({ ok: false, error: 'ghcr.io: HTTP 401 for component-descriptors/acme/x tags' });
  });

  it('does not follow a redirect of the token endpoint', async () => {
    // The realm passes the check (the registry's own host) and then redirects away.
    const { fetchFn, calls } = followingFetch((url) => {
      if (url.pathname === '/token') return redirectTo('https://intern.test/token');
      if (url.host === 'intern.test') return Response.json({ token: 'FOREIGN' });
      return challenge('https://registry.example/token');
    });
    const client = createOcmRegistryClient({
      fetchFn,
      credentialFor: () => Promise.resolve({ username: 'me', password: 'PAT' }),
    });
    const result = await client.listVersions('registry.example', 'acme/x');
    expect(calls.map((call) => new URL(call.url).host + new URL(call.url).pathname)).toEqual([
      'registry.example/v2/component-descriptors/acme/x/tags/list',
      'registry.example/token',
    ]);
    expect(result).toEqual({
      ok: false,
      error: 'registry.example: HTTP 401 for component-descriptors/acme/x tags',
    });
  });

  it('gives up on a redirect loop', async () => {
    const { fetchFn, calls } = followingFetch((url) => redirectTo(url.pathname));
    const client = createOcmRegistryClient({ fetchFn });
    const result = await client.listVersions('registry.example', 'acme/x');
    expect(calls).toHaveLength(6);
    expect(result).toEqual({
      ok: false,
      error: 'registry.example: HTTP 307 for component-descriptors/acme/x tags',
    });
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
