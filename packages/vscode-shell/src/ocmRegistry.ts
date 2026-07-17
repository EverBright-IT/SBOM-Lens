import { createHash } from 'node:crypto';
import type { HostToWebviewMessage, WebviewToHostMessage } from '@sbomlens/web/vscode-protocol';
import { writeTar } from './tar';

/**
 * OCI-distribution client for OCM component versions, running in the
 * extension host (Node fetch, no CORS). It downloads a component version's
 * OCI manifest and layers and packs them into a CTF-shaped tar — exactly
 * the artifact-set layout the delivery walker already reads, so descriptor
 * mapping, SBOM extraction, digest verdicts, and signature verification all
 * come for free downstream. Dependency-injected fetch and credentials keep
 * it testable without vscode and without a network.
 */

export interface RegistryCredential {
  /** Sent as Basic auth to the token endpoint (`user:password` / `user:PAT`). */
  username: string;
  password: string;
}

export interface RegistryClientOptions {
  fetchFn?: typeof fetch;
  /** Credential for a registry host, e.g. from VS Code secrets. */
  credentialFor?: (host: string) => Promise<RegistryCredential | undefined>;
  /** Layers above this are skipped (the resource shows without content). */
  layerMaxBytes?: number;
  /** Abort once the packed download exceeds this. */
  totalMaxBytes?: number;
}

export type VersionsResult = { ok: true; versions: string[] } | { ok: false; error: string };
export type ResolveResult =
  | { ok: true; fileName: string; ctf: Uint8Array; skippedLayers: number }
  | { ok: false; error: string };

export const LAYER_MAX_BYTES = 50 * 1024 * 1024;
export const TOTAL_MAX_BYTES = 256 * 1024 * 1024;

const CD_MEDIA_PREFIX = 'application/vnd.ocm.software.component-descriptor';
const MANIFEST_ACCEPT = [
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.docker.distribution.manifest.v2+json',
].join(', ');

export interface OcmRegistryClient {
  listVersions(registry: string, component: string): Promise<VersionsResult>;
  fetchComponentVersion(registry: string, component: string, version: string): Promise<ResolveResult>;
}

export function createOcmRegistryClient(options?: RegistryClientOptions): OcmRegistryClient {
  const fetchFn = options?.fetchFn ?? fetch;
  const credentialFor = options?.credentialFor ?? (() => Promise.resolve(undefined));
  const layerMax = options?.layerMaxBytes ?? LAYER_MAX_BYTES;
  const totalMax = options?.totalMaxBytes ?? TOTAL_MAX_BYTES;
  /** Bearer tokens per `${host} ${scope}` — one auth round-trip per repo. */
  const tokens = new Map<string, string>();

  async function authorizedGet(
    host: string,
    url: string,
    accept: string | undefined,
    scopeHint: string,
  ): Promise<Response> {
    const headers: Record<string, string> = accept ? { Accept: accept } : {};
    const cached = tokens.get(`${host} ${scopeHint}`);
    if (cached) headers.Authorization = `Bearer ${cached}`;
    let response = await fetchFn(url, { headers });
    if (response.status !== 401) return response;

    // Bearer challenge: fetch a token from the advertised realm (anonymous
    // works for public registries; a stored credential rides along as Basic).
    const challenge = parseBearerChallenge(response.headers.get('www-authenticate'));
    if (!challenge) return response;
    const params = new URLSearchParams();
    if (challenge.service) params.set('service', challenge.service);
    params.set('scope', challenge.scope ?? scopeHint);
    const tokenHeaders: Record<string, string> = {};
    const credential = await credentialFor(host);
    if (credential) {
      const basic = Buffer.from(`${credential.username}:${credential.password}`).toString('base64');
      tokenHeaders.Authorization = `Basic ${basic}`;
    }
    const tokenResponse = await fetchFn(`${challenge.realm}?${params.toString()}`, { headers: tokenHeaders });
    if (!tokenResponse.ok) return response;
    const body: unknown = await tokenResponse.json().catch(() => null);
    const token =
      body && typeof body === 'object'
        ? ((body as Record<string, unknown>).token ?? (body as Record<string, unknown>).access_token)
        : undefined;
    if (typeof token !== 'string' || token === '') return response;
    tokens.set(`${host} ${challenge.scope ?? scopeHint}`, token);

    response = await fetchFn(url, { headers: { ...headers, Authorization: `Bearer ${token}` } });
    return response;
  }

  async function getManifest(
    host: string,
    repo: string,
    reference: string,
  ): Promise<{ manifest: Record<string, unknown>; bytes: Uint8Array } | { error: string }> {
    const scope = `repository:${repo}:pull`;
    const response = await authorizedGet(
      host,
      `https://${host}/v2/${repo}/manifests/${reference}`,
      MANIFEST_ACCEPT,
      scope,
    );
    if (!response.ok) return { error: `manifest ${reference}: HTTP ${response.status}` };
    const bytes = new Uint8Array(await response.arrayBuffer());
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder().decode(bytes));
    } catch {
      return { error: `manifest ${reference}: not valid JSON` };
    }
    if (parsed === null || typeof parsed !== 'object') return { error: `manifest ${reference}: not an object` };
    const manifest = parsed as Record<string, unknown>;

    // An image index points at the actual manifest; follow the first entry
    // (component-descriptor repositories publish exactly one).
    if (!Array.isArray(manifest.layers) && Array.isArray(manifest.manifests)) {
      const first = manifest.manifests[0] as Record<string, unknown> | undefined;
      const digest = typeof first?.digest === 'string' ? first.digest : undefined;
      if (!digest) return { error: `manifest ${reference}: index without manifests` };
      return getManifest(host, repo, digest);
    }
    return { manifest, bytes };
  }

  return {
    async listVersions(registry, component) {
      try {
        const { host, repo } = repoFor(registry, component);
        const scope = `repository:${repo}:pull`;
        const response = await authorizedGet(host, `https://${host}/v2/${repo}/tags/list`, undefined, scope);
        if (!response.ok) {
          return { ok: false, error: `${host}: HTTP ${response.status} for ${repo} tags` };
        }
        const body: unknown = await response.json().catch(() => null);
        const tags =
          body && typeof body === 'object' && Array.isArray((body as Record<string, unknown>).tags)
            ? ((body as Record<string, unknown>).tags as unknown[]).filter((t): t is string => typeof t === 'string')
            : [];
        return { ok: true, versions: tags.map(versionFromTag).sort() };
      } catch (error) {
        return { ok: false, error: String(error) };
      }
    },

    async fetchComponentVersion(registry, component, version) {
      try {
        const { host, repo } = repoFor(registry, component);
        const scope = `repository:${repo}:pull`;
        const manifestResult = await getManifest(host, repo, tagFromVersion(version));
        if ('error' in manifestResult) return { ok: false, error: `${host}/${repo}: ${manifestResult.error}` };
        const { manifest, bytes: manifestBytes } = manifestResult;

        const layers = (Array.isArray(manifest.layers) ? manifest.layers : []) as Record<string, unknown>[];
        const cdLayer = layers.find(
          (l) => typeof l.mediaType === 'string' && l.mediaType.startsWith(CD_MEDIA_PREFIX),
        );
        if (!cdLayer) return { ok: false, error: `${repo}:${version}: no component-descriptor layer in the manifest` };

        // Download every layer that fits the caps; the component descriptor
        // is mandatory, everything else degrades to "not transported".
        const setEntries: { name: string; bytes: Uint8Array }[] = [];
        let total = manifestBytes.byteLength;
        let skippedLayers = 0;
        for (const layer of layers) {
          const digest = typeof layer.digest === 'string' ? layer.digest : undefined;
          if (!digest) continue;
          const size = typeof layer.size === 'number' ? layer.size : 0;
          const isCd = layer === cdLayer;
          if (!isCd && (size > layerMax || total + size > totalMax)) {
            skippedLayers++;
            continue;
          }
          const blobResponse = await authorizedGet(host, `https://${host}/v2/${repo}/blobs/${digest}`, undefined, scope);
          if (!blobResponse.ok) {
            if (isCd) return { ok: false, error: `${repo}:${version}: descriptor layer HTTP ${blobResponse.status}` };
            skippedLayers++;
            continue;
          }
          const blobBytes = new Uint8Array(await blobResponse.arrayBuffer());
          total += blobBytes.byteLength;
          setEntries.push({ name: `blobs/${digest.replace(':', '.')}`, bytes: blobBytes });
        }

        // CTF shape: artifact-index.json -> artifact-set tar (the manifest
        // plus its layer blobs) — byte-compatible with what `ocm transfer`
        // writes, so the existing walker does the rest.
        const setTar = writeTar([
          { name: 'artifact-set-descriptor.json', bytes: manifestBytes },
          ...setEntries,
        ]);
        const setDigest = createHash('sha256').update(setTar).digest('hex');
        const index = JSON.stringify({
          schemaVersion: 1,
          artifacts: [{ repository: repo, tag: tagFromVersion(version), digest: `sha256:${setDigest}` }],
        });
        const ctf = writeTar([
          { name: 'artifact-index.json', bytes: index },
          { name: `blobs/sha256.${setDigest}`, bytes: setTar },
        ]);
        return { ok: true, fileName: `${host}/${component}@${version}.ctf`, ctf, skippedLayers };
      } catch (error) {
        return { ok: false, error: String(error) };
      }
    },
  };
}

/**
 * The webview-facing half: claims the ocm* bridge messages and answers them
 * through the given post function. The resolved CTF rides the same
 * ingestFiles push as documents opened from disk, so the webview's ingest
 * pipeline stays one code path.
 */
export function createOcmBridgeHandler(
  client: OcmRegistryClient,
  post: (message: HostToWebviewMessage) => void,
): (message: WebviewToHostMessage) => Promise<boolean> {
  return async (message) => {
    if (message.type === 'ocmListVersions') {
      const result = await client.listVersions(message.registry, message.component);
      post(
        result.ok
          ? { type: 'ocmVersions', id: message.id, ok: true, versions: result.versions }
          : { type: 'ocmVersions', id: message.id, ok: false, error: result.error },
      );
      return true;
    }
    if (message.type === 'ocmResolve') {
      const result = await client.fetchComponentVersion(message.registry, message.component, message.version);
      if (result.ok) {
        post({ type: 'ingestFiles', files: [{ fileName: result.fileName, bytes: result.ctf }] });
        post({ type: 'ocmResolved', id: message.id, ok: true, skippedLayers: result.skippedLayers });
      } else {
        post({ type: 'ocmResolved', id: message.id, ok: false, error: result.error });
      }
      return true;
    }
    return false;
  };
}

/**
 * OCM's OCI mapping: the component version lives in
 * `<registry-path>/component-descriptors/<component-name>`. The registry
 * value may carry a base path (`ghcr.io/acme/ocm`).
 */
export function repoFor(registry: string, component: string): { host: string; repo: string } {
  const trimmed = registry.replace(/^oci:\/\/|^https:\/\//, '').replace(/\/+$/, '');
  const slash = trimmed.indexOf('/');
  const host = slash === -1 ? trimmed : trimmed.slice(0, slash);
  const base = slash === -1 ? '' : trimmed.slice(slash + 1);
  const repo = `${base ? `${base}/` : ''}component-descriptors/${component}`;
  return { host, repo };
}

/** OCI tags cannot contain `+`; the ocm CLI maps build metadata to `.build-`. */
export function tagFromVersion(version: string): string {
  return version.replace('+', '.build-');
}

export function versionFromTag(tag: string): string {
  return tag.replace('.build-', '+');
}

function parseBearerChallenge(
  header: string | null,
): { realm: string; service?: string; scope?: string } | null {
  if (!header || !/^bearer /i.test(header)) return null;
  const params = new Map<string, string>();
  for (const match of header.slice('bearer '.length).matchAll(/(\w+)="([^"]*)"/g)) {
    params.set(match[1]!.toLowerCase(), match[2]!);
  }
  const realm = params.get('realm');
  if (!realm) return null;
  return { realm, service: params.get('service'), scope: params.get('scope') };
}
