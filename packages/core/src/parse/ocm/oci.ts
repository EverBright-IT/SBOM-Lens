import { asRecordArray, asString, isRecord } from '../../util/narrow';

/**
 * Images and charts stored by value, recognised by their bytes. A descriptor
 * names the media type of a stored artifact in its access, and the signature
 * does not cover the access: a changed media type must not decide whether
 * the blobs behind a manifest are checked. The manifest bytes are covered,
 * through the resource's declared digest. So whether a blob is an OCI image
 * manifest or index, and which blobs it names, follows from the content
 * here, for the walk and the on-demand check alike.
 */

/** Registries refuse larger manifests; a larger blob is never read as one. */
export const OCI_MANIFEST_MAX = 4 * 1024 * 1024;

/**
 * The digest of the OCI empty descriptor's content `{}`. Its bytes follow
 * from the digest, so a layout that leaves the blob out hides nothing.
 */
export const OCI_EMPTY_DIGEST =
  'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a';

/** One blob an OCI manifest or index names. */
export interface OciPart {
  digest: string;
  /** Declared size; 0 when the descriptor gives none. */
  size: number;
  mediaType?: string;
  role: 'manifest' | 'config' | 'layer';
}

export type OciContent =
  | { kind: 'manifest'; config: OciPart; layers: OciPart[]; raw: Record<string, unknown> }
  | { kind: 'index'; manifests: OciPart[]; raw: Record<string, unknown> };

const INDEX_TYPES = new Set([
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
]);
const MANIFEST_TYPES = new Set([
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.v2+json',
]);

/**
 * The image manifest or index these bytes are, or undefined. Strict on
 * structure (schema version 2, a digest on every descriptor), so a JSON
 * document of a similar shape is not taken for one. The bytes are what the
 * signer's tooling wrote: the declared digest pins them.
 */
export function ociContent(bytes: Uint8Array): OciContent | undefined {
  if (bytes.byteLength === 0 || bytes.byteLength > OCI_MANIFEST_MAX) return undefined;
  if (firstNonSpace(bytes) !== 0x7b) return undefined;
  const text = new TextDecoder().decode(bytes);
  // Spares a JSON file of another kind (an SBOM, a config) the full parse.
  if (!text.includes('"schemaVersion"')) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (!isRecord(parsed) || parsed.schemaVersion !== 2) return undefined;
  const declared = asString(parsed.mediaType);
  if (
    Array.isArray(parsed.manifests) &&
    parsed.config === undefined &&
    parsed.layers === undefined &&
    !(declared && MANIFEST_TYPES.has(declared))
  ) {
    const manifests = descriptors(parsed.manifests, 'manifest');
    return manifests ? { kind: 'index', manifests, raw: parsed } : undefined;
  }
  if (isRecord(parsed.config) && Array.isArray(parsed.layers) && !(declared && INDEX_TYPES.has(declared))) {
    const config = descriptor(parsed.config, 'config');
    const layers = descriptors(parsed.layers, 'layer');
    return config && layers ? { kind: 'manifest', config, layers, raw: parsed } : undefined;
  }
  return undefined;
}

/** Whether a blob's first bytes can begin a manifest or index (a JSON object). */
export function mayBeOciContent(head: Uint8Array): boolean {
  const first = firstNonSpace(head);
  return first === undefined || first === 0x7b;
}

/** Markers of a descriptor manifest: ocm.software and legacy gardener spellings. */
export const CD_CONFIG_MARKER = 'component.config';
export const CD_LAYER_MARKER = 'component-descriptor';

/** Whether a manifest carries an OCM component descriptor rather than an artifact. */
export function carriesComponentDescriptor(manifest: Record<string, unknown>): boolean {
  const config = isRecord(manifest.config) ? (asString(manifest.config.mediaType) ?? '') : '';
  if (config.includes(CD_CONFIG_MARKER)) return true;
  return asRecordArray(manifest.layers).some((l) => (asString(l.mediaType) ?? '').includes(CD_LAYER_MARKER));
}

/** What `read` found under a digest: the bytes, nothing, or a blob too large to be a manifest. */
export type PartRead = Uint8Array | 'absent' | 'unreadable';

export interface StoredArtifactParts {
  /** Every blob below the artifact's own manifest, each once: nested manifests, configs, layers. */
  parts: OciPart[];
  /**
   * Nested manifests that are in the delivery but could not be read as a
   * manifest or index (too large, another format, nested too deep): what
   * they name is unknown, so no verdict can say every blob matches.
   */
  opaque: number;
}

/** Indexes of indexes are legal; past this depth the rest is opaque. */
const NESTING_MAX = 4;

/**
 * Every blob an image or chart stored by value consists of below its own
 * manifest: for an image manifest its config and layers; for an index each
 * manifest it names and, read through `read`, what those name in turn. The
 * parts are listed as named, not checked: a nested manifest whose bytes do
 * not match its digest names whatever it names, and the hash of that
 * manifest decides the verdict.
 */
export async function storedArtifactParts(
  content: OciContent,
  read: (digest: string) => Promise<PartRead>,
): Promise<StoredArtifactParts> {
  const parts: OciPart[] = [];
  const seen = new Set<string>();
  let opaque = 0;
  const visit = async (node: OciContent, depth: number): Promise<void> => {
    const named = node.kind === 'manifest' ? [node.config, ...node.layers] : node.manifests;
    for (const part of named) {
      const key = part.digest.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      parts.push(part);
      if (part.role !== 'manifest') continue;
      const bytes = await read(part.digest);
      if (bytes === 'absent') continue; // the part itself is missing; that decides
      const nested = bytes === 'unreadable' || depth >= NESTING_MAX ? undefined : ociContent(bytes);
      if (nested) await visit(nested, depth + 1);
      else opaque++;
    }
  };
  await visit(content, 1);
  return { parts, opaque };
}

function descriptors(list: unknown[], role: OciPart['role']): OciPart[] | undefined {
  const parts: OciPart[] = [];
  for (const node of list) {
    const part = isRecord(node) ? descriptor(node, role) : undefined;
    if (!part) return undefined;
    parts.push(part);
  }
  return parts;
}

function descriptor(node: Record<string, unknown>, role: OciPart['role']): OciPart | undefined {
  const digest = asString(node.digest);
  if (!digest || !/^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[a-zA-Z0-9=_-]+$/.test(digest)) return undefined;
  const size = typeof node.size === 'number' && Number.isSafeInteger(node.size) && node.size >= 0 ? node.size : 0;
  const mediaType = asString(node.mediaType);
  return mediaType ? { digest, size, mediaType, role } : { digest, size, role };
}

function firstNonSpace(bytes: Uint8Array): number | undefined {
  for (const byte of bytes) {
    if (byte !== 0x20 && byte !== 0x09 && byte !== 0x0a && byte !== 0x0d) return byte;
  }
  return undefined;
}
