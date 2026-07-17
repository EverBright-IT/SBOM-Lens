import type { OcmBlobInfo, OcmBlobPreview, OcmOciLayerInfo } from '../../model/ocm';
import { gunzip, sniffContainer } from '../../util/binary';
import { asRecordArray, asString, isRecord } from '../../util/narrow';
import { hashHex } from '../../util/sha1';
import type { TarEntry } from '../../util/tar';
import { readTar } from '../../util/tar';

/**
 * Inspects one localBlob of a delivery inside the worker: what kind of
 * artifact is it (helm chart, OCI artifact set, text, plain tar, binary)
 * and a capped preview of its contents. Only the resulting summary crosses
 * the thread boundary; the raw bytes are dropped after inspection.
 *
 * Inspection is per BLOB and cacheable; the digest check is per RESOURCE
 * (two resources may point at the same blob with different declared
 * digests), so it runs separately against the retained digest subjects.
 * Deliberately conservative: anything but an explicit, computable
 * normalisation stays 'unchecked' instead of risking a wrong verdict, and
 * for compressed blobs BOTH the stored and the uncompressed bytes are
 * accepted (the spec reading is "stored", but a sha256 match on either can
 * never be forged, while a wrong 'mismatch' would break trust for nothing).
 */

export const BLOB_PREVIEW_MAX = 64 * 1024;
export const BLOB_FILES_MAX = 500;
/** Full-decode ceiling for text kind detection; larger blobs go by media type. */
const TEXT_INSPECT_MAX = 1024 * 1024;
const HEX_HEAD_BYTES = 256;

/** Byte views the per-resource digest check hashes lazily. */
export interface BlobDigestSubjects {
  stored: Uint8Array;
  /** Present when the blob was gzip-compressed and unpacked successfully. */
  uncompressed?: Uint8Array;
  /** The OCI artifact set's manifest bytes, when one was identified. */
  manifest?: Uint8Array;
}

export interface BlobInspection {
  /** Content summary without a digest verdict (that is per resource). */
  info: OcmBlobInfo;
  subjects: BlobDigestSubjects;
}

export async function inspectBlob(stored: Uint8Array, mediaType: string | undefined): Promise<BlobInspection> {
  const info: OcmBlobInfo = { size: stored.byteLength, mediaType, kind: 'binary' };
  const subjects: BlobDigestSubjects = { stored };

  let bytes = stored;
  if (sniffContainer(stored) === 'gzip') {
    info.compressed = true;
    try {
      bytes = await gunzip(stored);
      subjects.uncompressed = bytes;
    } catch {
      info.previews = [hexPreview(stored)];
      return { info, subjects };
    }
  }

  if (sniffContainer(bytes) === 'tar') {
    const { entries } = readTar(bytes);
    const named = entries.map((e) => ({ ...e, name: e.name.replace(/^\.\//, '') }));
    info.files = named.slice(0, BLOB_FILES_MAX).map((e) => ({ name: e.name, size: e.bytes.byteLength }));
    if (named.length > BLOB_FILES_MAX) info.filesTruncated = true;

    // Helm charts pack as <chart>/Chart.yaml (one directory level).
    const chartYaml = named.find((e) => /^([^/]+\/)?Chart\.yaml$/.test(e.name));
    const indexEntry = named.find((e) => e.name === 'artifact-set-descriptor.json' || e.name === 'index.json');
    if (chartYaml) {
      info.kind = 'helm-chart';
      const dir = chartYaml.name.includes('/') ? chartYaml.name.slice(0, chartYaml.name.lastIndexOf('/') + 1) : '';
      const valuesYaml = named.find((e) => e.name === `${dir}values.yaml`);
      info.previews = [textPreview(chartYaml), ...(valuesYaml ? [textPreview(valuesYaml)] : [])];
    } else if (indexEntry) {
      info.kind = 'oci-artifact';
      const manifestEntry = resolveManifest(indexEntry, named);
      if (manifestEntry) {
        subjects.manifest = manifestEntry.bytes;
        info.previews = [textPreview({ ...manifestEntry, name: manifestEntry.name || 'manifest.json' })];
        info.oci = { layers: manifestLayers(manifestEntry) };
      }
    } else {
      info.kind = 'tar';
    }
  } else if (sniffContainer(bytes) === 'binary' || sniffContainer(bytes) === 'zip') {
    info.kind = 'binary';
    info.previews = [hexPreview(bytes)];
  } else {
    // Decode only what the preview can show — a multi-hundred-MB text blob
    // must never materialize as one JS string in the worker.
    const window = bytes.subarray(0, Math.min(bytes.byteLength, BLOB_PREVIEW_MAX));
    const text = new TextDecoder().decode(window);
    info.kind = textKind(bytes, text, mediaType);
    info.previews = [
      bytes.byteLength > window.byteLength ? { name: 'content', text, truncated: true } : cap('content', text),
    ];
  }

  return { info, subjects };
}

function textKind(bytes: Uint8Array, windowText: string, mediaType: string | undefined): 'json' | 'yaml' | 'text' {
  const media = (mediaType ?? '').toLowerCase();
  if (bytes.byteLength <= TEXT_INSPECT_MAX) {
    try {
      JSON.parse(bytes.byteLength <= BLOB_PREVIEW_MAX ? windowText : new TextDecoder().decode(bytes));
      return 'json';
    } catch {
      // fall through to media-type hints
    }
  } else if (media.includes('json')) {
    return 'json';
  }
  return media.includes('yaml') ? 'yaml' : 'text';
}

/** OCI index or manifest JSON → the entry holding the layer list. */
function resolveManifest(indexEntry: TarEntry, entries: TarEntry[]): TarEntry | undefined {
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(indexEntry.bytes));
    if (!isRecord(parsed)) return undefined;
    if (Array.isArray(parsed.layers)) return indexEntry;
    const manifests = asRecordArray(parsed.manifests);
    const digest = manifests.length > 0 ? asString(manifests[0]!.digest) : undefined;
    if (!digest) return undefined;
    return entries.find((e) => e.name === `blobs/${digest.replace(':', '.')}`);
  } catch {
    return undefined;
  }
}

function manifestLayers(manifestEntry: TarEntry): OcmOciLayerInfo[] {
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(manifestEntry.bytes));
    if (!isRecord(parsed)) return [];
    return asRecordArray(parsed.layers).map((layer) => ({
      digest: asString(layer.digest),
      size: typeof layer.size === 'number' ? layer.size : undefined,
      mediaType: asString(layer.mediaType),
    }));
  } catch {
    return [];
  }
}

/**
 * Per-resource digest verdict. genericBlobDigest/v1 hashes the blob bytes
 * (stored, with the uncompressed bytes accepted as an alternative until the
 * spelling is pinned against the ocm CLI); ociArtifactDigest/v1 hashes the
 * artifact set's manifest. Unknown normalisations and hash algorithms stay
 * 'unchecked'; no declared digest means no verdict at all.
 */
export async function checkDeclaredDigest(
  subjects: BlobDigestSubjects,
  declared: Record<string, unknown> | undefined,
): Promise<OcmBlobInfo['digestCheck']> {
  const value = asString(declared?.value);
  if (!value) return undefined;
  const algorithm = webCryptoName(asString(declared?.hashAlgorithm));
  const normalisation = asString(declared?.normalisationAlgorithm) ?? '';
  if (!algorithm) return 'unchecked';

  let candidates: Uint8Array[];
  if (normalisation === 'genericBlobDigest/v1') {
    candidates = subjects.uncompressed ? [subjects.stored, subjects.uncompressed] : [subjects.stored];
  } else if (normalisation === 'ociArtifactDigest/v1') {
    candidates = subjects.manifest ? [subjects.manifest] : [];
  } else {
    return 'unchecked';
  }
  if (candidates.length === 0) return 'unchecked';

  const expected = value.toLowerCase().replace(/^sha\d+:/, '');
  for (const candidate of candidates) {
    if ((await hashHex(algorithm, candidate)) === expected) return 'match';
  }
  return 'mismatch';
}

/**
 * Digest verdict for a blob that was never materialized: hashed in constant
 * memory straight off the archive source. Only genericBlobDigest/v1 with
 * sha256 is computable this way (the incremental hash is SHA-256 only, and
 * ociArtifactDigest/v1 would need the inner manifest). Both facts arrive as
 * lazy callbacks so the caller can (a) skip the multi-GB hash entirely when
 * the declaration is not computable and (b) cache it per blob when several
 * artifacts point at the same one. The either-or rule for gzip-stored blobs
 * carries over: when the stored bytes do not match and the blob is gzip,
 * the declared digest may be over the uncompressed bytes we did not produce
 * — that stays 'unchecked', never a false 'mismatch'. A non-gzip non-match
 * is a real mismatch.
 */
export async function checkDeclaredDigestIndexed(
  declared: Record<string, unknown> | undefined,
  actualSha256: () => Promise<string>,
  storedIsGzip: () => Promise<boolean>,
): Promise<OcmBlobInfo['digestCheck']> {
  const value = asString(declared?.value);
  if (!value) return undefined;
  const algorithm = (asString(declared?.hashAlgorithm) ?? '').toLowerCase().replace(/-/g, '');
  const normalisation = asString(declared?.normalisationAlgorithm) ?? '';
  if (algorithm !== 'sha256' || normalisation !== 'genericBlobDigest/v1') return 'unchecked';

  const expected = value.toLowerCase().replace(/^sha\d+:/, '');
  if ((await actualSha256()) === expected) return 'match';
  return (await storedIsGzip()) ? 'unchecked' : 'mismatch';
}

function webCryptoName(hashAlgorithm: string | undefined): 'SHA-256' | 'SHA-512' | undefined {
  const normalized = (hashAlgorithm ?? '').toLowerCase().replace(/-/g, '');
  if (normalized === 'sha256') return 'SHA-256';
  if (normalized === 'sha512') return 'SHA-512';
  return undefined;
}

function textPreview(entry: TarEntry): OcmBlobPreview {
  return cap(entry.name, new TextDecoder().decode(entry.bytes.subarray(0, Math.min(entry.bytes.byteLength, BLOB_PREVIEW_MAX * 2))));
}

function cap(name: string, text: string): OcmBlobPreview {
  if (text.length <= BLOB_PREVIEW_MAX) return { name, text };
  return { name, text: text.slice(0, BLOB_PREVIEW_MAX), truncated: true };
}

/** Classic hex dump of the first bytes — 16 per row, offset + hex + ASCII. */
function hexPreview(bytes: Uint8Array): OcmBlobPreview {
  const head = bytes.subarray(0, HEX_HEAD_BYTES);
  const rows: string[] = [];
  for (let offset = 0; offset < head.length; offset += 16) {
    const row = head.subarray(offset, offset + 16);
    const hex = [...row].map((b) => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = [...row].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('');
    rows.push(`${offset.toString(16).padStart(8, '0')}  ${hex.padEnd(47)}  ${ascii}`);
  }
  return { name: `first ${head.length} bytes`, text: rows.join('\n'), truncated: bytes.length > head.length };
}
