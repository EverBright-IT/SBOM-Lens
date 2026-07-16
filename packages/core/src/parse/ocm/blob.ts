import type { OcmBlobInfo, OcmBlobPreview, OcmOciLayerInfo } from '../../model/ocm';
import { gunzip, sniffContainer } from '../../util/binary';
import { asRecordArray, asString, isRecord } from '../../util/narrow';
import { hashHex } from '../../util/sha1';
import type { TarEntry } from '../../util/tar';
import { readTar } from '../../util/tar';

/**
 * Inspects one localBlob of a delivery inside the worker: what kind of
 * artifact is it (helm chart, OCI artifact set, text, plain tar, binary),
 * a capped preview of its contents, and whether the declared OCM digest
 * matches the actual bytes. Only the resulting summary crosses the thread
 * boundary — the raw bytes are dropped after inspection. Deliberately
 * conservative on digests: anything but an explicit, computable
 * normalisation stays 'unchecked' instead of risking a wrong verdict.
 */

export const BLOB_PREVIEW_MAX = 64 * 1024;
export const BLOB_FILES_MAX = 500;
const HEX_HEAD_BYTES = 256;

export async function inspectBlob(
  stored: Uint8Array,
  mediaType: string | undefined,
  declared: Record<string, unknown> | undefined,
): Promise<OcmBlobInfo> {
  const info: OcmBlobInfo = { size: stored.byteLength, mediaType, kind: 'binary' };

  let bytes = stored;
  if (sniffContainer(stored) === 'gzip') {
    info.compressed = true;
    try {
      bytes = await gunzip(stored);
    } catch {
      info.previews = [hexPreview(stored)];
      info.digestCheck = await checkDigest(declared, stored, undefined);
      return info;
    }
  }

  let manifestEntry: TarEntry | undefined;
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
      manifestEntry = resolveManifest(indexEntry, named);
      if (manifestEntry) {
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
    const text = new TextDecoder().decode(bytes);
    info.kind = textKind(text, mediaType);
    info.previews = [cap('content', text)];
  }

  info.digestCheck = await checkDigest(declared, stored, manifestEntry);
  return info;
}

function textKind(text: string, mediaType: string | undefined): 'json' | 'yaml' | 'text' {
  try {
    JSON.parse(text);
    return 'json';
  } catch {
    return (mediaType ?? '').toLowerCase().includes('yaml') ? 'yaml' : 'text';
  }
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
 * genericBlobDigest/v1 hashes the stored blob bytes; ociArtifactDigest/v1
 * hashes the artifact set's manifest. Unknown normalisations and hash
 * algorithms stay 'unchecked'.
 */
async function checkDigest(
  declared: Record<string, unknown> | undefined,
  stored: Uint8Array,
  manifestEntry: TarEntry | undefined,
): Promise<OcmBlobInfo['digestCheck']> {
  const value = asString(declared?.value);
  if (!value) return undefined;
  const algorithm = webCryptoName(asString(declared?.hashAlgorithm));
  const normalisation = asString(declared?.normalisationAlgorithm) ?? '';
  if (!algorithm) return 'unchecked';

  let subject: Uint8Array | undefined;
  if (normalisation === 'genericBlobDigest/v1') subject = stored;
  else if (normalisation === 'ociArtifactDigest/v1') subject = manifestEntry?.bytes;
  if (!subject) return 'unchecked';

  const copy = new Uint8Array(subject); // detach from the archive buffer
  const actual = await hashHex(algorithm, copy.buffer as ArrayBuffer);
  const expected = value.toLowerCase().replace(/^sha\d+:/, '');
  return actual === expected ? 'match' : 'mismatch';
}

function webCryptoName(hashAlgorithm: string | undefined): 'SHA-256' | 'SHA-512' | undefined {
  const normalized = (hashAlgorithm ?? '').toLowerCase().replace(/-/g, '');
  if (normalized === 'sha256') return 'SHA-256';
  if (normalized === 'sha512') return 'SHA-512';
  return undefined;
}

function textPreview(entry: TarEntry): OcmBlobPreview {
  return cap(entry.name, new TextDecoder().decode(entry.bytes));
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
