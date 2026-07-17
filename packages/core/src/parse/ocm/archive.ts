import type { Diagnostic } from '../../model/diagnostics';
import { diag } from '../../model/diagnostics';
import type { SbomDocument } from '../../model/document';
import { GunzipLimitError, GUNZIP_MAX_BYTES, gunzip, sniffContainer } from '../../util/binary';
import type { ByteSource } from '../../util/bytesource';
import { bufferSource, windowSource } from '../../util/bytesource';
import { asRecordArray, asString, isRecord } from '../../util/narrow';
import { sha1Hex } from '../../util/sha1';
import { sha256SourceHex } from '../../util/sha256';
import type { TarStreamEntry, TarStreamOptions } from '../../util/tar';
import { readTar, readTarFrom } from '../../util/tar';
import type { OcmBlobInfo } from '../../model/ocm';
import { detect } from '../detect';
import type { SourceInput } from '../parser';
import type { BlobInspection } from './blob';
import { checkDeclaredDigest, checkDeclaredDigestIndexed, inspectBlob } from './blob';
import { isSbomResource, parseOcmComponentDescriptor } from './cd';

/**
 * Walks a local OCM delivery — CTF tar(.gz), component archive, or any tar
 * of SPDX files — and returns the component descriptors mapped to documents
 * plus the extracted SPDX blobs. The CDs' SBOM refs carry the SHA-1 of the
 * sibling blob bytes, so the workspace links them the moment both land in
 * one batch. Tolerant end to end: per-artifact failures degrade to
 * diagnostics and a content sweep, never a throw.
 *
 * Everything reads through a ByteSource, so a multi-GB delivery never has
 * to exist as one buffer: descriptors, indexes, and SBOMs (all small) are
 * materialized, large artifact blobs stay index entries that are hashed in
 * constant memory for their digest verdict. Nested plain tars (artifact
 * sets) are walked through source windows the same way.
 */

export interface PreparsedDoc {
  fileName: string;
  sha1: string;
  byteSize: number;
  text: string;
  document: SbomDocument;
  diagnostics: Diagnostic[];
}

export interface DeliveryResult {
  documents: PreparsedDoc[];
  extracted: { fileName: string; bytes: Uint8Array }[];
  /** Archive-level diagnostics (no document to attach them to). */
  diagnostics: Diagnostic[];
}

const CD_MEDIA_PREFIX = 'application/vnd.ocm.software.component-descriptor';
/** An SBOM the walker will fetch in full even past the materialization cap. */
const SBOM_FETCH_MAX = 512 * 1024 * 1024;

/** One tar, indexed: entries by name plus the source their offsets address. */
interface TarIndex {
  source: ByteSource;
  byName: Map<string, TarStreamEntry>;
  options?: TarStreamOptions;
}

/** Buffer entry point (VS Code push channel, tests, nested buffers). */
export async function readOcmDelivery(fileName: string, bytes: Uint8Array): Promise<DeliveryResult> {
  return readOcmDeliveryFrom(fileName, bufferSource(bytes));
}

/** Source entry point: a browser File/Blob streams from disk through here. */
export async function readOcmDeliveryFrom(
  fileName: string,
  source: ByteSource,
  options?: TarStreamOptions,
): Promise<DeliveryResult> {
  const diagnostics: Diagnostic[] = [];

  const head = await source.read(0, 512);
  let tarSource = source;
  if (sniffContainer(head) === 'gzip') {
    // Compressed deliveries decompress into memory (DecompressionStream has
    // no random access), so they are capped; past the cap the honest answer
    // is a repack hint — plain .tar streams without any of these limits.
    if (source.size > GUNZIP_MAX_BYTES) {
      return {
        documents: [],
        extracted: [],
        diagnostics: [
          diag('error', 'GZIP_TOO_LARGE', `Compressed delivery exceeds ${GUNZIP_MAX_BYTES / (1024 * 1024 * 1024)} GiB. Repack it as plain .tar.`),
        ],
      };
    }
    let tarBytes: Uint8Array;
    try {
      tarBytes = await gunzip(await source.read(0, source.size));
    } catch (error) {
      return {
        documents: [],
        extracted: [],
        diagnostics: [
          error instanceof GunzipLimitError
            ? diag('error', 'GZIP_TOO_LARGE', `${error.message} Repack the delivery as plain .tar.`)
            : diag('error', 'GZIP_INVALID', 'Not a valid gzip stream.'),
        ],
      };
    }
    if (sniffContainer(tarBytes) !== 'tar') {
      return {
        documents: [],
        extracted: [],
        diagnostics: [diag('error', 'GZIP_NOT_TAR', 'The gzip stream does not contain a tar archive.')],
      };
    }
    tarSource = bufferSource(tarBytes);
  }

  const index = await indexTar(tarSource, diagnostics, options);
  const result: DeliveryResult = { documents: [], extracted: [], diagnostics };
  if (index.byName.size === 0) return result;

  const indexEntry = index.byName.get('artifact-index.json') ?? index.byName.get('artifact-descriptor.json');
  if (indexEntry) {
    await walkCtf(fileName, indexEntry, index, result);
  } else if (index.byName.has('component-descriptor.yaml')) {
    await walkComponentArchive(fileName, index, result);
  }

  if (result.documents.length === 0) {
    await sweep(fileName, index, result);
    if (result.documents.length === 0 && result.extracted.length === 0) {
      result.diagnostics.push(
        diag('error', 'ARCHIVE_NO_DOCUMENTS', 'No component descriptors or SPDX documents found in this archive.'),
      );
    }
  }
  return result;
}

async function indexTar(
  source: ByteSource,
  diagnostics: Diagnostic[],
  options?: TarStreamOptions,
): Promise<TarIndex> {
  const { entries, diagnostics: tarDiagnostics } = await readTarFrom(source, options);
  diagnostics.push(...tarDiagnostics);
  return { source, byName: new Map(entries.map((e) => [e.name.replace(/^\.\//, ''), e])), options };
}

/** CTF: artifact-index.json → per-artifact OCI layout (flat or artifact set). */
async function walkCtf(
  archiveName: string,
  indexEntry: TarStreamEntry,
  index: TarIndex,
  result: DeliveryResult,
): Promise<void> {
  let parsedIndex: unknown;
  try {
    parsedIndex = JSON.parse(decode(indexEntry.bytes ?? new Uint8Array(0)));
  } catch {
    result.diagnostics.push(diag('warning', 'CTF_INDEX_INVALID', 'artifact-index.json is not valid JSON: falling back to a content sweep.'));
    return;
  }
  const artifacts = isRecord(parsedIndex) ? asRecordArray(parsedIndex.artifacts) : [];
  if (artifacts.length === 0) {
    result.diagnostics.push(diag('warning', 'CTF_INDEX_INVALID', 'artifact-index.json lists no artifacts.'));
    return;
  }

  for (const artifact of artifacts) {
    const digest = asString(artifact.digest);
    const blob = digest ? index.byName.get(`blobs/${digest.replace(':', '.')}`) : undefined;
    if (!blob) {
      result.diagnostics.push(
        diag('warning', 'CTF_ARTIFACT_UNREADABLE', `Artifact ${asString(artifact.repository) ?? '?'}:${asString(artifact.tag) ?? '?'}: blob missing.`),
      );
      continue;
    }
    try {
      const head = blob.bytes ?? (await index.source.read(blob.offset, 512));
      if (sniffContainer(head) === 'tar') {
        // Nested artifact-set archive: its own index + blobs, walked through
        // a window so its large layers stay unmaterialized too.
        const setSource = blob.bytes ? bufferSource(blob.bytes) : windowSource(index.source, blob.offset, blob.size);
        const inner = await indexTar(setSource, result.diagnostics, index.options);
        const innerIndex =
          inner.byName.get('artifact-set-descriptor.json') ?? inner.byName.get('index.json');
        const manifestEntry = innerIndex ? manifestFromIndex(innerIndex, inner) : undefined;
        await walkOciManifest(archiveName, manifestEntry, inner, result);
      } else {
        // Flat layout: the blob IS the OCI manifest; layers are sibling blobs.
        await walkOciManifest(archiveName, blob, index, result);
      }
    } catch {
      result.diagnostics.push(
        diag('warning', 'CTF_ARTIFACT_UNREADABLE', `Artifact ${asString(artifact.repository) ?? '?'} could not be read.`),
      );
    }
  }
}

/** OCI image index/manifest JSON → find the manifest blob with layers. */
function manifestFromIndex(indexEntry: TarStreamEntry, index: TarIndex): TarStreamEntry | undefined {
  if (!indexEntry.bytes) return undefined;
  try {
    const parsed: unknown = JSON.parse(decode(indexEntry.bytes));
    if (!isRecord(parsed)) return undefined;
    if (Array.isArray(parsed.layers)) return indexEntry; // already a manifest
    const manifests = asRecordArray(parsed.manifests);
    const digest = manifests.length > 0 ? asString(manifests[0]!.digest) : undefined;
    return digest ? index.byName.get(`blobs/${digest.replace(':', '.')}`) : undefined;
  } catch {
    return undefined;
  }
}

async function walkOciManifest(
  archiveName: string,
  manifestEntry: TarStreamEntry | undefined,
  index: TarIndex,
  result: DeliveryResult,
): Promise<void> {
  if (!manifestEntry?.bytes) return;
  let manifest: unknown;
  try {
    manifest = JSON.parse(decode(manifestEntry.bytes));
  } catch {
    return;
  }
  if (!isRecord(manifest)) return;
  const layers = asRecordArray(manifest.layers);
  if (layers.length === 0) return;

  const layerEntry = (layer: Record<string, unknown>): TarStreamEntry | undefined => {
    const digest = asString(layer.digest);
    return digest ? index.byName.get(`blobs/${digest.replace(':', '.')}`) : undefined;
  };

  const cdLayer =
    layers.find((l) => (asString(l.mediaType) ?? '').startsWith(CD_MEDIA_PREFIX)) ?? layers[0]!;
  const cdEntry = layerEntry(cdLayer);
  if (!cdEntry?.bytes) return;

  let cdText: string;
  const cdMedia = asString(cdLayer.mediaType) ?? '';
  if (cdMedia.endsWith('+tar') || sniffContainer(cdEntry.bytes) === 'tar') {
    const innerCd = readTar(cdEntry.bytes).entries.find((e) =>
      e.name.replace(/^\.\//, '').endsWith('component-descriptor.yaml'),
    );
    if (!innerCd) return;
    cdText = decode(innerCd.bytes);
  } else {
    cdText = decode(cdEntry.bytes);
  }

  // Local blob store: every non-CD layer, keyed by its digest spellings.
  const blobs = new Map<string, TarStreamEntry>();
  for (const layer of layers) {
    const digest = asString(layer.digest);
    const entry = layerEntry(layer);
    if (!digest || !entry || layer === cdLayer) continue;
    blobs.set(digest, entry);
    blobs.set(digest.replace(':', '.'), entry);
  }
  await emitCd(archiveName, cdText, { source: index.source, byName: blobs }, result);
}

/** Component archive: component-descriptor.yaml + blobs/<algo>.<hex>. */
async function walkComponentArchive(
  archiveName: string,
  index: TarIndex,
  result: DeliveryResult,
): Promise<void> {
  const cd = index.byName.get('component-descriptor.yaml')!;
  if (!cd.bytes) return;
  const blobs = new Map<string, TarStreamEntry>();
  for (const [name, entry] of index.byName) {
    if (!name.startsWith('blobs/')) continue;
    const base = name.slice('blobs/'.length);
    blobs.set(base, entry);
    blobs.set(base.replace('.', ':'), entry);
  }
  await emitCd(archiveName, decode(cd.bytes), { source: index.source, byName: blobs }, result);
}

/** Parse one CD text, extract its SPDX blobs, wire refs by byte checksum. */
async function emitCd(
  archiveName: string,
  cdText: string,
  blobs: TarIndex,
  result: DeliveryResult,
): Promise<void> {
  const detection = detect(cdText);
  if (detection.format !== 'ocm-cd') {
    result.diagnostics.push(
      diag('warning', 'CTF_ARTIFACT_UNREADABLE', 'A component-descriptor layer did not parse as an OCM CD.'),
    );
    return;
  }

  // Pass 1: inspect EVERY localBlob the delivery physically carries (kind,
  // capped previews). Content inspection caches per blob; the digest verdict
  // is computed PER ARTIFACT, because two artifacts may point at the same
  // blob with different declared digests. Unmaterialized blobs skip content
  // inspection but still get a REAL digest verdict: their bytes are hashed
  // in constant memory straight off the source (cached per blob). Bytes stay
  // in this worker; only the summaries ride on the elements.
  const component = componentNode(detection.parsed);
  const specNode = isRecord(detection.parsed.spec) ? detection.parsed.spec : {};
  const resources = asRecordArray(component?.resources ?? specNode.resources);
  const sources = asRecordArray(component?.sources ?? specNode.sources);

  const inspections = new Map<string, BlobInspection>();
  const indexedHashes = new Map<string, Promise<string>>();
  const blobInfos = new Map<Record<string, unknown>, OcmBlobInfo>();
  for (const artifact of [...resources, ...sources]) {
    const access = isRecord(artifact.access) ? artifact.access : {};
    const localReference = asString(access.localReference) ?? asString(access.filename);
    if (!localReference) continue;
    const blob = blobs.byName.get(localReference);
    if (!blob) continue;
    const declared = isRecord(artifact.digest) ? artifact.digest : undefined;
    try {
      if (blob.bytes) {
        let inspection = inspections.get(localReference);
        if (!inspection) {
          inspection = await inspectBlob(blob.bytes, asString(access.mediaType));
          inspections.set(localReference, inspection);
        }
        const digestCheck = await checkDeclaredDigest(inspection.subjects, declared);
        blobInfos.set(artifact, {
          ...inspection.info,
          mediaType: asString(access.mediaType) ?? inspection.info.mediaType,
          digestCheck,
        });
      } else {
        const digestCheck = await checkDeclaredDigestIndexed(
          declared,
          () => {
            let hash = indexedHashes.get(localReference);
            if (!hash) {
              hash = sha256SourceHex(blobs.source, blob.offset, blob.size);
              indexedHashes.set(localReference, hash);
            }
            return hash;
          },
          async () => {
            const head = await blobs.source.read(blob.offset, 2);
            return head.byteLength === 2 && head[0] === 0x1f && head[1] === 0x8b;
          },
        );
        blobInfos.set(artifact, {
          size: blob.size,
          mediaType: asString(access.mediaType),
          kind: 'binary',
          notInspected: true,
          digestCheck,
        });
      }
    } catch {
      // Inspection is best-effort; the element simply carries no blob info.
    }
  }

  // Pass 2: extract SPDX blobs of SBOM resources (checksums first — the
  // mapper needs them while building the refs). An SBOM past the
  // materialization cap is worth a targeted full fetch: it is the reason
  // this product exists. Reuses pass 1's gunzip where available.
  const sbomChecksums = new Map<string, string>();
  for (const resource of resources) {
    const access = isRecord(resource.access) ? resource.access : {};
    if (!isSbomResource(resource, access)) continue;
    const localReference = asString(access.localReference) ?? asString(access.filename);
    if (!localReference) continue;
    const stored = blobs.byName.get(localReference);
    if (!stored) continue;
    let blob = inspections.get(localReference)?.subjects.uncompressed ?? stored.bytes ?? undefined;
    if (!blob) {
      if (stored.size > SBOM_FETCH_MAX) {
        result.diagnostics.push(
          diag(
            'warning',
            'OCM_SBOM_TOO_LARGE',
            `SBOM resource "${asString(resource.name) ?? localReference}" exceeds ${SBOM_FETCH_MAX / (1024 * 1024)} MB and was not extracted.`,
          ),
        );
        continue;
      }
      blob = await blobs.source.read(stored.offset, stored.size);
    }
    try {
      if (sniffContainer(blob) === 'gzip') blob = await gunzip(blob);
      if (sniffContainer(blob) === 'tar') {
        const first = readTar(blob).entries[0];
        if (!first) continue;
        blob = first.bytes;
      }
    } catch {
      continue;
    }
    if (detect(decode(blob)).format === 'unsupported') {
      result.diagnostics.push(
        diag(
          'warning',
          'OCM_SBOM_FORMAT_UNSUPPORTED',
          `SBOM resource "${asString(resource.name) ?? '?'}" is not SPDX (${asString(access.mediaType) ?? 'unknown media type'}): skipped.`,
        ),
      );
      continue;
    }
    const copy = new Uint8Array(blob); // detach from the archive buffer
    const sha1 = await sha1Hex(copy.buffer as ArrayBuffer);
    sbomChecksums.set(localReference, sha1);
    result.extracted.push({
      fileName: `${archiveName}!${asString(resource.name) ?? localReference}.spdx`,
      bytes: copy,
    });
  }

  // Pass 3: map the CD with checksums and blob summaries at hand.
  const cdBytes = new TextEncoder().encode(cdText);
  const sha1 = await sha1Hex(cdBytes.buffer as ArrayBuffer);
  const input: SourceInput = {
    fileName: `${archiveName}!component-descriptor.yaml`,
    text: cdText,
    sha1,
    byteSize: cdBytes.byteLength,
  };
  const parsed = parseOcmComponentDescriptor(input, detection.parsed, detection.serialization, {
    sbomChecksumFor: (ref) => sbomChecksums.get(ref),
    blobInfoFor: (artifact) => blobInfos.get(artifact),
  });
  if (parsed.document) {
    const componentLabel = parsed.document.name;
    result.documents.push({
      fileName: `${archiveName}!${componentLabel}/component-descriptor.yaml`,
      sha1,
      byteSize: cdBytes.byteLength,
      text: cdText,
      document: parsed.document,
      diagnostics: parsed.diagnostics,
    });
  } else {
    result.diagnostics.push(...parsed.diagnostics);
  }
}

function componentNode(parsed: Record<string, unknown>): Record<string, unknown> | null {
  return isRecord(parsed.component) ? parsed.component : null;
}

/** Fallback: treat the tar as a plain bundle of SPDX/OCM files. */
async function sweep(archiveName: string, index: TarIndex, result: DeliveryResult): Promise<void> {
  for (const [name, entry] of index.byName) {
    if (!entry.bytes) continue; // an unmaterialized blob is never an SPDX text
    if (sniffContainer(entry.bytes) !== 'text') continue;
    const text = decode(entry.bytes);
    const detection = detect(text);
    if (detection.format === 'unsupported') continue;
    result.extracted.push({
      fileName: `${archiveName}!${name}`,
      bytes: new Uint8Array(entry.bytes),
    });
  }
}

function decode(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}
