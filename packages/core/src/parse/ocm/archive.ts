import type { Diagnostic } from '../../model/diagnostics';
import { diag } from '../../model/diagnostics';
import type { SbomDocument } from '../../model/document';
import { gunzip, sniffContainer } from '../../util/binary';
import { asRecordArray, asString, isRecord } from '../../util/narrow';
import { sha1Hex } from '../../util/sha1';
import type { TarEntry } from '../../util/tar';
import { readTar } from '../../util/tar';
import type { OcmBlobInfo } from '../../model/ocm';
import { detect } from '../detect';
import type { SourceInput } from '../parser';
import type { BlobInspection } from './blob';
import { checkDeclaredDigest, inspectBlob } from './blob';
import { isSbomResource, parseOcmComponentDescriptor } from './cd';

/**
 * Walks a local OCM delivery — CTF tar(.gz), component archive, or any tar
 * of SPDX files — and returns the component descriptors mapped to documents
 * plus the extracted SPDX blobs. The CDs' SBOM refs carry the SHA-1 of the
 * sibling blob bytes, so the workspace links them the moment both land in
 * one batch. Tolerant end to end: per-artifact failures degrade to
 * diagnostics and a content sweep, never a throw.
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

export async function readOcmDelivery(fileName: string, bytes: Uint8Array): Promise<DeliveryResult> {
  const diagnostics: Diagnostic[] = [];

  let tarBytes = bytes;
  if (sniffContainer(bytes) === 'gzip') {
    try {
      tarBytes = await gunzip(bytes);
    } catch {
      return { documents: [], extracted: [], diagnostics: [diag('error', 'GZIP_INVALID', 'Not a valid gzip stream.')] };
    }
    if (sniffContainer(tarBytes) !== 'tar') {
      return {
        documents: [],
        extracted: [],
        diagnostics: [diag('error', 'GZIP_NOT_TAR', 'The gzip stream does not contain a tar archive.')],
      };
    }
  }

  const { entries, diagnostics: tarDiagnostics } = readTar(tarBytes);
  diagnostics.push(...tarDiagnostics);
  if (entries.length === 0) return { documents: [], extracted: [], diagnostics };

  const byName = new Map(entries.map((e) => [e.name.replace(/^\.\//, ''), e]));
  const result: DeliveryResult = { documents: [], extracted: [], diagnostics };

  const index = byName.get('artifact-index.json') ?? byName.get('artifact-descriptor.json');
  if (index) {
    await walkCtf(fileName, index, byName, result);
  } else if (byName.has('component-descriptor.yaml')) {
    await walkComponentArchive(fileName, byName, result);
  }

  if (result.documents.length === 0) {
    await sweep(fileName, entries, result);
    if (result.documents.length === 0 && result.extracted.length === 0) {
      result.diagnostics.push(
        diag('error', 'ARCHIVE_NO_DOCUMENTS', 'No component descriptors or SPDX documents found in this archive.'),
      );
    }
  }
  return result;
}

/** CTF: artifact-index.json → per-artifact OCI layout (flat or artifact set). */
async function walkCtf(
  archiveName: string,
  index: TarEntry,
  byName: Map<string, TarEntry>,
  result: DeliveryResult,
): Promise<void> {
  let parsedIndex: unknown;
  try {
    parsedIndex = JSON.parse(decode(index.bytes));
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
    const blob = digest ? byName.get(`blobs/${digest.replace(':', '.')}`) : undefined;
    if (!blob) {
      result.diagnostics.push(
        diag('warning', 'CTF_ARTIFACT_UNREADABLE', `Artifact ${asString(artifact.repository) ?? '?'}:${asString(artifact.tag) ?? '?'}: blob missing.`),
      );
      continue;
    }
    try {
      if (sniffContainer(blob.bytes) === 'tar') {
        // Nested artifact-set archive: its own index + blobs.
        const inner = readTar(blob.bytes);
        const innerByName = new Map(inner.entries.map((e) => [e.name.replace(/^\.\//, ''), e]));
        const innerIndex =
          innerByName.get('artifact-set-descriptor.json') ?? innerByName.get('index.json');
        const manifestEntry = innerIndex ? manifestFromIndex(innerIndex, innerByName) : undefined;
        await walkOciManifest(archiveName, manifestEntry, innerByName, result);
      } else {
        // Flat layout: the blob IS the OCI manifest; layers are sibling blobs.
        await walkOciManifest(archiveName, blob, byName, result);
      }
    } catch {
      result.diagnostics.push(
        diag('warning', 'CTF_ARTIFACT_UNREADABLE', `Artifact ${asString(artifact.repository) ?? '?'} could not be read.`),
      );
    }
  }
}

/** OCI image index/manifest JSON → find the manifest blob with layers. */
function manifestFromIndex(indexEntry: TarEntry, byName: Map<string, TarEntry>): TarEntry | undefined {
  try {
    const parsed: unknown = JSON.parse(decode(indexEntry.bytes));
    if (!isRecord(parsed)) return undefined;
    if (Array.isArray(parsed.layers)) return indexEntry; // already a manifest
    const manifests = asRecordArray(parsed.manifests);
    const digest = manifests.length > 0 ? asString(manifests[0]!.digest) : undefined;
    return digest ? byName.get(`blobs/${digest.replace(':', '.')}`) : undefined;
  } catch {
    return undefined;
  }
}

async function walkOciManifest(
  archiveName: string,
  manifestEntry: TarEntry | undefined,
  byName: Map<string, TarEntry>,
  result: DeliveryResult,
): Promise<void> {
  if (!manifestEntry) return;
  let manifest: unknown;
  try {
    manifest = JSON.parse(decode(manifestEntry.bytes));
  } catch {
    return;
  }
  if (!isRecord(manifest)) return;
  const layers = asRecordArray(manifest.layers);
  if (layers.length === 0) return;

  const layerEntry = (layer: Record<string, unknown>): TarEntry | undefined => {
    const digest = asString(layer.digest);
    return digest ? byName.get(`blobs/${digest.replace(':', '.')}`) : undefined;
  };

  const cdLayer =
    layers.find((l) => (asString(l.mediaType) ?? '').startsWith(CD_MEDIA_PREFIX)) ?? layers[0]!;
  const cdEntry = layerEntry(cdLayer);
  if (!cdEntry) return;

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
  const blobStore = new Map<string, Uint8Array>();
  for (const layer of layers) {
    const digest = asString(layer.digest);
    const entry = layerEntry(layer);
    if (!digest || !entry || layer === cdLayer) continue;
    blobStore.set(digest, entry.bytes);
    blobStore.set(digest.replace(':', '.'), entry.bytes);
  }
  await emitCd(archiveName, cdText, blobStore, result);
}

/** Component archive: component-descriptor.yaml + blobs/<algo>.<hex>. */
async function walkComponentArchive(
  archiveName: string,
  byName: Map<string, TarEntry>,
  result: DeliveryResult,
): Promise<void> {
  const cd = byName.get('component-descriptor.yaml')!;
  const blobStore = new Map<string, Uint8Array>();
  for (const [name, entry] of byName) {
    if (!name.startsWith('blobs/')) continue;
    const base = name.slice('blobs/'.length);
    blobStore.set(base, entry.bytes);
    blobStore.set(base.replace('.', ':'), entry.bytes);
  }
  await emitCd(archiveName, decode(cd.bytes), blobStore, result);
}

/** Parse one CD text, extract its SPDX blobs, wire refs by byte checksum. */
async function emitCd(
  archiveName: string,
  cdText: string,
  blobStore: Map<string, Uint8Array>,
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
  // blob with different declared digests. Bytes stay in this worker; only
  // the summaries ride on the elements, keyed by the artifact's own node.
  const component = componentNode(detection.parsed);
  const specNode = isRecord(detection.parsed.spec) ? detection.parsed.spec : {};
  const resources = asRecordArray(component?.resources ?? specNode.resources);
  const sources = asRecordArray(component?.sources ?? specNode.sources);

  const inspections = new Map<string, BlobInspection>();
  const blobInfos = new Map<Record<string, unknown>, OcmBlobInfo>();
  for (const artifact of [...resources, ...sources]) {
    const access = isRecord(artifact.access) ? artifact.access : {};
    const localReference = asString(access.localReference) ?? asString(access.filename);
    if (!localReference) continue;
    const blob = blobStore.get(localReference);
    if (!blob) continue;
    try {
      let inspection = inspections.get(localReference);
      if (!inspection) {
        inspection = await inspectBlob(blob, asString(access.mediaType));
        inspections.set(localReference, inspection);
      }
      const digestCheck = await checkDeclaredDigest(
        inspection.subjects,
        isRecord(artifact.digest) ? artifact.digest : undefined,
      );
      blobInfos.set(artifact, {
        ...inspection.info,
        mediaType: asString(access.mediaType) ?? inspection.info.mediaType,
        digestCheck,
      });
    } catch {
      // Inspection is best-effort; the element simply carries no blob info.
    }
  }

  // Pass 2: extract SPDX blobs of SBOM resources (checksums first — the
  // mapper needs them while building the refs). Reuses pass 1's gunzip.
  const sbomChecksums = new Map<string, string>();
  for (const resource of resources) {
    const access = isRecord(resource.access) ? resource.access : {};
    if (!isSbomResource(resource, access)) continue;
    const localReference = asString(access.localReference) ?? asString(access.filename);
    if (!localReference) continue;
    let blob = inspections.get(localReference)?.subjects.uncompressed ?? blobStore.get(localReference);
    if (!blob) continue;
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
async function sweep(archiveName: string, entries: TarEntry[], result: DeliveryResult): Promise<void> {
  for (const entry of entries) {
    if (sniffContainer(entry.bytes) !== 'text') continue;
    const text = decode(entry.bytes);
    const detection = detect(text);
    if (detection.format === 'unsupported') continue;
    result.extracted.push({
      fileName: `${archiveName}!${entry.name}`,
      bytes: new Uint8Array(entry.bytes),
    });
  }
}

function decode(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}
