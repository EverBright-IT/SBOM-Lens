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
import { MATERIALIZE_ENTRY_MAX, readTar, readTarFrom } from '../../util/tar';
import type { OcmBlobInfo } from '../../model/ocm';
import type { Detection } from '../detect';
import { detect } from '../detect';
import type { SourceInput } from '../parser';
import type { BlobInspection } from './blob';
import { checkDeclaredDigest, checkDeclaredDigestIndexed, inspectBlob } from './blob';
import { isSbomResource, parseOcmComponentDescriptor } from './cd';
import type { OciContent, OciPart, PartRead } from './oci';
import {
  CD_LAYER_MARKER,
  OCI_EMPTY_DIGEST,
  OCI_MANIFEST_MAX,
  carriesComponentDescriptor,
  mayBeOciContent,
  ociContent,
  storedArtifactParts,
} from './oci';

/**
 * Walks a local OCM delivery — CTF tar(.gz), component archive, or any tar
 * of SPDX files. The walk itself is model-free: it discovers component
 * descriptors, inspects every localBlob the delivery physically carries
 * (kind, capped previews, digest verdicts), and extracts embedded SBOMs.
 * Two consumers sit on top of it:
 *
 * - `readOcmDelivery(From)` maps the descriptors onto the SPDX document
 *   model (OCM Lens 1.x / the flavor pipeline), unchanged behavior.
 * - `readOcmBundle(From)` (see ./bundle.ts) builds the OCM-native bundle
 *   model of OCM Lens 2.0 from the same walk.
 *
 * Tolerant end to end: per-artifact failures degrade to diagnostics and a
 * content sweep, never a throw. Everything reads through a ByteSource, so a
 * multi-GB delivery never has to exist as one buffer: descriptors, indexes,
 * and SBOMs (all small) are materialized, large artifact blobs stay index
 * entries that are hashed in constant memory for their digest verdict.
 * Nested plain tars (artifact sets) are walked through source windows the
 * same way.
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

/** An embedded SBOM pulled out of the archive, linked to its resource. */
export interface CollectedSbom {
  sha1: string;
  fileName: string;
  size: number;
  format: 'spdx' | 'cyclonedx';
  /** Media type for saving the extracted file, from content detection. */
  contentType: string;
  /** Index into the walk's `extracted` list. */
  extractedIndex: number;
}

/** One non-descriptor blob a component version's manifest references. */
export interface CollectedLayer {
  /** Canonical `algo:hex` spelling. */
  digest: string;
  size: number;
  mediaType?: string;
}

/**
 * One component descriptor as discovered by the walk — raw node plus
 * everything the walk learned about its surroundings, before any model
 * mapping. `raw` is the verbatim parsed root; blob summaries are keyed by
 * the artifact's own raw node (two artifacts may share a blob but declare
 * different digests, so the verdict is theirs).
 */
export interface CollectedCd {
  raw: Record<string, unknown>;
  serialization: 'json' | 'yaml';
  text: string;
  sha1: string;
  byteSize: number;
  /** Input-style name: `<archive>!component-descriptor.yaml`. */
  fileName: string;
  blobInfos: Map<Record<string, unknown>, OcmBlobInfo>;
  /**
   * localReferences whose blob physically exists in the archive — distinct
   * from blobInfos, whose entries can be missing when inspection failed.
   */
  blobPresent: Set<string>;
  /** Extracted SBOMs by the resource's localReference. */
  sbomByRef: Map<string, CollectedSbom>;
  /** Non-descriptor blobs of this CV's manifest (for bundle blob stats). */
  layers: CollectedLayer[];
}

export interface DeliveryWalkOptions extends TarStreamOptions {
  /**
   * Byte budget for hashing UNMATERIALIZED blobs at load time (the one
   * full-byte read the walk otherwise performs). Blobs with a declared
   * digest beyond the budget get `digestCheck: 'pending'` instead of a
   * load-time verdict — checkable on demand via digestDeliveryBlob.
   * Default: unlimited (the 1.x path keeps its eager behavior).
   */
  eagerHashBudget?: number;
}

export interface DeliveryWalk {
  archiveName: string;
  cds: CollectedCd[];
  extracted: { fileName: string; bytes: Uint8Array }[];
  diagnostics: Diagnostic[];
  layout: 'ctf' | 'component-archive' | 'file-sweep' | 'empty';
  /** Whether the container arrived gzip-compressed. */
  compressed: boolean;
  /** Size of the archive as handed in (compressed size for .tgz). */
  archiveSize: number;
  /** Internal: remaining eager-hash budget, spent as collectCd hashes. */
  hashBudgetRemaining: number;
  /** Internal: extracted SBOMs by SHA-1, so a shared SBOM is extracted once. */
  extractedBySha1: Map<string, CollectedSbom>;
}

const CD_MEDIA_PREFIX = 'application/vnd.ocm.software.component-descriptor';
/** An SBOM the walker will fetch in full even past the materialization cap. */
const SBOM_FETCH_MAX = 512 * 1024 * 1024;
/**
 * Structure the walk reads even past the materialization budget: the
 * artifact index and a component descriptor up to the per-entry cap,
 * manifests and indexes up to the size registries accept.
 */
const STRUCTURE_READ_MAX = MATERIALIZE_ENTRY_MAX;
/** Config media types of OCI artifacts that are never component descriptors. */
const ARTIFACT_CONFIGS = new Set([
  'application/vnd.oci.image.config.v1+json',
  'application/vnd.docker.container.image.v1+json',
  'application/vnd.cncf.helm.config.v1+json',
  'application/vnd.oci.empty.v1+json',
]);

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

/**
 * Source entry point: a browser File/Blob streams from disk through here.
 * Walks the delivery, then maps every descriptor onto the SPDX model.
 */
export async function readOcmDeliveryFrom(
  fileName: string,
  source: ByteSource,
  options?: TarStreamOptions,
): Promise<DeliveryResult> {
  const walk = await walkOcmDelivery(fileName, source, options);
  const result: DeliveryResult = {
    documents: [],
    extracted: walk.extracted,
    diagnostics: walk.diagnostics,
  };
  for (const cd of walk.cds) {
    const input: SourceInput = {
      fileName: cd.fileName,
      text: cd.text,
      sha1: cd.sha1,
      byteSize: cd.byteSize,
    };
    const parsed = parseOcmComponentDescriptor(input, cd.raw, cd.serialization, {
      sbomChecksumFor: (ref) => cd.sbomByRef.get(ref)?.sha1,
      blobInfoFor: (artifact) => cd.blobInfos.get(artifact),
    });
    if (parsed.document) {
      const componentLabel = parsed.document.name;
      result.documents.push({
        fileName: `${walk.archiveName}!${componentLabel}/component-descriptor.yaml`,
        sha1: cd.sha1,
        byteSize: cd.byteSize,
        text: cd.text,
        document: parsed.document,
        diagnostics: parsed.diagnostics,
      });
    } else {
      result.diagnostics.push(...parsed.diagnostics);
    }
  }
  return result;
}

/** Model-free walk of a delivery archive — the shared foundation. */
export async function walkOcmDelivery(
  fileName: string,
  source: ByteSource,
  options?: DeliveryWalkOptions,
): Promise<DeliveryWalk> {
  const walk: DeliveryWalk = {
    archiveName: fileName,
    cds: [],
    extracted: [],
    diagnostics: [],
    layout: 'empty',
    compressed: false,
    archiveSize: source.size,
    hashBudgetRemaining: options?.eagerHashBudget ?? Infinity,
    extractedBySha1: new Map(),
  };

  const head = await source.read(0, 512);
  let tarSource = source;
  if (sniffContainer(head) === 'gzip') {
    walk.compressed = true;
    // Compressed deliveries decompress into memory (DecompressionStream has
    // no random access), so they are capped; past the cap the honest answer
    // is a repack hint — plain .tar streams without any of these limits.
    if (source.size > GUNZIP_MAX_BYTES) {
      walk.diagnostics.push(
        diag('error', 'GZIP_TOO_LARGE', `Compressed delivery exceeds ${GUNZIP_MAX_BYTES / (1024 * 1024 * 1024)} GiB. Repack it as plain .tar.`),
      );
      return walk;
    }
    let tarBytes: Uint8Array;
    try {
      tarBytes = await gunzip(await source.read(0, source.size));
    } catch (error) {
      walk.diagnostics.push(
        error instanceof GunzipLimitError
          ? diag('error', 'GZIP_TOO_LARGE', `${error.message} Repack the delivery as plain .tar.`)
          : diag('error', 'GZIP_INVALID', 'Not a valid gzip stream.'),
      );
      return walk;
    }
    if (sniffContainer(tarBytes) !== 'tar') {
      walk.diagnostics.push(diag('error', 'GZIP_NOT_TAR', 'The gzip stream does not contain a tar archive.'));
      return walk;
    }
    tarSource = bufferSource(tarBytes);
  }

  const index = await indexTar(tarSource, walk.diagnostics, options);
  if (index.byName.size === 0) return walk;

  const indexEntry = index.byName.get('artifact-index.json') ?? index.byName.get('artifact-descriptor.json');
  if (indexEntry) {
    walk.layout = 'ctf';
    await walkCtf(indexEntry, index, walk);
  } else if (index.byName.has('component-descriptor.yaml')) {
    walk.layout = 'component-archive';
    await walkComponentArchive(index, walk);
  }

  if (walk.cds.length === 0) {
    await sweep(index, walk);
    if (walk.extracted.length > 0) walk.layout = 'file-sweep';
    if (walk.cds.length === 0 && walk.extracted.length === 0) {
      walk.layout = 'empty';
      walk.diagnostics.push(
        diag('error', 'ARCHIVE_NO_DOCUMENTS', 'No component descriptors or SPDX documents found in this archive.'),
      );
    }
  }
  return walk;
}

async function indexTar(
  source: ByteSource,
  diagnostics: Diagnostic[],
  options?: TarStreamOptions,
): Promise<TarIndex> {
  const { entries, diagnostics: tarDiagnostics } = await readTarFrom(source, options);
  diagnostics.push(...tarDiagnostics);
  // The last entry of a name wins, as a tar reader extracts it. A repeated
  // name is no layout the ocm CLI writes, and the copies may differ: say so.
  const byName = new Map<string, TarStreamEntry>();
  const repeated = new Set<string>();
  for (const entry of entries) {
    const name = entry.name.replace(/^\.\//, '');
    if (byName.has(name)) repeated.add(name);
    byName.set(name, entry);
  }
  if (repeated.size > 0) {
    const sample = [...repeated].slice(0, 3).join(', ');
    diagnostics.push(
      diag(
        'warning',
        'ARCHIVE_DUPLICATE_ENTRY',
        `${repeated.size} name(s) occur more than once in the archive (${sample}${repeated.size > 3 ? ', ...' : ''}): the walk reads the last entry of each, and a download hands out only bytes that match the declared digest.`,
      ),
    );
  }
  return { source, byName, options };
}

/** CTF: artifact-index.json → per-artifact OCI layout (flat or artifact set). */
async function walkCtf(
  indexEntry: TarStreamEntry,
  index: TarIndex,
  walk: DeliveryWalk,
): Promise<void> {
  const indexBytes = await entryBytes(indexEntry, index.source, STRUCTURE_READ_MAX);
  if (!indexBytes) {
    walk.diagnostics.push(
      diag('warning', 'CTF_INDEX_INVALID', `artifact-index.json exceeds ${STRUCTURE_READ_MAX / (1024 * 1024)} MB: falling back to a content sweep.`),
    );
    return;
  }
  let parsedIndex: unknown;
  try {
    parsedIndex = JSON.parse(decode(indexBytes));
  } catch {
    walk.diagnostics.push(diag('warning', 'CTF_INDEX_INVALID', 'artifact-index.json is not valid JSON: falling back to a content sweep.'));
    return;
  }
  const artifacts = isRecord(parsedIndex) ? asRecordArray(parsedIndex.artifacts) : [];
  if (artifacts.length === 0) {
    walk.diagnostics.push(diag('warning', 'CTF_INDEX_INVALID', 'artifact-index.json lists no artifacts.'));
    return;
  }

  // Tagged artifacts are the component versions. Untagged ones are what the
  // ocm CLI leaves next to them: the descriptor manifest a tagged index
  // points at, a descriptor superseded by signing, and the manifests of
  // images and charts stored by value. Tagged first, so a superseded
  // descriptor never shadows the current one.
  const ordered = [...artifacts.filter((a) => asString(a.tag)), ...artifacts.filter((a) => !asString(a.tag))];
  const walked = new Set<TarStreamEntry>();
  for (const artifact of ordered) {
    const digest = asString(artifact.digest);
    const blob = digest ? index.byName.get(`blobs/${digest.replace(':', '.')}`) : undefined;
    if (!blob) {
      walk.diagnostics.push(
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
        const inner = await indexTar(setSource, walk.diagnostics, index.options);
        const innerIndex =
          inner.byName.get('artifact-set-descriptor.json') ?? inner.byName.get('index.json');
        const manifestEntry = innerIndex ? await manifestFromIndex(innerIndex, inner) : undefined;
        await walkOciManifest(manifestEntry, inner, walk);
      } else {
        // Flat layout: the blob is the descriptor manifest or an OCI index
        // around it; layers and stored artifacts are sibling blobs.
        const manifestEntry = await descriptorManifest(blob, index);
        if (!manifestEntry || walked.has(manifestEntry)) continue;
        walked.add(manifestEntry);
        await walkOciManifest(manifestEntry, index, walk, { ctf: index, superseded: !asString(artifact.tag) });
      }
    } catch {
      walk.diagnostics.push(
        diag('warning', 'CTF_ARTIFACT_UNREADABLE', `Artifact ${asString(artifact.repository) ?? '?'} could not be read.`),
      );
    }
  }
}

/** OCI image index/manifest JSON → find the manifest blob with layers. */
async function manifestFromIndex(indexEntry: TarStreamEntry, index: TarIndex): Promise<TarStreamEntry | undefined> {
  const parsed = await readJsonEntry(indexEntry, index);
  if (!parsed) return undefined;
  if (Array.isArray(parsed.layers)) return indexEntry; // already a manifest
  const refs = asRecordArray(parsed.manifests);
  return (await descriptorInIndex(refs, index)) ?? blobEntry(index, refs[0]?.digest);
}

/**
 * The manifest carrying a component descriptor, for a CTF blob that is that
 * manifest or an OCI index around it (the ocm CLI tags an index when it
 * stores images or charts next to the descriptor). Undefined for image and
 * chart manifests: those are resources stored by value, not component
 * versions.
 */
async function descriptorManifest(entry: TarStreamEntry, index: TarIndex): Promise<TarStreamEntry | undefined> {
  const parsed = await readJsonEntry(entry, index);
  if (!parsed) return entry; // not JSON: let the walk report it as before
  if (Array.isArray(parsed.manifests)) return descriptorInIndex(asRecordArray(parsed.manifests), index);
  return manifestRole(parsed) === 'artifact' ? undefined : entry;
}

async function descriptorInIndex(refs: Record<string, unknown>[], index: TarIndex): Promise<TarStreamEntry | undefined> {
  const typed = refs.find((r) => (asString(r.artifactType) ?? '').includes(CD_LAYER_MARKER));
  if (typed) return blobEntry(index, typed.digest);
  for (const ref of refs) {
    const candidate = blobEntry(index, ref.digest);
    const manifest = candidate ? await readJsonEntry(candidate, index) : undefined;
    if (manifest && manifestRole(manifest) === 'descriptor') return candidate;
  }
  return undefined;
}

/** 'unknown' keeps the legacy behavior: the walk tries it as a descriptor. */
function manifestRole(manifest: Record<string, unknown>): 'descriptor' | 'artifact' | 'unknown' {
  if (carriesComponentDescriptor(manifest)) return 'descriptor';
  const config = isRecord(manifest.config) ? (asString(manifest.config.mediaType) ?? '') : '';
  return ARTIFACT_CONFIGS.has(config) ? 'artifact' : 'unknown';
}

function blobEntry(index: TarIndex, digest: unknown): TarStreamEntry | undefined {
  const value = asString(digest);
  return value ? index.byName.get(`blobs/${value.replace(':', '.')}`) : undefined;
}

/**
 * An entry's bytes: as the tar reader loaded them, or read now when the
 * entry stayed index-only and is at most `max` bytes. Indexes, manifests
 * and descriptors are read this way, so a delivery past the
 * materialization budget loses none of its structure.
 */
async function entryBytes(
  entry: TarStreamEntry | undefined,
  source: ByteSource,
  max: number,
): Promise<Uint8Array | undefined> {
  if (!entry) return undefined;
  if (entry.bytes) return entry.bytes;
  if (entry.size > max) return undefined;
  try {
    return await source.read(entry.offset, entry.size);
  } catch {
    return undefined;
  }
}

/** A manifest or index entry as JSON, read on demand like any structure. */
async function readJsonEntry(entry: TarStreamEntry, index: TarIndex): Promise<Record<string, unknown> | undefined> {
  const bytes = await entryBytes(entry, index.source, OCI_MANIFEST_MAX);
  if (!bytes) return undefined;
  try {
    const parsed: unknown = JSON.parse(decode(bytes));
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/**
 * A CV's local blob store in a CTF: its manifest's layers, then every blob
 * of the archive. The ocm CLI stores images and charts by value as separate
 * manifests whose digest is the resource's localReference.
 */
class CtfBlobMap extends Map<string, TarStreamEntry> {
  readonly #ctf: TarIndex;
  constructor(ctf: TarIndex) {
    super();
    this.#ctf = ctf;
  }
  override get(key: string): TarStreamEntry | undefined {
    return super.get(key) ?? this.#ctf.byName.get(`blobs/${key.replace(':', '.')}`);
  }
}

interface ManifestWalkOptions {
  /** Resolve localReferences against the whole CTF, not only the layers. */
  ctf?: TarIndex;
  /** Untagged: skip when a tagged artifact already carried this CV. */
  superseded?: boolean;
}

async function walkOciManifest(
  manifestEntry: TarStreamEntry | undefined,
  index: TarIndex,
  walk: DeliveryWalk,
  options: ManifestWalkOptions = {},
): Promise<void> {
  const manifest = manifestEntry ? await readJsonEntry(manifestEntry, index) : undefined;
  if (!manifest) return;
  const layers = asRecordArray(manifest.layers);
  if (layers.length === 0) return;

  const layerEntry = (layer: Record<string, unknown>): TarStreamEntry | undefined => {
    const digest = asString(layer.digest);
    return digest ? index.byName.get(`blobs/${digest.replace(':', '.')}`) : undefined;
  };

  const typedLayer = layers.find((l) => (asString(l.mediaType) ?? '').startsWith(CD_MEDIA_PREFIX));
  const cdLayer = typedLayer ?? layers[0]!;
  const cdEntry = layerEntry(cdLayer);
  // A layer known to hold the descriptor is read past the materialization
  // budget too; the legacy guess (the first layer of an unmarked manifest)
  // only when the tar reader loaded it anyway.
  const known = typedLayer !== undefined || carriesComponentDescriptor(manifest);
  const cdBytes = known ? await entryBytes(cdEntry, index.source, STRUCTURE_READ_MAX) : (cdEntry?.bytes ?? undefined);
  if (!cdBytes) {
    if (known && cdEntry && cdEntry.size > STRUCTURE_READ_MAX) {
      walk.diagnostics.push(
        diag(
          'warning',
          'CTF_ARTIFACT_UNREADABLE',
          `A component descriptor of ${Math.round(cdEntry.size / (1024 * 1024))} MB exceeds ${STRUCTURE_READ_MAX / (1024 * 1024)} MB and was not read.`,
        ),
      );
    }
    return;
  }

  let cdText: string;
  const cdMedia = asString(cdLayer.mediaType) ?? '';
  if (cdMedia.endsWith('+tar') || sniffContainer(cdBytes) === 'tar') {
    const innerCd = readTar(cdBytes).entries.find((e) =>
      e.name.replace(/^\.\//, '').endsWith('component-descriptor.yaml'),
    );
    if (!innerCd) return;
    cdText = decode(innerCd.bytes);
  } else {
    cdText = decode(cdBytes);
  }

  // Local blob store: every non-CD layer, keyed by its digest spellings.
  const blobs = options.ctf ? new CtfBlobMap(options.ctf) : new Map<string, TarStreamEntry>();
  const layerSummaries: CollectedLayer[] = [];
  for (const layer of layers) {
    const digest = asString(layer.digest);
    const entry = layerEntry(layer);
    if (!digest || layer === cdLayer) continue;
    if (entry) {
      blobs.set(digest, entry);
      blobs.set(digest.replace(':', '.'), entry);
    }
    const declaredSize = typeof layer.size === 'number' ? layer.size : undefined;
    layerSummaries.push({
      digest,
      size: entry?.size ?? declaredSize ?? 0,
      mediaType: asString(layer.mediaType),
    });
  }
  await collectCd(cdText, { source: index.source, byName: blobs }, layerSummaries, walk, options.superseded);
}

/** Component archive: component-descriptor.yaml + blobs/<algo>.<hex>. */
async function walkComponentArchive(index: TarIndex, walk: DeliveryWalk): Promise<void> {
  const cd = index.byName.get('component-descriptor.yaml')!;
  const cdBytes = await entryBytes(cd, index.source, STRUCTURE_READ_MAX);
  if (!cdBytes) {
    walk.diagnostics.push(
      diag('warning', 'CTF_ARTIFACT_UNREADABLE', `component-descriptor.yaml exceeds ${STRUCTURE_READ_MAX / (1024 * 1024)} MB and was not read.`),
    );
    return;
  }
  const blobs = new Map<string, TarStreamEntry>();
  const layerSummaries: CollectedLayer[] = [];
  for (const [name, entry] of index.byName) {
    if (!name.startsWith('blobs/')) continue;
    const base = name.slice('blobs/'.length);
    blobs.set(base, entry);
    blobs.set(base.replace('.', ':'), entry);
    layerSummaries.push({ digest: base.replace('.', ':'), size: entry.size });
  }
  await collectCd(decode(cdBytes), { source: index.source, byName: blobs }, layerSummaries, walk);
}

/**
 * Collect one CD: detection, blob inspection (pass 1), SBOM extraction
 * (pass 2). Model mapping is the consumers' business. Returns nothing; a
 * successful collection lands in `walk.cds`, failures degrade to
 * diagnostics exactly as before the walk/mapping split.
 */
async function collectCd(
  cdText: string,
  blobs: TarIndex,
  layers: CollectedLayer[],
  walk: DeliveryWalk,
  superseded = false,
): Promise<void> {
  const detection = detect(cdText);
  if (detection.format !== 'ocm-cd') {
    walk.diagnostics.push(
      diag('warning', 'CTF_ARTIFACT_UNREADABLE', 'A component-descriptor layer did not parse as an OCM CD.'),
    );
    return;
  }
  // A descriptor the mapper could never name is not worth collecting: both
  // consumers need name+version, and the pre-split code surfaced exactly
  // this error at the archive level.
  const component = componentNode(detection.parsed);
  const metadataNode = isRecord(detection.parsed.metadata) ? detection.parsed.metadata : null;
  const named = component ?? metadataNode;
  if (!named || !asString(named.name) || !asString(named.version)) {
    walk.diagnostics.push(
      diag('error', 'OCM_CD_MALFORMED', 'Component descriptor has no component name/version.'),
    );
    return;
  }
  // An untagged descriptor for a CV a tag already delivered is a leftover
  // (signing rewrites the descriptor; the old manifest stays in the CTF).
  if (superseded && walk.cds.some((cd) => sameCv(cd.raw, named))) return;

  // Pass 1: inspect EVERY localBlob the delivery physically carries (kind,
  // capped previews). Content inspection caches per blob; the digest verdict
  // is computed PER ARTIFACT, because two artifacts may point at the same
  // blob with different declared digests. Unmaterialized blobs skip content
  // inspection but still get a REAL digest verdict: their bytes are hashed
  // in constant memory straight off the source (cached per blob). Bytes stay
  // in this worker; only the summaries ride on the elements.
  const specNode = isRecord(detection.parsed.spec) ? detection.parsed.spec : {};
  const resources = asRecordArray(component?.resources ?? specNode.resources);
  const sources = asRecordArray(component?.sources ?? specNode.sources);

  const inspections = new Map<string, BlobInspection>();
  const indexedHashes = new Map<string, Promise<string>>();
  const blobInfos = new Map<Record<string, unknown>, OcmBlobInfo>();
  const blobPresent = new Set<string>();
  const storedByRef = new Map<string, StoredArtifact | null>();
  for (const artifact of [...resources, ...sources]) {
    const access = isRecord(artifact.access) ? artifact.access : {};
    const localReference = asString(access.localReference) ?? asString(access.filename);
    if (!localReference) continue;
    const blob = blobs.byName.get(localReference);
    if (!blob) continue;
    // An image or chart stored by value, recognised by its bytes (the media
    // type in the access is not signed): the localReference is its manifest
    // or index, and it is only present if every blob below it is there, at
    // the size its manifest declares (a cheap check that catches a copy cut
    // short on its way to the air-gapped side).
    let stored = storedByRef.get(localReference);
    if (stored === undefined) {
      stored = (await storedArtifactAt(blob, blobs)) ?? null;
      storedByRef.set(localReference, stored);
    }
    if (stored) {
      const gap = storedArtifactGap(stored.parts, blobs);
      if (gap) {
        walk.diagnostics.push(
          diag(
            'warning',
            'OCM_ARTIFACT_INCOMPLETE',
            `Resource "${asString(artifact.name) ?? localReference}": ${gap} of the stored OCI artifact.`,
          ),
        );
        continue;
      }
      layers.push(...stored.parts.map(({ digest, size, mediaType }) => ({ digest, size, mediaType })));
    }
    blobPresent.add(localReference);
    const declared = isRecord(artifact.digest) ? artifact.digest : undefined;
    try {
      // A stored artifact's manifest is read even when the tar reader left
      // it index-only, so it is judged with everything below it.
      const bytes = blob.bytes ?? stored?.bytes;
      if (bytes) {
        let inspection = inspections.get(localReference);
        if (!inspection) {
          inspection = await inspectBlob(bytes, asString(access.mediaType));
          inspections.set(localReference, inspection);
        }
        let digestCheck = await checkDeclaredDigest(
          stored ? { ...inspection.subjects, manifest: bytes } : inspection.subjects,
          declared,
        );
        // A matching manifest vouches for nothing it points at: the
        // manifests, configs and layers of an image or chart stored by value
        // must match too.
        if (stored && digestCheck === 'match')
          digestCheck = await storedPartsVerdict(stored, blobs, walk, indexedHashes);
        const summary = ({ digest, size, mediaType }: OciPart) => ({ digest, size, mediaType });
        blobInfos.set(artifact, {
          ...inspection.info,
          mediaType: asString(access.mediaType) ?? inspection.info.mediaType,
          digestCheck,
          ...(stored
            ? {
                kind: 'oci-artifact' as const,
                size: blob.size + stored.parts.reduce((sum, part) => sum + part.size, 0),
                oci: {
                  layers: stored.parts.filter((part) => part.role === 'layer').map(summary),
                  // An index has a config per manifest; an image has one.
                  ...(stored.content.kind === 'manifest' ? { config: summary(stored.content.config) } : {}),
                },
              }
            : {}),
        });
      } else if (isRecord(declared) && asString(declared.value) && blob.size > walk.hashBudgetRemaining) {
        // Over the eager-hash budget: the one full-byte read the walk would
        // do is deferred. The verdict is honestly 'pending', checkable on
        // demand — opening a transfer-medium-sized delivery stays instant.
        blobInfos.set(artifact, {
          size: blob.size,
          mediaType: asString(access.mediaType),
          kind: 'binary',
          notInspected: true,
          digestCheck: 'pending',
        });
      } else {
        if (isRecord(declared) && asString(declared.value)) {
          // Budget is an upper bound on load-time reads; declarations that
          // are not computable under-spend it, which only errs toward
          // checking more.
          walk.hashBudgetRemaining -= blob.size;
        }
        const digestCheck = await checkDeclaredDigestIndexed(declared, () => {
          let hash = indexedHashes.get(localReference);
          if (!hash) {
            hash = sha256SourceHex(blobs.source, blob.offset, blob.size);
            indexedHashes.set(localReference, hash);
          }
          return hash;
        });
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

  // Pass 2: extract SBOM resources (checksums first: the 1.x mapper needs
  // them while building the refs). An SBOM past the materialization cap is
  // worth a targeted full fetch: it is the reason this product exists.
  // Reuses pass 1's gunzip where available. Format and file type come from
  // the content, never from the declared media type, and an SBOM shipped
  // under several component versions is extracted once.
  const sbomByRef = new Map<string, CollectedSbom>();
  const cvLabel = `${(asString(named.name) ?? 'component').split('/').pop()}-${asString(named.version) ?? ''}`;
  for (const resource of resources) {
    const access = isRecord(resource.access) ? resource.access : {};
    if (!isSbomResource(resource, access)) continue;
    const localReference = asString(access.localReference) ?? asString(access.filename);
    if (!localReference) continue;
    const stored = blobs.byName.get(localReference);
    if (!stored) continue;
    const resourceName = asString(resource.name) ?? localReference;
    const unreadable = (reason: string) =>
      walk.diagnostics.push(
        diag('warning', 'OCM_SBOM_UNREADABLE', `SBOM resource "${resourceName}" ${reason}: skipped.`),
      );
    let blob = inspections.get(localReference)?.subjects.uncompressed ?? stored.bytes ?? undefined;
    if (!blob) {
      if (stored.size > SBOM_FETCH_MAX) {
        walk.diagnostics.push(
          diag(
            'warning',
            'OCM_SBOM_TOO_LARGE',
            `SBOM resource "${resourceName}" exceeds ${SBOM_FETCH_MAX / (1024 * 1024)} MB and was not extracted.`,
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
        if (!first?.bytes) {
          unreadable('is an empty archive');
          continue;
        }
        blob = first.bytes;
      }
    } catch {
      unreadable('could not be unpacked');
      continue;
    }
    let kind: SbomFileKind | undefined;
    try {
      kind = sbomFileKind(detect(decode(blob)));
    } catch {
      // A text past the engine's string limit, or a parser crash, must not
      // cost the component version its other resources.
      unreadable('could not be decoded');
      continue;
    }
    if (!kind) {
      walk.diagnostics.push(
        diag(
          'warning',
          'OCM_SBOM_FORMAT_UNSUPPORTED',
          `SBOM resource "${resourceName}" is neither SPDX nor CycloneDX (${asString(access.mediaType) ?? 'unknown media type'}): skipped.`,
        ),
      );
      continue;
    }
    const copy = new Uint8Array(blob); // detach from the archive buffer
    const sha1 = await sha1Hex(copy.buffer as ArrayBuffer);
    const known = walk.extractedBySha1.get(sha1);
    if (known) {
      sbomByRef.set(localReference, known);
      continue;
    }
    const fileName = uniqueExtractedName(walk, [
      `${walk.archiveName}!${resourceName}${kind.extension}`,
      `${walk.archiveName}!${cvLabel}-${resourceName}${kind.extension}`,
    ]);
    const collected: CollectedSbom = {
      sha1,
      fileName,
      size: copy.byteLength,
      format: kind.format,
      contentType: kind.contentType,
      extractedIndex: walk.extracted.length,
    };
    sbomByRef.set(localReference, collected);
    walk.extractedBySha1.set(sha1, collected);
    walk.extracted.push({ fileName, bytes: copy });
  }

  const cdBytes = new TextEncoder().encode(cdText);
  const sha1 = await sha1Hex(cdBytes.buffer as ArrayBuffer);
  walk.cds.push({
    raw: detection.parsed,
    serialization: detection.serialization,
    text: cdText,
    sha1,
    byteSize: cdBytes.byteLength,
    fileName: `${walk.archiveName}!component-descriptor.yaml`,
    blobInfos,
    blobPresent,
    sbomByRef,
    layers,
  });
}

function componentNode(parsed: Record<string, unknown>): Record<string, unknown> | null {
  return isRecord(parsed.component) ? parsed.component : null;
}

function sameCv(raw: Record<string, unknown>, named: Record<string, unknown>): boolean {
  const other = componentNode(raw) ?? (isRecord(raw.metadata) ? raw.metadata : null);
  return !!other && other.name === named.name && other.version === named.version;
}

/** An image or chart stored by value, as the walk found it. */
interface StoredArtifact {
  /** The manifest or index bytes, read even when the tar reader left them index-only. */
  bytes: Uint8Array;
  content: OciContent;
  /** Every blob below the manifest or index, each once. */
  parts: OciPart[];
  /** Nested manifests present but not readable as one: what they name is unchecked. */
  opaque: number;
}

/**
 * The image or chart a resource's blob stores by value, recognised by its
 * bytes: an OCI manifest or index (never a descriptor manifest), with every
 * blob below it. Undefined for every other blob.
 */
async function storedArtifactAt(blob: TarStreamEntry, blobs: TarIndex): Promise<StoredArtifact | undefined> {
  if (!blob.bytes) {
    // Index-only: look at the head before reading a blob in full.
    if (blob.size === 0 || blob.size > OCI_MANIFEST_MAX) return undefined;
    const head = await blobs.source.read(blob.offset, Math.min(blob.size, 64)).catch(() => undefined);
    if (!head || !mayBeOciContent(head)) return undefined;
  }
  const bytes = await entryBytes(blob, blobs.source, OCI_MANIFEST_MAX);
  const content = bytes ? ociContent(bytes) : undefined;
  if (!bytes || !content || carriesComponentDescriptor(content.raw)) return undefined;
  const { parts, opaque } = await storedArtifactParts(content, async (digest): Promise<PartRead> => {
    const entry = blobs.byName.get(digest);
    if (!entry) return 'absent';
    return (await entryBytes(entry, blobs.source, OCI_MANIFEST_MAX)) ?? 'unreadable';
  });
  return { bytes, content, parts, opaque };
}

/**
 * Every blob below an image or chart stored by value, held against the
 * digest its manifest records (OCI blobs are named by their content
 * digest). Hashing them counts against the eager-hash budget; past it the
 * verdict is 'pending', and the on-demand check judges the manifest and
 * every part (see extract.ts). Only SHA-256 parts are computable.
 */
async function storedPartsVerdict(
  stored: StoredArtifact,
  blobs: TarIndex,
  walk: DeliveryWalk,
  hashes: Map<string, Promise<string>>,
): Promise<OcmBlobInfo['digestCheck']> {
  const parts = stored.parts.map((part) => ({
    part,
    entry: blobs.byName.get(part.digest),
    hex: /^sha256:([0-9a-f]{64})$/i.exec(part.digest)?.[1]?.toLowerCase(),
  }));
  // Only bytes still to be read count against the budget.
  const cost = parts
    .filter(({ part, entry, hex }) => entry && hex && !hashes.has(part.digest))
    .reduce((sum, { entry }) => sum + entry!.size, 0);
  if (cost > walk.hashBudgetRemaining) return 'pending';
  walk.hashBudgetRemaining -= cost;
  // What a nested manifest the walk could not read names, no one checked.
  let verdict: OcmBlobInfo['digestCheck'] = stored.opaque > 0 ? 'unchecked' : 'match';
  for (const { part, entry, hex } of parts) {
    if (!entry) {
      if (part.digest.toLowerCase() !== OCI_EMPTY_DIGEST) verdict = 'unchecked';
      continue;
    }
    if (!hex) {
      verdict = 'unchecked';
      continue;
    }
    let hash = hashes.get(part.digest);
    if (!hash) {
      hash = sha256SourceHex(blobs.source, entry.offset, entry.size);
      hashes.set(part.digest, hash);
    }
    if ((await hash) !== hex) return 'mismatch';
  }
  return verdict;
}

/** What keeps a stored artifact from being complete, or undefined. */
function storedArtifactGap(parts: OciPart[], blobs: TarIndex): string | undefined {
  let absent = 0;
  let resized = 0;
  for (const part of parts) {
    const entry = blobs.byName.get(part.digest);
    if (!entry) {
      // The empty descriptor's bytes follow from its digest.
      if (part.digest.toLowerCase() !== OCI_EMPTY_DIGEST) absent++;
    } else if (part.size > 0 && entry.size !== part.size) resized++;
  }
  const gaps = [
    absent > 0 ? `${absent} of ${parts.length} blob(s) missing from the delivery` : '',
    resized > 0 ? `${resized} of ${parts.length} blob(s) not at the declared size` : '',
  ].filter(Boolean);
  return gaps.length > 0 ? gaps.join(', ') : undefined;
}

interface SbomFileKind {
  format: 'spdx' | 'cyclonedx';
  extension: string;
  contentType: string;
}

/** What an SBOM resource's content is, or undefined when it is no SBOM. */
function sbomFileKind(detection: Detection): SbomFileKind | undefined {
  switch (detection.format) {
    case 'spdx2-json':
      return detection.serialization === 'yaml'
        ? { format: 'spdx', extension: '.spdx.yaml', contentType: 'application/yaml' }
        : { format: 'spdx', extension: '.spdx.json', contentType: 'application/spdx+json' };
    case 'spdx2-tag-value':
      return { format: 'spdx', extension: '.spdx', contentType: 'text/spdx' };
    case 'spdx3-json':
      return detection.serialization === 'yaml'
        ? { format: 'spdx', extension: '.spdx3.yaml', contentType: 'application/yaml' }
        : { format: 'spdx', extension: '.spdx3.json', contentType: 'application/spdx+json' };
    case 'cdx-json':
      if (detection.serialization === 'xml') {
        return { format: 'cyclonedx', extension: '.cdx.xml', contentType: 'application/vnd.cyclonedx+xml' };
      }
      return detection.serialization === 'yaml'
        ? { format: 'cyclonedx', extension: '.cdx.yaml', contentType: 'application/yaml' }
        : { format: 'cyclonedx', extension: '.cdx.json', contentType: 'application/vnd.cyclonedx+json' };
    default:
      // Unsupported formats, and a component descriptor is no SBOM either.
      return undefined;
  }
}

/** The first candidate no other extracted file uses, numbered as a last resort. */
function uniqueExtractedName(walk: DeliveryWalk, candidates: string[]): string {
  const taken = new Set(walk.extracted.map((e) => e.fileName));
  const free = candidates.find((c) => !taken.has(c));
  if (free) return free;
  const last = candidates[candidates.length - 1]!;
  for (let n = 2; ; n++) {
    const numbered = last.replace(/(\.[a-z0-9]+)+$/i, (ext) => `-${n}${ext}`);
    if (!taken.has(numbered)) return numbered;
  }
}

/** Fallback: treat the tar as a plain bundle of SPDX/OCM files. */
async function sweep(index: TarIndex, walk: DeliveryWalk): Promise<void> {
  for (const [name, entry] of index.byName) {
    if (!entry.bytes) continue; // an unmaterialized blob is never an SPDX text
    if (sniffContainer(entry.bytes) !== 'text') continue;
    const text = decode(entry.bytes);
    const detection = detect(text);
    if (detection.format === 'unsupported') continue;
    walk.extracted.push({
      fileName: `${walk.archiveName}!${name}`,
      bytes: new Uint8Array(entry.bytes),
    });
  }
}

function decode(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}
