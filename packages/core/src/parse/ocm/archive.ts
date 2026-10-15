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
}

const CD_MEDIA_PREFIX = 'application/vnd.ocm.software.component-descriptor';
/** An SBOM the walker will fetch in full even past the materialization cap. */
const SBOM_FETCH_MAX = 512 * 1024 * 1024;
/** Markers of a descriptor manifest: ocm.software and legacy gardener spellings. */
const CD_CONFIG_MARKER = 'component.config';
const CD_LAYER_MARKER = 'component-descriptor';
/** Config media types of OCI artifacts that are never component descriptors. */
const ARTIFACT_CONFIGS = new Set([
  'application/vnd.oci.image.config.v1+json',
  'application/vnd.docker.container.image.v1+json',
  'application/vnd.cncf.helm.config.v1+json',
  'application/vnd.oci.empty.v1+json',
]);
const OCI_MANIFEST_TYPES = new Set([
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.v2+json',
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
  return { source, byName: new Map(entries.map((e) => [e.name.replace(/^\.\//, ''), e])), options };
}

/** CTF: artifact-index.json → per-artifact OCI layout (flat or artifact set). */
async function walkCtf(
  indexEntry: TarStreamEntry,
  index: TarIndex,
  walk: DeliveryWalk,
): Promise<void> {
  let parsedIndex: unknown;
  try {
    parsedIndex = JSON.parse(decode(indexEntry.bytes ?? new Uint8Array(0)));
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
        const manifestEntry = innerIndex ? manifestFromIndex(innerIndex, inner) : undefined;
        await walkOciManifest(manifestEntry, inner, walk);
      } else {
        // Flat layout: the blob is the descriptor manifest or an OCI index
        // around it; layers and stored artifacts are sibling blobs.
        const manifestEntry = descriptorManifest(blob, index);
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
function manifestFromIndex(indexEntry: TarStreamEntry, index: TarIndex): TarStreamEntry | undefined {
  const parsed = parseJsonEntry(indexEntry);
  if (!parsed) return undefined;
  if (Array.isArray(parsed.layers)) return indexEntry; // already a manifest
  const refs = asRecordArray(parsed.manifests);
  return descriptorInIndex(refs, index) ?? blobEntry(index, refs[0]?.digest);
}

/**
 * The manifest carrying a component descriptor, for a CTF blob that is that
 * manifest or an OCI index around it (the ocm CLI tags an index when it
 * stores images or charts next to the descriptor). Undefined for image and
 * chart manifests: those are resources stored by value, not component
 * versions.
 */
function descriptorManifest(entry: TarStreamEntry, index: TarIndex): TarStreamEntry | undefined {
  const parsed = parseJsonEntry(entry);
  if (!parsed) return entry; // not JSON: let the walk report it as before
  if (Array.isArray(parsed.manifests)) return descriptorInIndex(asRecordArray(parsed.manifests), index);
  return manifestRole(parsed) === 'artifact' ? undefined : entry;
}

function descriptorInIndex(refs: Record<string, unknown>[], index: TarIndex): TarStreamEntry | undefined {
  const typed = refs.find((r) => (asString(r.artifactType) ?? '').includes(CD_LAYER_MARKER));
  if (typed) return blobEntry(index, typed.digest);
  for (const ref of refs) {
    const candidate = blobEntry(index, ref.digest);
    const manifest = candidate ? parseJsonEntry(candidate) : undefined;
    if (manifest && manifestRole(manifest) === 'descriptor') return candidate;
  }
  return undefined;
}

/** 'unknown' keeps the legacy behavior: the walk tries it as a descriptor. */
function manifestRole(manifest: Record<string, unknown>): 'descriptor' | 'artifact' | 'unknown' {
  const config = isRecord(manifest.config) ? (asString(manifest.config.mediaType) ?? '') : '';
  if (config.includes(CD_CONFIG_MARKER)) return 'descriptor';
  if (asRecordArray(manifest.layers).some((l) => (asString(l.mediaType) ?? '').includes(CD_LAYER_MARKER))) {
    return 'descriptor';
  }
  return ARTIFACT_CONFIGS.has(config) ? 'artifact' : 'unknown';
}

function blobEntry(index: TarIndex, digest: unknown): TarStreamEntry | undefined {
  const value = asString(digest);
  return value ? index.byName.get(`blobs/${value.replace(':', '.')}`) : undefined;
}

function parseJsonEntry(entry: TarStreamEntry): Record<string, unknown> | undefined {
  if (!entry.bytes) return undefined;
  try {
    const parsed: unknown = JSON.parse(decode(entry.bytes));
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
  if (!cd.bytes) return;
  const blobs = new Map<string, TarStreamEntry>();
  const layerSummaries: CollectedLayer[] = [];
  for (const [name, entry] of index.byName) {
    if (!name.startsWith('blobs/')) continue;
    const base = name.slice('blobs/'.length);
    blobs.set(base, entry);
    blobs.set(base.replace('.', ':'), entry);
    layerSummaries.push({ digest: base.replace('.', ':'), size: entry.size });
  }
  await collectCd(decode(cd.bytes), { source: index.source, byName: blobs }, layerSummaries, walk);
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
  for (const artifact of [...resources, ...sources]) {
    const access = isRecord(artifact.access) ? artifact.access : {};
    const localReference = asString(access.localReference) ?? asString(access.filename);
    if (!localReference) continue;
    const blob = blobs.byName.get(localReference);
    if (!blob) continue;
    // An image or chart stored by value: the localReference is its manifest,
    // and it is only present if every blob the manifest names is there, at
    // the size the manifest declares (a cheap check that catches a copy cut
    // short on its way to the air-gapped side).
    const stored = storedArtifactParts(blob, access);
    if (stored) {
      const gap = storedArtifactGap(stored, blobs);
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
      layers.push(...stored.map(({ digest, size, mediaType }) => ({ digest, size, mediaType })));
    }
    blobPresent.add(localReference);
    const declared = isRecord(artifact.digest) ? artifact.digest : undefined;
    try {
      if (blob.bytes) {
        let inspection = inspections.get(localReference);
        if (!inspection) {
          inspection = await inspectBlob(blob.bytes, asString(access.mediaType));
          inspections.set(localReference, inspection);
        }
        const digestCheck = await checkDeclaredDigest(
          stored ? { ...inspection.subjects, manifest: blob.bytes } : inspection.subjects,
          declared,
        );
        blobInfos.set(artifact, {
          ...inspection.info,
          mediaType: asString(access.mediaType) ?? inspection.info.mediaType,
          digestCheck,
          ...(stored
            ? {
                kind: 'oci-artifact' as const,
                size: blob.size + stored.reduce((sum, part) => sum + part.size, 0),
                oci: {
                  layers: stored
                    .filter((part) => part.role === 'layer')
                    .map(({ digest, size, mediaType }) => ({ digest, size, mediaType })),
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
          // Budget is an upper bound on load-time reads; gzip short-circuits
          // under-spend it, which only errs toward checking more.
          walk.hashBudgetRemaining -= blob.size;
        }
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
  const sbomByRef = new Map<string, CollectedSbom>();
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
        walk.diagnostics.push(
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
      walk.diagnostics.push(
        diag(
          'warning',
          'OCM_SBOM_FORMAT_UNSUPPORTED',
          `SBOM resource "${asString(resource.name) ?? '?'}" is neither SPDX nor CycloneDX (${asString(access.mediaType) ?? 'unknown media type'}): skipped.`,
        ),
      );
      continue;
    }
    const copy = new Uint8Array(blob); // detach from the archive buffer
    const sha1 = await sha1Hex(copy.buffer as ArrayBuffer);
    // Detection is by content; the suffix only keeps the tree honest about
    // what the resource is.
    const mediaType = asString(access.mediaType)?.toLowerCase() ?? '';
    const suffix = mediaType.includes('cyclonedx') ? (mediaType.includes('xml') ? '.cdx.xml' : '.cdx.json') : '.spdx';
    const fileName = `${walk.archiveName}!${asString(resource.name) ?? localReference}${suffix}`;
    sbomByRef.set(localReference, {
      sha1,
      fileName,
      size: copy.byteLength,
      format: suffix === '.spdx' ? 'spdx' : 'cyclonedx',
      extractedIndex: walk.extracted.length,
    });
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

interface StoredPart extends CollectedLayer {
  role: 'config' | 'layer';
}

/**
 * The config and layers an OCI manifest blob names, when the resource's
 * blob is such a manifest (image or chart stored by value). Undefined for
 * every other blob, descriptor manifests included.
 */
function storedArtifactParts(blob: TarStreamEntry, access: Record<string, unknown>): StoredPart[] | undefined {
  const mediaType = asString(access.mediaType);
  if (mediaType ? !OCI_MANIFEST_TYPES.has(mediaType) : blob.bytes?.[0] !== 0x7b) return undefined;
  const manifest = parseJsonEntry(blob);
  if (!manifest || !isRecord(manifest.config) || !Array.isArray(manifest.layers)) return undefined;
  if (manifestRole(manifest) === 'descriptor') return undefined;
  const part = (node: Record<string, unknown>, role: StoredPart['role']): StoredPart | undefined => {
    const digest = asString(node.digest);
    if (!digest) return undefined;
    return { digest, size: typeof node.size === 'number' ? node.size : 0, mediaType: asString(node.mediaType), role };
  };
  return [part(manifest.config, 'config'), ...asRecordArray(manifest.layers).map((l) => part(l, 'layer'))].filter(
    (p): p is StoredPart => p !== undefined,
  );
}

/** What keeps a stored artifact from being complete, or undefined. */
function storedArtifactGap(stored: StoredPart[], blobs: TarIndex): string | undefined {
  let absent = 0;
  let resized = 0;
  for (const part of stored) {
    const entry = blobs.byName.get(part.digest);
    if (!entry) absent++;
    else if (part.size > 0 && entry.size !== part.size) resized++;
  }
  const gaps = [
    absent > 0 ? `${absent} of ${stored.length} blob(s) missing from the delivery` : '',
    resized > 0 ? `${resized} of ${stored.length} blob(s) not at the declared size` : '',
  ].filter(Boolean);
  return gaps.length > 0 ? gaps.join(', ') : undefined;
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
