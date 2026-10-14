import type { Diagnostic } from '../../model/diagnostics';
import { diag } from '../../model/diagnostics';
import type {
  OcmArtifact,
  OcmBlobStat,
  OcmBundle,
  OcmBundleResult,
  OcmCompleteness,
  OcmCv,
  OcmCvId,
  OcmRef,
  OcmTransport,
} from '../../model/ocm-bundle';
import { ocmCvId } from '../../model/ocm-bundle';
import type { ByteSource } from '../../util/bytesource';
import { bufferSource } from '../../util/bytesource';
import { asString, isRecord } from '../../util/narrow';
import type { CollectedCd, CollectedLayer, DeliveryWalkOptions } from './archive';
import { walkOcmDelivery } from './archive';
import { detect } from '../detect';
import { sha1Hex } from '../../util/sha1';
import {
  artifactLocation,
  mapRepositoryContexts,
  mapSignatures,
  normalizeCd,
  ocmDigest,
  ocmLabels,
  stringRecord,
} from './cd';
import { validateCdStructure } from './validate';

/**
 * Builds the OCM-native bundle model (OCM Lens 2.0) from a delivery walk:
 * component versions in the spec's own vocabulary, the reference graph
 * reconstructed from the flat archive (roots, diamonds, cycle guard,
 * unbounded depth), the transport/completeness classification, and blob
 * statistics over the content-addressed store. Shares the walk, the
 * v2/v3alpha1 normalizer, and every node mapper with the 1.x path — one
 * reading of the spec, two models.
 */

/** Access types whose bytes live outside the bundle — deploying needs network. */
const EXTERNAL_ACCESS = new Set([
  'ociartifact',
  'ociimage',
  'ociregistry',
  'ociblob',
  'github',
  'git',
  'gitlab',
  's3',
  'npm',
  'helm',
  'maven',
  'wget',
  'http',
  'https',
]);

const LOCAL_ACCESS = new Set(['localblob', 'localfilesystemblob']);

/** Blob statistics are for orientation; past this count the table is noise. */
const MAX_BLOB_STATS = 500;

/**
 * Load-time hashing budget: a delivery whose unmaterialized declared blobs
 * stay under this opens with full digest verdicts (today's behavior for
 * ordinary bundles); past it, verdicts defer to 'pending' and the open is
 * instant even for transfer-medium-sized archives.
 */
export const EAGER_HASH_BUDGET_DEFAULT = 256 * 1024 * 1024;

export async function readOcmBundle(
  fileName: string,
  bytes: Uint8Array,
  options?: DeliveryWalkOptions,
): Promise<OcmBundleResult> {
  return readOcmBundleFrom(fileName, bufferSource(bytes), options);
}

export async function readOcmBundleFrom(
  fileName: string,
  source: ByteSource,
  options?: DeliveryWalkOptions,
): Promise<OcmBundleResult> {
  const walk = await walkOcmDelivery(fileName, source, {
    eagerHashBudget: EAGER_HASH_BUDGET_DEFAULT,
    ...options,
  });
  if (walk.cds.length === 0 || walk.layout === 'file-sweep' || walk.layout === 'empty') {
    return { bundle: null, extracted: walk.extracted, diagnostics: walk.diagnostics };
  }
  return {
    bundle: assembleBundle(
      walk.archiveName,
      walk.layout === 'ctf' ? 'ctf' : 'component-archive',
      walk.compressed,
      walk.archiveSize,
      walk.cds,
    ),
    extracted: walk.extracted,
    diagnostics: walk.diagnostics,
  };
}

/**
 * A bare component descriptor opened without a container: same model, one
 * CV, no blob store — every localBlob access is honestly `broken` until the
 * delivery it belongs to is opened.
 */
export async function bundleFromDescriptor(fileName: string, text: string): Promise<OcmBundleResult> {
  const detection = detect(text);
  if (detection.format !== 'ocm-cd') {
    return {
      bundle: null,
      extracted: [],
      diagnostics: [
        diag('error', 'OCM_NOT_A_DESCRIPTOR', 'Not an OCM component descriptor or delivery archive.'),
      ],
    };
  }
  const bytes = new TextEncoder().encode(text);
  const cd: CollectedCd = {
    raw: detection.parsed,
    serialization: detection.serialization,
    text,
    sha1: await sha1Hex(bytes.buffer as ArrayBuffer),
    byteSize: bytes.byteLength,
    fileName,
    blobInfos: new Map(),
    blobPresent: new Set(),
    sbomByRef: new Map(),
    layers: [],
  };
  return {
    bundle: assembleBundle(fileName, 'descriptor', false, bytes.byteLength, [cd]),
    extracted: [],
    diagnostics: [],
  };
}

function assembleBundle(
  fileName: string,
  layout: OcmBundle['layout'],
  compressed: boolean,
  archiveSize: number,
  cds: CollectedCd[],
): OcmBundle {
  const issues: Diagnostic[] = [];
  const cvs: OcmCv[] = [];
  const layersByCv: [OcmCvId, CollectedLayer[]][] = [];
  const shaById = new Map<OcmCvId, string>();

  for (const cd of cds) {
    const cv = buildCv(cd, fileName, layout, shaById, issues);
    if (!cv) continue;
    shaById.set(cv.id, cv.sha1);
    cvs.push(cv);
    layersByCv.push([cv.id, cd.layers]);
  }

  resolveReferences(cvs, issues);
  const roots = findRoots(cvs);
  const shared = findShared(cvs);
  const completeness = computeCompleteness(cvs, issues);
  const { blobs, dedupSavedBytes } = blobStats(layersByCv);

  let deferredBlobs = 0;
  let deferredBytes = 0;
  for (const cv of cvs) {
    for (const artifact of [...cv.resources, ...cv.sources]) {
      if (artifact.blob?.digestCheck === 'pending') {
        deferredBlobs++;
        deferredBytes += artifact.blob.size;
      }
    }
  }
  if (deferredBlobs > 0) {
    issues.push(
      diag(
        'info',
        'BUNDLE_DIGESTS_DEFERRED',
        `${deferredBlobs} blob digest check(s) (${Math.round(deferredBytes / (1024 * 1024))} MB) deferred at load — run them from the Verify view.`,
      ),
    );
  }

  return {
    fileName,
    layout,
    compressed,
    archiveSize,
    componentVersions: cvs,
    roots,
    shared,
    completeness,
    ...(deferredBlobs > 0 ? { digestsDeferred: { blobs: deferredBlobs, bytes: deferredBytes } } : {}),
    blobs,
    dedupSavedBytes,
    issues,
  };
}

function buildCv(
  cd: CollectedCd,
  archiveName: string,
  layout: OcmBundle['layout'],
  shaById: Map<OcmCvId, string>,
  issues: Diagnostic[],
): OcmCv | null {
  const normalized = normalizeCd(cd.raw);
  if (!normalized) return null; // collectCd guarantees name+version; defensive

  const diagnostics: Diagnostic[] = [];
  if (normalized.v3) {
    diagnostics.push(
      diag('info', 'OCM_V3ALPHA1', 'OCM v3alpha1 descriptor: mapped best-effort (v2 is the primary format).'),
    );
  }
  diagnostics.push(...validateCdStructure(cd.raw, normalized));

  let id = ocmCvId(normalized.name, normalized.version);
  const prior = shaById.get(id);
  if (prior === cd.sha1) {
    issues.push(diag('info', 'BUNDLE_DUPLICATE_CV', `${id} appears twice with identical content; kept once.`));
    return null;
  }
  if (prior !== undefined) {
    issues.push(
      diag('warning', 'BUNDLE_DUPLICATE_CV', `${id} appears twice with different content; both are shown, references resolve to the first.`),
    );
    let n = 2;
    while (shaById.has(`${id}#${n}`)) n++;
    id = `${id}#${n}`;
  }

  const mapArtifact = (raw: Record<string, unknown>, role: 'resource' | 'source'): OcmArtifact | null => {
    const name = asString(raw.name);
    if (!name) {
      diagnostics.push(diag('warning', 'OCM_RESOURCE_MALFORMED', `A ${role} without a name was skipped.`));
      return null;
    }
    const access = isRecord(raw.access) ? raw.access : {};
    const blob = cd.blobInfos.get(raw);
    if (blob?.digestCheck === 'mismatch') {
      diagnostics.push(
        diag(
          'warning',
          'OCM_DIGEST_MISMATCH',
          `${role === 'source' ? 'Source' : 'Resource'} "${name}": the blob in this delivery does not match its declared digest.`,
        ),
      );
    }
    const localReference = asString(access.localReference) ?? asString(access.filename);
    const sbom = role === 'resource' && localReference ? cd.sbomByRef.get(localReference) : undefined;
    return {
      role,
      name,
      version: asString(raw.version),
      type: asString(raw.type),
      relation: asString(raw.relation),
      extraIdentity: stringRecord(raw.extraIdentity),
      access: Object.keys(access).length > 0 ? { type: asString(access.type), raw: access } : undefined,
      digest: ocmDigest(raw.digest),
      labels: ocmLabels(raw.labels),
      blob,
      sbom,
      location: artifactLocation(access),
      transport: classifyTransport(access, localReference, cd.blobPresent),
      raw,
    };
  };

  const resources = normalized.resources
    .map((raw) => mapArtifact(raw, 'resource'))
    .filter((a): a is OcmArtifact => a !== null);
  const sources = normalized.sources
    .map((raw) => mapArtifact(raw, 'source'))
    .filter((a): a is OcmArtifact => a !== null);

  const references: OcmRef[] = [];
  for (const raw of normalized.references) {
    const name = asString(raw.name);
    const componentName = asString(raw.componentName);
    const version = asString(raw.version);
    if (!name || !componentName || !version) {
      diagnostics.push(
        diag('warning', 'OCM_REF_MALFORMED', 'A componentReference without name/componentName/version was skipped.'),
      );
      continue;
    }
    references.push({
      name,
      componentName,
      version,
      extraIdentity: stringRecord(raw.extraIdentity),
      digest: ocmDigest(raw.digest),
      labels: ocmLabels(raw.labels),
    });
  }

  return {
    id,
    name: normalized.name,
    version: normalized.version,
    schemaVersion: normalized.schemaLabel,
    provider:
      normalized.provider || normalized.providerLabels
        ? { name: normalized.provider, labels: normalized.providerLabels }
        : undefined,
    creationTime: normalized.creationTime,
    labels: normalized.labels,
    repositoryContexts: mapRepositoryContexts(normalized.repositoryContexts),
    signatures: mapSignatures(normalized.signatures),
    resources,
    sources,
    references,
    raw: cd.raw,
    serialization: cd.serialization,
    text: cd.text,
    sha1: cd.sha1,
    byteSize: cd.byteSize,
    fileName:
      layout === 'descriptor' ? archiveName : `${archiveName}!${normalized.name}/component-descriptor.yaml`,
    diagnostics,
  };
}

function classifyTransport(
  access: Record<string, unknown>,
  localReference: string | undefined,
  blobPresent: Set<string>,
): OcmTransport {
  // Real CLI output writes versioned access types ("LocalBlob/v1"); the
  // version suffix never changes the transport class.
  const type = asString(access.type)
    ?.toLowerCase()
    .replace(/\/v\d+[a-z0-9]*$/, '');
  if (!type) return 'none';
  if (LOCAL_ACCESS.has(type)) {
    return localReference !== undefined && blobPresent.has(localReference) ? 'transported' : 'broken';
  }
  if (EXTERNAL_ACCESS.has(type)) return 'external';
  return 'unknown';
}

/** Resolve in-bundle targets and mark the edges that would close a cycle. */
function resolveReferences(cvs: OcmCv[], issues: Diagnostic[]): void {
  const ids = new Set(cvs.map((cv) => cv.id));
  for (const cv of cvs) {
    for (const ref of cv.references) {
      const target = ocmCvId(ref.componentName, ref.version);
      if (ids.has(target)) ref.target = target;
    }
  }

  // Iterative DFS, three colors; a resolved edge into a node still on the
  // stack is a back-edge. The spec is silent on cycles, so the viewer keeps
  // them displayable: the edge is marked and the UI breaks the loop there.
  const byId = new Map(cvs.map((cv) => [cv.id, cv]));
  const state = new Map<OcmCvId, 'visiting' | 'done'>();
  let cycleEdges = 0;
  for (const start of cvs) {
    if (state.has(start.id)) continue;
    const stack: { cv: OcmCv; next: number }[] = [{ cv: start, next: 0 }];
    state.set(start.id, 'visiting');
    while (stack.length > 0) {
      const frame = stack[stack.length - 1]!;
      const refs = frame.cv.references;
      if (frame.next >= refs.length) {
        state.set(frame.cv.id, 'done');
        stack.pop();
        continue;
      }
      const ref = refs[frame.next++]!;
      if (!ref.target) continue;
      const targetState = state.get(ref.target);
      if (targetState === 'visiting') {
        ref.cyclic = true;
        cycleEdges++;
      } else if (targetState === undefined) {
        const target = byId.get(ref.target)!;
        state.set(target.id, 'visiting');
        stack.push({ cv: target, next: 0 });
      }
    }
  }
  if (cycleEdges > 0) {
    issues.push(
      diag(
        'warning',
        'BUNDLE_REFERENCE_CYCLE',
        `${cycleEdges} reference edge(s) close a cycle — the spec does not define this; the graph is shown with the cycle broken there.`,
      ),
    );
  }
}

/**
 * Roots are component versions no in-bundle reference points at. Cyclic
 * edges do not count as incoming: the DFS marks exactly one closing edge
 * per cycle, so every strongly connected subgraph loses one incoming edge
 * and surfaces a natural entry point — a pure cycle still gets a root.
 */
function findRoots(cvs: OcmCv[]): OcmCvId[] {
  const incoming = new Set<OcmCvId>();
  for (const cv of cvs) {
    for (const ref of cv.references) {
      if (ref.target && !ref.cyclic) incoming.add(ref.target);
    }
  }
  return cvs.filter((cv) => !incoming.has(cv.id)).map((cv) => cv.id);
}

function findShared(cvs: OcmCv[]): OcmCvId[] {
  const incoming = new Map<OcmCvId, number>();
  for (const cv of cvs) {
    for (const ref of cv.references) {
      if (ref.target) incoming.set(ref.target, (incoming.get(ref.target) ?? 0) + 1);
    }
  }
  return [...incoming.entries()].filter(([, count]) => count >= 2).map(([id]) => id);
}

/**
 * Resources decide air-gap fitness; sources are provenance and are counted
 * nowhere here. Unresolved references also break self-containment: the
 * closure the bundle claims to carry is incomplete.
 */
function computeCompleteness(cvs: OcmCv[], issues: Diagnostic[]): OcmCompleteness {
  const counts: Record<OcmTransport, number> = {
    transported: 0,
    external: 0,
    broken: 0,
    unknown: 0,
    none: 0,
  };
  for (const cv of cvs) {
    for (const resource of cv.resources) counts[resource.transport]++;
  }
  let unresolvedRefs = 0;
  for (const cv of cvs) {
    for (const ref of cv.references) {
      if (!ref.target) unresolvedRefs++;
    }
  }
  if (unresolvedRefs > 0) {
    issues.push(
      diag(
        'info',
        'BUNDLE_REFS_UNRESOLVED',
        `${unresolvedRefs} reference(s) point outside this bundle (by-reference delivery, or an incomplete closure).`,
      ),
    );
  }
  return {
    ...counts,
    unresolvedRefs,
    airGapReady:
      counts.external === 0 && counts.broken === 0 && counts.unknown === 0 && unresolvedRefs === 0,
  };
}

function blobStats(layersByCv: [OcmCvId, CollectedLayer[]][]): {
  blobs: OcmBlobStat[];
  dedupSavedBytes: number;
} {
  const stats = new Map<string, OcmBlobStat & { occurrences: number }>();
  for (const [cvId, layers] of layersByCv) {
    for (const layer of layers) {
      const existing = stats.get(layer.digest);
      if (existing) {
        existing.occurrences++;
        if (!existing.referencedBy.includes(cvId)) existing.referencedBy.push(cvId);
        if (!existing.mediaType && layer.mediaType) existing.mediaType = layer.mediaType;
      } else {
        stats.set(layer.digest, {
          digest: layer.digest,
          size: layer.size,
          mediaType: layer.mediaType,
          referencedBy: [cvId],
          occurrences: 1,
        });
      }
    }
  }
  let dedupSavedBytes = 0;
  const blobs: OcmBlobStat[] = [];
  for (const { occurrences, ...stat } of stats.values()) {
    dedupSavedBytes += (occurrences - 1) * stat.size;
    blobs.push(stat);
  }
  blobs.sort((a, b) => b.size - a.size);
  return { blobs: blobs.slice(0, MAX_BLOB_STATS), dedupSavedBytes };
}
