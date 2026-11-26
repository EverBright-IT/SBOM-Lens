import { GUNZIP_MAX_BYTES, gunzip, sniffContainer } from '../../util/binary';
import type { ByteSource } from '../../util/bytesource';
import { bufferSource, windowSource } from '../../util/bytesource';
import type { OcmBlobInfo } from '../../model/ocm';
import { asString, isRecord } from '../../util/narrow';
import { sha256SourceHex } from '../../util/sha256';
import { MATERIALIZE_ENTRY_MAX, readTarFrom } from '../../util/tar';
import { checkDeclaredDigest, checkDeclaredDigestIndexed, inspectBlob } from './blob';
import type { OciPart, PartRead } from './oci';
import {
  OCI_EMPTY_DIGEST,
  OCI_MANIFEST_MAX,
  carriesComponentDescriptor,
  ociContent,
  storedArtifactParts,
} from './oci';

/**
 * Pull ONE blob back out of a delivery archive, on demand — the viewer
 * discards blob bytes after inspection (they never reach the UI thread), so
 * "download this artifact" and reading a delivery's VEX re-open the archive
 * and extract exactly the requested localReference. Searches the top-level
 * blob store and one level of nested artifact-set tars, mirroring the
 * walker's layouts.
 *
 * The bytes handed out are bytes the walk would vouch for. An archive can
 * carry several entries under one blob name: a tar may repeat a name, and a
 * CTF may hold a top-level blob next to a nested artifact set's. The walk
 * judged only the entry its layout resolves, so every entry under the name
 * is a candidate here, each is held against the resource's declared digest
 * with the walk's own rules, and only a matching one is returned. Without a
 * computable declaration only an unambiguous blob is returned.
 */

const EXTRACT_MAX = 512 * 1024 * 1024;
/** Index only while searching: candidates are read when they are judged. */
const HEADERS_ONLY = { materializeEntryMax: 0, materializeTotalMax: 0 };

export type BlobExtraction =
  | { ok: true; bytes: Uint8Array }
  | { ok: false; reason: 'not-found' | 'too-large' | 'unreadable' | 'mismatch' | 'ambiguous' };

export async function extractDeliveryBlob(
  source: ByteSource,
  localReference: string,
  declared?: Record<string, unknown>,
): Promise<BlobExtraction> {
  const opened = await openDelivery(source);
  if ('reason' in opened) return { ok: false, reason: opened.reason };
  const candidates = candidatesIn(opened.scopes, localReference);
  if (candidates.length === 0) return { ok: false, reason: 'not-found' };
  let mismatch = false;
  const unverified: Candidate[] = [];
  for (const candidate of candidates) {
    const judged = await judge(candidate, declared);
    if (judged.verdict === 'match') return materialize(candidate, judged.bytes);
    if (judged.verdict === 'mismatch') mismatch = true;
    else unverified.push(candidate);
  }
  if (mismatch) return { ok: false, reason: 'mismatch' };
  if (unverified.length > 1 && !(await sameBytes(unverified))) return { ok: false, reason: 'ambiguous' };
  return materialize(unverified[0]!);
}

/**
 * Check one deferred blob digest on demand — the same verdict semantics the
 * walk uses for unmaterialized blobs (constant-memory hash off the archive;
 * stored bytes that do not hash to the declared value are a 'mismatch',
 * gzip-stored or not). An image or chart stored by value is its manifest
 * or index, recognised by its bytes as in the walk: it is held against the
 * declaration, then every blob below it (nested manifests, configs, layers)
 * against the digest recorded for it, as the walk does within its hash
 * budget. Every entry under a name is judged: one
 * that does not match is a mismatch, whichever entry the walk resolved.
 * Returns undefined when no digest value is declared.
 */
export async function digestDeliveryBlob(
  source: ByteSource,
  localReference: string,
  declared: Record<string, unknown> | undefined,
): Promise<OcmBlobInfo['digestCheck']> {
  if (!isRecord(declared) || !asString(declared.value)) return undefined;
  const opened = await openDelivery(source);
  if ('reason' in opened) return 'unchecked';
  const candidates = candidatesIn(opened.scopes, localReference);
  if (candidates.length === 0) return 'unchecked';
  let verdict: OcmBlobInfo['digestCheck'] = 'match';
  for (const candidate of candidates) {
    const one = await checkCandidate(candidate, declared, opened.scopes);
    if (one === 'mismatch') return 'mismatch';
    if (one !== 'match') verdict = one;
  }
  return verdict;
}

async function checkCandidate(
  candidate: Candidate,
  declared: Record<string, unknown>,
  scopes: Scope[],
): Promise<OcmBlobInfo['digestCheck']> {
  // The parts sit next to the manifest, or at the top of a CTF.
  const top = scopes[0]!;
  const where = candidate.scope === top ? [top] : [candidate.scope, top];
  const stored = await storedArtifact(candidate, where);
  if (!stored) return checkDeclaredDigestIndexed(declared, () => hashCandidate(candidate));
  const own = await checkDeclaredDigest({ stored: stored.bytes, manifest: stored.bytes }, declared);
  if (own !== 'match') return own;
  return storedPartsVerdict(stored, where);
}

interface StoredArtifact {
  bytes: Uint8Array;
  parts: OciPart[];
  opaque: number;
}

/**
 * A candidate that is an OCI manifest or index (an image or chart stored by
 * value), recognised by its bytes, with every blob below it. A nested
 * manifest is read from the first copy under its name: should copies
 * differ, one of them does not match and the verdict says so.
 */
async function storedArtifact(candidate: Candidate, where: Scope[]): Promise<StoredArtifact | undefined> {
  if (candidate.size === 0 || candidate.size > OCI_MANIFEST_MAX) return undefined;
  let bytes: Uint8Array;
  try {
    bytes = await candidate.container.read(candidate.offset, candidate.size);
  } catch {
    return undefined;
  }
  const content = ociContent(bytes);
  if (!content || carriesComponentDescriptor(content.raw)) return undefined;
  const { parts, opaque } = await storedArtifactParts(content, async (digest): Promise<PartRead> => {
    const copy = candidatesIn(where, digest)[0];
    if (!copy) return 'absent';
    if (copy.size > OCI_MANIFEST_MAX) return 'unreadable';
    try {
      return await copy.container.read(copy.offset, copy.size);
    } catch {
      return 'unreadable';
    }
  });
  return { bytes, parts, opaque };
}

/**
 * Each blob below the manifest held against the digest recorded for it,
 * every copy of it in the given tars. A part with no copy is 'unchecked'
 * (the empty descriptor excepted, its bytes follow from its digest), and so
 * is what an unreadable nested manifest names; only SHA-256 parts are
 * computable here.
 */
async function storedPartsVerdict(stored: StoredArtifact, where: Scope[]): Promise<OcmBlobInfo['digestCheck']> {
  let verdict: OcmBlobInfo['digestCheck'] = stored.opaque > 0 ? 'unchecked' : 'match';
  for (const part of stored.parts) {
    const hex = /^sha256:([0-9a-f]{64})$/i.exec(part.digest)?.[1]?.toLowerCase();
    if (!hex) {
      verdict = 'unchecked';
      continue;
    }
    const copies = candidatesIn(where, part.digest);
    if (copies.length === 0) {
      if (part.digest.toLowerCase() !== OCI_EMPTY_DIGEST) verdict = 'unchecked';
      continue;
    }
    for (const copy of copies) {
      if ((await hashCandidate(copy)) !== hex) return 'mismatch';
    }
  }
  return verdict;
}

/** One tar of the delivery, indexed: the delivery itself or a nested artifact set. */
interface Scope {
  container: ByteSource;
  entries: { name: string; offset: number; size: number }[];
}

interface Candidate {
  container: ByteSource;
  offset: number;
  size: number;
  scope: Scope;
}

type Opened = { scopes: Scope[] } | { reason: 'too-large' | 'unreadable' };

/** The delivery's tar and one level of nested artifact-set tars, headers only. */
async function openDelivery(source: ByteSource): Promise<Opened> {
  let tarSource = source;
  const head = await source.read(0, 512);
  if (sniffContainer(head) === 'gzip') {
    if (source.size > GUNZIP_MAX_BYTES) return { reason: 'too-large' };
    try {
      const tarBytes = await gunzip(await source.read(0, source.size));
      tarSource = bufferSource(tarBytes);
    } catch {
      return { reason: 'unreadable' };
    }
  }

  const indexed = (entry: { name: string; offset: number; size: number }) => ({
    name: entry.name.replace(/^\.\//, ''),
    offset: entry.offset,
    size: entry.size,
  });
  let top: Scope;
  try {
    top = {
      container: tarSource,
      entries: (await readTarFrom(tarSource, HEADERS_ONLY)).entries.map(indexed),
    };
  } catch {
    return { reason: 'unreadable' };
  }

  // Nested artifact sets: any top-level blob that is itself a tar.
  const scopes = [top];
  for (const entry of top.entries) {
    if (!entry.name.startsWith('blobs/') || entry.size < 512) continue;
    if (sniffContainer(await tarSource.read(entry.offset, 512)) !== 'tar') continue;
    const inner = windowSource(tarSource, entry.offset, entry.size);
    try {
      scopes.push({ container: inner, entries: (await readTarFrom(inner, HEADERS_ONLY)).entries.map(indexed) });
    } catch {
      // A corrupt nested set never hides a blob that exists elsewhere.
    }
  }
  return { scopes };
}

/** Every entry under the blob's name, in every given tar. */
function candidatesIn(scopes: Scope[], localReference: string): Candidate[] {
  const spellings = blobNames(localReference);
  return scopes.flatMap((scope) =>
    scope.entries
      .filter((entry) => spellings.has(entry.name))
      .map((entry) => ({
        container: scope.container,
        offset: entry.offset,
        size: entry.size,
        scope,
      })),
  );
}

function blobNames(localReference: string): Set<string> {
  const ref = localReference.replace(/^\.\//, '');
  return new Set([
    `blobs/${ref}`,
    `blobs/${ref.replace(':', '.')}`,
    `blobs/${ref.replace('.', ':')}`,
    ref,
  ]);
}

/**
 * One candidate held against the declared digest the way the walk holds the
 * entry it resolved: a blob the walk would load is inspected and judged on
 * its stored bytes, its unpacked bytes and, for an OCI artifact, its
 * manifest; a larger one by the constant-memory hash of its stored bytes.
 */
async function judge(
  candidate: Candidate,
  declared: Record<string, unknown> | undefined,
): Promise<{ verdict: 'match' | 'mismatch' | 'unchecked'; bytes?: Uint8Array }> {
  if (!isRecord(declared) || !asString(declared.value)) return { verdict: 'unchecked' };
  if (candidate.size <= MATERIALIZE_ENTRY_MAX) {
    let bytes: Uint8Array;
    try {
      bytes = await candidate.container.read(candidate.offset, candidate.size);
    } catch {
      return { verdict: 'unchecked' };
    }
    const { subjects } = await inspectBlob(bytes, undefined);
    // An image or chart stored by value: the blob is its manifest or index.
    const manifest = subjects.manifest ?? (isStoredArtifact(bytes) ? bytes : undefined);
    const verdict = await checkDeclaredDigest(manifest ? { ...subjects, manifest } : subjects, declared);
    return { verdict: verdict === 'match' || verdict === 'mismatch' ? verdict : 'unchecked', bytes };
  }
  const verdict = await checkDeclaredDigestIndexed(declared, () => hashCandidate(candidate));
  return { verdict: verdict === 'match' || verdict === 'mismatch' ? verdict : 'unchecked' };
}

function hashCandidate(candidate: Candidate): Promise<string> {
  return sha256SourceHex(candidate.container, candidate.offset, candidate.size);
}

/** Whether several candidates are the same bytes (as content-addressed copies are). */
async function sameBytes(candidates: Candidate[]): Promise<boolean> {
  if (new Set(candidates.map((c) => c.size)).size > 1) return false;
  const hashes = new Set<string>();
  for (const candidate of candidates) hashes.add(await hashCandidate(candidate));
  return hashes.size === 1;
}

/** Whether the bytes are an image or chart stored by value, by the walk's rule. */
function isStoredArtifact(bytes: Uint8Array): boolean {
  const content = ociContent(bytes);
  return content !== undefined && !carriesComponentDescriptor(content.raw);
}

async function materialize(candidate: Candidate, bytes?: Uint8Array): Promise<BlobExtraction> {
  if (candidate.size > EXTRACT_MAX) return { ok: false, reason: 'too-large' };
  if (bytes) return { ok: true, bytes };
  try {
    return { ok: true, bytes: await candidate.container.read(candidate.offset, candidate.size) };
  } catch {
    return { ok: false, reason: 'unreadable' };
  }
}
