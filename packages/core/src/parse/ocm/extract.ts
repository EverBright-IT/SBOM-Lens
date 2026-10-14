import { GUNZIP_MAX_BYTES, gunzip, sniffContainer } from '../../util/binary';
import type { ByteSource } from '../../util/bytesource';
import { bufferSource, windowSource } from '../../util/bytesource';
import type { OcmBlobInfo } from '../../model/ocm';
import { asString, isRecord } from '../../util/narrow';
import { sha256SourceHex } from '../../util/sha256';
import { readTarFrom } from '../../util/tar';
import { checkDeclaredDigestIndexed } from './blob';

/**
 * Pull ONE blob back out of a delivery archive, on demand — the viewer
 * discards blob bytes after inspection (they never reach the UI thread), so
 * "download this artifact" re-opens the archive and extracts exactly the
 * requested localReference. Searches the top-level blob store first, then
 * one level of nested artifact-set tars, mirroring the walker's layouts.
 */

const EXTRACT_MAX = 512 * 1024 * 1024;

export type BlobExtraction =
  | { ok: true; bytes: Uint8Array }
  | { ok: false; reason: 'not-found' | 'too-large' | 'unreadable' };

export async function extractDeliveryBlob(
  source: ByteSource,
  localReference: string,
): Promise<BlobExtraction> {
  const located = await locateDeliveryBlob(source, localReference);
  if ('reason' in located) return { ok: false, reason: located.reason };
  return materialize(located.container, located.offset, located.size, located.bytes);
}

/**
 * Check one deferred blob digest on demand — the same verdict semantics the
 * walk uses for unmaterialized blobs (constant-memory hash off the archive;
 * gzip-stored blobs stay 'unchecked' rather than risking a wrong verdict).
 * Returns undefined when no digest value is declared.
 */
export async function digestDeliveryBlob(
  source: ByteSource,
  localReference: string,
  declared: Record<string, unknown> | undefined,
): Promise<OcmBlobInfo['digestCheck']> {
  if (!isRecord(declared) || !asString(declared.value)) return undefined;
  const located = await locateDeliveryBlob(source, localReference);
  if ('reason' in located) return 'unchecked';
  const { container, offset, size, bytes } = located;
  return checkDeclaredDigestIndexed(
    declared,
    () =>
      bytes
        ? sha256SourceHex(bufferSource(bytes), 0, bytes.byteLength)
        : sha256SourceHex(container, offset, size),
    async () => {
      const head = bytes ? bytes.subarray(0, 2) : await container.read(offset, 2);
      return head.byteLength === 2 && head[0] === 0x1f && head[1] === 0x8b;
    },
  );
}

type LocatedBlob =
  | { container: ByteSource; offset: number; size: number; bytes: Uint8Array | null }
  | { reason: 'not-found' | 'too-large' | 'unreadable' };

async function locateDeliveryBlob(source: ByteSource, localReference: string): Promise<LocatedBlob> {
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

  const spellings = blobNames(localReference);
  let entries;
  try {
    entries = (await readTarFrom(tarSource)).entries;
  } catch {
    return { reason: 'unreadable' };
  }

  const direct = entries.find((e) => spellings.has(e.name.replace(/^\.\//, '')));
  if (direct) return { container: tarSource, offset: direct.offset, size: direct.size, bytes: direct.bytes };

  // Nested artifact sets: any top-level blob that is itself a tar.
  for (const entry of entries) {
    if (!entry.name.replace(/^\.\//, '').startsWith('blobs/')) continue;
    const entryHead = entry.bytes ?? (await tarSource.read(entry.offset, 512));
    if (sniffContainer(entryHead) !== 'tar') continue;
    const inner = entry.bytes ? bufferSource(entry.bytes) : windowSource(tarSource, entry.offset, entry.size);
    try {
      const innerEntries = (await readTarFrom(inner)).entries;
      const hit = innerEntries.find((e) => spellings.has(e.name.replace(/^\.\//, '')));
      if (hit) return { container: inner, offset: hit.offset, size: hit.size, bytes: hit.bytes };
    } catch {
      // A corrupt nested set never hides a blob that exists elsewhere.
    }
  }
  return { reason: 'not-found' };
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

async function materialize(
  source: ByteSource,
  offset: number,
  size: number,
  bytes: Uint8Array | null,
): Promise<BlobExtraction> {
  if (size > EXTRACT_MAX) return { ok: false, reason: 'too-large' };
  if (bytes) return { ok: true, bytes: new Uint8Array(bytes) };
  try {
    return { ok: true, bytes: await source.read(offset, size) };
  } catch {
    return { ok: false, reason: 'unreadable' };
  }
}
