/**
 * Container sniffing and decompression for delivery archives. Detection is
 * magic-byte based — file names prove nothing here either.
 */

export type ContainerKind = 'gzip' | 'tar' | 'zip' | 'binary' | 'text';

const NUL_SCAN_LIMIT = 8192;

export function sniffContainer(bytes: Uint8Array): ContainerKind {
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) return 'gzip';
  if (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04) {
    return 'zip';
  }
  if (looksLikeTar(bytes)) return 'tar';
  const limit = Math.min(bytes.length, NUL_SCAN_LIMIT);
  for (let i = 0; i < limit; i++) {
    if (bytes[i] === 0) return 'binary';
  }
  return 'text';
}

function looksLikeTar(bytes: Uint8Array): boolean {
  if (bytes.length < 263) return false;
  // POSIX ustar magic at offset 257: "ustar\0" or GNU "ustar  ".
  const magic = String.fromCharCode(...bytes.subarray(257, 262));
  return magic === 'ustar';
}

/**
 * Decompression bomb guard: a tiny gzip stream can expand without bound, and
 * it does so HERE — the tar reader downstream only creates zero-copy views.
 * The ceiling is sized to what a browser can hold as one buffer anyway; a
 * delivery larger than this must ship as plain .tar (which streams).
 */
export const GUNZIP_MAX_BYTES = 2 * 1024 * 1024 * 1024;

export class GunzipLimitError extends Error {
  constructor(limit: number) {
    super(`Decompressed size exceeds ${limit / (1024 * 1024 * 1024)} GiB.`);
    this.name = 'GunzipLimitError';
  }
}

/** Single-member gzip (what tgz tooling writes). Node ≥18 and all browsers. */
export async function gunzip(bytes: Uint8Array, maxBytes = GUNZIP_MAX_BYTES): Promise<Uint8Array> {
  // Fresh ArrayBuffer-backed copy: subarray views and SharedArrayBuffer-typed
  // inputs are not valid BlobParts under the DOM lib.
  const copy = new Uint8Array(bytes);
  const stream = new Blob([copy]).stream().pipeThrough(new DecompressionStream('gzip'));
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new GunzipLimitError(maxBytes);
    }
    chunks.push(value);
  }
  // Near the cap the single output buffer can exceed what this engine will
  // allocate; the user's remedy is the same as for the cap itself, so it
  // reports as the same honest error instead of "not a valid gzip stream".
  let out: Uint8Array;
  try {
    out = new Uint8Array(total);
  } catch {
    throw new GunzipLimitError(maxBytes);
  }
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}
