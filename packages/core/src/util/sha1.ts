/**
 * SHA-1 of raw file bytes. Not for security — SPDX ExternalDocumentRefs
 * identify their target document by SHA-1, so this drives cascade resolution.
 * `crypto.subtle` exists in browsers, workers, and Node ≥ 19.
 */
export async function sha1Hex(buffer: ArrayBuffer): Promise<string> {
  return hashHex('SHA-1', buffer);
}

/**
 * Hex digest for OCM blob checks (the digest triple names SHA-256/512).
 * Accepts views directly — `crypto.subtle.digest` reads a view's window
 * without copying, so large blobs are never duplicated just to hash them.
 */
export async function hashHex(
  algorithm: 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512',
  data: ArrayBuffer | Uint8Array,
): Promise<string> {
  // Cast: subtle.digest accepts views, but this tsconfig's lib surface types
  // it on ArrayBuffer only. None of our inputs are SharedArrayBuffer-backed
  // (file reads, tar views, TextEncoder output), so the view is safe as-is.
  const digest = await crypto.subtle.digest(algorithm, data as unknown as ArrayBuffer);
  let hex = '';
  for (const byte of new Uint8Array(digest)) hex += byte.toString(16).padStart(2, '0');
  return hex;
}
