/**
 * SHA-1 of raw file bytes. Not for security — SPDX ExternalDocumentRefs
 * identify their target document by SHA-1, so this drives cascade resolution.
 * `crypto.subtle` exists in browsers, workers, and Node ≥ 19.
 */
export async function sha1Hex(buffer: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-1', buffer);
  let hex = '';
  for (const byte of new Uint8Array(digest)) hex += byte.toString(16).padStart(2, '0');
  return hex;
}
