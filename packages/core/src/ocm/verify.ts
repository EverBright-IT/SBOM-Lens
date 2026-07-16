import type { SbomDocument } from '../model/document';
import { isRecord } from '../util/narrow';
import { hashHex } from '../util/sha1';
import { NormalizationError, normalizeDescriptor, SUPPORTED_NORMALISATIONS } from './normalize';
import { KeyImportError, spkiFromPem } from './pem';

/**
 * Client-side OCM signature verification. No server, no trust store: given a
 * component descriptor and a public key (PEM or certificate), recompute the
 * normalised digest and check the RSA signature over it with
 * `crypto.subtle`. Verified end to end against the `ocm` CLI, including the
 * critical salt-length detail below.
 *
 * Read-only and honest by construction: any gap (unknown normalisation or
 * signature algorithm, a non-canonicalisable descriptor, a key we cannot
 * import) yields `unverifiable` with a reason — never a false `valid` or a
 * false `invalid`.
 */

export type SignatureVerdict = 'valid' | 'invalid' | 'unverifiable';

export interface SignatureResult {
  name: string;
  verdict: SignatureVerdict;
  reason?: string;
  /** Whether the recorded digest matched our recomputed one. */
  digestMatch?: boolean;
}

type HashName = 'SHA-256' | 'SHA-512';

const RSA_PSS_MEDIA = 'application/vnd.ocm.signature.rsa.pss';
const RSA_PKCS1_MEDIA = 'application/vnd.ocm.signature.rsa';

export interface SignatureNode {
  name?: string;
  digest?: { hashAlgorithm?: string; normalisationAlgorithm?: string; value?: string };
  signature?: { algorithm?: string; value?: string; mediaType?: string };
}

/**
 * Verify one signature of a descriptor against a public key.
 * `rootDescriptor` is the full `{ meta?, component }` node as parsed.
 */
export async function verifySignature(
  rootDescriptor: Record<string, unknown>,
  signature: SignatureNode,
  publicKeyPem: string,
): Promise<SignatureResult> {
  const name = signature.name ?? 'signature';
  const digest = signature.digest ?? {};
  const normalisation = digest.normalisationAlgorithm ?? '';
  const hash = hashName(digest.hashAlgorithm);
  const recordedDigest = digest.value?.toLowerCase();
  const sigHex = signature.signature?.value;
  const algorithm = signatureAlgorithm(signature.signature);

  if (!SUPPORTED_NORMALISATIONS.includes(normalisation)) {
    return unverifiable(name, `unsupported normalisation "${normalisation || 'none'}"`);
  }
  if (!hash) return unverifiable(name, `unsupported hash "${digest.hashAlgorithm ?? 'none'}"`);
  if (!algorithm) return unverifiable(name, 'unsupported signature algorithm');
  if (!sigHex || !recordedDigest) return unverifiable(name, 'signature or digest missing');

  // 1) Recompute the normalised digest — proves the recorded digest matches
  //    the descriptor we are actually looking at.
  let normalized: Uint8Array;
  try {
    normalized = normalizeDescriptor(rootDescriptor, normalisation);
  } catch (error) {
    if (error instanceof NormalizationError) return unverifiable(name, error.message);
    throw error;
  }
  const actualDigest = await hashHex(hash, normalized);
  const digestMatch = actualDigest === stripPrefix(recordedDigest);

  // 2) Import the key and check the RSA signature over the normalised bytes.
  let key: CryptoKey;
  try {
    const spki = spkiFromPem(publicKeyPem);
    key = await crypto.subtle.importKey(
      'spki',
      spki as unknown as ArrayBuffer,
      algorithm === 'RSASSA-PSS' ? { name: 'RSA-PSS', hash } : { name: 'RSASSA-PKCS1-v1_5', hash },
      false,
      ['verify'],
    );
  } catch (error) {
    const reason = error instanceof KeyImportError ? error.message : 'could not import public key';
    return unverifiable(name, reason);
  }

  const sig = hexToBytes(sigHex);
  if (!sig) return unverifiable(name, 'signature value is not valid hex');

  const ok = await verifyRsa(algorithm, key, sig, normalized, hash);
  if (ok) return { name, verdict: 'valid', digestMatch };
  // A cryptographically failing signature is `invalid`; but if the digest
  // itself did not match, the more precise story is "descriptor changed".
  return {
    name,
    verdict: 'invalid',
    digestMatch,
    reason: digestMatch ? 'signature does not verify against this key' : 'descriptor does not match the signed digest',
  };
}

async function verifyRsa(
  algorithm: 'RSASSA-PSS' | 'RSASSA-PKCS1-v1_5',
  key: CryptoKey,
  sig: Uint8Array,
  message: Uint8Array,
  hash: HashName,
): Promise<boolean> {
  const data = message as unknown as ArrayBuffer;
  const signature = sig as unknown as ArrayBuffer;
  if (algorithm === 'RSASSA-PKCS1-v1_5') {
    return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, data);
  }
  // RSASSA-PSS: WebCrypto needs an explicit salt length, and the ocm CLI
  // signs with the MAXIMUM salt (RSA_PSS_SALTLEN_MAX), not the hash length.
  // Verified against the CLI: only maxSalt succeeds. Try maxSalt first, then
  // the hash-length convention other signers use — a valid PSS signature
  // cannot be forged for either, so accepting whichever verifies is sound.
  const hashLen = hash === 'SHA-512' ? 64 : 32;
  const modulusLength = (key.algorithm as unknown as { modulusLength: number }).modulusLength;
  const maxSalt = modulusLength / 8 - hashLen - 2;
  for (const saltLength of new Set([maxSalt, hashLen])) {
    if (saltLength < 0 || saltLength > maxSalt) continue;
    try {
      if (await crypto.subtle.verify({ name: 'RSA-PSS', saltLength }, key, signature, data)) return true;
    } catch {
      // A malformed signature/salt combination is "not verified with this
      // salt", not a crash — keep trying the other convention.
    }
  }
  return false;
}

function signatureAlgorithm(sig: SignatureNode['signature']): 'RSASSA-PSS' | 'RSASSA-PKCS1-v1_5' | null {
  const media = sig?.mediaType?.toLowerCase();
  const algo = sig?.algorithm?.toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (media === RSA_PSS_MEDIA || algo === 'RSASSAPSS') return 'RSASSA-PSS';
  if (media === RSA_PKCS1_MEDIA || algo === 'RSASSAPKCS1V15' || algo === 'RSASSAPKCS1V1_5' || algo === 'RSA') {
    return 'RSASSA-PKCS1-v1_5';
  }
  return null;
}

function hashName(algorithm: string | undefined): HashName | null {
  const normalized = (algorithm ?? '').toUpperCase().replace(/-/g, '');
  if (normalized === 'SHA256') return 'SHA-256';
  if (normalized === 'SHA512') return 'SHA-512';
  return null;
}

function stripPrefix(value: string): string {
  return value.replace(/^sha\d+:/, '');
}

function unverifiable(name: string, reason: string): SignatureResult {
  return { name, verdict: 'unverifiable', reason };
}

function hexToBytes(hex: string): Uint8Array | null {
  const clean = hex.trim().toLowerCase().replace(/^0x/, '');
  if (clean.length % 2 !== 0 || /[^0-9a-f]/.test(clean)) return null;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * Verify every signature on a loaded OCM document against one public key.
 * Reconstructs the signed descriptor from the root element's raw component
 * node (what the parser kept verbatim) and the mapped signature list — no
 * re-parsing, no extra model state. Returns one result per signature.
 */
export async function verifyDocumentSignatures(
  doc: SbomDocument,
  publicKeyPem: string,
): Promise<SignatureResult[]> {
  const signatures = doc.ocm?.signatures ?? [];
  if (signatures.length === 0) return [];

  const rootElement = doc.elements.find((el) => el.ocm?.role === 'component');
  const raw = rootElement?.raw;
  const component = raw?.kind === 'json' && isRecord(raw.value) ? raw.value : null;
  if (!component) {
    return signatures.map((sig) => unverifiable(sig.name ?? 'signature', 'component descriptor node not available'));
  }
  const root = { component };

  return Promise.all(
    signatures.map((sig) =>
      verifySignature(
        root,
        {
          name: sig.name,
          digest: sig.digest,
          signature: { algorithm: sig.algorithm, value: sig.value, mediaType: sig.mediaType },
        },
        publicKeyPem,
      ),
    ),
  );
}
