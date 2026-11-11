import type { SbomDocument } from '../model/document';
import { ocmCvId } from '../model/ocm-bundle';
import { asArray, asString, isRecord } from '../util/narrow';
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
/**
 * Verify every signature on a raw descriptor root against one public key.
 * The OCM Lens 2.0 bundle model keeps the parsed root verbatim (`OcmCv.raw`),
 * so this is the direct path: no document model in between.
 *
 * A verdict covers this descriptor alone. What it references is covered only
 * through the reference digests it records: see `referenceDigestChecker`.
 */
export async function verifyRawSignatures(
  rootDescriptor: Record<string, unknown>,
  publicKeyPem: string,
): Promise<SignatureResult[]> {
  const nodes = Array.isArray(rootDescriptor.signatures)
    ? rootDescriptor.signatures.filter(isRecord)
    : [];
  return Promise.all(
    nodes.map((node) =>
      verifySignature(
        rootDescriptor,
        {
          name: typeof node.name === 'string' ? node.name : undefined,
          digest: isRecord(node.digest) ? (node.digest as SignatureNode['digest']) : undefined,
          signature: isRecord(node.signature) ? (node.signature as SignatureNode['signature']) : undefined,
        },
        publicKeyPem,
      ),
    ),
  );
}

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

/**
 * What a descriptor's reference digests say about the component versions
 * delivered below it. A signature covers those digests, not the referenced
 * descriptors, so it vouches for the closure only where they hold:
 * - `match`: every referenced component version, transitively, is the one
 *   whose digest its referrer records.
 * - `mismatch`: a delivered component version is not the referenced one.
 * - `unchecked`: a reference could not be compared (not delivered, no
 *   digest recorded, unsupported algorithm).
 * `reason` names the first reference that is not a match.
 */
export interface ReferenceCheck {
  verdict: 'match' | 'mismatch' | 'unchecked';
  reason?: string;
}

/**
 * Every descriptor root a delivery carries for one component version. More
 * than one means the delivery is ambiguous there: all of them have to match.
 */
export type ReferenceResolver = (
  componentName: string,
  version: string,
) => Record<string, unknown>[];

/**
 * Check reference digests against the component versions a delivery really
 * carries: recompute the normalised digest of each referenced descriptor,
 * compare it with the one its referrer records, and follow the references of
 * every component version that matched. Without this a signed root says
 * nothing about a referenced component version that was swapped afterwards.
 *
 * The returned check keeps what it computed per descriptor, so one checker
 * serves a whole verification run. Same honesty rule as for signatures: a
 * gap is `unchecked`, never a false `match` or a false `mismatch`.
 */
export function referenceDigestChecker(
  resolve: ReferenceResolver,
): (rootDescriptor: Record<string, unknown>) => Promise<ReferenceCheck> {
  type Descriptor = Record<string, unknown>;
  const digests = new Map<Descriptor, Map<string, Promise<string>>>();
  const done = new Map<Descriptor, ReferenceCheck>();

  // Normalising is the expensive step: once per descriptor and algorithm pair.
  const digestOf = (target: Descriptor, normalisation: string, hash: HashName): Promise<string> => {
    const perTarget = digests.get(target) ?? new Map<string, Promise<string>>();
    digests.set(target, perTarget);
    const key = `${normalisation} ${hash}`;
    const digest =
      perTarget.get(key) ?? (async () => hashHex(hash, normalizeDescriptor(target, normalisation)))();
    perTarget.set(key, digest);
    return digest;
  };

  /** One reference against what the delivery carries for it: the target on a match. */
  const compare = async (reference: unknown): Promise<ReferenceCheck | { target: Descriptor }> => {
    const node = isRecord(reference) ? reference : {};
    const componentName = asString(node.componentName);
    const version = asString(node.version);
    if (!componentName || !version) return uncheckedReference('a component reference is malformed');
    const id = ocmCvId(componentName, version);
    const digest = isRecord(node.digest) ? node.digest : {};
    const normalisation = asString(digest.normalisationAlgorithm) ?? '';
    const hash = hashName(asString(digest.hashAlgorithm));
    const recorded = asString(digest.value)?.toLowerCase();
    if (!recorded) return uncheckedReference(`no digest is recorded for the referenced ${id}`);
    if (!hash || !SUPPORTED_NORMALISATIONS.includes(normalisation)) {
      return uncheckedReference(`the digest recorded for the referenced ${id} uses an unsupported algorithm`);
    }
    const targets = resolve(componentName, version);
    if (targets.length === 0) return uncheckedReference(`the referenced ${id} is not in this delivery`);
    for (const target of targets) {
      let actual: string;
      try {
        actual = await digestOf(target, normalisation, hash);
      } catch (error) {
        const detail = error instanceof NormalizationError ? `: ${error.message}` : '';
        return uncheckedReference(`the referenced ${id} cannot be normalised${detail}`);
      }
      if (actual === stripPrefix(recorded)) continue;
      // A descriptor stored without its artifact digests cannot reproduce the
      // form that was signed: that is a gap, not proof of a swap.
      if (!carriesDigests(target)) {
        return uncheckedReference(`the referenced ${id} records no digests for its own artifacts`);
      }
      return {
        verdict: 'mismatch',
        reason: `the referenced ${id} in this delivery does not match its recorded digest`,
      };
    }
    // Equal digests mean equal references below: following one target is enough.
    return { target: targets[0]! };
  };

  const walk = async (descriptor: Descriptor, path: Set<Descriptor>): Promise<ReferenceCheck> => {
    const known = done.get(descriptor);
    if (known) return known;
    const component = isRecord(descriptor.component) ? descriptor.component : {};
    let result: ReferenceCheck = { verdict: 'match' };
    path.add(descriptor);
    for (const reference of asArray(component.componentReferences)) {
      const outcome = await compare(reference);
      // Only a component version that IS the referenced one extends the
      // closure. A chain of matching digests cannot loop; the guard keeps a
      // delivery that claims otherwise from running forever.
      const check = !('target' in outcome)
        ? outcome
        : path.has(outcome.target)
          ? uncheckedReference('component references form a cycle')
          : await walk(outcome.target, path);
      if (check.verdict === 'mismatch' || result.verdict === 'match') result = check;
      if (result.verdict === 'mismatch') break;
    }
    path.delete(descriptor);
    done.set(descriptor, result);
    return result;
  };

  return (rootDescriptor) => walk(rootDescriptor, new Set());
}

function uncheckedReference(reason: string): ReferenceCheck {
  return { verdict: 'unchecked', reason };
}

/** Whether a descriptor records a digest for each of its resources and references. */
function carriesDigests(rootDescriptor: Record<string, unknown>): boolean {
  const component = isRecord(rootDescriptor.component) ? rootDescriptor.component : {};
  return [...asArray(component.resources), ...asArray(component.componentReferences)].every(
    (entry) => isRecord(entry) && isRecord(entry.digest),
  );
}
