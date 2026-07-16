/**
 * Public-key intake for OCM signature verification: PEM decoding plus a
 * minimal DER walk to extract the SubjectPublicKeyInfo from an X.509
 * certificate. No ASN.1 dependency — just enough to feed
 * `crypto.subtle.importKey('spki', …)`.
 */

export class KeyImportError extends Error {}

export type PemBlock = { label: string; der: Uint8Array };

/** Decode every PEM block in a text (a key, a cert, or a chain). */
export function decodePem(text: string): PemBlock[] {
  const blocks: PemBlock[] = [];
  const re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    blocks.push({ label: match[1]!.trim(), der: base64ToBytes(match[2]!.replace(/\s+/g, '')) });
  }
  if (blocks.length === 0) throw new KeyImportError('no PEM block found');
  return blocks;
}

/**
 * Resolve a PEM text to the SPKI DER bytes to import as a public key:
 * - `PUBLIC KEY` is already SPKI.
 * - `CERTIFICATE` — extract its SPKI (the chain is NOT validated; the leaf's
 *   key is used as-is, which the UI states plainly).
 * - `RSA PUBLIC KEY` is bare PKCS#1; wrap it in an rsaEncryption SPKI header.
 */
export function spkiFromPem(text: string): Uint8Array {
  const [block] = decodePem(text);
  switch (block!.label) {
    case 'PUBLIC KEY':
      return block!.der;
    case 'CERTIFICATE':
      return spkiFromCertificate(block!.der);
    case 'RSA PUBLIC KEY':
      return wrapPkcs1(block!.der);
    default:
      throw new KeyImportError(`unsupported PEM block "${block!.label}"`);
  }
}

// --- minimal DER ------------------------------------------------------------

interface Tlv {
  tag: number;
  /** Offset of the tag byte. */
  start: number;
  contentStart: number;
  contentEnd: number;
  /** Offset just past the value (start of the next TLV). */
  end: number;
}

/** Read one DER TLV header at `offset`. */
function readTlv(der: Uint8Array, offset: number): Tlv {
  const tag = der[offset]!;
  let pos = offset + 1;
  let len = der[pos]!;
  pos += 1;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new KeyImportError('unsupported DER length');
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | der[pos++]!;
  }
  return { tag, start: offset, contentStart: pos, contentEnd: pos + len, end: pos + len };
}

function children(der: Uint8Array, seq: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let pos = seq.contentStart;
  while (pos < seq.contentEnd) {
    const tlv = readTlv(der, pos);
    out.push(tlv);
    pos = tlv.end;
  }
  return out;
}

/**
 * X.509 Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
 * signatureValue }. tbsCertificate ::= SEQUENCE { [0] version?, serial,
 * signature, issuer, validity, subject, subjectPublicKeyInfo, … }. The SPKI
 * is the first inner SEQUENCE shaped `SEQUENCE(AlgorithmIdentifier,
 * BIT STRING)`, returned including its own header (that is what SPKI import
 * expects).
 */
function spkiFromCertificate(der: Uint8Array): Uint8Array {
  const cert = readTlv(der, 0);
  if (cert.tag !== 0x30) throw new KeyImportError('certificate is not a SEQUENCE');
  const tbs = children(der, cert)[0];
  if (!tbs || tbs.tag !== 0x30) throw new KeyImportError('malformed tbsCertificate');
  for (const field of children(der, tbs)) {
    if (field.tag !== 0x30) continue;
    const parts = children(der, field);
    if (parts.length === 2 && parts[0]!.tag === 0x30 && parts[1]!.tag === 0x03) {
      return der.slice(field.start, field.end);
    }
  }
  throw new KeyImportError('no SubjectPublicKeyInfo found in certificate');
}

/** RSAPublicKey (PKCS#1) → SPKI by prefixing the rsaEncryption header. */
function wrapPkcs1(pkcs1: Uint8Array): Uint8Array {
  // SPKI = SEQUENCE { AlgorithmIdentifier(rsaEncryption, NULL), BIT STRING(pkcs1) }
  const algId = new Uint8Array([
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
  ]);
  const bitString = concat(new Uint8Array([0x03]), derLength(pkcs1.length + 1), new Uint8Array([0x00]), pkcs1);
  const body = concat(algId, bitString);
  return concat(new Uint8Array([0x30]), derLength(body.length), body);
}

function derLength(len: number): Uint8Array {
  if (len < 0x80) return new Uint8Array([len]);
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const p of parts) {
    out.set(p, pos);
    pos += p.length;
  }
  return out;
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
