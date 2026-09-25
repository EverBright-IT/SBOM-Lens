import type { ComplianceProfile } from './model';
import { PROFILE_SCHEMA_V5 } from './model';

/**
 * BSI TR-02102-1 "Cryptographic Mechanisms: Recommendations and Key
 * Lengths", version 2026-01 (23 January 2026). The TR recommends
 * mechanisms and parameters for a security level of 120 bits and, since
 * this version, states migration horizons: the sole use of classical key
 * agreement is recommended only until the end of 2031 (end of 2030 for
 * very high protection needs), classical signatures until the end of 2035,
 * and quantum-safe mechanisms in hybrid form (section 2.1).
 *
 * Every check cites the table it comes from and counts how many assets in
 * scope state a recommended parameter. That is all it does: an asset that
 * does not match is outside the cited recommendation, which is a fact about
 * the BOM and the TR and not a verdict on the asset, and an asset that
 * matches is not thereby within the TR's conditions of use (those,
 * hybridisation and the implementation requirements live outside a BOM).
 *
 * Which field a row reads decides which BOMs it can see:
 *   - Rows filtered by `families` read the 1.7 algorithmFamily to know
 *     what an asset is. A 1.6 CBOM has no family field, so those rows read
 *     none in scope there.
 *   - The rows on the scheme itself read the asset NAME, so 1.6 and 1.7
 *     BOMs both count, and because FrodoKEM and Classic McEliece are not in
 *     the CycloneDX Cryptography Registry: a schema-valid 1.7 BOM cannot
 *     state them as a family. The spellings matched are on each row.
 *   - Parameter sets are read from parameterSetIdentifier as CycloneDX
 *     defines it: the key length in bits for RSA, DH and AES, the digest
 *     length for SHA-2/SHA-3, the parameter set name for ML-KEM, ML-DSA and
 *     SLH-DSA.
 *
 * Table attributions were checked against the PDF: Table 2.2 lists RSA,
 * DLIES, ECIES, DH and ECDH (3000 bits, or 250 for the EC schemes, until
 * 2031); DSA is section 5.3.2 with Remark 5.5 (only until 2029); the EC
 * signature schemes are section 5.3.3; Table 3.2 lists CBC, CTR, CCM, GCM
 * and AES-GCM-SIV, of which the CycloneDX mode vocabulary cannot express
 * the last.
 */
const RSA = ['RSASSA-PKCS1', 'RSASSA-PSS', 'RSA-X931', 'RSAES-PKCS1', 'RSAES-OAEP', 'RSA'];
/** Table 2.2 (ECIES, ECDH) and section 5.3.3 (ECDSA, ECKDSA, ECGDSA). */
const EC = ['ECDSA', 'ECDH', 'ECIES', 'ECKDSA', 'ECGDSA'];
const KEM_PRIMITIVES = ['key-agree', 'pke', 'kem'];
const AT_LEAST_3000 = '^(3[0-9]{3}|[4-9][0-9]{3}|[1-9][0-9]{4,})$';
/** An order of at least 250 bits, read off the curve name after an optional registry category (nist/P-256, brainpoolP512r1, secp384r1). */
const EC_ORDER_AT_LEAST_250 = '^(?:[^/]*/)?[A-Za-z -]*(25[0-9]|2[6-9][0-9]|[3-9][0-9]{2}|[1-9][0-9]{3})';
/** ML-KEM, FrodoKEM, Classic McEliece as BOMs spell them in an asset name. */
const PQ_KEM_NAMED = '(ML-?KEM|ml-?kem|[Ff]rodo|[Cc]lassic[- ]?[Mm]c[Ee]liece|mceliece)';
/** The recommended parameter sets of Tables 2.5 to 2.7, as names carry them. */
const PQ_KEM_PARAMETER_NAMED =
  '(ML-?KEM-?(768|1024)|ml-?kem-?(768|1024)|[Ff]rodo[- ]?(KEM|kem)-?(976|1344)|[Cc]lassic[- ]?[Mm]c[Ee]liece[- ]?(460896|6688128|8192128)|mceliece(460896|6688128|8192128))';
/** ML-DSA, SLH-DSA, XMSS (also XMSSMT), LMS as names carry them: MLDSA65, mldsa65, XMSSMT-SHA2_20/2_256, LMS_SHA256_M32_H5. */
const PQ_SIGNATURE_NAMED = '\\b(ML-?DSA|ml-?dsa|SLH-?DSA|slh-?dsa|XMSS|xmss|LMS|lms)';
const AES_NAMED = '(AES|aes)';
/**
 * The functions Table 4.1 lists, as names carry them: SHA-256, SHA-384,
 * SHA-512, SHA-512/256 (also sha256, SHA2-256) and SHA3-256/384/512 (also
 * sha3_256). SHA-224, SHA3-224 and SHA-1 are not in the table and do not match.
 */
const SHA2_OR_SHA3_NAMED = '(SHA|sha)[-_]?2?[-_]?(256|384|512)|(SHA|sha)[-_]?3[-_]?(256|384|512)';

export const CRYPTO_BSI_TR02102_PROFILE: ComplianceProfile = {
  schema: PROFILE_SCHEMA_V5,
  name: 'BSI TR-02102-1 (2026-01): recommended parameters',
  specUrl: 'https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.html',
  requires: { spec: 'cdx-1.6' },
  description:
    'Counts, per mechanism class, how many cryptographic assets of a ' +
    'CycloneDX CBOM state a parameter that BSI TR-02102-1 (Cryptographic ' +
    'Mechanisms: Recommendations and Key Lengths, version 2026-01 of 23 ' +
    'January 2026) recommends, citing the table each recommendation comes ' +
    'from: RSA, DLIES and DH moduli of at least 3000 bits and EC orders of ' +
    'at least 250 bits (Table 2.2, with DSA from section 5.3.2 and the EC ' +
    'signature schemes from 5.3.3), the brainpool curves of Table B.3, ' +
    'FrodoKEM-976 and -1344, Classic McEliece 460896, 6688128 and 8192128 ' +
    'and ML-KEM-768 and -1024 (Tables 2.5 to 2.7), AES-128, -192 and -256 ' +
    '(Table 3.1) in the modes of Table 3.2, the SHA-2 and SHA-3 functions ' +
    'with at least 256-bit output (Table 4.1), and the quantum-safe ' +
    'signature schemes ML-DSA-65 and -87, SLH-DSA at 192 or 256 bits, XMSS ' +
    'and LMS (Tables 5.3 and 5.6 to 5.8). The TR states migration horizons: ' +
    'the sole use of classical key agreement is recommended only until the ' +
    'end of 2031 (end of 2030 for very high protection needs), classical ' +
    'signatures until the end of 2035, quantum-safe mechanisms in hybrid ' +
    'form (section 2.1); the key-agreement meter shows the quantum-safe ' +
    'share, and the remainder is what that horizon concerns. Rows that read ' +
    'a parameter set, mode or curve identify the algorithm through the ' +
    'CycloneDX 1.7 algorithmFamily and read none in scope on a 1.6 CBOM, ' +
    'which has no family field; the rows on the scheme itself read the ' +
    'asset name, so both generations count and FrodoKEM and Classic ' +
    'McEliece, which the TR recommends but the Cryptography Registry does ' +
    'not list, count as well. A match means the stated parameter is within ' +
    'the cited recommendation and nothing more: the conditions of use in ' +
    'the TR, hybridisation and implementation requirements cannot be read ' +
    'off a BOM, an unmatched asset is outside the cited table and nothing ' +
    'else is said about it, and no threshold gates. A BOM without the assets ' +
    'a row refers to reads none in scope.',
  checks: [
    // --- Asymmetric: Table 2.2, Table B.3, Tables 2.5 to 2.7 ----------------
    {
      id: 'rsa-modulus',
      type: 'crypto-coverage',
      field: 'parameterSet',
      assetTypes: ['algorithm'],
      families: RSA,
      pattern: AT_LEAST_3000,
      label:
        'RSA: modulus of at least 3000 bits (Table 2.2 and 5.3.1; key transport until end of 2031, signatures until end of 2035; the padding scheme is not read)',
    },
    {
      id: 'dh-modulus',
      type: 'crypto-coverage',
      field: 'parameterSet',
      assetTypes: ['algorithm'],
      families: ['FFDH', 'DH', 'DLIES', 'DSA'],
      pattern: AT_LEAST_3000,
      label: 'DH, DLIES, DSA: prime of at least 3000 bits (Table 2.2; DSA in 5.3.2, recommended only until 2029)',
    },
    {
      id: 'ec-order',
      type: 'crypto-coverage',
      field: 'curve',
      assetTypes: ['algorithm'],
      families: EC,
      pattern: EC_ORDER_AT_LEAST_250,
      label: 'EC mechanisms: curve with an order of at least 250 bits, read off the curve name (Table 2.2, 5.3.3)',
    },
    {
      id: 'ec-brainpool',
      type: 'crypto-coverage',
      field: 'curve',
      assetTypes: ['algorithm'],
      families: EC,
      pattern: '^(brainpool/)?brainpoolP(256|320|384|512)r1$',
      label: 'EC mechanisms: brainpool curve of Table B.3',
    },
    {
      id: 'key-agreement-quantum-safe',
      type: 'crypto-coverage',
      field: 'name',
      assetTypes: ['algorithm'],
      primitives: KEM_PRIMITIVES,
      pattern: PQ_KEM_NAMED,
      label:
        'Key agreement and transport: quantum-safe scheme named, ML-KEM, FrodoKEM or Classic McEliece (Tables 2.5 to 2.7; classical schemes alone recommended only until end of 2031, section 2.1)',
    },
    {
      id: 'pq-kem-parameter-set',
      type: 'crypto-coverage',
      field: 'name',
      assetTypes: ['algorithm'],
      primitives: KEM_PRIMITIVES,
      pattern: PQ_KEM_PARAMETER_NAMED,
      label:
        'Key agreement and transport: recommended quantum-safe parameter set named, ML-KEM-768/1024, FrodoKEM-976/1344, Classic McEliece 460896/6688128/8192128 (Tables 2.5 to 2.7)',
    },
    {
      id: 'ml-kem-parameter-set',
      type: 'crypto-coverage',
      field: 'parameterSet',
      assetTypes: ['algorithm'],
      families: ['ML-KEM'],
      pattern: '^(ML-KEM-)?(768|1024)$',
      label: 'ML-KEM: parameter set 768 or 1024 (Table 2.7; CycloneDX 1.7 family and parameterSetIdentifier)',
    },
    // --- Symmetric: Tables 3.1 and 3.2 -------------------------------------
    {
      id: 'aes-key-length',
      type: 'crypto-coverage',
      field: 'parameterSet',
      assetTypes: ['algorithm'],
      families: ['AES'],
      pattern: '^(128|192|256)$',
      label: 'AES: 128, 192 or 256-bit key (Table 3.1)',
    },
    {
      id: 'aes-mode',
      type: 'crypto-coverage',
      field: 'mode',
      assetTypes: ['algorithm'],
      families: ['AES'],
      values: ['cbc', 'ctr', 'ccm', 'gcm'],
      label: 'AES: mode of operation from Table 3.2 (CBC, CTR, CCM, GCM; AES-GCM-SIV is in the table but has no CycloneDX mode value)',
    },
    {
      id: 'block-cipher-aes',
      type: 'crypto-coverage',
      field: 'name',
      assetTypes: ['algorithm'],
      primitives: ['block-cipher', 'ae'],
      pattern: AES_NAMED,
      label: 'Block ciphers and AEAD modes: AES named (Table 3.1 recommends AES as the block cipher)',
    },
    // --- Hash functions: Table 4.1 -----------------------------------------
    {
      id: 'hash-family',
      type: 'crypto-coverage',
      field: 'name',
      assetTypes: ['algorithm'],
      primitives: ['hash'],
      pattern: SHA2_OR_SHA3_NAMED,
      label: 'Hash functions: SHA-2 or SHA-3 function named (Table 4.1)',
    },
    {
      id: 'hash-length',
      type: 'crypto-coverage',
      field: 'parameterSet',
      assetTypes: ['algorithm'],
      families: ['SHA-2', 'SHA-3'],
      pattern: '^(256|384|512|512/256)$',
      label: 'SHA-2 and SHA-3: output of at least 256 bits (Table 4.1; CycloneDX 1.7 family and parameterSetIdentifier)',
    },
    // --- Signatures: Tables 5.3 and 5.6 to 5.8 -----------------------------
    {
      id: 'pq-signature',
      type: 'crypto-coverage',
      field: 'name',
      assetTypes: ['algorithm'],
      primitives: ['signature'],
      pattern: PQ_SIGNATURE_NAMED,
      label:
        'Signatures: quantum-safe scheme named, ML-DSA, SLH-DSA, XMSS or LMS (Table 5.3; classical schemes recommended until end of 2035, section 2.1)',
    },
    {
      id: 'ml-dsa-parameter-set',
      type: 'crypto-coverage',
      field: 'parameterSet',
      assetTypes: ['algorithm'],
      families: ['ML-DSA'],
      pattern: '^(ML-DSA-)?(65|87)$',
      label: 'ML-DSA: parameter set 65 or 87 (Table 5.7)',
    },
    {
      id: 'slh-dsa-parameter-set',
      type: 'crypto-coverage',
      field: 'parameterSet',
      assetTypes: ['algorithm'],
      families: ['SLH-DSA'],
      pattern: '(192|256)[sf]$',
      label: 'SLH-DSA: SHA2 or SHAKE parameter set at 192 or 256 bits, s or f (Table 5.6)',
    },
  ],
};
