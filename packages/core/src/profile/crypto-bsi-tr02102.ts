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
 * the BOM and the TR, not a verdict that it is insecure, and an asset that
 * matches is not thereby secure (the TR's conditions of use, hybridisation
 * and implementation requirements live outside a BOM). Families are
 * matched by the name the BOM states, so FrodoKEM and Classic McEliece,
 * which the TR recommends but the CycloneDX registry does not list yet,
 * still count here.
 *
 * Parameter sets are read from parameterSetIdentifier as CycloneDX defines
 * it: the key length in bits for RSA, DH and AES, the digest length for
 * SHA-2/SHA-3, the NIST parameter set name for ML-KEM, ML-DSA and SLH-DSA.
 */
const RSA = ['RSASSA-PKCS1', 'RSASSA-PSS', 'RSA-X931', 'RSAES-PKCS1', 'RSAES-OAEP', 'RSA'];
const EC = ['ECDSA', 'ECDH', 'ECIES', 'ECKDSA', 'ECKCDSA', 'ECGDSA', 'MQV'];
const AT_LEAST_3000 = '^(3[0-9]{3}|[4-9][0-9]{3}|[1-9][0-9]{4,})$';

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
    'from: RSA, DH and DLIES moduli of at least 3000 bits and EC orders of ' +
    'at least 250 bits (Table 2.2), the brainpool curves of Table B.3, ' +
    'FrodoKEM-976 and -1344, Classic McEliece 460896, 6688128 and 8192128 ' +
    'and ML-KEM-768 and -1024 (Tables 2.5 to 2.7), AES-128, -192 and -256 ' +
    '(Table 3.1) in the modes of Table 3.2, the SHA-2 and SHA-3 functions ' +
    'with at least 256-bit output (Table 4.1), and the quantum-safe ' +
    'signature schemes ML-DSA-65 and -87, SLH-DSA at NIST categories 3 and ' +
    '5, XMSS and LMS (Tables 5.6 to 5.8). The TR states migration horizons: ' +
    'the sole use of classical key agreement is recommended only until the ' +
    'end of 2031 (end of 2030 for very high protection needs), classical ' +
    'signatures until the end of 2035, quantum-safe mechanisms in hybrid ' +
    'form (section 2.1); the meter on classical key agreement shows how ' +
    'much of the inventory that horizon concerns. A match means the stated ' +
    'parameter is within the cited recommendation and nothing more: the ' +
    'conditions of use in the TR, hybridisation and implementation requirements ' +
    'cannot be read off a BOM, an unmatched asset is not thereby insecure, ' +
    'and no threshold gates. Families are matched by the name the BOM ' +
    'states; FrodoKEM and Classic McEliece, which the TR recommends but the ' +
    'CycloneDX Cryptography Registry does not list yet, count here even ' +
    'though the registry lint reports them as unknown. A BOM without the ' +
    'assets a row refers to reads none in scope.',
  checks: [
    // --- Asymmetric: Table 2.2, Table B.3, Tables 2.5 to 2.7 ----------------
    {
      id: 'rsa-modulus',
      type: 'crypto-coverage',
      field: 'parameterSet',
      assetTypes: ['algorithm'],
      families: RSA,
      pattern: AT_LEAST_3000,
      label: 'RSA: modulus of at least 3000 bits (Table 2.2; key transport until end of 2031, signatures until end of 2035)',
    },
    {
      id: 'dh-modulus',
      type: 'crypto-coverage',
      field: 'parameterSet',
      assetTypes: ['algorithm'],
      families: ['FFDH', 'DH', 'DLIES', 'ElGamal', 'DSA'],
      pattern: AT_LEAST_3000,
      label: 'DH, DLIES, DSA: prime of at least 3000 bits (Table 2.2; DSA only until 2029, 5.3.2)',
    },
    {
      id: 'ec-order',
      type: 'crypto-coverage',
      field: 'curve',
      assetTypes: ['algorithm'],
      families: EC,
      pattern: '(25[0-9]|2[6-9][0-9]|[3-9][0-9]{2}|[1-9][0-9]{3})',
      label: 'EC mechanisms: curve with an order of at least 250 bits (Table 2.2, 5.3.3)',
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
      id: 'classical-key-agreement',
      type: 'crypto-coverage',
      field: 'family',
      assetTypes: ['algorithm'],
      primitives: ['key-agree', 'pke', 'kem'],
      values: [...RSA, 'FFDH', 'DH', 'DLIES', 'ECDH', 'ECIES', 'MQV', 'ElGamal'],
      label: 'Key agreement and transport: classical family (sole use recommended only until end of 2031, section 2.1)',
    },
    {
      id: 'pq-kem',
      type: 'crypto-coverage',
      field: 'parameterSet',
      assetTypes: ['algorithm'],
      families: ['ML-KEM', 'FrodoKEM', 'Classic-McEliece', 'ClassicMcEliece', 'Classic McEliece'],
      pattern: '^(ML-KEM-)?(768|1024)$|^(FrodoKEM-)?(976|1344)$|^(mceliece)?(460896|6688128|8192128)f?$',
      label: 'Quantum-safe KEM: FrodoKEM-976/1344, Classic McEliece 460896/6688128/8192128, ML-KEM-768/1024 (Tables 2.5 to 2.7)',
    },
    // --- Symmetric: Tables 3.1 and 3.2 -------------------------------------
    {
      id: 'aes-key-length',
      type: 'crypto-coverage',
      field: 'parameterSet',
      assetTypes: ['algorithm'],
      families: ['AES'],
      pattern: '^(128|192|256)$',
      label: 'AES: 128, 192 or 256-bit key (Table 3.1; 256 advisable for long-term protection)',
    },
    {
      id: 'aes-mode',
      type: 'crypto-coverage',
      field: 'mode',
      assetTypes: ['algorithm'],
      families: ['AES'],
      values: ['cbc', 'ctr', 'ccm', 'gcm'],
      label: 'AES: mode of operation from Table 3.2 (CBC, CTR, CCM, GCM)',
    },
    {
      id: 'block-cipher-aes',
      type: 'crypto-coverage',
      field: 'family',
      assetTypes: ['algorithm'],
      primitives: ['block-cipher', 'ae'],
      values: ['AES'],
      label: 'Block ciphers: AES, the only block cipher Table 3.1 recommends',
    },
    // --- Hash functions: Table 4.1 -----------------------------------------
    {
      id: 'hash-family',
      type: 'crypto-coverage',
      field: 'family',
      assetTypes: ['algorithm'],
      primitives: ['hash'],
      values: ['SHA-2', 'SHA-3'],
      label: 'Hash functions: SHA-2 or SHA-3 family (Table 4.1; SHA-1 never as a secure hash, Remark 4.2)',
    },
    {
      id: 'hash-length',
      type: 'crypto-coverage',
      field: 'parameterSet',
      assetTypes: ['algorithm'],
      families: ['SHA-2', 'SHA-3'],
      pattern: '^(256|384|512|512/256)$',
      label: 'SHA-2 and SHA-3: output of at least 256 bits (Table 4.1)',
    },
    // --- Signatures: Tables 5.3 and 5.6 to 5.8 -----------------------------
    {
      id: 'pq-signature-family',
      type: 'crypto-coverage',
      field: 'family',
      assetTypes: ['algorithm'],
      primitives: ['signature'],
      values: ['ML-DSA', 'SLH-DSA', 'XMSS', 'LMS'],
      label: 'Signatures: quantum-safe scheme of Table 5.3 (classical schemes recommended until end of 2035, section 2.1)',
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
