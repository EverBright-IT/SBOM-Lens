import type { ComplianceProfile } from './model';
import { PROFILE_SCHEMA_V5 } from './model';

/**
 * Coordinated Implementation Roadmap for the Transition to Post-Quantum
 * Cryptography (NIS Cooperation Group, version 1.1, 11 June 2025). Its first
 * milestone, by the end of 2026, is that Member States start the transition
 * with national strategies, risk assessments and cryptographic inventories;
 * high-risk use cases follow by the end of 2030, the rest by the end of
 * 2035. CycloneDX names the CBOM as the machine-readable form of such an
 * inventory, and this profile measures how complete one is: does every
 * asset say what it is, does every algorithm name its family, parameter
 * set and primitive, does every certificate carry its validity, does every
 * protocol list its cipher suites, and is the quantum-safe share visible.
 *
 * A complete inventory is the roadmap's first step, not its goal; nothing
 * here says whether a mechanism should be replaced. The profile gates only
 * the format baseline (CBOM data exists from CycloneDX 1.6 on).
 */
export const CRYPTO_EU_ROADMAP_PROFILE: ComplianceProfile = {
  schema: PROFILE_SCHEMA_V5,
  name: 'EU PQC roadmap: cryptographic inventory',
  specUrl:
    'https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography',
  requires: { spec: 'cdx-1.6' },
  description:
    'Measures how complete a cryptographic inventory (CycloneDX CBOM, ' +
    'cryptoProperties) is against what the Coordinated Implementation ' +
    'Roadmap for the Transition to Post-Quantum Cryptography (NIS ' +
    'Cooperation Group, version 1.1, 11 June 2025) asks Member States to ' +
    'start with by the end of 2026: cryptographic inventories alongside ' +
    'national strategies and risk assessments, with high-risk use cases ' +
    'transitioned by the end of 2030 and the remainder by the end of 2035. ' +
    'Every check is a coverage meter over the cryptographic assets of the ' +
    'BOM: asset kind stated; for algorithms the family, parameter set, ' +
    'primitive and security level; for certificates subject, issuer and ' +
    'validity; for keys and other material the lifecycle state and ' +
    'expiration; for protocols the version and cipher suites; and the ' +
    'relationships that say which component provides which asset. The ' +
    'quantum-safe share of key encapsulation and signature algorithms is a ' +
    'meter as well (ML-KEM, ML-DSA, SLH-DSA, XMSS, LMS, FrodoKEM, Classic ' +
    'McEliece and HQC as the BOM names them). A complete inventory is the ' +
    'first step of the roadmap, not a statement about the risk of any ' +
    'mechanism, and no threshold gates: only the format baseline does, ' +
    'because CBOM data exists from CycloneDX 1.6 on. A BOM without ' +
    'cryptographic assets reads none in scope.',
  checks: [
    { id: 'asset-type', type: 'crypto-coverage', field: 'assetType', label: 'Asset kind stated (algorithm, certificate, protocol, material)' },
    { id: 'algorithm-family', type: 'crypto-coverage', field: 'family', assetTypes: ['algorithm'], label: 'Algorithms: family named' },
    { id: 'algorithm-parameter-set', type: 'crypto-coverage', field: 'parameterSet', assetTypes: ['algorithm'], label: 'Algorithms: parameter set (key or digest length) stated' },
    { id: 'algorithm-primitive', type: 'crypto-coverage', field: 'primitive', assetTypes: ['algorithm'], label: 'Algorithms: primitive stated' },
    { id: 'algorithm-security-level', type: 'crypto-coverage', field: 'securityLevel', assetTypes: ['algorithm'], label: 'Algorithms: classical or NIST quantum security level stated' },
    {
      id: 'quantum-safe-kem',
      type: 'crypto-coverage',
      field: 'family',
      assetTypes: ['algorithm'],
      primitives: ['kem', 'key-agree'],
      values: ['ML-KEM', 'FrodoKEM', 'Classic-McEliece', 'ClassicMcEliece', 'Classic McEliece', 'HQC'],
      label: 'Key agreement and encapsulation: quantum-safe family (share of the inventory)',
    },
    {
      id: 'quantum-safe-signature',
      type: 'crypto-coverage',
      field: 'family',
      assetTypes: ['algorithm'],
      primitives: ['signature'],
      values: ['ML-DSA', 'SLH-DSA', 'XMSS', 'LMS'],
      label: 'Signatures: quantum-safe family (share of the inventory)',
    },
    { id: 'certificate-subject', type: 'crypto-coverage', field: 'certificateSubject', assetTypes: ['certificate'], label: 'Certificates: subject stated' },
    { id: 'certificate-issuer', type: 'crypto-coverage', field: 'certificateIssuer', assetTypes: ['certificate'], label: 'Certificates: issuer stated' },
    { id: 'certificate-validity', type: 'crypto-coverage', field: 'certificateValidity', assetTypes: ['certificate'], label: 'Certificates: validity end stated' },
    { id: 'material-state', type: 'crypto-coverage', field: 'materialState', assetTypes: ['related-crypto-material'], label: 'Keys and material: lifecycle state stated' },
    { id: 'material-expiration', type: 'crypto-coverage', field: 'materialExpiration', assetTypes: ['related-crypto-material'], label: 'Keys and material: expiration stated' },
    { id: 'protocol-version', type: 'crypto-coverage', field: 'protocolVersion', assetTypes: ['protocol'], label: 'Protocols: version stated' },
    { id: 'protocol-cipher-suites', type: 'crypto-coverage', field: 'cipherSuites', assetTypes: ['protocol'], label: 'Protocols: cipher suites listed' },
    { id: 'relationships', type: 'relationships', informational: true, label: 'Relationships stated (which component provides or depends on which asset)' },
  ],
};
