/**
 * Cryptographic asset data as CycloneDX 1.6/1.7 `cryptoProperties` carries
 * it (the CBOM profile), attached to an element as `crypto`. Field names
 * follow the specification with one simplification: the four asset kinds
 * keep their own blocks, and every bom-ref that points at another asset
 * (the 1.7 relatedCryptographicAssets, and the 1.6 per-field refs they
 * replaced) is collected under `related` so a reader sees the graph in one
 * place.
 *
 * Read, never rated: whether a primitive or key length is adequate is a
 * question for the requirement sources the crypto profiles cite.
 */

export interface CryptoAlgorithm {
  /** drbg, mac, block-cipher, stream-cipher, signature, hash, pke, xof, kdf, key-agree, kem, ae, combiner, key-wrap, other, unknown */
  primitive?: string;
  /** 1.7 algorithmFamily, a Cryptography Registry name (RSASSA-PSS, AES, ML-KEM, ...). */
  family?: string;
  /** parameterSetIdentifier: "128" in AES-128, "3072" for an RSA modulus, "65" in ML-DSA-65. */
  parameterSet?: string;
  /** 1.7 ellipticCurve (`nist/P-256`, `brainpool/brainpoolP256r1`). */
  ellipticCurve?: string;
  /** 1.6 `curve`, deprecated in 1.7 in favour of ellipticCurve; kept verbatim. */
  curve?: string;
  executionEnvironment?: string;
  implementationPlatform?: string;
  certificationLevel?: string[];
  mode?: string;
  padding?: string;
  cryptoFunctions?: string[];
  classicalSecurityLevel?: number;
  nistQuantumSecurityLevel?: number;
}

export interface CryptoCertificate {
  serialNumber?: string;
  subjectName?: string;
  issuerName?: string;
  notValidBefore?: string;
  notValidAfter?: string;
  certificateFormat?: string;
  /** 1.7 certificateFileExtension, or the 1.6 certificateExtension it replaced. */
  fileExtension?: string;
  /** Lifecycle states (1.7), the pre-defined names or the custom ones. */
  states?: string[];
  creationDate?: string;
  activationDate?: string;
  deactivationDate?: string;
  revocationDate?: string;
  destructionDate?: string;
  fingerprint?: { algorithm?: string; value?: string };
}

export interface CryptoMaterial {
  /** private-key, public-key, secret-key, key, ciphertext, signature, digest, ... */
  type?: string;
  id?: string;
  /** pre-activation, active, suspended, deactivated, compromised, destroyed */
  state?: string;
  creationDate?: string;
  activationDate?: string;
  updateDate?: string;
  expirationDate?: string;
  /** Size in bits. */
  size?: number;
  format?: string;
  securedBy?: { mechanism?: string; algorithmRef?: string };
}

export interface CryptoCipherSuite {
  name?: string;
  /** bom-refs of the algorithms the suite uses. */
  algorithms?: string[];
  /** IANA identifiers such as 0xC0,0x2F. */
  identifiers?: string[];
}

export interface CryptoProtocol {
  /** tls, ssh, ipsec, ike, sstp, wpa, dtls, quic, eap-aka, ... */
  type?: string;
  version?: string;
  cipherSuites?: CryptoCipherSuite[];
}

/** A bom-ref to another cryptographic asset and what role it plays for this one. */
export interface CryptoRelatedAsset {
  /** 1.7 relationship type (signs, verifies, encrypts, ... ) or the 1.6 field the ref came from (signatureAlgorithm, subjectPublicKey, algorithm, protocolCrypto). */
  type: string;
  ref: string;
}

export interface CryptoElementExt {
  /** algorithm, certificate, protocol, related-crypto-material; undefined when the BOM omitted it. */
  assetType?: string;
  oid?: string;
  algorithm?: CryptoAlgorithm;
  certificate?: CryptoCertificate;
  material?: CryptoMaterial;
  protocol?: CryptoProtocol;
  related?: CryptoRelatedAsset[];
}
