import type { Diagnostic } from '../../model/diagnostics';
import { canonicalCurve, isKnownCryptoFamily, isKnownCurve, resolveCryptoFamily } from '../../spec/cdx-crypto-registry';
import { asRecordArray, asString, asStringArray, isRecord } from '../../util/narrow';
import { checksumProblem, createLint, createTally, licenseExpressionError } from '../spec-lint';

/**
 * Spec lint for CycloneDX BOMs, the counterpart to the SPDX and OCM ones. The
 * CDX parser is deliberately version-agnostic (it maps 1.x without insisting
 * on a version), so the lint carries the version expectations instead: an
 * unknown specVersion, a serial number that is not a URN, component types
 * outside the vocabulary, digests that cannot be digests.
 */

/** Known CycloneDX specification versions (1.0 through 1.7). */
const SPEC_VERSIONS = new Set(['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7']);

/** component.type vocabulary as of CycloneDX 1.6. */
const COMPONENT_TYPES = new Set([
  'application',
  'framework',
  'library',
  'container',
  'platform',
  'operating-system',
  'device',
  'device-driver',
  'firmware',
  'file',
  'machine-learning-model',
  'data',
  'cryptographic-asset',
]);

const URN_UUID = /^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/**
 * cryptoProperties vocabularies as of CycloneDX 1.7 (the 1.6 values are a
 * subset). The registry-backed ones (algorithmFamily, ellipticCurve) live in
 * spec/cdx-crypto-registry.ts.
 */
const CRYPTO_VOCAB: Record<string, ReadonlySet<string>> = {
  assetType: new Set(['algorithm', 'certificate', 'protocol', 'related-crypto-material']),
  primitive: new Set([
    'drbg', 'mac', 'block-cipher', 'stream-cipher', 'signature', 'hash', 'pke', 'xof', 'kdf', 'key-agree', 'kem', 'ae',
    'combiner', 'key-wrap', 'other', 'unknown',
  ]),
  executionEnvironment: new Set(['software-plain-ram', 'software-encrypted-ram', 'software-tee', 'hardware', 'other', 'unknown']),
  implementationPlatform: new Set([
    'generic', 'x86_32', 'x86_64', 'armv7-a', 'armv7-m', 'armv8-a', 'armv8-m', 'armv9-a', 'armv9-m', 's390x', 'ppc64',
    'ppc64le', 'other', 'unknown',
  ]),
  mode: new Set(['cbc', 'ecb', 'ccm', 'gcm', 'cfb', 'ofb', 'ctr', 'other', 'unknown']),
  padding: new Set(['pkcs5', 'pkcs7', 'pkcs1v15', 'oaep', 'raw', 'other', 'unknown']),
  cryptoFunctions: new Set([
    'generate', 'keygen', 'encrypt', 'decrypt', 'digest', 'tag', 'keyderive', 'sign', 'verify', 'encapsulate', 'decapsulate',
    'other', 'unknown',
  ]),
  materialType: new Set([
    'private-key', 'public-key', 'secret-key', 'key', 'ciphertext', 'signature', 'digest', 'initialization-vector', 'nonce',
    'seed', 'salt', 'shared-secret', 'tag', 'additional-data', 'password', 'credential', 'token', 'other', 'unknown',
  ]),
  materialState: new Set(['pre-activation', 'active', 'suspended', 'deactivated', 'compromised', 'destroyed']),
  protocolType: new Set(['tls', 'ssh', 'ipsec', 'ike', 'sstp', 'wpa', 'dtls', 'quic', 'eap-aka', 'eap-aka-prime', 'prins', '5g-aka', 'other', 'unknown']),
};

/** Fields 1.7 deprecated and what replaced them; a finding only on 1.7+ BOMs, where they are legal in 1.6. */
const CRYPTO_DEPRECATED: ReadonlyArray<readonly [block: string, field: string, replacement: string]> = [
  ['algorithmProperties', 'curve', 'ellipticCurve'],
  ['certificateProperties', 'signatureAlgorithmRef', 'relatedCryptographicAssets'],
  ['certificateProperties', 'subjectPublicKeyRef', 'relatedCryptographicAssets'],
  ['certificateProperties', 'certificateExtension', 'certificateFileExtension'],
  ['relatedCryptoMaterialProperties', 'algorithmRef', 'relatedCryptographicAssets'],
  ['protocolProperties', 'cryptoRefArray', 'relatedCryptographicAssets'],
];

function specAtLeast(specVersion: string | undefined, major: number, minor: number): boolean {
  const match = /^(\d+)\.(\d+)/.exec(specVersion ?? '');
  if (!match) return false;
  const [, a, b] = match;
  return Number(a) > major || (Number(a) === major && Number(b) >= minor);
}

/** licenseAcknowledgementEnumeration, CycloneDX 1.6. */
const ACKNOWLEDGEMENTS = new Set(['declared', 'concluded']);

export function validateCdxStructure(root: Record<string, unknown>): Diagnostic[] {
  const lint = createLint();
  const { warn } = lint;

  // The parser accepts any specVersion so a future BOM still opens; the lint
  // is where that tolerance gets a voice.
  const specVersion = asString(root.specVersion);
  if (specVersion !== undefined && !SPEC_VERSIONS.has(specVersion)) {
    warn('CDX_SCHEMA_UNKNOWN_SPEC_VERSION', `specVersion "${specVersion}" is not a known CycloneDX version; it was read as 1.x.`);
  }

  // serialNumber is the BOM's identity and the anchor of every BOM-Link, so a
  // malformed one breaks cross-document references.
  const serialNumber = asString(root.serialNumber);
  if (serialNumber !== undefined && !URN_UUID.test(serialNumber)) {
    warn('CDX_SCHEMA_BAD_SERIAL_NUMBER', `serialNumber "${serialNumber}" is not a urn:uuid: URN.`);
  }

  // version counts the revisions of one serialNumber; it is a positive integer.
  const version = root.version;
  if (version !== undefined && (typeof version !== 'number' || !Number.isInteger(version) || version < 1)) {
    warn('CDX_SCHEMA_BAD_VERSION', `version ${JSON.stringify(version)} is not a positive integer.`);
  }

  const badType = createTally();
  const badHash = createTally();
  const badPurl = createTally();
  const badLicense = createTally();
  const badAcknowledgement = createTally();
  const duplicateRef = createTally({ unique: true });
  const seenRefs = new Set<string>();
  const cryptoMissingAssetType = createTally();
  const cryptoBadVocabulary = createTally();
  const cryptoUnknownFamily = createTally();
  const cryptoUnknownCurve = createTally();
  const cryptoDeprecated = createTally();
  const deprecationApplies = specAtLeast(specVersion, 1, 7);

  // CBOM: the asset kind is mandatory, the closed vocabularies are checked as
  // such, and the two registry-backed names against the registry. 1.6 fields
  // that 1.7 deprecated count only on 1.7+ BOMs.
  const visitCrypto = (name: string, type: string | undefined, cp: Record<string, unknown> | undefined) => {
    if (type !== 'cryptographic-asset' && !cp) return;
    const assetType = cp ? asString(cp.assetType) : undefined;
    if (assetType === undefined) cryptoMissingAssetType.add(name);
    else if (!CRYPTO_VOCAB.assetType!.has(assetType)) cryptoBadVocabulary.add(`${name}: assetType=${assetType}`);
    if (!cp) return;
    const vocab = (block: Record<string, unknown> | undefined, field: string, set: string) => {
      if (!block) return;
      const values = Array.isArray(block[field]) ? asStringArray(block[field]) : asString(block[field]) !== undefined ? [asString(block[field])!] : [];
      for (const value of values) if (!CRYPTO_VOCAB[set]!.has(value)) cryptoBadVocabulary.add(`${name}: ${field}=${value}`);
    };
    const ap = isRecord(cp.algorithmProperties) ? cp.algorithmProperties : undefined;
    vocab(ap, 'primitive', 'primitive');
    vocab(ap, 'executionEnvironment', 'executionEnvironment');
    vocab(ap, 'implementationPlatform', 'implementationPlatform');
    vocab(ap, 'mode', 'mode');
    vocab(ap, 'padding', 'padding');
    vocab(ap, 'cryptoFunctions', 'cryptoFunctions');
    const family = ap ? asString(ap.algorithmFamily) : undefined;
    if (family !== undefined && !isKnownCryptoFamily(family)) {
      const known = resolveCryptoFamily(family);
      cryptoUnknownFamily.add(`${name}: ${family}${known ? ` (registry spells it ${known.family})` : ''}`);
    }
    const curve = ap ? asString(ap.ellipticCurve) : undefined;
    if (curve !== undefined && !isKnownCurve(curve)) {
      const canonical = canonicalCurve(curve);
      cryptoUnknownCurve.add(`${name}: ${curve}${canonical ? ` (registry: ${canonical})` : ''}`);
    }
    const mat = isRecord(cp.relatedCryptoMaterialProperties) ? cp.relatedCryptoMaterialProperties : undefined;
    vocab(mat, 'type', 'materialType');
    vocab(mat, 'state', 'materialState');
    const proto = isRecord(cp.protocolProperties) ? cp.protocolProperties : undefined;
    vocab(proto, 'type', 'protocolType');
    if (deprecationApplies) {
      for (const [block, field, replacement] of CRYPTO_DEPRECATED) {
        const node = isRecord(cp[block]) ? cp[block] : undefined;
        if (node && node[field] !== undefined) cryptoDeprecated.add(`${name}: ${block}.${field} (use ${replacement})`);
      }
    }
  };

  const visit = (component: Record<string, unknown>) => {
    const name = asString(component.name) ?? '(unnamed component)';

    const type = asString(component.type);
    if (type !== undefined && !COMPONENT_TYPES.has(type)) badType.add(`${name} (${type})`);

    // bom-refs address components from dependencies and BOM-Links; a duplicate
    // makes those references ambiguous.
    const bomRef = asString(component['bom-ref']);
    if (bomRef !== undefined) {
      if (seenRefs.has(bomRef)) duplicateRef.add(bomRef);
      else seenRefs.add(bomRef);
    }

    for (const entry of asRecordArray(component.hashes)) {
      const algorithm = asString(entry.alg);
      const content = asString(entry.content);
      if (algorithm === undefined || content === undefined) continue;
      const problem = checksumProblem(algorithm, content);
      if (problem) badHash.add(`${name}: ${problem}`);
    }

    const purl = asString(component.purl);
    if (purl !== undefined && !purl.startsWith('pkg:')) badPurl.add(`${name} (${purl})`);

    visitCrypto(name, type, isRecord(component.cryptoProperties) ? component.cryptoProperties : undefined);

    for (const entry of asRecordArray(component.licenses)) {
      const expression = asString(entry.expression);
      if (expression !== undefined) {
        const problem = licenseExpressionError(expression);
        if (problem) badLicense.add(`${name}: ${problem}`);
      }
      // license is either an id or a name, never both (the schema says oneOf).
      const license = isRecord(entry.license) ? entry.license : undefined;
      if (license && asString(license.id) && asString(license.name)) {
        badLicense.add(`${name}: license carries both id and name`);
      }
      // 1.6: acknowledgement says whether the entry is declared or concluded.
      // It sits on the license object, or next to an expression; the parser
      // reads both places, so the lint checks both.
      const acknowledgement = asString(entry.acknowledgement) ?? (license ? asString(license.acknowledgement) : undefined);
      if (acknowledgement !== undefined && !ACKNOWLEDGEMENTS.has(acknowledgement)) {
        badAcknowledgement.add(`${name} (${acknowledgement})`);
      }
    }

    for (const nested of asRecordArray(component.components)) visit(nested);
  };

  const metadataComponent = isRecord(root.metadata) ? root.metadata.component : undefined;
  if (isRecord(metadataComponent)) visit(metadataComponent);
  for (const component of asRecordArray(root.components)) visit(component);

  lint.warnTally('CDX_SCHEMA_BAD_COMPONENT_TYPE', badType, (count, list) => `${count} component(s) with a type outside the CycloneDX vocabulary: ${list}.`);
  lint.warnTally('CDX_SCHEMA_DUPLICATE_BOM_REF', duplicateRef, (count, list) => `${count} bom-ref(s) are used more than once, which makes references ambiguous: ${list}.`);
  lint.warnTally('CDX_SCHEMA_BAD_HASH', badHash, (count, list) => `${count} hash(es) do not match their algorithm: ${list}.`);
  lint.warnTally('CDX_SCHEMA_BAD_PURL', badPurl, (count, list) => `${count} purl(s) do not start with "pkg:": ${list}.`);
  lint.warnTally('CDX_SCHEMA_BAD_LICENSE_EXPRESSION', badLicense, (count, list) => `${count} license ${count === 1 ? 'entry is' : 'entries are'} malformed: ${list}.`);
  lint.warnTally(
    'CDX_SCHEMA_BAD_ACKNOWLEDGEMENT',
    badAcknowledgement,
    (count, list) => `${count} license acknowledgement(s) outside the CycloneDX 1.6 vocabulary (declared, concluded): ${list}.`,
  );
  lint.warnTally(
    'CDX_SCHEMA_CRYPTO_MISSING_ASSET_TYPE',
    cryptoMissingAssetType,
    (count, list) => `${count} cryptographic asset(s) without cryptoProperties.assetType (algorithm, certificate, protocol, related-crypto-material): ${list}.`,
  );
  lint.warnTally(
    'CDX_SCHEMA_CRYPTO_BAD_VOCABULARY',
    cryptoBadVocabulary,
    (count, list) => `${count} cryptoProperties value(s) outside the CycloneDX vocabulary: ${list}.`,
  );
  lint.warnTally(
    'CDX_SCHEMA_CRYPTO_UNKNOWN_FAMILY',
    cryptoUnknownFamily,
    (count, list) => `${count} algorithmFamily value(s) not in the CycloneDX Cryptography Registry: ${list}.`,
  );
  lint.warnTally(
    'CDX_SCHEMA_CRYPTO_UNKNOWN_CURVE',
    cryptoUnknownCurve,
    (count, list) => `${count} ellipticCurve value(s) not in the CycloneDX Cryptography Registry (expected category/name, e.g. nist/P-256): ${list}.`,
  );
  lint.warnTally(
    'CDX_SCHEMA_CRYPTO_DEPRECATED_FIELD',
    cryptoDeprecated,
    (count, list) => `${count} cryptoProperties field(s) deprecated since CycloneDX 1.7 in a 1.7+ BOM: ${list}.`,
  );

  return lint.diagnostics;
}
